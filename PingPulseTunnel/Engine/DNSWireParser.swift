import Foundation

public enum DNSRecordType: UInt16, Sendable {
    case a = 1
    case cname = 5
    case ptr = 12
    case mx = 15
    case txt = 16
    case aaaa = 28
    case srv = 33
    case https = 65

    public var label: String {
        switch self {
        case .a: return "A"
        case .cname: return "CNAME"
        case .ptr: return "PTR"
        case .mx: return "MX"
        case .txt: return "TXT"
        case .aaaa: return "AAAA"
        case .srv: return "SRV"
        case .https: return "HTTPS"
        }
    }
}

public struct DNSQuestion: Sendable {
    public let transactionID: UInt16
    public let domain: String
    public let qtype: UInt16
    public let qclass: UInt16
    public let questionEndOffset: Int

    public var recordTypeLabel: String {
        DNSRecordType(rawValue: qtype)?.label ?? "TYPE\(qtype)"
    }
}

public enum DNSWireParser {
    public static func parseQuestion(from data: Data) -> DNSQuestion? {
        guard data.count >= 17 else { return nil }
        let start = data.startIndex
        let txID = (UInt16(data[start]) << 8) | UInt16(data[start + 1])
        let flags = (UInt16(data[start + 2]) << 8) | UInt16(data[start + 3])
        // QR bit (0x8000) must be 0 for a query
        guard (flags & 0x8000) == 0 else { return nil }

        let qdCount = (UInt16(data[start + 4]) << 8) | UInt16(data[start + 5])
        guard qdCount >= 1 else { return nil }

        guard let (domain, nextOffset) = readDomainName(data: data, offset: 12),
              nextOffset + 4 <= data.count else {
            return nil
        }

        let qtype = (UInt16(data[start + nextOffset]) << 8) | UInt16(data[start + nextOffset + 1])
        let qclass = (UInt16(data[start + nextOffset + 2]) << 8) | UInt16(data[start + nextOffset + 3])

        return DNSQuestion(
            transactionID: txID,
            domain: domain.lowercased(),
            qtype: qtype,
            qclass: qclass,
            questionEndOffset: nextOffset + 4
        )
    }

    public static func rewriteTransactionID(in response: Data, to transactionID: UInt16) -> Data {
        guard response.count >= 2 else { return response }
        var copy = response
        copy[copy.startIndex] = UInt8((transactionID >> 8) & 0xFF)
        copy[copy.startIndex + 1] = UInt8(transactionID & 0xFF)
        return copy
    }

    /// Extracts the minimum TTL from the Answer section of a DNS wire response.
    public static func extractMinTTL(from response: Data, fallbackTTL: UInt32 = 60) -> UInt32 {
        guard response.count >= 12 else { return fallbackTTL }
        let start = response.startIndex
        let qdCount = Int((UInt16(response[start + 4]) << 8) | UInt16(response[start + 5]))
        let anCount = Int((UInt16(response[start + 6]) << 8) | UInt16(response[start + 7]))
        guard anCount > 0 else { return fallbackTTL }

        var offset = 12
        for _ in 0..<qdCount {
            guard let (_, afterName) = readDomainName(data: response, offset: offset),
                  afterName + 4 <= response.count else {
                return fallbackTTL
            }
            offset = afterName + 4
        }

        var minTTL = UInt32.max
        for _ in 0..<anCount {
            guard let (_, afterName) = readDomainName(data: response, offset: offset),
                  afterName + 10 <= response.count else {
                break
            }
            let ttlOffset = start + afterName + 4
            let ttl = (UInt32(response[ttlOffset]) << 24)
                | (UInt32(response[ttlOffset + 1]) << 16)
                | (UInt32(response[ttlOffset + 2]) << 8)
                | UInt32(response[ttlOffset + 3])
            minTTL = min(minTTL, ttl)

            let rdLen = Int((UInt16(response[start + afterName + 8]) << 8) | UInt16(response[start + afterName + 9]))
            offset = afterName + 10 + rdLen
            if offset > response.count { break }
        }

        return minTTL == UInt32.max ? fallbackTTL : minTTL
    }

    /// Builds an NXDOMAIN or NOERROR empty response (useful for noise blocking or AAAA suppression).
    public static func buildSyntheticResponse(
        for query: Data,
        question: DNSQuestion,
        rcode: UInt8,
        zeroAddressAnswer: Bool = false,
        ttl: UInt32 = 300
    ) -> Data {
        let headerAndQuestion = query.prefix(min(query.count, question.questionEndOffset))
        guard headerAndQuestion.count >= 12 else { return Data() }

        var response = Data(headerAndQuestion)
        // Standard response flags: QR=1, RD copied, RA=1, RCODE=rcode
        let reqRD = response[response.startIndex + 2] & 0x01
        response[response.startIndex + 2] = 0x81 | reqRD
        response[response.startIndex + 3] = 0x80 | (rcode & 0x0F)
        // QDCOUNT = 1
        response[response.startIndex + 4] = 0x00
        response[response.startIndex + 5] = 0x01
        // ANCOUNT
        response[response.startIndex + 6] = 0x00
        response[response.startIndex + 7] = (zeroAddressAnswer && question.qtype == DNSRecordType.a.rawValue) ? 0x01 : 0x00
        // NSCOUNT & ARCOUNT = 0
        response[response.startIndex + 8] = 0x00
        response[response.startIndex + 9] = 0x00
        response[response.startIndex + 10] = 0x00
        response[response.startIndex + 11] = 0x00

        if zeroAddressAnswer && question.qtype == DNSRecordType.a.rawValue {
            // Pointer to QNAME at offset 12 (0xC00C)
            response.append(contentsOf: [0xC0, 0x0C])
            // TYPE A (1), CLASS IN (1)
            response.append(contentsOf: [0x00, 0x01, 0x00, 0x01])
            // TTL
            response.append(UInt8((ttl >> 24) & 0xFF))
            response.append(UInt8((ttl >> 16) & 0xFF))
            response.append(UInt8((ttl >> 8) & 0xFF))
            response.append(UInt8(ttl & 0xFF))
            // RDLENGTH = 4, RDATA = 0.0.0.0
            response.append(contentsOf: [0x00, 0x04, 0x00, 0x00, 0x00, 0x00])
        }

        return response
    }

    public static func readDomainName(data: Data, offset: Int) -> (String, Int)? {
        var labels: [String] = []
        var cursor = offset
        var jumped = false
        var endOffset = offset
        var jumpCount = 0
        let start = data.startIndex

        while cursor < data.count {
            let len = Int(data[start + cursor])
            if len == 0 {
                if !jumped { endOffset = cursor + 1 }
                return (labels.joined(separator: "."), endOffset)
            }

            if (len & 0xC0) == 0xC0 {
                guard cursor + 1 < data.count else { return nil }
                let pointer = ((len & 0x3F) << 8) | Int(data[start + cursor + 1])
                guard pointer < data.count else { return nil }
                if !jumped { endOffset = cursor + 2 }
                jumped = true
                cursor = pointer
                jumpCount += 1
                if jumpCount > 12 { return nil }
                continue
            }

            guard len <= 63, cursor + 1 + len <= data.count else { return nil }
            let labelRange = (start + cursor + 1)..<(start + cursor + 1 + len)
            guard let label = String(data: data.subdata(in: labelRange), encoding: .utf8) else {
                return nil
            }
            labels.append(label)
            cursor += 1 + len
        }

        return nil
    }
}
