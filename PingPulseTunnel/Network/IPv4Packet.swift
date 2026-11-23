import Foundation

public enum IPProtocolNumber: UInt8, Sendable {
    case icmp = 1
    case tcp = 6
    case udp = 17
}

public struct TCPFlags: OptionSet, Sendable {
    public let rawValue: UInt8
    public init(rawValue: UInt8) { self.rawValue = rawValue }

    public static let fin = TCPFlags(rawValue: 1 << 0)
    public static let syn = TCPFlags(rawValue: 1 << 1)
    public static let rst = TCPFlags(rawValue: 1 << 2)
    public static let psh = TCPFlags(rawValue: 1 << 3)
    public static let ack = TCPFlags(rawValue: 1 << 4)
    public static let urg = TCPFlags(rawValue: 1 << 5)
}

public struct IPv4Packet: Sendable {
    public let rawData: Data
    public let headerLength: Int
    public let totalLength: Int
    public let dscp: UInt8
    public let proto: UInt8
    public let sourceIP: UInt32
    public let destinationIP: UInt32
    public let payload: Data

    public init?(data: Data) {
        guard data.count >= 20 else { return nil }
        let versionIHL = data[data.startIndex]
        let version = versionIHL >> 4
        guard version == 4 else { return nil }

        let ihl = Int(versionIHL & 0x0F) * 4
        guard ihl >= 20, data.count >= ihl else { return nil }

        let totLen = (Int(data[data.startIndex + 2]) << 8) | Int(data[data.startIndex + 3])
        let effectiveLen = min(data.count, max(ihl, totLen))
        guard effectiveLen >= ihl else { return nil }

        self.rawData = data.prefix(effectiveLen)
        self.headerLength = ihl
        self.totalLength = effectiveLen
        self.dscp = data[data.startIndex + 1] >> 2
        self.proto = data[data.startIndex + 9]
        self.sourceIP = IPv4Packet.readUInt32(data, offset: 12)
        self.destinationIP = IPv4Packet.readUInt32(data, offset: 16)
        self.payload = data.subdata(in: (data.startIndex + ihl)..<(data.startIndex + effectiveLen))
    }

    public var sourceIPString: String { IPv4Packet.formatIPv4(sourceIP) }
    public var destinationIPString: String { IPv4Packet.formatIPv4(destinationIP) }

    public var udpSegment: UDPSegment? {
        guard proto == IPProtocolNumber.udp.rawValue else { return nil }
        return UDPSegment(data: payload)
    }

    public var tcpSegment: TCPSegment? {
        guard proto == IPProtocolNumber.tcp.rawValue else { return nil }
        return TCPSegment(data: payload)
    }

    public static func readUInt16(_ data: Data, offset: Int) -> UInt16 {
        let i = data.startIndex + offset
        return (UInt16(data[i]) << 8) | UInt16(data[i + 1])
    }

    public static func readUInt32(_ data: Data, offset: Int) -> UInt32 {
        let i = data.startIndex + offset
        return (UInt32(data[i]) << 24)
            | (UInt32(data[i + 1]) << 16)
            | (UInt32(data[i + 2]) << 8)
            | UInt32(data[i + 3])
    }

    public static func formatIPv4(_ ip: UInt32) -> String {
        "\((ip >> 24) & 0xFF).\((ip >> 16) & 0xFF).\((ip >> 8) & 0xFF).\(ip & 0xFF)"
    }

    public static func parseIPv4(_ string: String) -> UInt32? {
        let parts = string.split(separator: ".")
        guard parts.count == 4 else { return nil }
        var result: UInt32 = 0
        for part in parts {
            guard let byte = UInt8(part) else { return nil }
            result = (result << 8) | UInt32(byte)
        }
        return result
    }

    public static func buildUDPReply(
        sourceIP: UInt32,
        sourcePort: UInt16,
        destinationIP: UInt32,
        destinationPort: UInt16,
        udpPayload: Data,
        dscp: UInt8 = 46 // EF (Expedited Forwarding) for low-latency control/DNS
    ) -> Data {
        let ipHeaderLen = 20
        let udpHeaderLen = 8
        let udpTotalLen = udpHeaderLen + udpPayload.count
        let ipTotalLen = ipHeaderLen + udpTotalLen

        var packet = Data(count: ipTotalLen)

        // IPv4 Header
        packet[0] = 0x45 // Version 4, IHL 5
        packet[1] = (dscp & 0x3F) << 2
        packet[2] = UInt8((ipTotalLen >> 8) & 0xFF)
        packet[3] = UInt8(ipTotalLen & 0xFF)
        packet[4] = 0x00
        packet[5] = 0x00
        packet[6] = 0x40 // Don't Fragment
        packet[7] = 0x00
        packet[8] = 64   // TTL
        packet[9] = IPProtocolNumber.udp.rawValue
        packet[10] = 0x00
        packet[11] = 0x00

        writeUInt32(&packet, offset: 12, value: sourceIP)
        writeUInt32(&packet, offset: 16, value: destinationIP)

        let ipChecksum = internetChecksum(packet.prefix(ipHeaderLen))
        packet[10] = UInt8((ipChecksum >> 8) & 0xFF)
        packet[11] = UInt8(ipChecksum & 0xFF)

        // UDP Header
        packet[20] = UInt8((sourcePort >> 8) & 0xFF)
        packet[21] = UInt8(sourcePort & 0xFF)
        packet[22] = UInt8((destinationPort >> 8) & 0xFF)
        packet[23] = UInt8(destinationPort & 0xFF)
        packet[24] = UInt8((udpTotalLen >> 8) & 0xFF)
        packet[25] = UInt8(udpTotalLen & 0xFF)
        packet[26] = 0x00
        packet[27] = 0x00

        packet.replaceSubrange(28..<ipTotalLen, with: udpPayload)

        let udpChecksum = computeUDPChecksum(
            sourceIP: sourceIP,
            destinationIP: destinationIP,
            udpSegment: packet.subdata(in: 20..<ipTotalLen)
        )
        packet[26] = UInt8((udpChecksum >> 8) & 0xFF)
        packet[27] = UInt8(udpChecksum & 0xFF)

        return packet
    }

    public static func buildICMPEchoReply(for request: IPv4Packet) -> Data? {
        guard request.proto == IPProtocolNumber.icmp.rawValue,
              request.payload.count >= 8,
              request.payload[request.payload.startIndex] == 8 else { // Type 8 = Echo Request
            return nil
        }

        var icmpPayload = request.payload
        icmpPayload[icmpPayload.startIndex] = 0 // Type 0 = Echo Reply
        icmpPayload[icmpPayload.startIndex + 2] = 0
        icmpPayload[icmpPayload.startIndex + 3] = 0
        let icmpSum = internetChecksum(icmpPayload)
        icmpPayload[icmpPayload.startIndex + 2] = UInt8((icmpSum >> 8) & 0xFF)
        icmpPayload[icmpPayload.startIndex + 3] = UInt8(icmpSum & 0xFF)

        let ipHeaderLen = 20
        let totalLen = ipHeaderLen + icmpPayload.count
        var packet = Data(count: totalLen)
        packet[0] = 0x45
        packet[1] = 0xB8 // DSCP EF
        packet[2] = UInt8((totalLen >> 8) & 0xFF)
        packet[3] = UInt8(totalLen & 0xFF)
        packet[6] = 0x40
        packet[8] = 64
        packet[9] = IPProtocolNumber.icmp.rawValue
        writeUInt32(&packet, offset: 12, value: request.destinationIP)
        writeUInt32(&packet, offset: 16, value: request.sourceIP)

        let ipSum = internetChecksum(packet.prefix(ipHeaderLen))
        packet[10] = UInt8((ipSum >> 8) & 0xFF)
        packet[11] = UInt8(ipSum & 0xFF)
        packet.replaceSubrange(20..<totalLen, with: icmpPayload)
        return packet
    }

    private static func writeUInt32(_ data: inout Data, offset: Int, value: UInt32) {
        data[offset] = UInt8((value >> 24) & 0xFF)
        data[offset + 1] = UInt8((value >> 16) & 0xFF)
        data[offset + 2] = UInt8((value >> 8) & 0xFF)
        data[offset + 3] = UInt8(value & 0xFF)
    }

    public static func internetChecksum(_ data: Data) -> UInt16 {
        var sum: UInt32 = 0
        var idx = data.startIndex
        let end = data.endIndex
        while idx + 1 < end {
            let word = (UInt32(data[idx]) << 8) | UInt32(data[idx + 1])
            sum += word
            idx += 2
        }
        if idx < end {
            sum += UInt32(data[idx]) << 8
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16)
        }
        return ~UInt16(sum & 0xFFFF)
    }

    private static func computeUDPChecksum(sourceIP: UInt32, destinationIP: UInt32, udpSegment: Data) -> UInt16 {
        var pseudo = Data(capacity: 12 + udpSegment.count)
        pseudo.append(UInt8((sourceIP >> 24) & 0xFF))
        pseudo.append(UInt8((sourceIP >> 16) & 0xFF))
        pseudo.append(UInt8((sourceIP >> 8) & 0xFF))
        pseudo.append(UInt8(sourceIP & 0xFF))
        pseudo.append(UInt8((destinationIP >> 24) & 0xFF))
        pseudo.append(UInt8((destinationIP >> 16) & 0xFF))
        pseudo.append(UInt8((destinationIP >> 8) & 0xFF))
        pseudo.append(UInt8(destinationIP & 0xFF))
        pseudo.append(0)
        pseudo.append(IPProtocolNumber.udp.rawValue)
        let len = UInt16(udpSegment.count)
        pseudo.append(UInt8((len >> 8) & 0xFF))
        pseudo.append(UInt8(len & 0xFF))
        pseudo.append(udpSegment)

        let sum = internetChecksum(pseudo)
        return sum == 0 ? 0xFFFF : sum
    }
}

public struct UDPSegment: Sendable {
    public let sourcePort: UInt16
    public let destinationPort: UInt16
    public let length: Int
    public let payload: Data

    public init?(data: Data) {
        guard data.count >= 8 else { return nil }
        self.sourcePort = IPv4Packet.readUInt16(data, offset: 0)
        self.destinationPort = IPv4Packet.readUInt16(data, offset: 2)
        self.length = Int(IPv4Packet.readUInt16(data, offset: 4))
        let payloadEnd = min(data.endIndex, data.startIndex + max(8, length))
        self.payload = data.subdata(in: (data.startIndex + 8)..<payloadEnd)
    }
}

public struct TCPSegment: Sendable {
    public let sourcePort: UInt16
    public let destinationPort: UInt16
    public let dataOffset: Int
    public let flags: TCPFlags
    public let payloadLength: Int

    public init?(data: Data) {
        guard data.count >= 20 else { return nil }
        self.sourcePort = IPv4Packet.readUInt16(data, offset: 0)
        self.destinationPort = IPv4Packet.readUInt16(data, offset: 2)
        let offsetBytes = Int((data[data.startIndex + 12] >> 4) & 0x0F) * 4
        guard offsetBytes >= 20, data.count >= offsetBytes else { return nil }
        self.dataOffset = offsetBytes
        self.flags = TCPFlags(rawValue: data[data.startIndex + 13])
        self.payloadLength = data.count - offsetBytes
    }
}
