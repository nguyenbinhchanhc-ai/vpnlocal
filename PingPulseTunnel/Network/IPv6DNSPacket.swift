import Foundation

/// Minimal IPv6 + UDP/53 parser and reply builder so iOS dual-stack DNS queries
/// hitting fd11:0:0:1::1 are handled seamlessly alongside IPv4.
public struct IPv6UDPPacket: Sendable {
    public let sourceAddress: Data      // 16 bytes
    public let destinationAddress: Data // 16 bytes
    public let sourcePort: UInt16
    public let destinationPort: UInt16
    public let udpPayload: Data

    public init?(data: Data) {
        guard data.count >= 48 else { return nil }
        let start = data.startIndex
        let version = data[start] >> 4
        guard version == 6 else { return nil }

        // Only handle unfragmented UDP (Next Header == 17) directly
        let nextHeader = data[start + 6]
        guard nextHeader == IPProtocolNumber.udp.rawValue else { return nil }

        let src = data.subdata(in: (start + 8)..<(start + 24))
        let dst = data.subdata(in: (start + 24)..<(start + 40))
        let udpStart = start + 40
        let srcPort = (UInt16(data[udpStart]) << 8) | UInt16(data[udpStart + 1])
        let dstPort = (UInt16(data[udpStart + 2]) << 8) | UInt16(data[udpStart + 3])
        let udpLen = Int((UInt16(data[udpStart + 4]) << 8) | UInt16(data[udpStart + 5]))
        let payloadEnd = min(data.endIndex, udpStart + max(8, udpLen))

        self.sourceAddress = src
        self.destinationAddress = dst
        self.sourcePort = srcPort
        self.destinationPort = dstPort
        self.udpPayload = data.subdata(in: (udpStart + 8)..<payloadEnd)
    }

    public static func buildUDPReply(
        sourceAddress: Data,
        sourcePort: UInt16,
        destinationAddress: Data,
        destinationPort: UInt16,
        udpPayload: Data
    ) -> Data {
        guard sourceAddress.count == 16, destinationAddress.count == 16 else { return Data() }
        let udpLen = 8 + udpPayload.count
        var packet = Data(count: 40 + udpLen)

        // IPv6 header: Version 6, Traffic Class EF (0xB8)
        packet[0] = 0x6B
        packet[1] = 0x80
        packet[2] = 0x00
        packet[3] = 0x00
        packet[4] = UInt8((udpLen >> 8) & 0xFF)
        packet[5] = UInt8(udpLen & 0xFF)
        packet[6] = IPProtocolNumber.udp.rawValue
        packet[7] = 64 // Hop Limit

        packet.replaceSubrange(8..<24, with: sourceAddress)
        packet.replaceSubrange(24..<40, with: destinationAddress)

        // UDP header
        packet[40] = UInt8((sourcePort >> 8) & 0xFF)
        packet[41] = UInt8(sourcePort & 0xFF)
        packet[42] = UInt8((destinationPort >> 8) & 0xFF)
        packet[43] = UInt8(destinationPort & 0xFF)
        packet[44] = UInt8((udpLen >> 8) & 0xFF)
        packet[45] = UInt8(udpLen & 0xFF)
        packet[46] = 0x00
        packet[47] = 0x00
        packet.replaceSubrange(48..<(40 + udpLen), with: udpPayload)

        // IPv6 UDP checksum (mandatory in IPv6)
        var pseudo = Data(capacity: 40 + udpLen)
        pseudo.append(sourceAddress)
        pseudo.append(destinationAddress)
        let len32 = UInt32(udpLen)
        pseudo.append(UInt8((len32 >> 24) & 0xFF))
        pseudo.append(UInt8((len32 >> 16) & 0xFF))
        pseudo.append(UInt8((len32 >> 8) & 0xFF))
        pseudo.append(UInt8(len32 & 0xFF))
        pseudo.append(contentsOf: [0x00, 0x00, 0x00, IPProtocolNumber.udp.rawValue])
        pseudo.append(packet.subdata(in: 40..<(40 + udpLen)))

        let sum = IPv4Packet.internetChecksum(pseudo)
        let finalSum = sum == 0 ? 0xFFFF : sum
        packet[46] = UInt8((finalSum >> 8) & 0xFF)
        packet[47] = UInt8(finalSum & 0xFF)
        return packet
    }
}
