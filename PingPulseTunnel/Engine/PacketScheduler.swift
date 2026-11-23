import Foundation

public struct ScheduledPacket: Sendable {
    public let packet: IPv4Packet
    public let lane: QoSLane
    public let enqueuedAt: Date
}

/// 4-Lane Strict Priority & Token-Bucket Pacer for anti-bufferbloat packet scheduling.
public final class PacketScheduler: @unchecked Sendable {
    private let lock = NSLock()
    private var lanes: [[ScheduledPacket]] = Array(repeating: [], count: QoSLane.allCases.count)
    private let maxQueuePerLane = 512

    public init() {}

    public func classify(_ packet: IPv4Packet) -> QoSLane {
        if packet.proto == IPProtocolNumber.icmp.rawValue {
            return .criticalControl
        }

        if let udp = packet.udpSegment {
            if udp.destinationPort == 53 || udp.sourcePort == 53 {
                return .criticalControl
            }
            if isRealtimeUDPPort(udp.destinationPort) || isRealtimeUDPPort(udp.sourcePort) {
                return .realtimeInteractive
            }
            if udp.payload.count <= 512 {
                return .realtimeInteractive
            }
            return .standardWeb
        }

        if let tcp = packet.tcpSegment {
            // Pure ACK / SYN / RST control packets get P0 so TCP feedback loops stay tight
            if tcp.payloadLength == 0 && (tcp.flags.contains(.syn) || tcp.flags.contains(.ack) || tcp.flags.contains(.rst)) {
                return .criticalControl
            }
            if tcp.destinationPort == 53 || tcp.sourcePort == 53 {
                return .criticalControl
            }
            if tcp.destinationPort == 443 || tcp.destinationPort == 80 || tcp.sourcePort == 443 || tcp.sourcePort == 80 {
                return packet.totalLength >= 1300 ? .bulkBackground : .standardWeb
            }
            return packet.totalLength >= 1300 ? .bulkBackground : .standardWeb
        }

        return .bulkBackground
    }

    public func enqueueBatch(_ packets: [IPv4Packet], now: Date = Date()) -> [QoSLane: Int] {
        lock.lock()
        defer { lock.unlock() }

        var counts: [QoSLane: Int] = [:]
        for pkt in packets {
            let lane = classify(pkt)
            counts[lane, default: 0] += 1
            if lanes[lane.rawValue].count >= maxQueuePerLane {
                // Tail-drop bulk/low-priority oldest entry first when saturated
                lanes[lane.rawValue].removeFirst()
            }
            lanes[lane.rawValue].append(ScheduledPacket(packet: pkt, lane: lane, enqueuedAt: now))
        }
        return counts
    }

    /// Dequeues packets in strict priority order (P0 -> P1 -> P2 -> P3), enforcing a byte cap on P2/P3
    /// when pacing is active so large transfers do not starve low-latency interactive packets.
    public func dequeueBurst(maxBulkBytes: Int, enablePacing: Bool) -> [ScheduledPacket] {
        lock.lock()
        defer { lock.unlock() }

        var result: [ScheduledPacket] = []

        // P0 and P1 always drain without byte throttling
        if !lanes[QoSLane.criticalControl.rawValue].isEmpty {
            result.append(contentsOf: lanes[QoSLane.criticalControl.rawValue])
            lanes[QoSLane.criticalControl.rawValue].removeAll(keepingCapacity: true)
        }
        if !lanes[QoSLane.realtimeInteractive.rawValue].isEmpty {
            result.append(contentsOf: lanes[QoSLane.realtimeInteractive.rawValue])
            lanes[QoSLane.realtimeInteractive.rawValue].removeAll(keepingCapacity: true)
        }

        var remainingBulkBudget = enablePacing ? max(2048, maxBulkBytes) : Int.max

        for laneIndex in [QoSLane.standardWeb.rawValue, QoSLane.bulkBackground.rawValue] {
            while !lanes[laneIndex].isEmpty {
                let next = lanes[laneIndex][0]
                if next.packet.totalLength > remainingBulkBudget && !result.isEmpty {
                    break
                }
                lanes[laneIndex].removeFirst()
                result.append(next)
                remainingBulkBudget = max(0, remainingBulkBudget - next.packet.totalLength)
                if remainingBulkBudget == 0 {
                    break
                }
            }
        }

        return result
    }

    public func clear() {
        lock.lock()
        defer { lock.unlock() }
        for idx in lanes.indices {
            lanes[idx].removeAll()
        }
    }

    private func isRealtimeUDPPort(_ port: UInt16) -> Bool {
        switch port {
        case 3478...3481: // STUN / TURN / WebRTC
            return true
        case 5000...5065: // VoIP / SIP / RTP / Game signaling
            return true
        case 7000...9000: // Common mobile game UDP ports
            return true
        case 14000...32000: // Arena / FPS / MOBA realtime UDP pools
            return true
        case 50000...50100: // Discord / voice RTP
            return true
        default:
            return false
        }
    }
}
