import Foundation
import Network

/// Lightweight userspace UDP NAT relay using NWConnection with interactiveVideo QoS
/// for custom low-latency CIDR routes (e.g. game servers or VoIP relays).
public final class UDPRelayEngine: @unchecked Sendable {
    private struct FlowKey: Hashable {
        let srcIP: UInt32
        let srcPort: UInt16
        let dstIP: UInt32
        let dstPort: UInt16
    }

    private final class Session {
        let key: FlowKey
        let connection: NWConnection
        var lastActive: Date
        var isReady: Bool = false
        var pendingPayloads: [Data] = []

        init(key: FlowKey, connection: NWConnection) {
            self.key = key
            self.connection = connection
            self.lastActive = Date()
        }
    }

    private let lock = NSLock()
    private var sessions: [FlowKey: Session] = [:]
    private let maxSessions = 256
    private let queue = DispatchQueue(label: "com.nguyenbinhchanh.pingpulse.udprelay", qos: .userInteractive)
    private let onDownstreamPacket: @Sendable (Data) -> Void
    private var lastSweep = Date()

    public init(onDownstreamPacket: @escaping @Sendable (Data) -> Void) {
        self.onDownstreamPacket = onDownstreamPacket
    }

    public func forwardUpstream(packet: IPv4Packet, udp: UDPSegment) {
        let key = FlowKey(
            srcIP: packet.sourceIP,
            srcPort: udp.sourcePort,
            dstIP: packet.destinationIP,
            dstPort: udp.destinationPort
        )

        lock.lock()
        let now = Date()
        if now.timeIntervalSince(lastSweep) > 15 {
            sweepExpiredLocked(now: now)
            lastSweep = now
        }

        if let existing = sessions[key] {
            existing.lastActive = now
            if existing.isReady {
                let conn = existing.connection
                lock.unlock()
                conn.send(content: udp.payload, completion: .idempotent)
            } else {
                if existing.pendingPayloads.count < 16 {
                    existing.pendingPayloads.append(udp.payload)
                }
                lock.unlock()
            }
            return
        }

        if sessions.count >= maxSessions {
            if let oldest = sessions.min(by: { $0.value.lastActive < $1.value.lastActive }) {
                oldest.value.connection.cancel()
                sessions.removeValue(forKey: oldest.key)
            }
        }

        guard let nwPort = NWEndpoint.Port(rawValue: udp.destinationPort) else {
            lock.unlock()
            return
        }

        let params = NWParameters.udp
        params.serviceClass = .interactiveVideo
        let host = NWEndpoint.Host(IPv4Packet.formatIPv4(packet.destinationIP))
        let connection = NWConnection(host: host, port: nwPort, using: params)
        let session = Session(key: key, connection: connection)
        session.pendingPayloads.append(udp.payload)
        sessions[key] = session
        lock.unlock()

        connection.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                self.lock.lock()
                session.isReady = true
                let queued = session.pendingPayloads
                session.pendingPayloads.removeAll()
                self.lock.unlock()

                for payload in queued {
                    connection.send(content: payload, completion: .idempotent)
                }
                self.startReceiveLoop(session: session)

            case .failed, .cancelled:
                self.lock.lock()
                self.sessions.removeValue(forKey: key)
                self.lock.unlock()
            default:
                break
            }
        }

        connection.start(queue: queue)
    }

    public func stopAll() {
        lock.lock()
        let all = Array(sessions.values)
        sessions.removeAll()
        lock.unlock()
        for session in all {
            session.connection.cancel()
        }
    }

    private func startReceiveLoop(session: Session) {
        session.connection.receiveMessage { [weak self] data, _, _, error in
            guard let self else { return }
            if let data, !data.isEmpty {
                self.lock.lock()
                session.lastActive = Date()
                self.lock.unlock()

                let replyPacket = IPv4Packet.buildUDPReply(
                    sourceIP: session.key.dstIP,
                    sourcePort: session.key.dstPort,
                    destinationIP: session.key.srcIP,
                    destinationPort: session.key.srcPort,
                    udpPayload: data,
                    dscp: 46
                )
                self.onDownstreamPacket(replyPacket)
            }

            if error == nil {
                self.startReceiveLoop(session: session)
            } else {
                self.lock.lock()
                self.sessions.removeValue(forKey: session.key)
                self.lock.unlock()
                session.connection.cancel()
            }
        }
    }

    private func sweepExpiredLocked(now: Date) {
        let expiredKeys = sessions.compactMap { (key, session) -> FlowKey? in
            now.timeIntervalSince(session.lastActive) > 60 ? key : nil
        }
        for key in expiredKeys {
            sessions[key]?.connection.cancel()
            sessions.removeValue(forKey: key)
        }
    }
}
