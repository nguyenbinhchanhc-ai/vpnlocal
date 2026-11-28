import Darwin
import Foundation
import Network

public struct Socks5UDPFrame: Sendable {
    public let host: String
    public let port: UInt16
    public let headerPrefix: Data
    public let payload: Data
}

public enum Socks5Codec {
    public static func parseAddress(
        from data: Data,
        startingAt offset: Int
    ) -> (host: String, port: UInt16, rawAddressAndPort: Data, nextOffset: Int)? {
        guard offset < data.count else { return nil }
        let start = data.startIndex
        let atyp = data[start + offset]
        var cursor = offset + 1

        let host: String
        switch atyp {
        case 0x01: // IPv4
            guard cursor + 4 + 2 <= data.count else { return nil }
            let b0 = data[start + cursor]
            let b1 = data[start + cursor + 1]
            let b2 = data[start + cursor + 2]
            let b3 = data[start + cursor + 3]
            host = "\(b0).\(b1).\(b2).\(b3)"
            cursor += 4

        case 0x03: // Domain
            guard cursor + 1 <= data.count else { return nil }
            let len = Int(data[start + cursor])
            cursor += 1
            guard len > 0, cursor + len + 2 <= data.count else { return nil }
            guard let domain = String(data: data.subdata(in: (start + cursor)..<(start + cursor + len)), encoding: .utf8) else {
                return nil
            }
            host = domain
            cursor += len

        case 0x04: // IPv6
            guard cursor + 16 + 2 <= data.count else { return nil }
            var groups: [String] = []
            groups.reserveCapacity(8)
            for idx in stride(from: 0, to: 16, by: 2) {
                let word = (UInt16(data[start + cursor + idx]) << 8) | UInt16(data[start + cursor + idx + 1])
                groups.append(String(format: "%x", word))
            }
            host = groups.joined(separator: ":")
            cursor += 16

        default:
            return nil
        }

        let port = (UInt16(data[start + cursor]) << 8) | UInt16(data[start + cursor + 1])
        cursor += 2
        let rawSlice = data.subdata(in: (start + offset)..<(start + cursor))
        return (host, port, rawSlice, cursor)
    }

    public static func parseUDPFrame(_ datagram: Data) -> Socks5UDPFrame? {
        guard datagram.count >= 10 else { return nil }
        let start = datagram.startIndex
        // RSV (2 bytes) + FRAG (1 byte)
        let frag = datagram[start + 2]
        guard frag == 0x00 else { return nil } // Fragmented UDP not supported

        guard let parsed = parseAddress(from: datagram, startingAt: 3) else {
            return nil
        }
        let headerPrefix = datagram.subdata(in: start..<(start + parsed.nextOffset))
        let payload = datagram.subdata(in: (start + parsed.nextOffset)..<datagram.endIndex)
        return Socks5UDPFrame(host: parsed.host, port: parsed.port, headerPrefix: headerPrefix, payload: payload)
    }

    public static func buildUDPFrame(headerPrefix: Data, payload: Data) -> Data {
        var out = Data(capacity: headerPrefix.count + payload.count)
        out.append(headerPrefix)
        out.append(payload)
        return out
    }
}

/// In-process RFC 1928 SOCKS5 TCP + UDP orchestrator backing `Tun2SocksKit` (`hev-socks5-tunnel`).
/// Intercepts all DNS queries (UDP/53 & TCP/53) through `DNSEngine` and classifies/relays all
/// other TCP/UDP traffic with `NWParameters.prohibitedInterfaceTypes = [.other]` and QoS classes.
public final class LocalSocks5Orchestrator: @unchecked Sendable {
    private struct UDPFlowKey: Hashable {
        let clientPort: UInt16
        let dstHost: String
        let dstPort: UInt16
    }

    private final class UDPRelaySession: @unchecked Sendable {
        let key: UDPFlowKey
        let connection: NWConnection
        private let lock = NSLock()
        var clientAddrData: Data
        var headerPrefix: Data
        var lastActive: Date
        var isReady: Bool = false
        var pending: [Data] = []

        init(key: UDPFlowKey, connection: NWConnection, clientAddrData: Data, headerPrefix: Data) {
            self.key = key
            self.connection = connection
            self.clientAddrData = clientAddrData
            self.headerPrefix = headerPrefix
            self.lastActive = Date()
        }

        func updateEndpoint(clientAddrData: Data, headerPrefix: Data) {
            lock.lock()
            self.clientAddrData = clientAddrData
            self.headerPrefix = headerPrefix
            self.lastActive = Date()
            lock.unlock()
        }

        func enqueueOrCheckReady(_ payload: Data) -> NWConnection? {
            lock.lock()
            defer { lock.unlock() }
            lastActive = Date()
            if isReady { return connection }
            if pending.count < 16 { pending.append(payload) }
            return nil
        }

        func markReadyAndDrain() -> [Data] {
            lock.lock()
            defer { lock.unlock() }
            isReady = true
            let items = pending
            pending.removeAll()
            return items
        }

        func snapshotReplyTarget() -> (Data, Data) {
            lock.lock()
            defer { lock.unlock() }
            lastActive = Date()
            return (clientAddrData, headerPrefix)
        }

        func lastActiveDate() -> Date {
            lock.lock()
            defer { lock.unlock() }
            return lastActive
        }
    }

    private final class TCPReadyFlag: @unchecked Sendable {
        private let lock = NSLock()
        private var done = false
        func claim() -> Bool {
            lock.lock()
            defer { lock.unlock() }
            if done { return false }
            done = true
            return true
        }
    }

    public typealias PacketEventHandler = @Sendable (_ lane: QoSLane, _ isDNS: Bool, _ isUDPRelay: Bool) -> Void
    public typealias DNSResultHandler = @Sendable (DNSProcessResult) -> Void

    private let dnsEngine: DNSEngine
    private let configProvider: @Sendable () -> OptimizationConfig
    private let onPacketEvent: PacketEventHandler
    private let onDNSResult: DNSResultHandler

    private let listenerQueue = DispatchQueue(label: "com.nguyenbinhchanh.pingpulse.socks5.tcp", qos: .userInteractive)
    private let udpQueue = DispatchQueue(label: "com.nguyenbinhchanh.pingpulse.socks5.udp", qos: .userInteractive)
    private let lock = NSLock()

    private var tcpListener: NWListener?
    private var udpFD: Int32 = -1
    private var udpPort: UInt16 = 0
    private var udpReadSource: DispatchSourceRead?
    private var udpSessions: [UDPFlowKey: UDPRelaySession] = [:]
    private var lastUDPSweep = Date()
    private let maxUDPSessions = 160

    public init(
        dnsEngine: DNSEngine,
        configProvider: @escaping @Sendable () -> OptimizationConfig,
        onPacketEvent: @escaping PacketEventHandler,
        onDNSResult: @escaping DNSResultHandler
    ) {
        self.dnsEngine = dnsEngine
        self.configProvider = configProvider
        self.onPacketEvent = onPacketEvent
        self.onDNSResult = onDNSResult
    }

    public func start(completion: @escaping @Sendable (Result<UInt16, Error>) -> Void) {
        do {
            let boundUDP = try startUDPSocket()
            lock.lock()
            self.udpPort = boundUDP
            lock.unlock()

            let params = NWParameters.tcp
            params.allowLocalEndpointReuse = true
            params.requiredLocalEndpoint = NWEndpoint.hostPort(host: "127.0.0.1", port: .any)
            if let tcpOpts = params.defaultProtocolStack.transportProtocol as? NWProtocolTCP.Options {
                tcpOpts.noDelay = true
            }

            let listener = try NWListener(using: params)
            let startedFlag = TCPReadyFlag()

            listener.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    if startedFlag.claim(), let port = listener.port?.rawValue {
                        completion(.success(port))
                    }
                case .failed(let error):
                    if startedFlag.claim() {
                        completion(.failure(error))
                    }
                default:
                    break
                }
            }

            listener.newConnectionHandler = { [weak self] conn in
                self?.handleNewTCPClient(conn)
            }

            lock.lock()
            self.tcpListener = listener
            lock.unlock()
            listener.start(queue: listenerQueue)
        } catch {
            completion(.failure(error))
        }
    }

    public func stop() {
        lock.lock()
        let listener = tcpListener
        tcpListener = nil
        let source = udpReadSource
        udpReadSource = nil
        let fd = udpFD
        udpFD = -1
        let sessions = Array(udpSessions.values)
        udpSessions.removeAll()
        lock.unlock()

        listener?.cancel()
        source?.cancel()
        if fd >= 0 {
            Darwin.close(fd)
        }
        for s in sessions {
            s.connection.cancel()
        }
    }

    // MARK: - UDP Associate Socket (BSD Non-Blocking)

    private func startUDPSocket() throws -> UInt16 {
        let fd = Darwin.socket(AF_INET, SOCK_DGRAM, 0)
        guard fd >= 0 else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
        }

        var yes: Int32 = 1
        Darwin.setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, socklen_t(MemoryLayout<Int32>.size))
        let flags = Darwin.fcntl(fd, F_GETFL, 0)
        _ = Darwin.fcntl(fd, F_SETFL, flags | O_NONBLOCK)

        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = 0
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")

        let bindRes = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bindRes == 0 else {
            let err = Int(errno)
            Darwin.close(fd)
            throw NSError(domain: NSPOSIXErrorDomain, code: err)
        }

        var boundAddr = sockaddr_in()
        var addrLen = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &boundAddr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.getsockname(fd, $0, &addrLen)
            }
        }
        let port = UInt16(bigEndian: boundAddr.sin_port)

        let source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: udpQueue)
        source.setEventHandler { [weak self] in
            self?.drainUDPSocket(fd: fd)
        }
        source.resume()

        lock.lock()
        self.udpFD = fd
        self.udpReadSource = source
        lock.unlock()

        return port
    }

    private func drainUDPSocket(fd: Int32) {
        var buffer = [UInt8](repeating: 0, count: 4096)
        while true {
            var storage = sockaddr_storage()
            var storageLen = socklen_t(MemoryLayout<sockaddr_storage>.size)
            let bytesRead = withUnsafeMutablePointer(to: &storage) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { saPtr in
                    Darwin.recvfrom(fd, &buffer, buffer.count, 0, saPtr, &storageLen)
                }
            }
            if bytesRead <= 0 { break }

            let datagram = Data(bytes: buffer, count: bytesRead)
            let clientAddrData = withUnsafePointer(to: &storage) {
                Data(bytes: $0, count: Int(storageLen))
            }
            let clientPort: UInt16 = withUnsafePointer(to: &storage) {
                $0.withMemoryRebound(to: sockaddr_in.self, capacity: 1) {
                    UInt16(bigEndian: $0.pointee.sin_port)
                }
            }

            handleUDPDatagram(datagram, clientAddrData: clientAddrData, clientPort: clientPort)
        }
    }

    private func handleUDPDatagram(_ datagram: Data, clientAddrData: Data, clientPort: UInt16) {
        guard let frame = Socks5Codec.parseUDPFrame(datagram) else { return }

        if frame.port == 53 {
            onPacketEvent(.criticalControl, true, false)
            let cfg = configProvider()
            dnsEngine.processQuery(payload: frame.payload, config: cfg) { [weak self] result in
                guard let self, let result else { return }
                self.onDNSResult(result)
                let reply = Socks5Codec.buildUDPFrame(headerPrefix: frame.headerPrefix, payload: result.responseData)
                self.sendUDPReply(reply, to: clientAddrData)
            }
            return
        }

        let lane = classifyPort(frame.port, payloadSize: frame.payload.count, isUDP: true)
        onPacketEvent(lane, false, true)
        relayUDPDatagram(frame: frame, clientAddrData: clientAddrData, clientPort: clientPort, lane: lane)
    }

    private func relayUDPDatagram(
        frame: Socks5UDPFrame,
        clientAddrData: Data,
        clientPort: UInt16,
        lane: QoSLane
    ) {
        let key = UDPFlowKey(clientPort: clientPort, dstHost: frame.host, dstPort: frame.port)

        lock.lock()
        let now = Date()
        if now.timeIntervalSince(lastUDPSweep) > 15 {
            sweepUDPSessionsLocked(now: now)
            lastUDPSweep = now
        }

        if let existing = udpSessions[key] {
            lock.unlock()
            existing.updateEndpoint(clientAddrData: clientAddrData, headerPrefix: frame.headerPrefix)
            if let readyConn = existing.enqueueOrCheckReady(frame.payload) {
                readyConn.send(content: frame.payload, completion: .idempotent)
            }
            return
        }

        if udpSessions.count >= maxUDPSessions {
            if let oldest = udpSessions.min(by: { $0.value.lastActiveDate() < $1.value.lastActiveDate() }) {
                oldest.value.connection.cancel()
                udpSessions.removeValue(forKey: oldest.key)
            }
        }

        guard let nwPort = NWEndpoint.Port(rawValue: frame.port) else {
            lock.unlock()
            return
        }

        let params = NWParameters.udp
        params.prohibitedInterfaceTypes = [.other]
        params.preferNoProxies = true
        params.serviceClass = (lane == .realtimeInteractive || lane == .criticalControl) ? .interactiveVideo : .responsiveData

        let conn = NWConnection(host: NWEndpoint.Host(frame.host), port: nwPort, using: params)
        let session = UDPRelaySession(
            key: key,
            connection: conn,
            clientAddrData: clientAddrData,
            headerPrefix: frame.headerPrefix
        )
        _ = session.enqueueOrCheckReady(frame.payload)
        udpSessions[key] = session
        lock.unlock()

        conn.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                let queued = session.markReadyAndDrain()
                for item in queued {
                    conn.send(content: item, completion: .idempotent)
                }
                self.startUDPReceiveLoop(session: session)
            case .failed, .cancelled:
                self.lock.lock()
                self.udpSessions.removeValue(forKey: key)
                self.lock.unlock()
            default:
                break
            }
        }
        conn.start(queue: udpQueue)
    }

    private func startUDPReceiveLoop(session: UDPRelaySession) {
        session.connection.receiveMessage { [weak self] data, _, _, error in
            guard let self else { return }
            if let data, !data.isEmpty {
                let (clientAddr, headerPrefix) = session.snapshotReplyTarget()
                let frame = Socks5Codec.buildUDPFrame(headerPrefix: headerPrefix, payload: data)
                self.sendUDPReply(frame, to: clientAddr)
            }
            if error == nil {
                self.startUDPReceiveLoop(session: session)
            } else {
                self.lock.lock()
                self.udpSessions.removeValue(forKey: session.key)
                self.lock.unlock()
                session.connection.cancel()
            }
        }
    }

    private func sendUDPReply(_ packet: Data, to clientAddrData: Data) {
        lock.lock()
        let fd = udpFD
        lock.unlock()
        guard fd >= 0 else { return }

        packet.withUnsafeBytes { rawBuf in
            guard let base = rawBuf.baseAddress else { return }
            clientAddrData.withUnsafeBytes { addrBuf in
                guard let sa = addrBuf.baseAddress?.assumingMemoryBound(to: sockaddr.self) else { return }
                _ = Darwin.sendto(fd, base, packet.count, 0, sa, socklen_t(clientAddrData.count))
            }
        }
    }

    private func sweepUDPSessionsLocked(now: Date) {
        let expired = udpSessions.compactMap { (key, session) -> UDPFlowKey? in
            now.timeIntervalSince(session.lastActiveDate()) > 45 ? key : nil
        }
        for key in expired {
            udpSessions[key]?.connection.cancel()
            udpSessions.removeValue(forKey: key)
        }
    }

    // MARK: - TCP SOCKS5 Handshake & Relay

    private func handleNewTCPClient(_ client: NWConnection) {
        client.start(queue: listenerQueue)
        client.receive(minimumIncompleteLength: 2, maximumLength: 258) { [weak self] data, _, _, err in
            guard let self, err == nil, let data, data.count >= 2, data[data.startIndex] == 0x05 else {
                client.cancel()
                return
            }
            // Reply: Version 5, No Authentication (0x00)
            client.send(content: Data([0x05, 0x00]), completion: .contentProcessed { [weak self] sendErr in
                guard let self, sendErr == nil else {
                    client.cancel()
                    return
                }
                self.readSocks5Request(client)
            })
        }
    }

    private func readSocks5Request(_ client: NWConnection) {
        client.receive(minimumIncompleteLength: 7, maximumLength: 512) { [weak self] data, _, _, err in
            guard let self, err == nil, let data, data.count >= 7,
                  data[data.startIndex] == 0x05 else {
                client.cancel()
                return
            }

            let cmd = data[data.startIndex + 1]
            guard let target = Socks5Codec.parseAddress(from: data, startingAt: 3) else {
                client.cancel()
                return
            }

            if cmd == 0x03 {
                // UDP ASSOCIATE: return bound 127.0.0.1:<udpPort> and keep TCP control channel open
                self.lock.lock()
                let port = self.udpPort
                self.lock.unlock()
                let reply = Data([
                    0x05, 0x00, 0x00, 0x01,
                    127, 0, 0, 1,
                    UInt8((port >> 8) & 0xFF), UInt8(port & 0xFF)
                ])
                client.send(content: reply, completion: .contentProcessed { sendErr in
                    if sendErr != nil {
                        client.cancel()
                        return
                    }
                    self.holdControlConnection(client)
                })
                return
            }

            guard cmd == 0x01 else {
                client.send(content: Data([0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]), completion: .contentProcessed { _ in
                    client.cancel()
                })
                return
            }

            // TCP CONNECT
            if target.port == 53 {
                self.onPacketEvent(.criticalControl, true, false)
                let reply = Data([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                client.send(content: reply, completion: .contentProcessed { [weak self] sendErr in
                    guard let self, sendErr == nil else {
                        client.cancel()
                        return
                    }
                    self.handleTCPDNSStream(client)
                })
                return
            }

            if self.dnsEngine.filter.shouldBlock(domain: target.host) {
                client.send(content: Data([0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0]), completion: .contentProcessed { _ in
                    client.cancel()
                })
                return
            }

            self.openRemoteTCPRelay(client: client, host: target.host, port: target.port)
        }
    }

    private func holdControlConnection(_ client: NWConnection) {
        client.receive(minimumIncompleteLength: 1, maximumLength: 256) { [weak self] _, _, isComplete, err in
            if isComplete || err != nil {
                client.cancel()
            } else {
                self?.holdControlConnection(client)
            }
        }
    }

    private func handleTCPDNSStream(_ client: NWConnection) {
        client.receive(minimumIncompleteLength: 2, maximumLength: 4096) { [weak self] data, _, _, err in
            guard let self, err == nil, let data, data.count >= 2 else {
                client.cancel()
                return
            }
            let msgLen = Int((UInt16(data[data.startIndex]) << 8) | UInt16(data[data.startIndex + 1]))
            guard data.count >= 2 + msgLen else {
                client.cancel()
                return
            }
            let query = data.subdata(in: (data.startIndex + 2)..<(data.startIndex + 2 + msgLen))
            self.dnsEngine.processQuery(payload: query, config: self.configProvider()) { [weak self] result in
                guard let self, let result else {
                    client.cancel()
                    return
                }
                self.onDNSResult(result)
                let resp = result.responseData
                var framed = Data(capacity: 2 + resp.count)
                framed.append(UInt8((resp.count >> 8) & 0xFF))
                framed.append(UInt8(resp.count & 0xFF))
                framed.append(resp)
                client.send(content: framed, completion: .contentProcessed { _ in
                    client.cancel()
                })
            }
        }
    }

    private func openRemoteTCPRelay(client: NWConnection, host: String, port: UInt16) {
        guard let nwPort = NWEndpoint.Port(rawValue: port) else {
            client.cancel()
            return
        }

        let lane = classifyPort(port, payloadSize: 256, isUDP: false)
        onPacketEvent(lane, false, false)

        let tcpOpts = NWProtocolTCP.Options()
        tcpOpts.noDelay = true
        let params = NWParameters(tls: nil, tcp: tcpOpts)
        params.prohibitedInterfaceTypes = [.other]
        params.preferNoProxies = true
        params.serviceClass = (lane == .criticalControl || lane == .realtimeInteractive)
            ? .interactiveVoice
            : (lane == .standardWeb ? .responsiveData : .background)

        let remote = NWConnection(host: NWEndpoint.Host(host), port: nwPort, using: params)
        let flag = TCPReadyFlag()

        remote.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                guard flag.claim() else { return }
                let okReply = Data([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                client.send(content: okReply, completion: .contentProcessed { sendErr in
                    if sendErr != nil {
                        client.cancel()
                        remote.cancel()
                        return
                    }
                    self.pumpTCP(from: client, to: remote)
                    self.pumpTCP(from: remote, to: client)
                })
            case .failed, .cancelled:
                if flag.claim() {
                    let failReply = Data([0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    client.send(content: failReply, completion: .contentProcessed { _ in
                        client.cancel()
                    })
                } else {
                    client.cancel()
                }
            default:
                break
            }
        }
        remote.start(queue: listenerQueue)
    }

    private func pumpTCP(from source: NWConnection, to destination: NWConnection) {
        source.receive(minimumIncompleteLength: 1, maximumLength: 16384) { [weak self] data, _, isComplete, err in
            if let data, !data.isEmpty {
                destination.send(content: data, completion: .contentProcessed { sendErr in
                    if sendErr != nil || isComplete || err != nil {
                        source.cancel()
                        destination.cancel()
                    } else {
                        self?.pumpTCP(from: source, to: destination)
                    }
                })
            } else {
                source.cancel()
                destination.cancel()
            }
        }
    }

    private func classifyPort(_ port: UInt16, payloadSize: Int, isUDP: Bool) -> QoSLane {
        if port == 53 { return .criticalControl }
        if isUDP {
            switch port {
            case 3478...3481, 5000...5065, 7000...9000, 14000...32000, 50000...50100:
                return .realtimeInteractive
            default:
                return payloadSize <= 512 ? .realtimeInteractive : .standardWeb
            }
        }
        switch port {
        case 80, 443, 8080, 8443:
            return .standardWeb
        case 5223, 5228: // Push / interactive signaling
            return .criticalControl
        default:
            return .bulkBackground
        }
    }
}
