import Foundation
import Network
import NetworkExtension

public final class PacketTunnelProvider: NEPacketTunnelProvider {
    private let store = SharedStore.shared
    private let scheduler = PacketScheduler()
    private let dnsCache = DNSCache(maxEntries: 2048)
    private let filterEngine = TrafficFilterEngine()
    private let upstreamRacer = UpstreamRacer()
    private var udpRelay: UDPRelayEngine?

    private var pathMonitor: NWPathMonitor?
    private let engineQueue = DispatchQueue(label: "com.nguyenbinhchanh.pingpulse.tunnel.engine", qos: .userInteractive)
    private let persistenceQueue = DispatchQueue(label: "com.nguyenbinhchanh.pingpulse.tunnel.persist", qos: .utility)

    private let stateLock = NSLock()
    private var config: OptimizationConfig = .defaultConfig
    private var stats = TunnelStats()
    private var recentLogs: [QueryLogEntry] = []
    private var isRunning = false
    private var activeMTU = 1420
    private var activePathLabel = "Detecting"
    private var persistTimer: DispatchSourceTimer?

    public override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        let loadedConfig = store.loadConfig()
        stateLock.lock()
        self.config = loadedConfig
        self.stats = TunnelStats(startedAt: Date())
        self.recentLogs = store.loadQueryLogs()
        self.isRunning = true
        stateLock.unlock()

        filterEngine.update(config: loadedConfig)
        upstreamRacer.updateResolvers(loadedConfig.resolvers)

        udpRelay = UDPRelayEngine { [weak self] replyData in
            guard let self else { return }
            self.writeTunnelPackets([replyData], protocols: [NSNumber(value: AF_INET)])
            self.stateLock.lock()
            self.stats.udpRelayedPackets += 1
            self.stateLock.unlock()
        }

        startPathMonitoring(initialConfig: loadedConfig)
        startPersistenceTimer()

        applyTunnelNetworkSettings(config: loadedConfig, mtu: loadedConfig.wifiMTU) { [weak self] error in
            if let error {
                completionHandler(error)
                return
            }
            completionHandler(nil)
            self?.readPacketsLoop()
        }
    }

    public override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        stateLock.lock()
        isRunning = false
        stateLock.unlock()

        persistTimer?.cancel()
        persistTimer = nil
        pathMonitor?.cancel()
        pathMonitor = nil
        udpRelay?.stopAll()
        scheduler.clear()
        flushTelemetryNow()
        completionHandler()
    }

    public override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        guard let cmdRaw = String(data: messageData, encoding: .utf8),
              let cmd = AppGroupConstants.IPCCommand(rawValue: cmdRaw) else {
            completionHandler?(nil)
            return
        }

        switch cmd {
        case .getLiveStats:
            flushTelemetryNow()
            stateLock.lock()
            let currentStats = stats
            stateLock.unlock()
            let encoded = try? JSONEncoder().encode(currentStats)
            completionHandler?(encoded)

        case .reloadConfig:
            let updated = store.loadConfig()
            stateLock.lock()
            self.config = updated
            stateLock.unlock()
            filterEngine.update(config: updated)
            upstreamRacer.updateResolvers(updated.resolvers)
            applyTunnelNetworkSettings(config: updated, mtu: activeMTU) { _ in
                completionHandler?(Data("OK".utf8))
            }

        case .flushCache:
            dnsCache.clear()
            completionHandler?(Data("FLUSHED".utf8))

        case .clearLogs:
            stateLock.lock()
            recentLogs.removeAll()
            stateLock.unlock()
            store.saveQueryLogs([])
            completionHandler?(Data("CLEARED".utf8))
        }
    }

    // MARK: - Network Settings & Adaptive Path

    private func startPathMonitoring(initialConfig: OptimizationConfig) {
        let monitor = NWPathMonitor()
        monitor.pathUpdateHandler = { [weak self] path in
            guard let self else { return }
            let currentConfig = self.currentConfig()
            let isCellular = path.usesInterfaceType(.cellular)
            let isWifi = path.usesInterfaceType(.wifi)

            let targetMTU: Int
            let label: String
            if isCellular {
                targetMTU = currentConfig.adaptiveMTUEnabled ? currentConfig.cellularMTU : currentConfig.wifiMTU
                label = path.isConstrained ? "Cellular (Low Data)" : "4G/5G Cellular"
            } else if isWifi {
                targetMTU = currentConfig.wifiMTU
                label = "Wi-Fi"
            } else {
                targetMTU = currentConfig.wifiMTU
                label = path.status == .satisfied ? "Connected" : "Reconnecting"
            }

            self.stateLock.lock()
            let mtuChanged = self.activeMTU != targetMTU
            self.activeMTU = targetMTU
            self.activePathLabel = label
            self.stats.activeMTU = targetMTU
            self.stats.networkPathDescription = label
            self.stateLock.unlock()

            if mtuChanged && self.tunnelRunning() {
                self.applyTunnelNetworkSettings(config: currentConfig, mtu: targetMTU) { _ in }
            }
        }
        monitor.start(queue: engineQueue)
        self.pathMonitor = monitor
        self.activeMTU = initialConfig.wifiMTU
    }

    private func applyTunnelNetworkSettings(
        config: OptimizationConfig,
        mtu: Int,
        completion: @escaping (Error?) -> Void
    ) {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: AppGroupConstants.tunnelGatewayAddress)
        settings.mtu = NSNumber(value: max(1280, min(1500, mtu)))

        let ipv4 = NEIPv4Settings(
            addresses: [AppGroupConstants.tunnelVirtualAddress],
            subnetMasks: [AppGroupConstants.tunnelSubnetMask]
        )

        var included: [NEIPv4Route] = [
            NEIPv4Route(destinationAddress: "10.11.0.0", subnetMask: "255.255.255.0")
        ]
        if config.enableUDPRelayRoutes {
            for rule in config.customRoutes where rule.isEnabled {
                if let parsed = rule.parsedNetwork {
                    included.append(NEIPv4Route(destinationAddress: parsed.address, subnetMask: parsed.subnetMask))
                }
            }
        }
        ipv4.includedRoutes = included

        var excluded: [NEIPv4Route] = [
            NEIPv4Route(destinationAddress: "192.168.0.0", subnetMask: "255.255.0.0"),
            NEIPv4Route(destinationAddress: "172.16.0.0", subnetMask: "255.240.0.0"),
            NEIPv4Route(destinationAddress: "127.0.0.0", subnetMask: "255.0.0.0"),
            NEIPv4Route(destinationAddress: "224.0.0.0", subnetMask: "240.0.0.0")
        ]
        // Exclude upstream resolver IPs so extension queries never loop into the tunnel
        for resolver in config.resolvers where !resolver.address.isEmpty {
            excluded.append(NEIPv4Route(destinationAddress: resolver.address, subnetMask: "255.255.255.255"))
        }
        ipv4.excludedRoutes = excluded
        settings.ipv4Settings = ipv4

        let dnsSettings = NEDNSSettings(servers: [
            AppGroupConstants.tunnelDNSServer,
            AppGroupConstants.tunnelSecondaryDNSServer
        ])
        dnsSettings.matchDomains = [""]
        dnsSettings.matchDomainsNoSearch = true
        settings.dnsSettings = dnsSettings

        setTunnelNetworkSettings(settings, completionHandler: completion)
    }

    // MARK: - Packet Loop & QoS Dispatch

    private func readPacketsLoop() {
        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self, self.tunnelRunning() else { return }

            self.engineQueue.async {
                self.processIncomingBatch(packets: packets, protocols: protocols)
                self.readPacketsLoop()
            }
        }
    }

    private func processIncomingBatch(packets: [Data], protocols: [NSNumber]) {
        var parsedPackets: [IPv4Packet] = []
        parsedPackets.reserveCapacity(packets.count)

        for (index, raw) in packets.enumerated() {
            let protoFamily = index < protocols.count ? protocols[index].int32Value : AF_INET
            guard protoFamily == AF_INET, let ipv4 = IPv4Packet(data: raw) else { continue }
            parsedPackets.append(ipv4)
        }

        guard !parsedPackets.isEmpty else { return }

        let counts = scheduler.enqueueBatch(parsedPackets)
        let currentCfg = currentConfig()

        stateLock.lock()
        stats.packetsScheduledP0 += counts[.criticalControl, default: 0]
        stats.packetsScheduledP1 += counts[.realtimeInteractive, default: 0]
        stats.packetsScheduledP2 += counts[.standardWeb, default: 0]
        stats.packetsScheduledP3 += counts[.bulkBackground, default: 0]
        stateLock.unlock()

        let scheduled = scheduler.dequeueBurst(
            maxBulkBytes: currentCfg.maxBurstBytesPerTick,
            enablePacing: currentCfg.enableQoSPacing
        )

        for item in scheduled {
            dispatchScheduledPacket(item.packet, config: currentCfg)
        }
    }

    private func dispatchScheduledPacket(_ packet: IPv4Packet, config: OptimizationConfig) {
        if packet.proto == IPProtocolNumber.icmp.rawValue,
           let reply = IPv4Packet.buildICMPEchoReply(for: packet) {
            writeTunnelPackets([reply], protocols: [NSNumber(value: AF_INET)])
            return
        }

        guard let udp = packet.udpSegment else { return }

        if udp.destinationPort == 53 {
            handleDNSQuery(packet: packet, udp: udp, config: config)
            return
        }

        if config.enableUDPRelayRoutes {
            udpRelay?.forwardUpstream(packet: packet, udp: udp)
        }
    }

    // MARK: - On-Device DNS Query Optimizer

    private func handleDNSQuery(packet: IPv4Packet, udp: UDPSegment, config: OptimizationConfig) {
        let startTime = DispatchTime.now()
        guard let question = DNSWireParser.parseQuestion(from: udp.payload) else { return }

        // 1. Background Noise & Telemetry Shield
        if filterEngine.shouldBlock(domain: question.domain) {
            let synth = DNSWireParser.buildSyntheticResponse(
                for: udp.payload,
                question: question,
                rcode: 3, // NXDOMAIN
                zeroAddressAnswer: false
            )
            sendDNSReply(synth, originalPacket: packet, originalUDP: udp)
            recordDNSLog(
                domain: question.domain,
                recordType: question.recordTypeLabel,
                outcome: .blockedNoise,
                latencyMs: elapsedMs(since: startTime),
                upstream: "Local Noise Shield"
            )
            return
        }

        // 2. Optional IPv6 AAAA Suppression (prevents slow Happy-Eyeballs fallback when IPv6 path lags)
        if config.suppressIPv6AAAA && question.qtype == DNSRecordType.aaaa.rawValue {
            let emptyNoError = DNSWireParser.buildSyntheticResponse(
                for: udp.payload,
                question: question,
                rcode: 0,
                zeroAddressAnswer: false
            )
            sendDNSReply(emptyNoError, originalPacket: packet, originalUDP: udp)
            recordDNSLog(
                domain: question.domain,
                recordType: question.recordTypeLabel,
                outcome: .ipv6Suppressed,
                latencyMs: elapsedMs(since: startTime),
                upstream: "IPv4 Fast-Path"
            )
            return
        }

        let cacheKey = DNSCacheKey(domain: question.domain, qtype: question.qtype, qclass: question.qclass)
        let lookup = dnsCache.lookup(
            key: cacheKey,
            transactionID: question.transactionID,
            enableSWR: config.enableSWRCache
        )

        switch lookup {
        case let .freshHit(response, shouldPrefetch, upstreamName):
            sendDNSReply(response, originalPacket: packet, originalUDP: udp)
            recordDNSLog(
                domain: question.domain,
                recordType: question.recordTypeLabel,
                outcome: .cacheHit,
                latencyMs: elapsedMs(since: startTime),
                upstream: "RAM (\(upstreamName))"
            )
            if shouldPrefetch {
                revalidateInBackground(queryPayload: udp.payload, key: cacheKey, config: config)
            }

        case let .staleHit(response, upstreamName):
            sendDNSReply(response, originalPacket: packet, originalUDP: udp)
            recordDNSLog(
                domain: question.domain,
                recordType: question.recordTypeLabel,
                outcome: .swrHit,
                latencyMs: elapsedMs(since: startTime),
                upstream: "SWR (\(upstreamName))"
            )
            revalidateInBackground(queryPayload: udp.payload, key: cacheKey, config: config)

        case .miss:
            upstreamRacer.resolve(
                queryData: udp.payload,
                enableHedgedRacing: config.enableHedgedRacing,
                hedgeDelayMs: config.hedgeDelayMs
            ) { [weak self] resolution in
                guard let self else { return }
                if let resolution {
                    let rewritten = DNSWireParser.rewriteTransactionID(in: resolution.responseData, to: question.transactionID)
                    self.sendDNSReply(rewritten, originalPacket: packet, originalUDP: udp)

                    let ttl = DNSWireParser.extractMinTTL(from: rewritten, fallbackTTL: config.minCacheTTLSeconds)
                    self.dnsCache.insert(
                        key: cacheKey,
                        response: rewritten,
                        ttlSeconds: ttl,
                        minTTLSeconds: config.minCacheTTLSeconds,
                        swrGraceSeconds: config.swrGraceSeconds,
                        upstreamName: resolution.resolverName
                    )

                    self.recordDNSLog(
                        domain: question.domain,
                        recordType: question.recordTypeLabel,
                        outcome: .upstreamRace,
                        latencyMs: resolution.latencyMs,
                        upstream: resolution.resolverName,
                        hedgedWin: resolution.wasHedgedWin
                    )
                } else {
                    let servFail = DNSWireParser.buildSyntheticResponse(
                        for: udp.payload,
                        question: question,
                        rcode: 2
                    )
                    self.sendDNSReply(servFail, originalPacket: packet, originalUDP: udp)
                    self.recordDNSLog(
                        domain: question.domain,
                        recordType: question.recordTypeLabel,
                        outcome: .failed,
                        latencyMs: self.elapsedMs(since: startTime),
                        upstream: "Timeout"
                    )
                }
            }
        }
    }

    private func revalidateInBackground(queryPayload: Data, key: DNSCacheKey, config: OptimizationConfig) {
        upstreamRacer.resolve(
            queryData: queryPayload,
            enableHedgedRacing: config.enableHedgedRacing,
            hedgeDelayMs: config.hedgeDelayMs
        ) { [weak self] resolution in
            guard let self, let resolution else { return }
            let ttl = DNSWireParser.extractMinTTL(from: resolution.responseData, fallbackTTL: config.minCacheTTLSeconds)
            self.dnsCache.insert(
                key: key,
                response: resolution.responseData,
                ttlSeconds: ttl,
                minTTLSeconds: config.minCacheTTLSeconds,
                swrGraceSeconds: config.swrGraceSeconds,
                upstreamName: resolution.resolverName
            )
        }
    }

    private func sendDNSReply(_ dnsPayload: Data, originalPacket: IPv4Packet, originalUDP: UDPSegment) {
        guard !dnsPayload.isEmpty else { return }
        let ipReply = IPv4Packet.buildUDPReply(
            sourceIP: originalPacket.destinationIP,
            sourcePort: originalUDP.destinationPort,
            destinationIP: originalPacket.sourceIP,
            destinationPort: originalUDP.sourcePort,
            udpPayload: dnsPayload,
            dscp: 46
        )
        writeTunnelPackets([ipReply], protocols: [NSNumber(value: AF_INET)])
    }

    private func writeTunnelPackets(_ packets: [Data], protocols: [NSNumber]) {
        packetFlow.writePackets(packets, withProtocols: protocols)
    }

    // MARK: - Telemetry & Persistence

    private func recordDNSLog(
        domain: String,
        recordType: String,
        outcome: QueryResolutionOutcome,
        latencyMs: Double,
        upstream: String,
        hedgedWin: Bool = false
    ) {
        let entry = QueryLogEntry(
            domain: domain,
            recordType: recordType,
            outcome: outcome,
            latencyMs: latencyMs,
            upstreamUsed: upstream
        )

        stateLock.lock()
        stats.totalQueries += 1
        switch outcome {
        case .cacheHit: stats.cacheHits += 1
        case .swrHit: stats.swrHits += 1
        case .blockedNoise: stats.blockedNoiseQueries += 1
        case .upstreamRace, .ipv6Suppressed, .failed: break
        }
        if hedgedWin { stats.hedgedSaves += 1 }
        let count = Double(stats.totalQueries)
        stats.averageLocalResolutionMs = ((stats.averageLocalResolutionMs * (count - 1)) + latencyMs) / count
        stats.updatedAt = Date()

        recentLogs.insert(entry, at: 0)
        if recentLogs.count > 200 {
            recentLogs.removeLast(recentLogs.count - 200)
        }
        stateLock.unlock()
    }

    private func startPersistenceTimer() {
        let timer = DispatchSource.makeTimerSource(queue: persistenceQueue)
        timer.schedule(deadline: .now() + .seconds(2), repeating: .seconds(2))
        timer.setEventHandler { [weak self] in
            self?.flushTelemetryNow()
        }
        timer.resume()
        self.persistTimer = timer
    }

    private func flushTelemetryNow() {
        stateLock.lock()
        let statsSnapshot = stats
        let logsSnapshot = recentLogs
        stateLock.unlock()

        store.saveStats(statsSnapshot)
        store.saveQueryLogs(logsSnapshot)
        store.saveResolverMetrics(upstreamRacer.currentMetricsSnapshot())
    }

    private func currentConfig() -> OptimizationConfig {
        stateLock.lock()
        defer { stateLock.unlock() }
        return config
    }

    private func tunnelRunning() -> Bool {
        stateLock.lock()
        defer { stateLock.unlock() }
        return isRunning
    }

    private func elapsedMs(since start: DispatchTime) -> Double {
        Double(DispatchTime.now().uptimeNanoseconds - start.uptimeNanoseconds) / 1_000_000.0
    }
}
