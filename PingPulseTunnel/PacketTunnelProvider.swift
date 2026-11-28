import Foundation
import Network
import NetworkExtension
import Tun2SocksKit

public final class PacketTunnelProvider: NEPacketTunnelProvider {
    private let store = SharedStore.shared
    private let dnsEngine = DNSEngine()
    private var orchestrator: LocalSocks5Orchestrator?

    private var pathMonitor: NWPathMonitor?
    private let tunnelQueue = DispatchQueue(label: "com.nguyenbinhchanh.pingpulse.tunnel.main", qos: .userInteractive)
    private let persistenceQueue = DispatchQueue(label: "com.nguyenbinhchanh.pingpulse.tunnel.persist", qos: .utility)

    private let stateLock = NSLock()
    private var config: OptimizationConfig = .defaultConfig
    private var stats = TunnelStats()
    private var recentLogs: [QueryLogEntry] = []
    private var isRunning = false
    private var activeMTU = 1420
    private var persistTimer: DispatchSourceTimer?

    public override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        let loadedConfig = store.loadConfig()
        stateLock.lock()
        self.config = loadedConfig
        self.stats = TunnelStats(
            activeMTU: loadedConfig.wifiMTU,
            networkPathDescription: "Full-Tunnel Active",
            startedAt: Date()
        )
        self.recentLogs = store.loadQueryLogs()
        self.isRunning = true
        self.activeMTU = loadedConfig.wifiMTU
        stateLock.unlock()

        dnsEngine.updateConfig(loadedConfig)
        startPhysicalPathMonitoring(initialConfig: loadedConfig)
        startPersistenceTimer()

        let localOrchestrator = LocalSocks5Orchestrator(
            dnsEngine: dnsEngine,
            configProvider: { [weak self] in
                self?.currentConfig() ?? .defaultConfig
            },
            onPacketEvent: { [weak self] lane, isDNS, isUDPRelay in
                self?.recordPacketEvent(lane: lane, isDNS: isDNS, isUDPRelay: isUDPRelay)
            },
            onDNSResult: { [weak self] result in
                self?.recordDNSResult(result)
            }
        )
        self.orchestrator = localOrchestrator

        localOrchestrator.start { [weak self] result in
            guard let self else { return }
            switch result {
            case .failure(let error):
                completionHandler(error)

            case .success(let socksPort):
                let mtu = self.currentMTU()
                self.applyFullTunnelSettings(mtu: mtu) { [weak self] settingsError in
                    if let settingsError {
                        completionHandler(settingsError)
                        return
                    }
                    completionHandler(nil)
                    self?.launchHevSocks5Tunnel(socksPort: socksPort, mtu: mtu)
                }
            }
        }
    }

    public override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        stateLock.lock()
        isRunning = false
        stateLock.unlock()

        Socks5Tunnel.quit()
        orchestrator?.stop()
        orchestrator = nil

        persistTimer?.cancel()
        persistTimer = nil
        pathMonitor?.cancel()
        pathMonitor = nil

        flushTelemetryNow()
        completionHandler()
    }

    public override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        let envelope = try? JSONDecoder().decode(IPCEnvelope.self, from: messageData)
        let cmd: AppGroupConstants.IPCCommand?
        if let envelope {
            cmd = envelope.command
        } else if let cmdRaw = String(data: messageData, encoding: .utf8) {
            cmd = AppGroupConstants.IPCCommand(rawValue: cmdRaw)
        } else {
            cmd = nil
        }

        guard let cmd else {
            completionHandler?(nil)
            return
        }

        switch cmd {
        case .getLiveStats:
            syncSocks5Stats()
            flushTelemetryNow()
            stateLock.lock()
            let currentStats = stats
            stateLock.unlock()
            completionHandler?(try? JSONEncoder().encode(currentStats))

        case .getFullTelemetry:
            syncSocks5Stats()
            flushTelemetryNow()
            stateLock.lock()
            let snapshot = TelemetrySnapshot(
                stats: stats,
                logs: recentLogs,
                resolverMetrics: dnsEngine.racer.currentMetricsSnapshot()
            )
            stateLock.unlock()
            completionHandler?(try? JSONEncoder().encode(snapshot))

        case .pushConfig:
            let updated = envelope?.config ?? store.loadConfig()
            store.saveConfig(updated)
            stateLock.lock()
            self.config = updated
            stateLock.unlock()
            dnsEngine.updateConfig(updated)
            completionHandler?(Data("OK".utf8))

        case .reloadConfig:
            let updated = store.loadConfig()
            stateLock.lock()
            self.config = updated
            stateLock.unlock()
            dnsEngine.updateConfig(updated)
            completionHandler?(Data("OK".utf8))

        case .flushCache:
            dnsEngine.cache.clear()
            completionHandler?(Data("FLUSHED".utf8))

        case .clearLogs:
            stateLock.lock()
            recentLogs.removeAll()
            stateLock.unlock()
            store.saveQueryLogs([])
            completionHandler?(Data("CLEARED".utf8))
        }
    }

    // MARK: - Full-Tunnel Settings & Tun2SocksKit Lifecycle

    private func applyFullTunnelSettings(mtu: Int, completion: @escaping (Error?) -> Void) {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: AppGroupConstants.tunnelGatewayAddress)
        settings.mtu = NSNumber(value: max(1280, min(1500, mtu)))

        let ipv4 = NEIPv4Settings(
            addresses: [AppGroupConstants.tunnelVirtualAddress],
            subnetMasks: [AppGroupConstants.tunnelSubnetMask]
        )
        ipv4.includedRoutes = [NEIPv4Route.default()]
        ipv4.excludedRoutes = [
            NEIPv4Route(destinationAddress: "127.0.0.0", subnetMask: "255.0.0.0"),
            NEIPv4Route(destinationAddress: "10.0.0.0", subnetMask: "255.0.0.0"),
            NEIPv4Route(destinationAddress: "169.254.0.0", subnetMask: "255.255.0.0"),
            NEIPv4Route(destinationAddress: "172.16.0.0", subnetMask: "255.240.0.0"),
            NEIPv4Route(destinationAddress: "192.168.0.0", subnetMask: "255.255.0.0"),
            NEIPv4Route(destinationAddress: "224.0.0.0", subnetMask: "240.0.0.0"),
            NEIPv4Route(destinationAddress: "255.255.255.255", subnetMask: "255.255.255.255")
        ]
        settings.ipv4Settings = ipv4

        let ipv6 = NEIPv6Settings(
            addresses: ["fd18::2"],
            networkPrefixLengths: [64]
        )
        ipv6.includedRoutes = [NEIPv6Route.default()]
        ipv6.excludedRoutes = [
            NEIPv6Route(destinationAddress: "::1", networkPrefixLength: 128),
            NEIPv6Route(destinationAddress: "fe80::", networkPrefixLength: 10),
            NEIPv6Route(destinationAddress: "ff00::", networkPrefixLength: 8)
        ]
        settings.ipv6Settings = ipv6

        let dnsSettings = NEDNSSettings(servers: [
            AppGroupConstants.tunnelDNSServer,
            "fd18::3"
        ])
        dnsSettings.matchDomains = [""]
        settings.dnsSettings = dnsSettings

        setTunnelNetworkSettings(settings, completionHandler: completion)
    }

    private func launchHevSocks5Tunnel(socksPort: UInt16, mtu: Int) {
        let yamlConfig = """
        tunnel:
          mtu: \(max(1280, min(1500, mtu)))

        socks5:
          port: \(socksPort)
          address: 127.0.0.1
          udp: 'udp'

        misc:
          task-stack-size: 24576
          tcp-buffer-size: 4096
          max-session-count: 512
          connect-timeout: 5000
          read-write-timeout: 60000
          log-file: stderr
          log-level: error
          limit-nofile: 65535
        """

        tunnelQueue.async { [weak self] in
            guard let self else { return }
            for attempt in 0..<8 {
                if !self.tunnelRunning() { return }
                let code = Socks5Tunnel.run(withConfig: .string(content: yamlConfig))
                if code == 0 || !self.tunnelRunning() {
                    break
                }
                // Wait briefly in case utun FD is still registering after setTunnelNetworkSettings
                if attempt < 7 {
                    Thread.sleep(forTimeInterval: 0.08)
                }
            }
        }
    }

    private func startPhysicalPathMonitoring(initialConfig: OptimizationConfig) {
        let monitor = NWPathMonitor(prohibitedInterfaceTypes: [.other])
        monitor.pathUpdateHandler = { [weak self] path in
            guard let self else { return }
            let cfg = self.currentConfig()
            let targetMTU: Int
            let label: String
            if path.usesInterfaceType(.cellular) {
                targetMTU = cfg.adaptiveMTUEnabled ? cfg.cellularMTU : cfg.wifiMTU
                label = path.isConstrained ? "Cellular (Low Data)" : "4G/5G Cellular"
            } else if path.usesInterfaceType(.wifi) {
                targetMTU = cfg.wifiMTU
                label = "Wi-Fi"
            } else {
                targetMTU = cfg.wifiMTU
                label = path.status == .satisfied ? "Full-Tunnel Active" : "Reconnecting"
            }

            self.stateLock.lock()
            self.activeMTU = targetMTU
            self.stats.activeMTU = targetMTU
            self.stats.networkPathDescription = label
            self.stateLock.unlock()
        }
        monitor.start(queue: persistenceQueue)
        self.pathMonitor = monitor
        self.activeMTU = initialConfig.wifiMTU
    }

    // MARK: - Telemetry & Persistence

    private func recordPacketEvent(lane: QoSLane, isDNS: Bool, isUDPRelay: Bool) {
        stateLock.lock()
        switch lane {
        case .criticalControl: stats.packetsScheduledP0 += 1
        case .realtimeInteractive: stats.packetsScheduledP1 += 1
        case .standardWeb: stats.packetsScheduledP2 += 1
        case .bulkBackground: stats.packetsScheduledP3 += 1
        }
        if isDNS { stats.dnsPacketsRead += 1 }
        if isUDPRelay { stats.udpRelayedPackets += 1 }
        stats.updatedAt = Date()
        stateLock.unlock()
    }

    private func recordDNSResult(_ result: DNSProcessResult) {
        let entry = result.logEntry
        stateLock.lock()
        stats.totalQueries += 1
        switch entry.outcome {
        case .cacheHit: stats.cacheHits += 1
        case .swrHit: stats.swrHits += 1
        case .blockedNoise: stats.blockedNoiseQueries += 1
        case .upstreamRace, .ipv6Suppressed, .failed: break
        }
        if result.hedgedWin { stats.hedgedSaves += 1 }
        let count = Double(stats.totalQueries)
        stats.averageLocalResolutionMs = ((stats.averageLocalResolutionMs * (count - 1)) + entry.latencyMs) / count
        stats.updatedAt = Date()

        recentLogs.insert(entry, at: 0)
        if recentLogs.count > 200 {
            recentLogs.removeLast(recentLogs.count - 200)
        }
        stateLock.unlock()
    }

    private func syncSocks5Stats() {
        let tunStats = Socks5Tunnel.stats
        let totalTunPackets = tunStats.up.packets + tunStats.down.packets
        stateLock.lock()
        if totalTunPackets > 0 {
            stats.rawPacketsRead = totalTunPackets
        } else {
            stats.rawPacketsRead = stats.totalPacketsScheduled
        }
        stateLock.unlock()
    }

    private func startPersistenceTimer() {
        let timer = DispatchSource.makeTimerSource(queue: persistenceQueue)
        timer.schedule(deadline: .now() + .seconds(2), repeating: .seconds(2))
        timer.setEventHandler { [weak self] in
            self?.syncSocks5Stats()
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
        store.saveResolverMetrics(dnsEngine.racer.currentMetricsSnapshot())
    }

    private func currentConfig() -> OptimizationConfig {
        stateLock.lock()
        defer { stateLock.unlock() }
        return config
    }

    private func currentMTU() -> Int {
        stateLock.lock()
        defer { stateLock.unlock() }
        return activeMTU
    }

    private func tunnelRunning() -> Bool {
        stateLock.lock()
        defer { stateLock.unlock() }
        return isRunning
    }
}
