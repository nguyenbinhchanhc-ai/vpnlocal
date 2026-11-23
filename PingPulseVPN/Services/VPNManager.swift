import Combine
import Foundation
import NetworkExtension

@MainActor
public final class VPNManager: ObservableObject {
    @Published public private(set) var status: NEVPNStatus = .disconnected
    @Published public var config: OptimizationConfig
    @Published public private(set) var stats: TunnelStats
    @Published public private(set) var queryLogs: [QueryLogEntry] = []
    @Published public private(set) var resolverMetrics: [ResolverHealthMetric] = []
    @Published public var lastErrorMessage: String?

    private let store = SharedStore.shared
    private var manager: NETunnelProviderManager?
    private var statusObserver: NSObjectProtocol?
    private var pollTimer: Timer?

    public init() {
        self.config = store.loadConfig()
        self.stats = store.loadStats()
        self.queryLogs = store.loadQueryLogs()
        self.resolverMetrics = store.loadResolverMetrics()

        observeVPNStatus()
        Task {
            await loadOrCreateManager()
        }
        startPolling()
    }

    deinit {
        if let statusObserver {
            NotificationCenter.default.removeObserver(statusObserver)
        }
        pollTimer?.invalidate()
    }

    public var isConnectedOrConnecting: Bool {
        status == .connected || status == .connecting || status == .reasserting
    }

    public var statusDisplayText: String {
        switch status {
        case .invalid: return "Not Configured"
        case .disconnected: return "Disconnected"
        case .connecting: return "Starting Local Engine..."
        case .connected: return "Active • Local QoS + DNS"
        case .reasserting: return "Adapting Network Path..."
        case .disconnecting: return "Stopping..."
        @unknown default: return "Unknown"
        }
    }

    public func toggleVPN() {
        lastErrorMessage = nil
        if isConnectedOrConnecting {
            manager?.connection.stopVPNTunnel()
        } else {
            Task {
                await startVPN()
            }
        }
    }

    public func applyConfig(_ newConfig: OptimizationConfig) {
        config = newConfig
        store.saveConfig(newConfig)
        sendIPC(.reloadConfig)
        Task {
            await syncOnDemandRules()
        }
    }

    public func selectProfile(_ profile: TrafficProfile) {
        var updated = config
        updated.applyProfilePreset(profile)
        applyConfig(updated)
    }

    public func flushDNSCache() {
        sendIPC(.flushCache)
    }

    public func clearLogs() {
        queryLogs = []
        store.saveQueryLogs([])
        sendIPC(.clearLogs)
    }

    public func refreshFromStore() {
        queryLogs = store.loadQueryLogs()
        resolverMetrics = store.loadResolverMetrics()
        if status == .connected {
            sendIPC(.getLiveStats)
        } else {
            stats = store.loadStats()
        }
    }

    // MARK: - NETunnelProviderManager Lifecycle

    private func loadOrCreateManager() async {
        do {
            let managers = try await NETunnelProviderManager.loadAllFromPreferences()
            if let existing = managers.first(where: {
                ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == AppGroupConstants.tunnelBundleIdentifier
            }) {
                self.manager = existing
                self.status = existing.connection.status
            } else {
                let created = NETunnelProviderManager()
                configureProtocol(on: created)
                try await created.saveToPreferences()
                try await created.loadFromPreferences()
                self.manager = created
                self.status = created.connection.status
            }
        } catch {
            self.lastErrorMessage = "VPN profile error: \(error.localizedDescription)"
        }
    }

    private func startVPN() async {
        do {
            if manager == nil {
                await loadOrCreateManager()
            }
            guard let mgr = manager else { return }
            configureProtocol(on: mgr)
            try await mgr.saveToPreferences()
            try await mgr.loadFromPreferences()
            try mgr.connection.startVPNTunnel()
        } catch {
            self.lastErrorMessage = "Cannot start local VPN: \(error.localizedDescription)"
        }
    }

    private func syncOnDemandRules() async {
        guard let mgr = manager else { return }
        configureProtocol(on: mgr)
        do {
            try await mgr.saveToPreferences()
            try await mgr.loadFromPreferences()
        } catch {
            self.lastErrorMessage = "Failed to update On-Demand rules: \(error.localizedDescription)"
        }
    }

    private func configureProtocol(on mgr: NETunnelProviderManager) {
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = AppGroupConstants.tunnelBundleIdentifier
        proto.serverAddress = "PingPulse Local Engine (10.11.0.1)"
        mgr.protocolConfiguration = proto
        mgr.localizedDescription = "PingPulse Local Anti-Ping VPN"
        mgr.isEnabled = true

        if config.onDemandAutoConnect {
            let connectRule = NEOnDemandRuleConnect()
            connectRule.interfaceTypeMatch = .any
            mgr.onDemandRules = [connectRule]
            mgr.isOnDemandEnabled = true
        } else {
            mgr.onDemandRules = []
            mgr.isOnDemandEnabled = false
        }
    }

    private func observeVPNStatus() {
        statusObserver = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: nil,
            queue: .main
        ) { [weak self] notification in
            guard let self,
                  let session = notification.object as? NETunnelProviderSession else { return }
            Task { @MainActor in
                self.status = session.status
                self.refreshFromStore()
            }
        }
    }

    private func startPolling() {
        pollTimer = Timer.scheduledTimer(withTimeInterval: 2.0, repeats: true) { [weak self] _ in
            Task { @MainActor in
                self?.refreshFromStore()
            }
        }
    }

    private func sendIPC(_ command: AppGroupConstants.IPCCommand) {
        guard let session = manager?.connection as? NETunnelProviderSession,
              status == .connected || status == .reasserting else {
            return
        }
        let payload = Data(command.rawValue.utf8)
        do {
            try session.sendProviderMessage(payload) { [weak self] responseData in
                guard let self, command == .getLiveStats, let responseData,
                      let decoded = try? JSONDecoder().decode(TunnelStats.self, from: responseData) else {
                    return
                }
                Task { @MainActor in
                    self.stats = decoded
                }
            }
        } catch {
            // Extension may still be transitioning state
        }
    }
}
