import Combine
import Foundation
import Network
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
        if isConnectedOrConnecting || status == .disconnecting {
            Task {
                await stopVPN()
            }
        } else {
            Task {
                await startVPN()
            }
        }
    }

    public func applyConfig(_ newConfig: OptimizationConfig) {
        config = newConfig
        store.saveConfig(newConfig)
        sendIPCEnvelope(IPCEnvelope(command: .pushConfig, config: newConfig))
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
        sendIPCEnvelope(IPCEnvelope(command: .flushCache))
    }

    public func clearLogs() {
        queryLogs = []
        store.saveQueryLogs([])
        sendIPCEnvelope(IPCEnvelope(command: .clearLogs))
    }

    public func refreshFromStore() {
        if status == .connected || status == .reasserting {
            sendIPCEnvelope(IPCEnvelope(command: .getFullTelemetry))
        } else {
            stats = store.loadStats()
            queryLogs = store.loadQueryLogs()
            resolverMetrics = store.loadResolverMetrics()
        }
    }

    /// Triggers a live HTTPS/DNS lookup through iOS networking to immediately exercise
    /// the local tunnel DNS optimizer and verify query capture.
    public func runDNSTestQuery() {
        lastErrorMessage = nil
        let conn = NWConnection(host: "one.one.one.one", port: .https, using: .tcp)
        conn.stateUpdateHandler = { [weak self] state in
            switch state {
            case .ready, .failed, .cancelled:
                conn.cancel()
                Task { @MainActor [weak self] in
                    try? await Task.sleep(nanoseconds: 350_000_000)
                    self?.refreshFromStore()
                }
            default:
                break
            }
        }
        conn.start(queue: .global(qos: .userInitiated))
    }

    // MARK: - NETunnelProviderManager Lifecycle

    private func loadOrCreateManager() async {
        do {
            let managers = try await NETunnelProviderManager.loadAllFromPreferences()
            let targetBundleID = AppGroupConstants.resolvedTunnelBundleIdentifier
            if let existing = managers.first(where: { mgr in
                let protoID = (mgr.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier
                return protoID == targetBundleID || protoID == AppGroupConstants.tunnelBundleIdentifier || (protoID?.hasSuffix(".tunnel") == true)
            }) {
                self.manager = existing
                self.status = existing.connection.status
                self.refreshFromStore()
            } else {
                let created = NETunnelProviderManager()
                configureProtocol(on: created, allowOnDemand: config.onDemandAutoConnect)
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
            configureProtocol(on: mgr, allowOnDemand: config.onDemandAutoConnect)
            try await mgr.saveToPreferences()
            try await mgr.loadFromPreferences()
            try mgr.connection.startVPNTunnel()
        } catch {
            self.lastErrorMessage = "Cannot start local VPN: \(error.localizedDescription)"
        }
    }

    /// Disables On-Demand BEFORE stopping the tunnel so iOS nesessionmanager does not
    /// immediately restart the VPN when the user turns it off.
    private func stopVPN() async {
        guard let mgr = manager else { return }
        do {
            mgr.isOnDemandEnabled = false
            mgr.onDemandRules = []
            try await mgr.saveToPreferences()
            try await mgr.loadFromPreferences()
        } catch {
            self.lastErrorMessage = "Stop warning: \(error.localizedDescription)"
        }
        mgr.connection.stopVPNTunnel()
    }

    private func syncOnDemandRules() async {
        guard let mgr = manager else { return }
        let shouldEnableOnDemand = isConnectedOrConnecting && config.onDemandAutoConnect
        configureProtocol(on: mgr, allowOnDemand: shouldEnableOnDemand)
        do {
            try await mgr.saveToPreferences()
            try await mgr.loadFromPreferences()
        } catch {
            self.lastErrorMessage = "Failed to update On-Demand rules: \(error.localizedDescription)"
        }
    }

    private func configureProtocol(on mgr: NETunnelProviderManager, allowOnDemand: Bool) {
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = AppGroupConstants.resolvedTunnelBundleIdentifier
        proto.serverAddress = "PingPulse Local Engine (10.11.0.1)"
        mgr.protocolConfiguration = proto
        mgr.localizedDescription = "PingPulse Local Anti-Ping VPN"
        mgr.isEnabled = true

        if allowOnDemand {
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
        pollTimer = Timer.scheduledTimer(withTimeInterval: 1.5, repeats: true) { [weak self] _ in
            Task { @MainActor in
                self?.refreshFromStore()
            }
        }
    }

    private func sendIPCEnvelope(_ envelope: IPCEnvelope) {
        guard let session = manager?.connection as? NETunnelProviderSession,
              status == .connected || status == .reasserting else {
            return
        }
        guard let payload = try? JSONEncoder().encode(envelope) else { return }
        do {
            try session.sendProviderMessage(payload) { [weak self] responseData in
                guard let self else { return }
                Task { @MainActor in
                    guard let responseData else {
                        if envelope.command == .getFullTelemetry {
                            // Fall back to App Group store if provider returned nil
                            self.stats = self.store.loadStats()
                            self.queryLogs = self.store.loadQueryLogs()
                            self.resolverMetrics = self.store.loadResolverMetrics()
                        }
                        return
                    }

                    if envelope.command == .getFullTelemetry,
                       let snapshot = try? JSONDecoder().decode(TelemetrySnapshot.self, from: responseData) {
                        self.stats = snapshot.stats
                        self.queryLogs = snapshot.logs
                        self.resolverMetrics = snapshot.resolverMetrics
                    } else if envelope.command == .getLiveStats,
                              let decoded = try? JSONDecoder().decode(TunnelStats.self, from: responseData) {
                        self.stats = decoded
                    }
                }
            }
        } catch {
            self.lastErrorMessage = "Extension IPC error: \(error.localizedDescription)"
        }
    }
}
