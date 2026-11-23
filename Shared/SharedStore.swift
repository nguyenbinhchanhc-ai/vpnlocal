import Foundation

public final class SharedStore: @unchecked Sendable {
    public static let shared = SharedStore()

    private let lock = NSLock()
    private let defaults: UserDefaults
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()

    public init(suiteName: String = AppGroupConstants.appGroupIdentifier) {
        self.defaults = UserDefaults(suiteName: suiteName) ?? .standard
    }

    public func loadConfig() -> OptimizationConfig {
        lock.lock()
        defer { lock.unlock() }
        guard let data = defaults.data(forKey: AppGroupConstants.Keys.optimizationConfig),
              let config = try? decoder.decode(OptimizationConfig.self, from: data) else {
            return .defaultConfig
        }
        return config
    }

    public func saveConfig(_ config: OptimizationConfig) {
        lock.lock()
        defer { lock.unlock() }
        if let data = try? encoder.encode(config) {
            defaults.set(data, forKey: AppGroupConstants.Keys.optimizationConfig)
        }
    }

    public func loadStats() -> TunnelStats {
        lock.lock()
        defer { lock.unlock() }
        guard let data = defaults.data(forKey: AppGroupConstants.Keys.tunnelStats),
              let stats = try? decoder.decode(TunnelStats.self, from: data) else {
            return TunnelStats()
        }
        return stats
    }

    public func saveStats(_ stats: TunnelStats) {
        lock.lock()
        defer { lock.unlock() }
        if let data = try? encoder.encode(stats) {
            defaults.set(data, forKey: AppGroupConstants.Keys.tunnelStats)
        }
    }

    public func loadQueryLogs() -> [QueryLogEntry] {
        lock.lock()
        defer { lock.unlock() }
        guard let data = defaults.data(forKey: AppGroupConstants.Keys.queryLogs),
              let logs = try? decoder.decode([QueryLogEntry].self, from: data) else {
            return []
        }
        return logs
    }

    public func saveQueryLogs(_ logs: [QueryLogEntry], maxCount: Int = 200) {
        lock.lock()
        defer { lock.unlock() }
        let trimmed = Array(logs.prefix(maxCount))
        if let data = try? encoder.encode(trimmed) {
            defaults.set(data, forKey: AppGroupConstants.Keys.queryLogs)
        }
    }

    public func loadResolverMetrics() -> [ResolverHealthMetric] {
        lock.lock()
        defer { lock.unlock() }
        guard let data = defaults.data(forKey: AppGroupConstants.Keys.resolverMetrics),
              let metrics = try? decoder.decode([ResolverHealthMetric].self, from: data) else {
            return []
        }
        return metrics
    }

    public func saveResolverMetrics(_ metrics: [ResolverHealthMetric]) {
        lock.lock()
        defer { lock.unlock() }
        if let data = try? encoder.encode(metrics) {
            defaults.set(data, forKey: AppGroupConstants.Keys.resolverMetrics)
        }
    }
}
