import Foundation

public enum AppGroupConstants {
    public static let appGroupIdentifier = "group.com.nguyenbinhchanh.pingpulse"
    public static let tunnelBundleIdentifier = "com.nguyenbinhchanh.pingpulse.tunnel"

    public static let tunnelVirtualAddress = "10.11.0.2"
    public static let tunnelSubnetMask = "255.255.255.0"
    public static let tunnelGatewayAddress = "10.11.0.1"
    public static let tunnelDNSServer = "10.11.0.1"
    public static let tunnelSecondaryDNSServer = "10.11.0.3"

    public enum Keys {
        public static let optimizationConfig = "pingpulse.optimizationConfig.v1"
        public static let tunnelStats = "pingpulse.tunnelStats.v1"
        public static let queryLogs = "pingpulse.queryLogs.v1"
        public static let resolverMetrics = "pingpulse.resolverMetrics.v1"
    }

    public enum IPCCommand: String, Codable, Sendable {
        case getLiveStats = "GET_LIVE_STATS"
        case reloadConfig = "RELOAD_CONFIG"
        case flushCache = "FLUSH_CACHE"
        case clearLogs = "CLEAR_LOGS"
    }
}
