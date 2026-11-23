import Foundation

public enum AppGroupConstants {
    public static let appGroupIdentifier = "group.com.nguyenbinhchanh.pingpulse"
    public static let tunnelBundleIdentifier = "com.nguyenbinhchanh.pingpulse.tunnel"

    public static var resolvedTunnelBundleIdentifier: String {
        if let mainID = Bundle.main.bundleIdentifier, !mainID.isEmpty {
            if mainID.hasSuffix(".tunnel") {
                return mainID
            }
            return "\(mainID).tunnel"
        }
        return tunnelBundleIdentifier
    }

    public static let tunnelVirtualAddress = "10.11.0.2"
    public static let tunnelSubnetMask = "255.255.255.0"
    public static let tunnelGatewayAddress = "10.11.0.1"
    public static let tunnelDNSServer = "10.11.0.1"

    public static let tunnelVirtualIPv6Address = "fd11:0:0:1::2"
    public static let tunnelDNSIPv6Server = "fd11:0:0:1::1"

    public enum Keys {
        public static let optimizationConfig = "pingpulse.optimizationConfig.v1"
        public static let tunnelStats = "pingpulse.tunnelStats.v1"
        public static let queryLogs = "pingpulse.queryLogs.v1"
        public static let resolverMetrics = "pingpulse.resolverMetrics.v1"
    }

    public enum IPCCommand: String, Codable, Sendable {
        case getLiveStats = "GET_LIVE_STATS"
        case getFullTelemetry = "GET_FULL_TELEMETRY"
        case pushConfig = "PUSH_CONFIG"
        case reloadConfig = "RELOAD_CONFIG"
        case flushCache = "FLUSH_CACHE"
        case clearLogs = "CLEAR_LOGS"
    }
}
