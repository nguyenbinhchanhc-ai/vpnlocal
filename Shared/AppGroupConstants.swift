import Foundation

public enum AppGroupConstants {
    public static let appGroupIdentifier = "group.com.nguyenbinhchanh.pingpulse"
    public static let tunnelBundleIdentifier = "com.nguyenbinhchanh.pingpulse.tunnel"

    /// Resolves the actual embedded Network Extension bundle identifier at runtime,
    /// handling cases where a sideloading/signing tool rewrote the app or extension bundle ID.
    public static var resolvedTunnelBundleIdentifier: String {
        if let plugInsURL = Bundle.main.builtInPlugInsURL,
           let contents = try? FileManager.default.contentsOfDirectory(at: plugInsURL, includingPropertiesForKeys: nil),
           let appexURL = contents.first(where: { $0.pathExtension == "appex" }),
           let extBundle = Bundle(url: appexURL),
           let extID = extBundle.bundleIdentifier,
           !extID.isEmpty {
            return extID
        }
        if let mainID = Bundle.main.bundleIdentifier, !mainID.isEmpty {
            if mainID.hasSuffix(".tunnel") {
                return mainID
            }
            return "\(mainID).tunnel"
        }
        return tunnelBundleIdentifier
    }

    // Distinct RFC 2544 virtual addresses so tunnelRemoteAddress != local TUN IP != DNS server IP
    public static let tunnelGatewayAddress = "198.18.0.1"
    public static let tunnelVirtualAddress = "198.18.0.2"
    public static let tunnelSubnetMask = "255.255.255.0"
    public static let tunnelDNSServer = "198.18.0.3"
    public static let tunnelSecondaryDNSServer = "198.18.0.4"

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
