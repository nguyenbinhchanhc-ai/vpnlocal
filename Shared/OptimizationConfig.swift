import Foundation

public enum TrafficProfile: String, Codable, CaseIterable, Identifiable, Sendable {
    case gamingShield = "gaming_shield"
    case balanced = "balanced"
    case strictMinimal = "strict_minimal"

    public var id: String { rawValue }

    public var displayName: String {
        switch self {
        case .gamingShield: return "Gaming & Low-Ping"
        case .balanced: return "Balanced QoS"
        case .strictMinimal: return "Strict Noise Shield"
        }
    }

    public var summary: String {
        switch self {
        case .gamingShield:
            return "Aggressive hedged DNS racing (30ms), background telemetry blocking, strict P0/P1 packet priority, and cellular MTU tuning."
        case .balanced:
            return "Smart SWR DNS caching, moderate telemetry shielding, and fair-queue pacing for everyday browsing & streaming."
        case .strictMinimal:
            return "Maximum tracker/telemetry suppression to minimize background upload bursts and radio wakeups."
        }
    }
}

public enum ResolverProtocol: String, Codable, CaseIterable, Sendable {
    case doh = "DoH"
    case udp = "UDP"
}

public struct UpstreamResolver: Codable, Identifiable, Equatable, Hashable, Sendable {
    public let id: String
    public var name: String
    public var endpoint: String
    public var address: String
    public var port: UInt16
    public var proto: ResolverProtocol
    public var isEnabled: Bool
    public var regionTag: String

    public init(
        id: String = UUID().uuidString,
        name: String,
        endpoint: String,
        address: String,
        port: UInt16,
        proto: ResolverProtocol,
        isEnabled: Bool = true,
        regionTag: String = "Global"
    ) {
        self.id = id
        self.name = name
        self.endpoint = endpoint
        self.address = address
        self.port = port
        self.proto = proto
        self.isEnabled = isEnabled
        self.regionTag = regionTag
    }

    public static let defaults: [UpstreamResolver] = [
        UpstreamResolver(
            id: "cloudflare-udp",
            name: "Cloudflare Edge UDP",
            endpoint: "1.1.1.1:53",
            address: "1.1.1.1",
            port: 53,
            proto: .udp,
            isEnabled: true,
            regionTag: "Anycast"
        ),
        UpstreamResolver(
            id: "google-udp",
            name: "Google Fast UDP",
            endpoint: "8.8.8.8:53",
            address: "8.8.8.8",
            port: 53,
            proto: .udp,
            isEnabled: true,
            regionTag: "Anycast"
        ),
        UpstreamResolver(
            id: "cloudflare-doh",
            name: "Cloudflare DoH",
            endpoint: "https://1.1.1.1/dns-query",
            address: "1.1.1.1",
            port: 443,
            proto: .doh,
            isEnabled: true,
            regionTag: "Encrypted"
        ),
        UpstreamResolver(
            id: "google-doh",
            name: "Google DoH",
            endpoint: "https://8.8.8.8/dns-query",
            address: "8.8.8.8",
            port: 443,
            proto: .doh,
            isEnabled: true,
            regionTag: "Encrypted"
        ),
        UpstreamResolver(
            id: "quad9-doh",
            name: "Quad9 Secure DoH",
            endpoint: "https://9.9.9.9/dns-query",
            address: "9.9.9.9",
            port: 443,
            proto: .doh,
            isEnabled: false,
            regionTag: "Security"
        ),
        UpstreamResolver(
            id: "opendns-udp",
            name: "OpenDNS Edge UDP",
            endpoint: "208.67.222.222:53",
            address: "208.67.222.222",
            port: 53,
            proto: .udp,
            isEnabled: false,
            regionTag: "Global"
        )
    ]
}

public struct CustomRouteRule: Codable, Identifiable, Equatable, Hashable, Sendable {
    public let id: String
    public var label: String
    public var cidr: String
    public var isEnabled: Bool

    public init(id: String = UUID().uuidString, label: String, cidr: String, isEnabled: Bool = true) {
        self.id = id
        self.label = label
        self.cidr = cidr
        self.isEnabled = isEnabled
    }

    public var parsedNetwork: (address: String, subnetMask: String)? {
        let parts = cidr.split(separator: "/")
        guard parts.count == 2,
              let prefix = Int(parts[1]),
              prefix >= 8, prefix <= 32 else {
            return nil
        }
        let ip = String(parts[0]).trimmingCharacters(in: .whitespaces)
        let octets = ip.split(separator: ".").compactMap { UInt8($0) }
        guard octets.count == 4 else { return nil }
        let maskBits: UInt32 = prefix == 0 ? 0 : (0xFFFFFFFF << (32 - prefix))
        let mask = "\( (maskBits >> 24) & 0xFF ).\( (maskBits >> 16) & 0xFF ).\( (maskBits >> 8) & 0xFF ).\( maskBits & 0xFF )"
        return (ip, mask)
    }
}

public struct OptimizationConfig: Codable, Equatable, Sendable {
    public var profile: TrafficProfile
    public var enableSWRCache: Bool
    public var swrGraceSeconds: TimeInterval
    public var minCacheTTLSeconds: UInt32
    public var enableHedgedRacing: Bool
    public var hedgeDelayMs: Int
    public var blockBackgroundNoise: Bool
    public var suppressIPv6AAAA: Bool
    public var adaptiveMTUEnabled: Bool
    public var wifiMTU: Int
    public var cellularMTU: Int
    public var enableQoSPacing: Bool
    public var maxBurstBytesPerTick: Int
    public var enableUDPRelayRoutes: Bool
    public var onDemandAutoConnect: Bool
    public var resolvers: [UpstreamResolver]
    public var customRoutes: [CustomRouteRule]
    public var customBlockedDomains: [String]
    public var customAllowedDomains: [String]

    public static let defaultConfig = OptimizationConfig(
        profile: .gamingShield,
        enableSWRCache: true,
        swrGraceSeconds: 3600,
        minCacheTTLSeconds: 60,
        enableHedgedRacing: true,
        hedgeDelayMs: 30,
        blockBackgroundNoise: true,
        suppressIPv6AAAA: false,
        adaptiveMTUEnabled: true,
        wifiMTU: 1420,
        cellularMTU: 1360,
        enableQoSPacing: true,
        maxBurstBytesPerTick: 32768,
        enableUDPRelayRoutes: false,
        onDemandAutoConnect: true,
        resolvers: UpstreamResolver.defaults,
        customRoutes: [
            CustomRouteRule(label: "Game Relay Sample (Disabled)", cidr: "103.28.54.0/24", isEnabled: false)
        ],
        customBlockedDomains: [],
        customAllowedDomains: []
    )

    public mutating func applyProfilePreset(_ newProfile: TrafficProfile) {
        profile = newProfile
        switch newProfile {
        case .gamingShield:
            enableSWRCache = true
            swrGraceSeconds = 3600
            minCacheTTLSeconds = 90
            enableHedgedRacing = true
            hedgeDelayMs = 30
            blockBackgroundNoise = true
            enableQoSPacing = true
            cellularMTU = 1360
        case .balanced:
            enableSWRCache = true
            swrGraceSeconds = 1800
            minCacheTTLSeconds = 60
            enableHedgedRacing = true
            hedgeDelayMs = 45
            blockBackgroundNoise = true
            enableQoSPacing = true
            cellularMTU = 1380
        case .strictMinimal:
            enableSWRCache = true
            swrGraceSeconds = 7200
            minCacheTTLSeconds = 120
            enableHedgedRacing = true
            hedgeDelayMs = 35
            blockBackgroundNoise = true
            enableQoSPacing = true
            cellularMTU = 1360
        }
    }
}
