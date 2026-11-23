import Foundation

public enum QueryResolutionOutcome: String, Codable, Sendable {
    case cacheHit = "CACHE"
    case swrHit = "SWR"
    case upstreamRace = "RACED"
    case blockedNoise = "SHIELD"
    case ipv6Suppressed = "V4_ONLY"
    case failed = "ERR"
}

public enum QoSLane: Int, Codable, Comparable, CaseIterable, Sendable {
    case criticalControl = 0   // DNS, ICMP, SYN/ACK
    case realtimeInteractive = 1 // Small UDP / Game / VoIP
    case standardWeb = 2       // HTTPS / HTTP
    case bulkBackground = 3    // Large sustained payloads

    public static func < (lhs: QoSLane, rhs: QoSLane) -> Bool {
        lhs.rawValue < rhs.rawValue
    }

    public var label: String {
        switch self {
        case .criticalControl: return "P0 Control"
        case .realtimeInteractive: return "P1 Realtime"
        case .standardWeb: return "P2 Web"
        case .bulkBackground: return "P3 Bulk"
        }
    }
}

public struct QueryLogEntry: Codable, Identifiable, Equatable, Sendable {
    public let id: UUID
    public let timestamp: Date
    public let domain: String
    public let recordType: String
    public let outcome: QueryResolutionOutcome
    public let latencyMs: Double
    public let upstreamUsed: String

    public init(
        id: UUID = UUID(),
        timestamp: Date = Date(),
        domain: String,
        recordType: String,
        outcome: QueryResolutionOutcome,
        latencyMs: Double,
        upstreamUsed: String
    ) {
        self.id = id
        self.timestamp = timestamp
        self.domain = domain
        self.recordType = recordType
        self.outcome = outcome
        self.latencyMs = latencyMs
        self.upstreamUsed = upstreamUsed
    }
}

public struct ResolverHealthMetric: Codable, Identifiable, Equatable, Sendable {
    public let id: String
    public let name: String
    public let proto: ResolverProtocol
    public var ewmaLatencyMs: Double
    public var successCount: Int
    public var failureCount: Int
    public var lastChecked: Date

    public init(
        id: String,
        name: String,
        proto: ResolverProtocol,
        ewmaLatencyMs: Double,
        successCount: Int,
        failureCount: Int,
        lastChecked: Date = Date()
    ) {
        self.id = id
        self.name = name
        self.proto = proto
        self.ewmaLatencyMs = ewmaLatencyMs
        self.successCount = successCount
        self.failureCount = failureCount
        self.lastChecked = lastChecked
    }
}

public struct TunnelStats: Codable, Equatable, Sendable {
    public var totalQueries: Int
    public var cacheHits: Int
    public var swrHits: Int
    public var blockedNoiseQueries: Int
    public var hedgedSaves: Int
    public var packetsScheduledP0: Int
    public var packetsScheduledP1: Int
    public var packetsScheduledP2: Int
    public var packetsScheduledP3: Int
    public var udpRelayedPackets: Int
    public var averageLocalResolutionMs: Double
    public var activeMTU: Int
    public var networkPathDescription: String
    public var startedAt: Date?
    public var updatedAt: Date

    public init(
        totalQueries: Int = 0,
        cacheHits: Int = 0,
        swrHits: Int = 0,
        blockedNoiseQueries: Int = 0,
        hedgedSaves: Int = 0,
        packetsScheduledP0: Int = 0,
        packetsScheduledP1: Int = 0,
        packetsScheduledP2: Int = 0,
        packetsScheduledP3: Int = 0,
        udpRelayedPackets: Int = 0,
        averageLocalResolutionMs: Double = 0,
        activeMTU: Int = 1420,
        networkPathDescription: String = "Idle",
        startedAt: Date? = nil,
        updatedAt: Date = Date()
    ) {
        self.totalQueries = totalQueries
        self.cacheHits = cacheHits
        self.swrHits = swrHits
        self.blockedNoiseQueries = blockedNoiseQueries
        self.hedgedSaves = hedgedSaves
        self.packetsScheduledP0 = packetsScheduledP0
        self.packetsScheduledP1 = packetsScheduledP1
        self.packetsScheduledP2 = packetsScheduledP2
        self.packetsScheduledP3 = packetsScheduledP3
        self.udpRelayedPackets = udpRelayedPackets
        self.averageLocalResolutionMs = averageLocalResolutionMs
        self.activeMTU = activeMTU
        self.networkPathDescription = networkPathDescription
        self.startedAt = startedAt
        self.updatedAt = updatedAt
    }

    public var cacheHitRatio: Double {
        guard totalQueries > 0 else { return 0 }
        return Double(cacheHits + swrHits) / Double(totalQueries)
    }

    public var totalPacketsScheduled: Int {
        packetsScheduledP0 + packetsScheduledP1 + packetsScheduledP2 + packetsScheduledP3
    }
}

public struct LatencySample: Identifiable, Equatable, Sendable {
    public let id = UUID()
    public let timestamp: Date
    public let rttMs: Double
    public let isLoss: Bool
}
