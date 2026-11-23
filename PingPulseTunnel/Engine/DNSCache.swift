import Foundation

public struct DNSCacheKey: Hashable, Sendable {
    public let domain: String
    public let qtype: UInt16
    public let qclass: UInt16
}

public enum DNSCacheLookupResult: Sendable {
    case miss
    case freshHit(response: Data, shouldPrefetch: Bool, upstreamName: String)
    case staleHit(response: Data, upstreamName: String)
}

/// Memory-bounded LRU + Stale-While-Revalidate (SWR) DNS cache optimized for iOS NetworkExtension limits.
public final class DNSCache: @unchecked Sendable {
    private struct Entry {
        let response: Data
        let insertedAt: Date
        let expiresAt: Date
        let staleUntil: Date
        let upstreamName: String
        var lastAccessedAt: Date
    }

    private let lock = NSLock()
    private let maxEntries: Int
    private var entries: [DNSCacheKey: Entry] = [:]

    public init(maxEntries: Int = 2048) {
        self.maxEntries = max(64, maxEntries)
    }

    public func lookup(
        key: DNSCacheKey,
        transactionID: UInt16,
        enableSWR: Bool,
        now: Date = Date()
    ) -> DNSCacheLookupResult {
        lock.lock()
        defer { lock.unlock() }

        guard var entry = entries[key] else {
            return .miss
        }

        entry.lastAccessedAt = now
        entries[key] = entry

        if now < entry.expiresAt {
            let totalTTL = entry.expiresAt.timeIntervalSince(entry.insertedAt)
            let remaining = entry.expiresAt.timeIntervalSince(now)
            let shouldPrefetch = totalTTL > 10 && remaining <= (totalTTL * 0.2)
            let rewritten = DNSWireParser.rewriteTransactionID(in: entry.response, to: transactionID)
            return .freshHit(response: rewritten, shouldPrefetch: shouldPrefetch, upstreamName: entry.upstreamName)
        }

        if enableSWR && now < entry.staleUntil {
            let rewritten = DNSWireParser.rewriteTransactionID(in: entry.response, to: transactionID)
            return .staleHit(response: rewritten, upstreamName: entry.upstreamName)
        }

        entries.removeValue(forKey: key)
        return .miss
    }

    public func insert(
        key: DNSCacheKey,
        response: Data,
        ttlSeconds: UInt32,
        minTTLSeconds: UInt32,
        swrGraceSeconds: TimeInterval,
        upstreamName: String,
        now: Date = Date()
    ) {
        lock.lock()
        defer { lock.unlock() }

        if entries.count >= maxEntries, entries[key] == nil {
            evictOldest()
        }

        let effectiveTTL = TimeInterval(max(ttlSeconds, minTTLSeconds))
        let expiresAt = now.addingTimeInterval(effectiveTTL)
        let staleUntil = expiresAt.addingTimeInterval(max(0, swrGraceSeconds))

        entries[key] = Entry(
            response: response,
            insertedAt: now,
            expiresAt: expiresAt,
            staleUntil: staleUntil,
            upstreamName: upstreamName,
            lastAccessedAt: now
        )
    }

    public func clear() {
        lock.lock()
        defer { lock.unlock() }
        entries.removeAll(keepingCapacity: true)
    }

    public var count: Int {
        lock.lock()
        defer { lock.unlock() }
        return entries.count
    }

    private func evictOldest() {
        let evictCount = max(1, maxEntries / 8)
        let sorted = entries.sorted { $0.value.lastAccessedAt < $1.value.lastAccessedAt }
        for (key, _) in sorted.prefix(evictCount) {
            entries.removeValue(forKey: key)
        }
    }
}
