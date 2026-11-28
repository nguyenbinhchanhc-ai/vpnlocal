import Foundation

public struct DNSProcessResult: Sendable {
    public let responseData: Data
    public let logEntry: QueryLogEntry
    public let hedgedWin: Bool
}

/// Reusable on-device DNS optimizer pipeline:
/// Noise Shield -> IPv4 Fast-Path -> RAM LRU + SWR Cache -> Hedged Parallel Upstream Racing.
public final class DNSEngine: @unchecked Sendable {
    public let cache: DNSCache
    public let filter: TrafficFilterEngine
    public let racer: UpstreamRacer

    public init(
        cache: DNSCache = DNSCache(maxEntries: 2048),
        filter: TrafficFilterEngine = TrafficFilterEngine(),
        racer: UpstreamRacer = UpstreamRacer()
    ) {
        self.cache = cache
        self.filter = filter
        self.racer = racer
    }

    public func updateConfig(_ config: OptimizationConfig) {
        filter.update(config: config)
        racer.updateResolvers(config.resolvers)
    }

    public func processQuery(
        payload: Data,
        config: OptimizationConfig,
        completion: @escaping @Sendable (DNSProcessResult?) -> Void
    ) {
        let startTime = DispatchTime.now()
        guard let question = DNSWireParser.parseQuestion(from: payload) else {
            completion(nil)
            return
        }

        if filter.shouldBlock(domain: question.domain) {
            let synth = DNSWireParser.buildSyntheticResponse(
                for: payload,
                question: question,
                rcode: 3,
                zeroAddressAnswer: false
            )
            let entry = QueryLogEntry(
                domain: question.domain,
                recordType: question.recordTypeLabel,
                outcome: .blockedNoise,
                latencyMs: elapsedMs(since: startTime),
                upstreamUsed: "Local Noise Shield"
            )
            completion(DNSProcessResult(responseData: synth, logEntry: entry, hedgedWin: false))
            return
        }

        if config.suppressIPv6AAAA && question.qtype == DNSRecordType.aaaa.rawValue {
            let emptyNoError = DNSWireParser.buildSyntheticResponse(
                for: payload,
                question: question,
                rcode: 0,
                zeroAddressAnswer: false
            )
            let entry = QueryLogEntry(
                domain: question.domain,
                recordType: question.recordTypeLabel,
                outcome: .ipv6Suppressed,
                latencyMs: elapsedMs(since: startTime),
                upstreamUsed: "IPv4 Fast-Path"
            )
            completion(DNSProcessResult(responseData: emptyNoError, logEntry: entry, hedgedWin: false))
            return
        }

        let cacheKey = DNSCacheKey(domain: question.domain, qtype: question.qtype, qclass: question.qclass)
        let lookup = cache.lookup(
            key: cacheKey,
            transactionID: question.transactionID,
            enableSWR: config.enableSWRCache
        )

        switch lookup {
        case let .freshHit(response, shouldPrefetch, upstreamName):
            let entry = QueryLogEntry(
                domain: question.domain,
                recordType: question.recordTypeLabel,
                outcome: .cacheHit,
                latencyMs: elapsedMs(since: startTime),
                upstreamUsed: "RAM (\(upstreamName))"
            )
            completion(DNSProcessResult(responseData: response, logEntry: entry, hedgedWin: false))
            if shouldPrefetch {
                revalidateInBackground(queryPayload: payload, key: cacheKey, config: config)
            }

        case let .staleHit(response, upstreamName):
            let entry = QueryLogEntry(
                domain: question.domain,
                recordType: question.recordTypeLabel,
                outcome: .swrHit,
                latencyMs: elapsedMs(since: startTime),
                upstreamUsed: "SWR (\(upstreamName))"
            )
            completion(DNSProcessResult(responseData: response, logEntry: entry, hedgedWin: false))
            revalidateInBackground(queryPayload: payload, key: cacheKey, config: config)

        case .miss:
            racer.resolve(
                queryData: payload,
                enableHedgedRacing: config.enableHedgedRacing,
                hedgeDelayMs: config.hedgeDelayMs
            ) { [weak self] resolution in
                guard let self else { return }
                if let resolution {
                    let rewritten = DNSWireParser.rewriteTransactionID(in: resolution.responseData, to: question.transactionID)
                    let ttl = DNSWireParser.extractMinTTL(from: rewritten, fallbackTTL: config.minCacheTTLSeconds)
                    self.cache.insert(
                        key: cacheKey,
                        response: rewritten,
                        ttlSeconds: ttl,
                        minTTLSeconds: config.minCacheTTLSeconds,
                        swrGraceSeconds: config.swrGraceSeconds,
                        upstreamName: resolution.resolverName
                    )
                    let entry = QueryLogEntry(
                        domain: question.domain,
                        recordType: question.recordTypeLabel,
                        outcome: .upstreamRace,
                        latencyMs: resolution.latencyMs,
                        upstreamUsed: resolution.resolverName
                    )
                    completion(DNSProcessResult(responseData: rewritten, logEntry: entry, hedgedWin: resolution.wasHedgedWin))
                } else {
                    let servFail = DNSWireParser.buildSyntheticResponse(
                        for: payload,
                        question: question,
                        rcode: 2
                    )
                    let entry = QueryLogEntry(
                        domain: question.domain,
                        recordType: question.recordTypeLabel,
                        outcome: .failed,
                        latencyMs: self.elapsedMs(since: startTime),
                        upstreamUsed: "Timeout"
                    )
                    completion(DNSProcessResult(responseData: servFail, logEntry: entry, hedgedWin: false))
                }
            }
        }
    }

    private func revalidateInBackground(queryPayload: Data, key: DNSCacheKey, config: OptimizationConfig) {
        racer.resolve(
            queryData: queryPayload,
            enableHedgedRacing: config.enableHedgedRacing,
            hedgeDelayMs: config.hedgeDelayMs
        ) { [weak self] resolution in
            guard let self, let resolution else { return }
            let ttl = DNSWireParser.extractMinTTL(from: resolution.responseData, fallbackTTL: config.minCacheTTLSeconds)
            self.cache.insert(
                key: key,
                response: resolution.responseData,
                ttlSeconds: ttl,
                minTTLSeconds: config.minCacheTTLSeconds,
                swrGraceSeconds: config.swrGraceSeconds,
                upstreamName: resolution.resolverName
            )
        }
    }

    private func elapsedMs(since start: DispatchTime) -> Double {
        Double(DispatchTime.now().uptimeNanoseconds - start.uptimeNanoseconds) / 1_000_000.0
    }
}
