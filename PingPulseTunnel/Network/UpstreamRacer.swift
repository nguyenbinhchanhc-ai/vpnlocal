import Foundation
import Network

public struct UpstreamResolution: Sendable {
    public let responseData: Data
    public let resolverName: String
    public let latencyMs: Double
    public let wasHedgedWin: Bool
}

/// EWMA-scored DNS upstream racer supporting both low-latency UDP/53 (with QoS serviceClass)
/// and RFC 8484 binary DoH, with hedged parallel failover to eliminate tail-latency spikes.
public final class UpstreamRacer: @unchecked Sendable {
    private let lock = NSLock()
    private var resolvers: [UpstreamResolver] = []
    private var metrics: [String: ResolverHealthMetric] = [:]
    private let queue = DispatchQueue(label: "com.nguyenbinhchanh.pingpulse.racer", qos: .userInteractive, attributes: .concurrent)
    private let urlSession: URLSession

    public init() {
        let sessionConfig = URLSessionConfiguration.ephemeral
        sessionConfig.timeoutIntervalForRequest = 2.0
        sessionConfig.timeoutIntervalForResource = 2.5
        sessionConfig.networkServiceType = .responsiveData
        sessionConfig.httpMaximumConnectionsPerHost = 4
        sessionConfig.waitsForConnectivity = false
        self.urlSession = URLSession(configuration: sessionConfig)
    }

    public func updateResolvers(_ list: [UpstreamResolver]) {
        lock.lock()
        defer { lock.unlock() }
        self.resolvers = list.filter { $0.isEnabled }
        for r in self.resolvers where metrics[r.id] == nil {
            metrics[r.id] = ResolverHealthMetric(
                id: r.id,
                name: r.name,
                proto: r.proto,
                ewmaLatencyMs: r.proto == .udp ? 25.0 : 40.0,
                successCount: 0,
                failureCount: 0
            )
        }
    }

    public func currentMetricsSnapshot() -> [ResolverHealthMetric] {
        lock.lock()
        defer { lock.unlock() }
        return Array(metrics.values).sorted { $0.ewmaLatencyMs < $1.ewmaLatencyMs }
    }

    private final class RaceState: @unchecked Sendable {
        private let lock = NSLock()
        private var completed = false
        private var hedgedFired = false
        private var remainingAttempts: Int

        init(attempts: Int) {
            self.remainingAttempts = attempts
        }

        func tryCompleteSuccess() -> Bool {
            lock.lock()
            defer { lock.unlock() }
            if completed { return false }
            completed = true
            return true
        }

        func tryFireHedge() -> Bool {
            lock.lock()
            defer { lock.unlock() }
            if completed || hedgedFired { return false }
            hedgedFired = true
            return true
        }

        func recordFailureAndShouldFailOut() -> Bool {
            lock.lock()
            defer { lock.unlock() }
            remainingAttempts -= 1
            if !completed && remainingAttempts <= 0 {
                completed = true
                return true
            }
            return false
        }
    }

    private final class OnceFlag: @unchecked Sendable {
        private let lock = NSLock()
        private var fired = false
        func claim() -> Bool {
            lock.lock()
            defer { lock.unlock() }
            if fired { return false }
            fired = true
            return true
        }
    }

    public func resolve(
        queryData: Data,
        enableHedgedRacing: Bool,
        hedgeDelayMs: Int,
        completion: @escaping @Sendable (UpstreamResolution?) -> Void
    ) {
        let candidates = rankedResolvers()
        guard let primary = candidates.first else {
            completion(nil)
            return
        }

        let secondary = (enableHedgedRacing && candidates.count > 1) ? candidates[1] : nil
        let startTime = DispatchTime.now()
        let raceState = RaceState(attempts: secondary != nil ? 2 : 1)

        @Sendable func finishSuccess(_ data: Data, from resolver: UpstreamResolver, isHedge: Bool) {
            guard raceState.tryCompleteSuccess() else { return }
            let elapsedMs = Double(DispatchTime.now().uptimeNanoseconds - startTime.uptimeNanoseconds) / 1_000_000.0
            recordResult(resolverID: resolver.id, latencyMs: elapsedMs, success: true)
            completion(UpstreamResolution(
                responseData: data,
                resolverName: resolver.name,
                latencyMs: elapsedMs,
                wasHedgedWin: isHedge
            ))
        }

        @Sendable func finishFailure(for resolver: UpstreamResolver) {
            recordResult(resolverID: resolver.id, latencyMs: 500.0, success: false)
            if raceState.recordFailureAndShouldFailOut() {
                completion(nil)
            }
        }

        sendSingleQuery(queryData: queryData, to: primary) { [weak self] data in
            guard self != nil else { return }
            if let data, data.count >= 12 {
                finishSuccess(data, from: primary, isHedge: false)
            } else {
                finishFailure(for: primary)
            }
        }

        if let backup = secondary {
            let delay = DispatchTimeInterval.milliseconds(max(15, min(150, hedgeDelayMs)))
            queue.asyncAfter(deadline: .now() + delay) { [weak self] in
                guard let self, raceState.tryFireHedge() else { return }
                self.sendSingleQuery(queryData: queryData, to: backup) { data in
                    if let data, data.count >= 12 {
                        finishSuccess(data, from: backup, isHedge: true)
                    } else {
                        finishFailure(for: backup)
                    }
                }
            }
        }
    }

    private func rankedResolvers() -> [UpstreamResolver] {
        lock.lock()
        defer { lock.unlock() }
        return resolvers.sorted { lhs, rhs in
            let lScore = metrics[lhs.id]?.ewmaLatencyMs ?? 50.0
            let rScore = metrics[rhs.id]?.ewmaLatencyMs ?? 50.0
            return lScore < rScore
        }
    }

    private func recordResult(resolverID: String, latencyMs: Double, success: Bool) {
        lock.lock()
        defer { lock.unlock() }
        guard var m = metrics[resolverID] else { return }
        if success {
            m.ewmaLatencyMs = (m.ewmaLatencyMs * 0.7) + (latencyMs * 0.3)
            m.successCount += 1
        } else {
            m.ewmaLatencyMs = min(999.0, (m.ewmaLatencyMs * 0.6) + (350.0 * 0.4))
            m.failureCount += 1
        }
        m.lastChecked = Date()
        metrics[resolverID] = m
    }

    private func sendSingleQuery(
        queryData: Data,
        to resolver: UpstreamResolver,
        completion: @escaping @Sendable (Data?) -> Void
    ) {
        switch resolver.proto {
        case .udp:
            sendUDPQuery(queryData: queryData, host: resolver.address, port: resolver.port, completion: completion)
        case .doh:
            sendDoHQuery(queryData: queryData, urlString: resolver.endpoint, completion: completion)
        }
    }

    private func sendUDPQuery(
        queryData: Data,
        host: String,
        port: UInt16,
        completion: @escaping @Sendable (Data?) -> Void
    ) {
        guard let nwPort = NWEndpoint.Port(rawValue: port) else {
            completion(nil)
            return
        }

        let params = NWParameters.udp
        params.serviceClass = .interactiveVoice
        let connection = NWConnection(host: NWEndpoint.Host(host), port: nwPort, using: params)

        let onceFlag = OnceFlag()

        @Sendable func finish(_ data: Data?) {
            guard onceFlag.claim() else { return }
            connection.cancel()
            completion(data)
        }

        queue.asyncAfter(deadline: .now() + .milliseconds(1400)) {
            finish(nil)
        }

        connection.stateUpdateHandler = { state in
            switch state {
            case .ready:
                connection.send(content: queryData, completion: .contentProcessed { sendErr in
                    if sendErr != nil {
                        finish(nil)
                        return
                    }
                    connection.receiveMessage { content, _, _, recvErr in
                        if recvErr == nil, let content, !content.isEmpty {
                            finish(content)
                        } else {
                            finish(nil)
                        }
                    }
                })
            case .failed, .cancelled:
                finish(nil)
            default:
                break
            }
        }
        connection.start(queue: queue)
    }

    private func sendDoHQuery(
        queryData: Data,
        urlString: String,
        completion: @escaping @Sendable (Data?) -> Void
    ) {
        guard let url = URL(string: urlString) else {
            completion(nil)
            return
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.httpBody = queryData
        request.setValue("application/dns-message", forHTTPHeaderField: "Content-Type")
        request.setValue("application/dns-message", forHTTPHeaderField: "Accept")
        request.networkServiceType = .responsiveData
        request.timeoutInterval = 1.8

        let task = urlSession.dataTask(with: request) { data, response, error in
            guard error == nil,
                  let http = response as? HTTPURLResponse,
                  (200...299).contains(http.statusCode),
                  let data,
                  data.count >= 12 else {
                completion(nil)
                return
            }
            completion(data)
        }
        task.resume()
    }
}
