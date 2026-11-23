import Combine
import Foundation
import Network

/// Measures real-time TCP edge RTT, jitter, packet loss, and stability score from the iOS device.
@MainActor
public final class LatencyMonitor: ObservableObject {
    @Published public private(set) var currentPingMs: Double = 0
    @Published public private(set) var jitterMs: Double = 0
    @Published public private(set) var packetLossPercent: Double = 0
    @Published public private(set) var samples: [LatencySample] = []
    @Published public private(set) var isProbing: Bool = false

    private var timer: Timer?
    private let probeQueue = DispatchQueue(label: "com.nguyenbinhchanh.pingpulse.probe", qos: .userInteractive)
    private let targetHost = "1.1.1.1"
    private let targetPort: UInt16 = 443

    public init() {
        startMonitoring()
    }

    deinit {
        timer?.invalidate()
    }

    public var stabilityScore: Int {
        guard !samples.isEmpty else { return 100 }
        let pingPenalty = min(50.0, max(0.0, (currentPingMs - 20.0) * 0.35))
        let jitterPenalty = min(30.0, jitterMs * 1.2)
        let lossPenalty = min(40.0, packetLossPercent * 2.5)
        return max(0, min(100, Int(round(100.0 - pingPenalty - jitterPenalty - lossPenalty))))
    }

    public func startMonitoring() {
        guard timer == nil else { return }
        runSingleProbe()
        timer = Timer.scheduledTimer(withTimeInterval: 1.5, repeats: true) { [weak self] _ in
            Task { @MainActor in
                self?.runSingleProbe()
            }
        }
    }

    public func stopMonitoring() {
        timer?.invalidate()
        timer = nil
    }

    private final class ProbeFlag: @unchecked Sendable {
        private let lock = NSLock()
        private var done = false
        func claim() -> Bool {
            lock.lock()
            defer { lock.unlock() }
            if done { return false }
            done = true
            return true
        }
    }

    public func runSingleProbe() {
        guard !isProbing else { return }
        isProbing = true

        let host = NWEndpoint.Host(targetHost)
        let port = NWEndpoint.Port(rawValue: targetPort) ?? .https
        let params = NWParameters.tcp
        params.serviceClass = .responsiveData

        let connection = NWConnection(host: host, port: port, using: params)
        let start = DispatchTime.now()
        let flag = ProbeFlag()

        @Sendable func finish(rttMs: Double?, loss: Bool) {
            guard flag.claim() else { return }
            connection.cancel()

            Task { @MainActor [weak self] in
                self?.recordSample(rttMs: rttMs ?? 0, isLoss: loss)
                self?.isProbing = false
            }
        }

        probeQueue.asyncAfter(deadline: .now() + .milliseconds(1200)) {
            finish(rttMs: nil, loss: true)
        }

        connection.stateUpdateHandler = { state in
            switch state {
            case .ready:
                let ms = Double(DispatchTime.now().uptimeNanoseconds - start.uptimeNanoseconds) / 1_000_000.0
                finish(rttMs: ms, loss: false)
            case .failed:
                finish(rttMs: nil, loss: true)
            default:
                break
            }
        }

        connection.start(queue: probeQueue)
    }

    private func recordSample(rttMs: Double, isLoss: Bool) {
        let sample = LatencySample(timestamp: Date(), rttMs: rttMs, isLoss: isLoss)
        samples.append(sample)
        if samples.count > 30 {
            samples.removeFirst(samples.count - 30)
        }

        let validSamples = samples.filter { !$0.isLoss }
        if let latest = validSamples.last {
            currentPingMs = latest.rttMs
        }

        if validSamples.count >= 2 {
            var deltas: [Double] = []
            for idx in 1..<validSamples.count {
                deltas.append(abs(validSamples[idx].rttMs - validSamples[idx - 1].rttMs))
            }
            jitterMs = deltas.reduce(0, +) / Double(deltas.count)
        } else {
            jitterMs = 0
        }

        let lossCount = samples.filter { $0.isLoss }.count
        packetLossPercent = samples.isEmpty ? 0 : (Double(lossCount) / Double(samples.count)) * 100.0
    }
}
