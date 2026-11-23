import SwiftUI

struct DashboardView: View {
    @EnvironmentObject private var vpnManager: VPNManager
    @EnvironmentObject private var latencyMonitor: LatencyMonitor

    private let accentCyan = Color(red: 0.06, green: 0.78, blue: 0.96)
    private let accentEmerald = Color(red: 0.10, green: 0.85, blue: 0.58)

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 16) {
                    heroConnectionCard
                    liveTelemetryGrid
                    pingSparklineCard
                    trafficProfileSelector
                    qosLaneBreakdownCard
                }
                .padding()
            }
            .background(Color(red: 0.04, green: 0.06, blue: 0.10).ignoresSafeArea())
            .navigationTitle("PingPulse VPN")
            .navigationBarTitleDisplayMode(.inline)
        }
    }

    private var heroConnectionCard: some View {
        let active = vpnManager.status == .connected
        let transitioning = vpnManager.status == .connecting || vpnManager.status == .reasserting

        return VStack(spacing: 14) {
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Text("ON-DEVICE TRAFFIC ORCHESTRATOR")
                        .font(.caption2.weight(.semibold))
                        .foregroundColor(.secondary)
                    Text(vpnManager.statusDisplayText)
                        .font(.headline)
                        .foregroundColor(active ? accentEmerald : .white)
                }
                Spacer()
                Text("MTU \(vpnManager.stats.activeMTU)")
                    .font(.caption.monospacedDigit().weight(.semibold))
                    .padding(.horizontal, 10)
                    .padding(.vertical, 5)
                    .background(Color.white.opacity(0.08))
                    .clipShape(Capsule())
            }

            Button {
                vpnManager.toggleVPN()
            } label: {
                ZStack {
                    Circle()
                        .stroke(
                            active ? accentEmerald.opacity(0.35) : accentCyan.opacity(0.25),
                            lineWidth: 10
                        )
                        .frame(width: 126, height: 126)

                    Circle()
                        .fill(
                            LinearGradient(
                                colors: active
                                    ? [accentEmerald.opacity(0.9), Color(red: 0.04, green: 0.48, blue: 0.36)]
                                    : [Color(red: 0.10, green: 0.16, blue: 0.26), Color(red: 0.06, green: 0.10, blue: 0.18)],
                                startPoint: .topLeading,
                                endPoint: .bottomTrailing
                            )
                        )
                        .frame(width: 108, height: 108)
                        .shadow(color: (active ? accentEmerald : accentCyan).opacity(0.35), radius: 14)

                    VStack(spacing: 4) {
                        Image(systemName: active ? "bolt.shield.fill" : "power")
                            .font(.system(size: 30, weight: .bold))
                            .foregroundColor(.white)
                        Text(active ? "ACTIVE" : (transitioning ? "..." : "START"))
                            .font(.caption.weight(.bold))
                            .foregroundColor(.white.opacity(0.92))
                    }
                }
            }
            .buttonStyle(.plain)
            .padding(.vertical, 4)

            HStack(spacing: 12) {
                Label(vpnManager.stats.networkPathDescription, systemImage: "antenna.radiowaves.left.and.right")
                Text("•")
                Label(vpnManager.config.profile.displayName, systemImage: "gauge.with.dots.needle.67percent")
            }
            .font(.caption)
            .foregroundColor(.secondary)

            if let errorMessage = vpnManager.lastErrorMessage {
                Text(errorMessage)
                    .font(.caption)
                    .foregroundColor(.orange)
                    .multilineTextAlignment(.center)
            }
        }
        .padding(18)
        .background(Color(red: 0.08, green: 0.11, blue: 0.17))
        .clipShape(RoundedRectangle(cornerRadius: 20))
        .overlay(
            RoundedRectangle(cornerRadius: 20)
                .stroke(Color.white.opacity(0.07), lineWidth: 1)
        )
    }

    private var liveTelemetryGrid: some View {
        let hitPct = Int(round(vpnManager.stats.cacheHitRatio * 100))

        return LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 12) {
            MetricTile(
                title: "Live Ping",
                value: String(format: "%.0f ms", latencyMonitor.currentPingMs),
                subtitle: "Stability \(latencyMonitor.stabilityScore)/100",
                icon: "timer",
                tint: latencyMonitor.currentPingMs < 60 ? accentEmerald : .orange
            )
            MetricTile(
                title: "Jitter / Loss",
                value: String(format: "%.1f ms", latencyMonitor.jitterMs),
                subtitle: String(format: "Loss %.0f%%", latencyMonitor.packetLossPercent),
                icon: "waveform",
                tint: latencyMonitor.jitterMs < 12 ? accentCyan : .yellow
            )
            MetricTile(
                title: "Local Cache Hit",
                value: "\(hitPct)%",
                subtitle: "\(vpnManager.stats.cacheHits + vpnManager.stats.swrHits) / \(vpnManager.stats.totalQueries) queries",
                icon: "memorychip",
                tint: accentEmerald
            )
            MetricTile(
                title: "Noise Blocked",
                value: "\(vpnManager.stats.blockedNoiseQueries)",
                subtitle: "Avg DNS \(String(format: "%.1f ms", vpnManager.stats.averageLocalResolutionMs))",
                icon: "shield.lefthalf.filled",
                tint: accentCyan
            )
        }
    }

    private var pingSparklineCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text("Real-Time Ping Trajectory")
                    .font(.subheadline.weight(.semibold))
                Spacer()
                Button("Probe") {
                    latencyMonitor.runSingleProbe()
                }
                .font(.caption.weight(.semibold))
                .foregroundColor(accentCyan)
            }

            PingSparklineView(samples: latencyMonitor.samples, accentColor: accentCyan)
                .frame(height: 76)
        }
        .padding(16)
        .background(Color(red: 0.08, green: 0.11, blue: 0.17))
        .clipShape(RoundedRectangle(cornerRadius: 16))
    }

    private var trafficProfileSelector: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Traffic Orchestration Profile")
                .font(.subheadline.weight(.semibold))

            ForEach(TrafficProfile.allCases) { profile in
                let isSelected = vpnManager.config.profile == profile
                Button {
                    vpnManager.selectProfile(profile)
                } label: {
                    HStack(alignment: .top, spacing: 12) {
                        Image(systemName: isSelected ? "checkmark.circle.fill" : "circle")
                            .foregroundColor(isSelected ? accentCyan : .secondary)
                            .padding(.top, 2)
                        VStack(alignment: .leading, spacing: 3) {
                            Text(profile.displayName)
                                .font(.subheadline.weight(.semibold))
                                .foregroundColor(.white)
                            Text(profile.summary)
                                .font(.caption)
                                .foregroundColor(.secondary)
                                .multilineTextAlignment(.leading)
                        }
                        Spacer()
                    }
                    .padding(12)
                    .background(isSelected ? accentCyan.opacity(0.12) : Color.white.opacity(0.03))
                    .clipShape(RoundedRectangle(cornerRadius: 12))
                }
                .buttonStyle(.plain)
            }
        }
        .padding(16)
        .background(Color(red: 0.08, green: 0.11, blue: 0.17))
        .clipShape(RoundedRectangle(cornerRadius: 16))
    }

    private var qosLaneBreakdownCard: some View {
        let s = vpnManager.stats
        return VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text("Local QoS Lane Scheduler")
                    .font(.subheadline.weight(.semibold))
                Spacer()
                Text("Hedged Wins: \(s.hedgedSaves)")
                    .font(.caption.monospacedDigit())
                    .foregroundColor(accentEmerald)
            }

            HStack(spacing: 8) {
                LanePill(label: "P0 Ctrl", count: s.packetsScheduledP0, color: accentEmerald)
                LanePill(label: "P1 Real", count: s.packetsScheduledP1, color: accentCyan)
                LanePill(label: "P2 Web", count: s.packetsScheduledP2, color: .blue)
                LanePill(label: "P3 Bulk", count: s.packetsScheduledP3, color: .gray)
            }
        }
        .padding(16)
        .background(Color(red: 0.08, green: 0.11, blue: 0.17))
        .clipShape(RoundedRectangle(cornerRadius: 16))
    }
}

private struct MetricTile: View {
    let title: String
    let value: String
    let subtitle: String
    let icon: String
    let tint: Color

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Image(systemName: icon)
                    .foregroundColor(tint)
                Text(title)
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
            Text(value)
                .font(.title2.bold().monospacedDigit())
                .foregroundColor(.white)
            Text(subtitle)
                .font(.caption2)
                .foregroundColor(.secondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(14)
        .background(Color(red: 0.08, green: 0.11, blue: 0.17))
        .clipShape(RoundedRectangle(cornerRadius: 14))
    }
}

private struct LanePill: View {
    let label: String
    let count: Int
    let color: Color

    var body: some View {
        VStack(spacing: 3) {
            Text(label)
                .font(.caption2.weight(.semibold))
                .foregroundColor(color)
            Text("\(count)")
                .font(.caption.monospacedDigit().bold())
                .foregroundColor(.white)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 8)
        .background(color.opacity(0.12))
        .clipShape(RoundedRectangle(cornerRadius: 10))
    }
}

private struct PingSparklineView: View {
    let samples: [LatencySample]
    let accentColor: Color

    var body: some View {
        GeometryReader { geo in
            let valid = samples.map { $0.isLoss ? 0.0 : $0.rttMs }
            let maxVal = max(60.0, valid.max() ?? 100.0)

            ZStack {
                RoundedRectangle(cornerRadius: 10)
                    .fill(Color.white.opacity(0.03))

                if valid.count >= 2 {
                    Path { path in
                        let stepX = geo.size.width / CGFloat(max(1, valid.count - 1))
                        for (index, val) in valid.enumerated() {
                            let x = CGFloat(index) * stepX
                            let ratio = min(1.0, max(0.0, val / maxVal))
                            let y = geo.size.height - (CGFloat(ratio) * (geo.size.height - 14)) - 7
                            if index == 0 {
                                path.move(to: CGPoint(x: x, y: y))
                            } else {
                                path.addLine(to: CGPoint(x: x, y: y))
                            }
                        }
                    }
                    .stroke(accentColor, style: StrokeStyle(lineWidth: 2.2, lineCap: .round, lineJoin: .round))
                } else {
                    Text("Collecting samples...")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }
        }
    }
}
