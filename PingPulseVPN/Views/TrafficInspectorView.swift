import SwiftUI

struct TrafficInspectorView: View {
    @EnvironmentObject private var vpnManager: VPNManager
    @State private var searchText = ""
    @State private var selectedOutcome: QueryResolutionOutcome?

    private var filteredLogs: [QueryLogEntry] {
        vpnManager.queryLogs.filter { entry in
            let matchesOutcome = selectedOutcome == nil || entry.outcome == selectedOutcome
            let matchesSearch = searchText.isEmpty || entry.domain.localizedCaseInsensitiveContains(searchText)
            return matchesOutcome && matchesSearch
        }
    }

    var body: some View {
        NavigationStack {
            VStack(spacing: 10) {
                filterBar

                if filteredLogs.isEmpty {
                    VStack(spacing: 10) {
                        Spacer()
                        Image(systemName: "waveform.path.ecg.rectangle")
                            .font(.system(size: 40))
                            .foregroundColor(.secondary)
                        Text("No Local Query Telemetry Yet")
                            .font(.headline)
                        Text("Activate PingPulse VPN on the Pulse tab to inspect on-device cache hits, SWR revalidations, hedged races, and blocked background noise.")
                            .font(.caption)
                            .foregroundColor(.secondary)
                            .multilineTextAlignment(.center)
                            .padding(.horizontal, 32)
                        Spacer()
                    }
                } else {
                    List(filteredLogs) { entry in
                        HStack(spacing: 12) {
                            outcomeBadge(entry.outcome)

                            VStack(alignment: .leading, spacing: 3) {
                                Text(entry.domain)
                                    .font(.subheadline.weight(.medium))
                                    .lineLimit(1)
                                HStack(spacing: 8) {
                                    Text(entry.recordType)
                                        .font(.caption2.monospaced())
                                        .padding(.horizontal, 6)
                                        .padding(.vertical, 2)
                                        .background(Color.white.opacity(0.08))
                                        .clipShape(RoundedRectangle(cornerRadius: 4))
                                    Text(entry.upstreamUsed)
                                        .font(.caption2)
                                        .foregroundColor(.secondary)
                                }
                            }

                            Spacer()

                            Text(String(format: "%.1f ms", entry.latencyMs))
                                .font(.caption.monospacedDigit().weight(.semibold))
                                .foregroundColor(entry.latencyMs < 5.0 ? .green : .cyan)
                        }
                        .listRowBackground(Color(red: 0.08, green: 0.11, blue: 0.17))
                    }
                    .listStyle(.plain)
                }
            }
            .background(Color(red: 0.04, green: 0.06, blue: 0.10).ignoresSafeArea())
            .navigationTitle("Query Inspector")
            .navigationBarTitleDisplayMode(.inline)
            .searchable(text: $searchText, prompt: "Filter domain...")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Clear") {
                        vpnManager.clearLogs()
                    }
                }
            }
        }
    }

    private var filterBar: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 8) {
                FilterChip(title: "All", isSelected: selectedOutcome == nil) {
                    selectedOutcome = nil
                }
                ForEach(
                    [
                        QueryResolutionOutcome.cacheHit,
                        .swrHit,
                        .upstreamRace,
                        .blockedNoise,
                        .ipv6Suppressed
                    ],
                    id: \.rawValue
                ) { outcome in
                    FilterChip(title: outcome.rawValue, isSelected: selectedOutcome == outcome) {
                        selectedOutcome = (selectedOutcome == outcome) ? nil : outcome
                    }
                }
            }
            .padding(.horizontal)
            .padding(.top, 6)
        }
    }

    private func outcomeBadge(_ outcome: QueryResolutionOutcome) -> some View {
        let color: Color
        switch outcome {
        case .cacheHit: color = .green
        case .swrHit: color = .mint
        case .upstreamRace: color = .cyan
        case .blockedNoise: color = .orange
        case .ipv6Suppressed: color = .purple
        case .failed: color = .red
        }
        return Text(outcome.rawValue)
            .font(.caption2.bold().monospaced())
            .foregroundColor(color)
            .padding(.horizontal, 8)
            .padding(.vertical, 5)
            .background(color.opacity(0.16))
            .clipShape(RoundedRectangle(cornerRadius: 8))
    }
}

private struct FilterChip: View {
    let title: String
    let isSelected: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Text(title)
                .font(.caption.weight(.semibold))
                .padding(.horizontal, 12)
                .padding(.vertical, 6)
                .background(isSelected ? Color.cyan.opacity(0.28) : Color.white.opacity(0.07))
                .foregroundColor(isSelected ? .cyan : .white)
                .clipShape(Capsule())
        }
        .buttonStyle(.plain)
    }
}
