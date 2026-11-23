import SwiftUI

struct ResolversAndRoutesView: View {
    @EnvironmentObject private var vpnManager: VPNManager
    @State private var newRouteLabel = ""
    @State private var newRouteCIDR = ""

    var body: some View {
        NavigationStack {
            List {
                Section {
                    ForEach($vpnManager.config.resolvers) { $resolver in
                        HStack {
                            VStack(alignment: .leading, spacing: 3) {
                                HStack(spacing: 6) {
                                    Text(resolver.name)
                                        .font(.subheadline.weight(.semibold))
                                    Text(resolver.proto.rawValue)
                                        .font(.caption2.bold())
                                        .padding(.horizontal, 6)
                                        .padding(.vertical, 2)
                                        .background(Color.cyan.opacity(0.18))
                                        .foregroundColor(.cyan)
                                        .clipShape(RoundedRectangle(cornerRadius: 4))
                                }
                                Text(resolver.endpoint)
                                    .font(.caption2.monospaced())
                                    .foregroundColor(.secondary)

                                if let metric = vpnManager.resolverMetrics.first(where: { $0.id == resolver.id }) {
                                    Text("EWMA \(String(format: "%.1f ms", metric.ewmaLatencyMs)) • OK \(metric.successCount) / Fail \(metric.failureCount)")
                                        .font(.caption2)
                                        .foregroundColor(.green)
                                }
                            }
                            Spacer()
                            Toggle("", isOn: $resolver.isEnabled)
                                .labelsHidden()
                                .onChange(of: resolver.isEnabled) { _ in
                                    vpnManager.applyConfig(vpnManager.config)
                                }
                        }
                    }
                } header: {
                    Text("Upstream DNS Racers (EWMA Auto-Ranked)")
                } footer: {
                    Text("PingPulse races the top two fastest healthy resolvers when hedged racing is enabled.")
                }

                Section {
                    Toggle("Enable Custom UDP QoS Routes", isOn: $vpnManager.config.enableUDPRelayRoutes)
                        .onChange(of: vpnManager.config.enableUDPRelayRoutes) { _ in
                            vpnManager.applyConfig(vpnManager.config)
                        }

                    ForEach($vpnManager.config.customRoutes) { $route in
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(route.label)
                                    .font(.subheadline)
                                Text(route.cidr)
                                    .font(.caption.monospaced())
                                    .foregroundColor(.secondary)
                            }
                            Spacer()
                            Toggle("", isOn: $route.isEnabled)
                                .labelsHidden()
                                .onChange(of: route.isEnabled) { _ in
                                    vpnManager.applyConfig(vpnManager.config)
                                }
                        }
                    }
                    .onDelete { offsets in
                        vpnManager.config.customRoutes.remove(atOffsets: offsets)
                        vpnManager.applyConfig(vpnManager.config)
                    }

                    VStack(spacing: 8) {
                        TextField("Label (e.g. Game Server SG)", text: $newRouteLabel)
                        TextField("CIDR (e.g. 103.28.54.0/24)", text: $newRouteCIDR)
                            .keyboardType(.numbersAndPunctuation)
                        Button("Add Low-Latency UDP Route") {
                            addRoute()
                        }
                        .disabled(newRouteCIDR.trimmingCharacters(in: .whitespaces).isEmpty)
                    }
                } header: {
                    Text("Custom UDP Relay CIDRs (.interactiveVideo QoS)")
                } footer: {
                    Text("Routes matching UDP traffic through the local priority NAT relay without touching normal TCP web flows.")
                }
            }
            .scrollContentBackground(.hidden)
            .background(Color(red: 0.04, green: 0.06, blue: 0.10).ignoresSafeArea())
            .navigationTitle("Routing & Racers")
            .navigationBarTitleDisplayMode(.inline)
        }
    }

    private func addRoute() {
        let trimmedCIDR = newRouteCIDR.trimmingCharacters(in: .whitespacesAndNewlines)
        let label = newRouteLabel.trimmingCharacters(in: .whitespacesAndNewlines)
        let rule = CustomRouteRule(
            label: label.isEmpty ? "Custom Route" : label,
            cidr: trimmedCIDR,
            isEnabled: true
        )
        guard rule.parsedNetwork != nil else { return }
        vpnManager.config.customRoutes.append(rule)
        vpnManager.applyConfig(vpnManager.config)
        newRouteLabel = ""
        newRouteCIDR = ""
    }
}
