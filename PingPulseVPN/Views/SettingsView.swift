import SwiftUI

struct SettingsView: View {
    @EnvironmentObject private var vpnManager: VPNManager
    @State private var newBlockedDomain = ""
    @State private var newAllowedDomain = ""

    var body: some View {
        NavigationStack {
            Form {
                Section("Local DNS Query Optimization") {
                    Toggle("Stale-While-Revalidate (0ms Cache)", isOn: $vpnManager.config.enableSWRCache)
                        .onChange(of: vpnManager.config.enableSWRCache) { _ in save() }

                    Stepper("Min TTL Floor: \(vpnManager.config.minCacheTTLSeconds)s", value: $vpnManager.config.minCacheTTLSeconds, in: 10...600, step: 15)
                        .onChange(of: vpnManager.config.minCacheTTLSeconds) { _ in save() }

                    Toggle("Hedged Parallel DNS Racing", isOn: $vpnManager.config.enableHedgedRacing)
                        .onChange(of: vpnManager.config.enableHedgedRacing) { _ in save() }

                    if vpnManager.config.enableHedgedRacing {
                        Stepper("Hedge Delay: \(vpnManager.config.hedgeDelayMs) ms", value: $vpnManager.config.hedgeDelayMs, in: 15...150, step: 5)
                            .onChange(of: vpnManager.config.hedgeDelayMs) { _ in save() }
                    }

                    Toggle("Suppress IPv6 AAAA (IPv4 Fast-Path)", isOn: $vpnManager.config.suppressIPv6AAAA)
                        .onChange(of: vpnManager.config.suppressIPv6AAAA) { _ in save() }
                }

                Section("Anti-Bufferbloat & Path Adaptation") {
                    Toggle("Background Telemetry & Noise Shield", isOn: $vpnManager.config.blockBackgroundNoise)
                        .onChange(of: vpnManager.config.blockBackgroundNoise) { _ in save() }

                    Toggle("Strict QoS P0/P1 Lane Pacing", isOn: $vpnManager.config.enableQoSPacing)
                        .onChange(of: vpnManager.config.enableQoSPacing) { _ in save() }

                    Toggle("Adaptive Cellular/Wi-Fi MTU", isOn: $vpnManager.config.adaptiveMTUEnabled)
                        .onChange(of: vpnManager.config.adaptiveMTUEnabled) { _ in save() }

                    Stepper("Cellular MTU: \(vpnManager.config.cellularMTU)", value: $vpnManager.config.cellularMTU, in: 1280...1420, step: 20)
                        .onChange(of: vpnManager.config.cellularMTU) { _ in save() }

                    Toggle("On-Demand Auto-Connect", isOn: $vpnManager.config.onDemandAutoConnect)
                        .onChange(of: vpnManager.config.onDemandAutoConnect) { _ in save() }
                }

                Section("Custom Noise Blocklist") {
                    HStack {
                        TextField("Add domain suffix (e.g. tracker.example.com)", text: $newBlockedDomain)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                        Button("Add") {
                            let clean = newBlockedDomain.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
                            guard !clean.isEmpty else { return }
                            vpnManager.config.customBlockedDomains.append(clean)
                            newBlockedDomain = ""
                            save()
                        }
                    }

                    ForEach(vpnManager.config.customBlockedDomains, id: \.self) { domain in
                        Text(domain)
                            .font(.caption.monospaced())
                    }
                    .onDelete { offsets in
                        vpnManager.config.customBlockedDomains.remove(atOffsets: offsets)
                        save()
                    }
                }

                Section("Custom Allowlist (Bypass Shield)") {
                    HStack {
                        TextField("Allow domain suffix", text: $newAllowedDomain)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                        Button("Add") {
                            let clean = newAllowedDomain.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
                            guard !clean.isEmpty else { return }
                            vpnManager.config.customAllowedDomains.append(clean)
                            newAllowedDomain = ""
                            save()
                        }
                    }

                    ForEach(vpnManager.config.customAllowedDomains, id: \.self) { domain in
                        Text(domain)
                            .font(.caption.monospaced())
                    }
                    .onDelete { offsets in
                        vpnManager.config.customAllowedDomains.remove(atOffsets: offsets)
                        save()
                    }
                }

                Section("Maintenance") {
                    Button("Flush On-Device DNS Cache", role: .destructive) {
                        vpnManager.flushDNSCache()
                    }
                    Button("Reset to Gaming & Low-Ping Defaults") {
                        vpnManager.applyConfig(.defaultConfig)
                    }
                }
            }
            .scrollContentBackground(.hidden)
            .background(Color(red: 0.04, green: 0.06, blue: 0.10).ignoresSafeArea())
            .navigationTitle("Engine Tuning")
            .navigationBarTitleDisplayMode(.inline)
        }
    }

    private func save() {
        vpnManager.applyConfig(vpnManager.config)
    }
}
