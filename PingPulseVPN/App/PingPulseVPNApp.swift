import SwiftUI

@main
struct PingPulseVPNApp: App {
    @StateObject private var vpnManager = VPNManager()
    @StateObject private var latencyMonitor = LatencyMonitor()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(vpnManager)
                .environmentObject(latencyMonitor)
                .preferredColorScheme(.dark)
        }
    }
}
