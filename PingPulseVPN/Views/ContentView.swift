import SwiftUI

struct ContentView: View {
    var body: some View {
        TabView {
            DashboardView()
                .tabItem {
                    Label("Pulse", systemImage: "waveform.path.ecg")
                }

            TrafficInspectorView()
                .tabItem {
                    Label("Queries", systemImage: "list.bullet.rectangle.portrait")
                }

            ResolversAndRoutesView()
                .tabItem {
                    Label("Routing", systemImage: "point.3.connected.trianglepath.dotted")
                }

            SettingsView()
                .tabItem {
                    Label("Tune", systemImage: "slider.horizontal.3")
                }
        }
        .tint(Color(red: 0.06, green: 0.78, blue: 0.96))
    }
}
