import Foundation

/// Blocks background telemetry, analytics, and ad-beacon chatter that trigger upload bufferbloat
/// and cellular radio wakeups, while respecting user allowlist overrides.
public final class TrafficFilterEngine: @unchecked Sendable {
    private static let defaultNoiseSuffixes: Set<String> = [
        "app-measurement.com",
        "firebase-settings.crashlytics.com",
        "crashlytics.com",
        "doubleclick.net",
        "googlesyndication.com",
        "googleadservices.com",
        "adservice.google.com",
        "analytics.google.com",
        "pagead2.googlesyndication.com",
        "analytics.adjust.com",
        "app.adjust.com",
        "api2.branch.io",
        "an.facebook.com",
        "pixel.facebook.com",
        "ads.facebook.com",
        "metrics.icloud.com",
        "telemetry.sdk.qcloud.com",
        "log.byteoversea.com",
        "mon.byteoversea.com",
        "analytics.tiktok.com",
        "ads.tiktok.com",
        "events.mapbox.com",
        "sentry.io",
        "bugsnag.com",
        "amplitude.com",
        "mixpanel.com",
        "api.segment.io",
        "appsflyer.com",
        "adcolony.com",
        "unityads.unity3d.com",
        "applovin.com",
        "vungle.com",
        "ironsrc.com",
        "scorecardresearch.com",
        "taboola.com",
        "outbrain.com"
    ]

    private let lock = NSLock()
    private var blockedSuffixes: Set<String> = TrafficFilterEngine.defaultNoiseSuffixes
    private var allowedSuffixes: Set<String> = []
    private var enabled: Bool = true

    public init() {}

    public func update(config: OptimizationConfig) {
        lock.lock()
        defer { lock.unlock() }

        self.enabled = config.blockBackgroundNoise
        var mergedBlocked = Self.defaultNoiseSuffixes
        for domain in config.customBlockedDomains {
            let clean = normalize(domain)
            if !clean.isEmpty { mergedBlocked.insert(clean) }
        }
        self.blockedSuffixes = mergedBlocked

        var mergedAllowed: Set<String> = []
        for domain in config.customAllowedDomains {
            let clean = normalize(domain)
            if !clean.isEmpty { mergedAllowed.insert(clean) }
        }
        self.allowedSuffixes = mergedAllowed
    }

    public func shouldBlock(domain: String) -> Bool {
        lock.lock()
        defer { lock.unlock() }

        guard enabled else { return false }
        let normalized = normalize(domain)
        guard !normalized.isEmpty else { return false }

        if matchesAnySuffix(normalized, suffixes: allowedSuffixes) {
            return false
        }
        return matchesAnySuffix(normalized, suffixes: blockedSuffixes)
    }

    private func normalize(_ domain: String) -> String {
        domain
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .trimmingCharacters(in: CharacterSet(charactersIn: "."))
            .lowercased()
    }

    private func matchesAnySuffix(_ domain: String, suffixes: Set<String>) -> Bool {
        if suffixes.contains(domain) { return true }
        var idx = domain.startIndex
        while let dot = domain[idx...].firstIndex(of: ".") {
            let next = domain.index(after: dot)
            if next < domain.endIndex {
                let candidate = String(domain[next...])
                if suffixes.contains(candidate) { return true }
                idx = next
            } else {
                break
            }
        }
        return false
    }
}
