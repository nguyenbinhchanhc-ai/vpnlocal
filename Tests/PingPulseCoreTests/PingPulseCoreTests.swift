import XCTest

final class PingPulseCoreTests: XCTestCase {

    func testIPv4AndUDPReplyBuildAndParse() {
        let srcIP = IPv4Packet.parseIPv4("10.11.0.1")!
        let dstIP = IPv4Packet.parseIPv4("10.11.0.2")!
        let payload = Data([0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])

        let built = IPv4Packet.buildUDPReply(
            sourceIP: srcIP,
            sourcePort: 53,
            destinationIP: dstIP,
            destinationPort: 51234,
            udpPayload: payload
        )

        let parsed = IPv4Packet(data: built)
        XCTAssertNotNil(parsed)
        XCTAssertEqual(parsed?.sourceIPString, "10.11.0.1")
        XCTAssertEqual(parsed?.destinationIPString, "10.11.0.2")
        XCTAssertEqual(parsed?.proto, IPProtocolNumber.udp.rawValue)
        XCTAssertEqual(parsed?.udpSegment?.sourcePort, 53)
        XCTAssertEqual(parsed?.udpSegment?.destinationPort, 51234)
        XCTAssertEqual(parsed?.udpSegment?.payload, payload)

        // Verify IPv4 header checksum sums to 0x0000 (complement ~0xFFFF == 0)
        let headerSum = IPv4Packet.internetChecksum(built.prefix(20))
        XCTAssertEqual(headerSum, 0)
    }

    func testPacketSchedulerStrictPriorityOrdering() {
        let scheduler = PacketScheduler()
        let src = IPv4Packet.parseIPv4("10.11.0.2")!
        let dst = IPv4Packet.parseIPv4("1.1.1.1")!

        // P3 bulk-sized UDP packet
        let bulkPayload = Data(repeating: 0xAA, count: 1350)
        let bulkRaw = IPv4Packet.buildUDPReply(
            sourceIP: src,
            sourcePort: 40000,
            destinationIP: dst,
            destinationPort: 443,
            udpPayload: bulkPayload
        )

        // P1 small realtime game UDP packet
        let gamePayload = Data(repeating: 0x55, count: 64)
        let gameRaw = IPv4Packet.buildUDPReply(
            sourceIP: src,
            sourcePort: 50001,
            destinationIP: dst,
            destinationPort: 7500,
            udpPayload: gamePayload
        )

        // P0 DNS control packet
        let dnsPayload = Data(repeating: 0x01, count: 32)
        let dnsRaw = IPv4Packet.buildUDPReply(
            sourceIP: src,
            sourcePort: 52000,
            destinationIP: IPv4Packet.parseIPv4("10.11.0.1")!,
            destinationPort: 53,
            udpPayload: dnsPayload
        )

        let batch = [
            IPv4Packet(data: bulkRaw)!,
            IPv4Packet(data: gameRaw)!,
            IPv4Packet(data: dnsRaw)!
        ]

        let counts = scheduler.enqueueBatch(batch)
        XCTAssertEqual(counts[.criticalControl], 1)
        XCTAssertEqual(counts[.realtimeInteractive], 1)
        XCTAssertEqual(counts[.standardWeb], 1)

        let ordered = scheduler.dequeueBurst(maxBulkBytes: 4096, enablePacing: true)
        XCTAssertEqual(ordered.count, 3)
        XCTAssertEqual(ordered[0].lane, .criticalControl)
        XCTAssertEqual(ordered[1].lane, .realtimeInteractive)
        XCTAssertEqual(ordered[2].lane, .standardWeb)
    }

    func testDNSWireParserAndSyntheticResponse() {
        let query = makeDNSQuery(txID: 0xBEEF, domain: "api.example.com", qtype: 1)
        let question = DNSWireParser.parseQuestion(from: query)
        XCTAssertNotNil(question)
        XCTAssertEqual(question?.transactionID, 0xBEEF)
        XCTAssertEqual(question?.domain, "api.example.com")
        XCTAssertEqual(question?.qtype, 1)

        let nx = DNSWireParser.buildSyntheticResponse(for: query, question: question!, rcode: 3)
        XCTAssertEqual(nx.count, query.count)
        XCTAssertEqual(nx[0], 0xBE)
        XCTAssertEqual(nx[1], 0xEF)
        XCTAssertEqual(nx[3] & 0x0F, 3) // RCODE = NXDOMAIN
    }

    func testDNSCacheFreshAndSWR() {
        let cache = DNSCache(maxEntries: 64)
        let query = makeDNSQuery(txID: 0x1111, domain: "fast.game.net", qtype: 1)
        let question = DNSWireParser.parseQuestion(from: query)!
        let answer = DNSWireParser.buildSyntheticResponse(for: query, question: question, rcode: 0, zeroAddressAnswer: true, ttl: 30)

        let key = DNSCacheKey(domain: "fast.game.net", qtype: 1, qclass: 1)
        let t0 = Date(timeIntervalSince1970: 1000)

        cache.insert(
            key: key,
            response: answer,
            ttlSeconds: 30,
            minTTLSeconds: 30,
            swrGraceSeconds: 120,
            upstreamName: "Cloudflare Edge UDP",
            now: t0
        )

        // Fresh lookup at t0 + 10s
        if case let .freshHit(resp, shouldPrefetch, _) = cache.lookup(
            key: key,
            transactionID: 0x2222,
            enableSWR: true,
            now: t0.addingTimeInterval(10)
        ) {
            XCTAssertFalse(shouldPrefetch)
            XCTAssertEqual(resp[0], 0x22)
            XCTAssertEqual(resp[1], 0x22)
        } else {
            XCTFail("Expected freshHit")
        }

        // Stale-While-Revalidate lookup at t0 + 45s (past 30s TTL, inside 120s grace)
        if case let .staleHit(resp, _) = cache.lookup(
            key: key,
            transactionID: 0x3333,
            enableSWR: true,
            now: t0.addingTimeInterval(45)
        ) {
            XCTAssertEqual(resp[0], 0x33)
            XCTAssertEqual(resp[1], 0x33)
        } else {
            XCTFail("Expected staleHit")
        }
    }

    func testTrafficFilterEngineAllowsOverrides() {
        let engine = TrafficFilterEngine()
        var cfg = OptimizationConfig.defaultConfig
        cfg.customAllowedDomains = ["firebase-settings.crashlytics.com"]
        cfg.customBlockedDomains = ["noisy-telemetry.custom.io"]
        engine.update(config: cfg)

        XCTAssertTrue(engine.shouldBlock(domain: "app-measurement.com"))
        XCTAssertTrue(engine.shouldBlock(domain: "sub.noisy-telemetry.custom.io"))
        XCTAssertFalse(engine.shouldBlock(domain: "firebase-settings.crashlytics.com"))
        XCTAssertFalse(engine.shouldBlock(domain: "apple.com"))
    }

    func testCustomRouteRuleCIDRParsing() {
        let rule = CustomRouteRule(label: "SG", cidr: "103.28.54.0/24")
        let parsed = rule.parsedNetwork
        XCTAssertEqual(parsed?.address, "103.28.54.0")
        XCTAssertEqual(parsed?.subnetMask, "255.255.255.0")
    }

    func testIPv6UDPPacketBuildAndParse() {
        var srcAddr = Data(count: 16)
        srcAddr[0] = 0xFD; srcAddr[1] = 0x11; srcAddr[15] = 0x01
        var dstAddr = Data(count: 16)
        dstAddr[0] = 0xFD; dstAddr[1] = 0x11; dstAddr[15] = 0x02

        let dnsPayload = Data([0xAB, 0xCD, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00])
        let built = IPv6UDPPacket.buildUDPReply(
            sourceAddress: srcAddr,
            sourcePort: 53,
            destinationAddress: dstAddr,
            destinationPort: 55000,
            udpPayload: dnsPayload
        )
        let parsed = IPv6UDPPacket(data: built)
        XCTAssertNotNil(parsed)
        XCTAssertEqual(parsed?.sourcePort, 53)
        XCTAssertEqual(parsed?.destinationPort, 55000)
        XCTAssertEqual(parsed?.udpPayload, dnsPayload)
    }

    func testIPCEnvelopeAndTelemetrySnapshotCodable() throws {
        let env = IPCEnvelope(command: .pushConfig, config: .defaultConfig)
        let encoded = try JSONEncoder().encode(env)
        let decoded = try JSONDecoder().decode(IPCEnvelope.self, from: encoded)
        XCTAssertEqual(decoded.command, .pushConfig)
        XCTAssertEqual(decoded.config?.profile, .gamingShield)

        let snap = TelemetrySnapshot(
            stats: TunnelStats(totalQueries: 12, cacheHits: 9, networkPathDescription: "Wi-Fi"),
            logs: [QueryLogEntry(domain: "one.one.one.one", recordType: "A", outcome: .cacheHit, latencyMs: 0.4, upstreamUsed: "RAM")],
            resolverMetrics: []
        )
        let snapData = try JSONEncoder().encode(snap)
        let snapDecoded = try JSONDecoder().decode(TelemetrySnapshot.self, from: snapData)
        XCTAssertEqual(snapDecoded.stats.networkPathDescription, "Wi-Fi")
        XCTAssertEqual(snapDecoded.logs.count, 1)
    }

    private func makeDNSQuery(txID: UInt16, domain: String, qtype: UInt16) -> Data {
        var data = Data()
        data.append(UInt8((txID >> 8) & 0xFF))
        data.append(UInt8(txID & 0xFF))
        data.append(contentsOf: [0x01, 0x00]) // Standard query, RD=1
        data.append(contentsOf: [0x00, 0x01]) // QDCOUNT=1
        data.append(contentsOf: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        for label in domain.split(separator: ".") {
            let bytes = Array(label.utf8)
            data.append(UInt8(bytes.count))
            data.append(contentsOf: bytes)
        }
        data.append(0x00)
        data.append(UInt8((qtype >> 8) & 0xFF))
        data.append(UInt8(qtype & 0xFF))
        data.append(contentsOf: [0x00, 0x01]) // IN
        return data
    }
}
