#!/usr/bin/env python3
"""
Cross-platform validator for PingPulseVPN on Windows/Linux before macOS CI build.
Checks:
1. Required files & XcodeGen project.yml structure
2. XML plist validity for Info.plist and .entitlements
3. JSON validity for Assets.xcassets
4. Balanced braces & basic Swift syntax sanity across all .swift files
5. End-to-end simulation of IPv4+UDP checksums and DNS wire query construction
"""

import json
import os
import re
import struct
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def check_required_files():
    required = [
        "project.yml",
        "README.md",
        ".github/workflows/build-ipa.yml",
        "PingPulseVPN/Resources/Info.plist",
        "PingPulseVPN/Resources/PingPulseVPN.entitlements",
        "PingPulseTunnel/Resources/Info.plist",
        "PingPulseTunnel/Resources/PingPulseTunnel.entitlements",
        "Shared/AppGroupConstants.swift",
        "Shared/OptimizationConfig.swift",
        "Shared/TelemetryModels.swift",
        "Shared/SharedStore.swift",
        "PingPulseTunnel/PacketTunnelProvider.swift",
        "PingPulseTunnel/HevTunnelBridge.swift",
        "PingPulseTunnel/Bridge/PingPulseTunnel-Bridging-Header.h",
        "PingPulseTunnel/Network/IPv4Packet.swift",
        "PingPulseTunnel/Network/IPv6DNSPacket.swift",
        "PingPulseTunnel/Network/LocalSocks5Orchestrator.swift",
        "PingPulseTunnel/Network/UpstreamRacer.swift",
        "PingPulseTunnel/Network/UDPRelayEngine.swift",
        "PingPulseTunnel/Engine/DNSEngine.swift",
        "PingPulseTunnel/Engine/PacketScheduler.swift",
        "PingPulseTunnel/Engine/DNSWireParser.swift",
        "PingPulseTunnel/Engine/DNSCache.swift",
        "PingPulseTunnel/Engine/TrafficFilterEngine.swift",
        "PingPulseVPN/App/PingPulseVPNApp.swift",
        "PingPulseVPN/Services/VPNManager.swift",
        "PingPulseVPN/Services/LatencyMonitor.swift",
        "PingPulseVPN/Views/ContentView.swift",
        "PingPulseVPN/Views/DashboardView.swift",
        "PingPulseVPN/Views/TrafficInspectorView.swift",
        "PingPulseVPN/Views/ResolversAndRoutesView.swift",
        "PingPulseVPN/Views/SettingsView.swift",
        "Tests/PingPulseCoreTests/PingPulseCoreTests.swift",
    ]
    missing = [p for p in required if not (ROOT / p).exists()]
    if missing:
        raise AssertionError(f"Missing required files: {missing}")
    print(f"[OK] All {len(required)} required project files present.")


def check_xml_and_json():
    xml_files = [
        "PingPulseVPN/Resources/Info.plist",
        "PingPulseVPN/Resources/PingPulseVPN.entitlements",
        "PingPulseTunnel/Resources/Info.plist",
        "PingPulseTunnel/Resources/PingPulseTunnel.entitlements",
    ]
    for rel in xml_files:
        ET.parse(ROOT / rel)

    json_files = list((ROOT / "PingPulseVPN/Resources/Assets.xcassets").rglob("*.json"))
    assert len(json_files) >= 3, "Expected Assets.xcassets JSON files"
    for jf in json_files:
        with open(jf, "r", encoding="utf-8") as f:
            json.load(f)
    print(f"[OK] Validated {len(xml_files)} XML plist/entitlement files and {len(json_files)} asset JSON files.")


def check_swift_syntax_sanity():
    swift_files = list(ROOT.rglob("*.swift"))
    assert len(swift_files) >= 18
    for sf in swift_files:
        text = sf.read_text(encoding="utf-8")
        # Strip string literals and comments roughly for brace balance check
        cleaned = re.sub(r"//.*", "", text)
        cleaned = re.sub(r"/\*.*?\*/", "", cleaned, flags=re.S)
        cleaned = re.sub(r'"(?:\\.|[^"\\])*"', '""', cleaned)
        opens = cleaned.count("{")
        closes = cleaned.count("}")
        if opens != closes:
            raise AssertionError(f"Unbalanced braces in {sf.relative_to(ROOT)}: {{={opens}, }}={closes}")
        if "TODO" in text or "FIXME" in text:
            raise AssertionError(f"Placeholder comment found in {sf.relative_to(ROOT)}")
    print(f"[OK] Verified brace balance and zero placeholders across {len(swift_files)} Swift files.")


def internet_checksum(data: bytes) -> int:
    if len(data) % 2 == 1:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def simulate_packet_and_dns_wire():
    # Build a synthetic DNS query for api.pingpulse.test
    tx_id = 0xCAFE
    domain_labels = b"".join(bytes([len(p)]) + p.encode() for p in "api.pingpulse.test".split(".")) + b"\x00"
    dns_query = struct.pack("!HHHHHH", tx_id, 0x0100, 1, 0, 0, 0) + domain_labels + struct.pack("!HH", 1, 1)

    # Wrap in IPv4 + UDP header and verify checksum invariant
    src_ip = struct.pack("!4B", 10, 11, 0, 2)
    dst_ip = struct.pack("!4B", 10, 11, 0, 1)
    udp_len = 8 + len(dns_query)
    ip_total = 20 + udp_len
    ip_hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0xB8, ip_total, 0, 0x4000, 64, 17, 0, src_ip, dst_ip)
    ip_sum = internet_checksum(ip_hdr)
    ip_hdr = ip_hdr[:10] + struct.pack("!H", ip_sum) + ip_hdr[12:]
    assert internet_checksum(ip_hdr) == 0, "IPv4 header checksum verification failed"

    udp_hdr = struct.pack("!HHHH", 53000, 53, udp_len, 0)
    pseudo = src_ip + dst_ip + struct.pack("!BBH", 0, 17, udp_len)
    udp_sum = internet_checksum(pseudo + udp_hdr + dns_query) or 0xFFFF
    udp_hdr = struct.pack("!HHHH", 53000, 53, udp_len, udp_sum)
    assert internet_checksum(pseudo + udp_hdr + dns_query) == 0, "UDP checksum verification failed"
    print("[OK] Simulated RFC 1035 DNS wire query + IPv4/UDP checksum math verified.")


def main():
    check_required_files()
    check_xml_and_json()
    check_swift_syntax_sanity()
    simulate_packet_and_dns_wire()
    print("ALL VALIDATION CHECKS PASSED.")


if __name__ == "__main__":
    main()
