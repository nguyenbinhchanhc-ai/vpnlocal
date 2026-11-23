# PingPulse VPN (iOS Local Traffic & Anti-Ping Optimizer)

**PingPulse VPN** là ứng dụng **VPN Local (`NEPacketTunnelProvider`)** chạy trực tiếp trên iPhone (iOS 16.0+) giúp điều phối lưu lượng ngay trên thiết bị, tối ưu truy vấn DNS tại chỗ và giảm hiện tượng giật lag / ping cao (bufferbloat & DNS tail-latency).

---

## Tính năng chính (On-Device Engine)

1. **Local DNS Query Optimizer (`10.11.0.1:53`)**:
   - **RFC 1035 Wire Parser & RAM LRU Cache**: Trả kết quả truy vấn DNS trong `< 1 ms` ngay trên điện thoại.
   - **Stale-While-Revalidate (SWR)**: Khi cache hết hạn trong cửa sổ ân hạn (mặc định 3600s), trả ngay IP cũ (`0 ms`) để kết nối tức thì rồi tự làm mới ngầm ở background.
   - **Hedged Parallel Upstream Racing**: Chấm điểm các DNS (UDP/53 QoS + DoH RFC 8484) theo EWMA RTT. Nếu resolver #1 phản hồi chậm quá `hedgeDelayMs` (mặc định `30 ms`), tự động bắn song song sang resolver #2 và lấy kết quả về trước.
   - **IPv4 Fast-Path (`Suppress AAAA`)**: Tùy chọn lọc `AAAA` nếu mạng di động gặp lỗi IPv6 khiến iOS bị trễ Happy Eyeballs.

2. **Chống Bufferbloat & Điều phối QoS 4 làn (`PacketScheduler`)**:
   - Phân loại gói tin trực tiếp trên TUN:
     - `P0 Control`: DNS, ICMP, TCP SYN/ACK nhỏ
     - `P1 Realtime`: UDP game/VoIP/STUN/QUIC
     - `P2 Web`: HTTP/HTTPS thông thường
     - `P3 Bulk`: Tải nền dung lượng lớn
   - Áp dụng **Token-Bucket Pacing** lên làn `P2/P3` để lưu lượng tải nền không chen hàng làm tăng ping của gói `P0/P1`.

3. **Background Noise Shield (`TrafficFilterEngine`)**:
   - Chặn tại chỗ các domain telemetry/analytics/crash-report chạy ngầm hay spam upload gây nghẽn băng thông upload và đánh thức sóng di động liên tục.

4. **Adaptive Cellular/Wi-Fi MTU & Custom UDP Relay (`UDPRelayEngine`)**:
   - Tự theo dõi chuyển mạng bằng `NWPathMonitor`, điều chỉnh MTU (`1360` cho 4G/5G và `1420` cho Wi-Fi) để hạn chế phân mảnh gói tin.
   - Hỗ trợ định tuyến các dải IP UDP tùy chọn (Game/VoIP CIDR) qua `NWConnection` gắn cờ QoS `.interactiveVideo`.

---

## Cấu trúc dự án

- `project.yml` — File cấu hình XcodeGen tạo `PingPulseVPN.xcodeproj`
- `Shared/` — Constants, Config, Telemetry Models và `SharedStore` (App Group IPC)
- `PingPulseTunnel/` — Network Extension (`NEPacketTunnelProvider`), Packet Scheduler, DNS Cache/SWR/Racer, Noise Shield, UDP Relay
- `PingPulseVPN/` — Giao diện SwiftUI (`Dashboard`, `Query Inspector`, `Routing & Racers`, `Tune`) + `VPNManager` + `LatencyMonitor`
- `Tests/PingPulseCoreTests/` — Bộ kiểm thử XCTest cho toàn bộ lõi xử lý gói tin và DNS
- `.github/workflows/build-ipa.yml` — GitHub Actions tự động biên dịch `.ipa` trên `macos-14`

---

## Cách lấy file `.ipa` từ GitHub Actions

Mỗi lần push lên nhánh `main`:
1. GitHub Actions (`macos-14`) chạy `xcodegen generate`, chạy unit test `PingPulseCoreTests`, biên dịch `PingPulseVPN.app` (kèm `PingPulseTunnel.appex`) và đóng gói thành **`PingPulseVPN.ipa`**.
2. Vào tab **Releases** hoặc **Actions -> Build iOS PingPulseVPN IPA -> Artifacts** để tải `PingPulseVPN.ipa`.

### Lưu ý khi cài đặt trên iPhone
- File `.ipa` xuất từ CI là bản **unsigned**.
- Vì ứng dụng sử dụng `NEPacketTunnelProvider` (Network Extension) và App Group, để VPN chạy thật trên iPhone:
  - Dùng **TrollStore** (với các máy hỗ trợ), hoặc
  - Ký lại bằng **Apple Developer Certificate** có entitlement `com.apple.developer.networking.networkextension` (`packet-tunnel-provider`) và `com.apple.security.application-groups` (`group.com.nguyenbinhchanh.pingpulse`) qua Xcode hoặc công cụ ký có hỗ trợ NetworkExtension.
  - Tài khoản Apple ID miễn phí (AltStore/Sideloadly bản free) không được Apple cấp entitlement `packet-tunnel-provider`.
