import Darwin
import Foundation
import HevSocks5Tunnel

public enum HevTunnelBridge {
    public struct Stats: Sendable {
        public let upPackets: Int
        public let upBytes: Int
        public let downPackets: Int
        public let downBytes: Int
    }

    public static var tunnelFileDescriptor: Int32? {
        var ctlInfo = pingpulse_ctl_info()
        withUnsafeMutablePointer(to: &ctlInfo.ctl_name) {
            $0.withMemoryRebound(to: CChar.self, capacity: 96) { ptr in
                _ = strcpy(ptr, "com.apple.net.utun_control")
            }
        }

        for fd: Int32 in 0...1024 {
            var addr = pingpulse_sockaddr_ctl()
            var ret: Int32 = -1
            var len = socklen_t(MemoryLayout<pingpulse_sockaddr_ctl>.size)
            withUnsafeMutablePointer(to: &addr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { saPtr in
                    ret = Darwin.getpeername(fd, saPtr, &len)
                }
            }
            if ret != 0 || addr.sc_family != UInt8(AF_SYSTEM) {
                continue
            }
            if ctlInfo.ctl_id == 0 {
                ret = Darwin.ioctl(fd, PINGPULSE_CTLIOCGINFO, &ctlInfo)
                if ret != 0 {
                    continue
                }
            }
            if addr.sc_id == ctlInfo.ctl_id {
                return fd
            }
        }
        return nil
    }

    public static func run(configString: String) -> Int32 {
        guard let fd = tunnelFileDescriptor else {
            return -1
        }
        let utf8 = Array(configString.utf8)
        return utf8.withUnsafeBufferPointer { buf in
            hev_socks5_tunnel_main_from_str(buf.baseAddress, UInt32(buf.count), fd)
        }
    }

    public static var stats: Stats {
        var tPackets = 0
        var tBytes = 0
        var rPackets = 0
        var rBytes = 0
        hev_socks5_tunnel_stats(&tPackets, &tBytes, &rPackets, &rBytes)
        return Stats(
            upPackets: tPackets,
            upBytes: tBytes,
            downPackets: rPackets,
            downBytes: rBytes
        )
    }

    public static func quit() {
        hev_socks5_tunnel_quit()
    }
}
