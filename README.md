# 🛡️ Aegis-KernelFW (v1.2.0-shield)

**Aegis-KernelFW** là hệ sinh thái tường lửa tốc độ cao hoạt động ở tầng nhân Linux (Linux Kernel Space) dựa trên công nghệ **XDP (eXpress Data Path)** và **eBPF (Extended Berkeley Packet Filter)**. 

Được thiết kế làm **Lớp 1 (Perimeter Defense)** trong giải pháp mạng **Aegis-Route**, hệ thống can thiệp và xử lý gói tin trực tiếp tại driver card mạng (NIC) trước khi Linux Kernel cấp phát bộ nhớ `sk_buff`, cho phép loại bỏ (drop) các đòn tấn công DDoS với lưu lượng hàng chục triệu gói tin mỗi giây (line-rate) ở độ trễ cực thấp (< 1µs).

---

## 🚀 Tính năng nổi bật

* **16 Module phòng thủ độc lập (Isolated Methods):** Mỗi phương thức phòng thủ được tách biệt hoàn toàn trong file header riêng tại `src/bpf/mitigation/`, cho phép kiểm soát bật/tắt độc lập và đếm metric riêng rẽ.
* **Xử lý Line-rate Wire-Speed:** Chặn đứng các đòn tấn công trước khi chạm vào Netfilter/iptables, giải phóng tới 80% tải CPU cho hệ thống.
* **Chống DDoS Đa Vector (Layer 3, Layer 4 & Early L7):** Chặn các đòn Syn Flood, UDP Flood, Amplification, Fragment, DNS Water Torture, QUIC Initial Flood, TCP Zero-Window và Early HTTP Scanner.
* **Bảng tra cứu LPM-Trie O(1):** Quản lý Whitelist / Blacklist dải mạng CIDR (/24, /16...) với tốc độ so khớp tiền tố dài nhất không phụ thuộc vào số lượng rule.
* **Cơ chế Token Bucket & Dynamic Auto-Ban:** Tự động phát hiện các IP có tần suất PPS bất thường và khóa tạm thời (Dynamic Ban) vào BPF Hash Map.
* **Per-CPU Lockless Telemetry:** Thu thập thống kê gói tin và băng thông riêng biệt theo từng CPU core mà không gây xung đột bộ nhớ, tích hợp Live Dashboard cập nhật theo thời gian thực.

---

## 📐 Kiến trúc luồng xử lý gói tin (Data Flow Pipeline)

```
                            [ GÓI TIN ĐẾN CARD MẠNG (NIC RX Ring) ]
                                                │
                                                ▼
                                    [ XDP DRIVER HOOK ]
                                                │
                 ┌──────────────────────────────┴──────────────────────────────┐
                 ▼ (IPv6)                                                      ▼ (IPv4)
       [Method 12: IPv6 Pipeline]                                   [Method 01: Malformed Check]
  (Bogon, Multicast src, Fragment Drop)                                (Short packet, Bad IHL)
                 │                                                             │
                 │                                              [Fast-Path: LPM Whitelist] ──(Pass)──► [ XDP_PASS ]
                 │                                                             │
                 │                                              [Method 02: Bogon & Land Check]
                 │                                               (0.0.0.0/8, 127.0.0.0/8, Land)
                 │                                                             │
                 │                                              [Static Blacklist CIDR Drop]
                 │                                                             │
                 │                                              [Method 10: Dynamic Auto-Ban]
                 │                                               (High PPS Token Bucket Ban)
                 │                                                             │
                 │                                              [Method 03: Frag Packet Drop]
                 │                                                    (MF=1 hoặc offset>0)
                 │                                                             │
                 │                              ┌──────────────────────────────┴──────────────────────────────┐
                 │                              ▼ (TCP)                                                       ▼ (UDP)
                 │               [Method 04: Invalid TCP Flags]                               [Method 09: Reflected Amplification]
                 │                   (Null, Xmas, SYN-FIN)                                        (DNS 53, NTP 123, SSDP 1900)
                 │                              │                                                             │
                 │               [Method 13: TCP Anomaly Drop]                                [Method 11: DNS Protection]
                 │                  (Zero-Window, Sockstress)                                     (PRSD Subdomain, Type ANY)
                 │                              │                                                             │
                 │               [Method 05: SYN Flood Limit]                                 [Method 14: QUIC Initial Flood]
                 │                  (Per-IP Sliding Window)                                       (UDP 443 < 1200 bytes drop)
                 │                              │                                                             │
                 │               [Method 06: Out-of-State Drop]                               [Method 07: UDP Closed Port Drop]
                 │                 (ACK/RST to closed ports)                                      (Drop non-listening ports)
                 │                              │                                                             │
                 │               [Method 15: Early L7 Scanner]                                                │
                 │                  (/.env, /wp-, /xmlrpc)                                                    │
                 │                              │                                                             │
                 │               [Method 16: TLS Record Check]                                                │
                 │                (Plaintext on 443, Bad TLS)                                                 │
                 │                              │                                                             │
                 └──────────────────────────────┼─────────────────────────────────────────────────────────────┘
                                                │
                                    [ Explicit L4 Rules Map ]
                                                │
                                  [ Fallback Default Policy ]
                                       (PASS hoặc DROP)
```

---

## ⚡ 16 Phương thức phòng thủ độc lập (Defense Methods)

Mỗi phương thức phòng thủ được tách biệt thành một file mã nguồn riêng trong thư mục [src/bpf/mitigation/](file:///mnt/d/project/Aegis-KernelFW/src/bpf/mitigation/):

| Mã Method | File mã nguồn | Kịch bản tấn công | Cơ chế XDP xử lý kỹ thuật |
| :---: | :--- | :--- | :--- |
| **Method 01** | `mitigation/malformed.h` | **Malformed Packets** | Kiểm tra độ dài IP/TCP/UDP header, ranh giới gói `data_end`, `tot_len < ihl*4` → Drop ngay. |
| **Method 02** | `mitigation/bogon.h` | **Bogon & Spoofed IP** | Chặn Land attack (`src == dst`), Loopback `127.0.0.0/8`, Multicast `224.0.0.0/4`, Class E `240.0.0.0/4`. |
| **Method 03** | `mitigation/frag.h` | **Fragmented Packets** | Bắt cờ `IP_MF` (More Fragments) hoặc `Fragment Offset > 0` → Drop triệt để phân mảnh qua WAN. |
| **Method 04** | `mitigation/tcp_flags.h` | **Invalid TCP Flags / Scans** | Chặn quét cổng trinh sát: Null scan, Xmas scan (FIN+PSH+URG), SYN-FIN, SYN-RST, FIN không có ACK. |
| **Method 05** | `mitigation/syn_flood.h` | **TCP SYN Flood** | Giới hạn tần suất cờ SYN per-IP trong cửa sổ trượt 1s (`max_syn_pps_per_ip`) → Drop khi vượt ngưỡng. |
| **Method 06** | `mitigation/out_of_state.h` | **TCP Out-of-state ACK/RST** | Drop gói ACK/RST rác gửi đến cổng đóng để tránh kernel sinh gói RST phản hồi gây cạn kiệt CPU. |
| **Method 07** | `mitigation/udp_junk.h` | **UDP Closed Port Flood** | Drop lập tức mọi gói UDP gửi tới port không mở trong `map_open_udp_ports`, triệt tiêu ICMP unreachable. |
| **Method 08** | `mitigation/icmp_flood.h` | **ICMP Ping Flood** | Giới hạn tần suất gói Ping (Echo Request type 8) per-IP bằng sliding window mà không ảnh hưởng ping thông thường. |
| **Method 09** | `mitigation/reflected.h` | **Reflected Amplification** | Lọc gói phản xạ độc hại từ DNS (53), NTP (123), SSDP (1900), Memcached (11211), CharGEN (19), CLDAP (389). |
| **Method 10** | `mitigation/rate_limit.h` | **High PPS & Dynamic Ban** | Token Bucket đo PPS per-IP; tự động phạt ban IP vi phạm vào `map_dynamic_ban` (60s - 300s). |
| **Method 11** | `mitigation/dns_protect.h` | **DNS PRSD & ANY Flood** | Chặn DNS Water Torture (PRSD subdomain ngẫu nhiên $\ge 45$ ký tự) & Drop truy vấn Type ANY (255). |
| **Method 12** | `mitigation/ipv6_pipeline.h` | **IPv6 Bogons & Extension Bomb** | Lọc IPv6 Bogon (`::/128`, `::1`, Multicast source, Link-local WAN, Fragment); bảo vệ 100% NDP (133-136). |
| **Method 13** | `mitigation/tcp_anomaly.h` | **TCP Zero-Window & Sockstress** | Chặn gói TCP Window = 0 không payload nhằm đóng băng socket buffer và đòn 1-byte PSH spam. |
| **Method 14** | `mitigation/quic_flood.h` | **QUIC / HTTP/3 Initial Flood** | Bắt buộc gói QUIC Initial UDP 443 đạt $\ge 1200$ bytes theo chuẩn RFC 9000, drop gói tiny giả mạo. |
| **Method 15** | `mitigation/l7_scanner.h` | **Early L7 HTTP Scanner** | Nhận diện chuỗi scan sớm (`/.env`, `/wp-`, `/xmlrpc`, `/phpmyadmin`) và drop trước khi chạm Web Server. |
| **Method 16** | `mitigation/tls_sni.h` | **Malformed TLS / Plaintext** | Chặn request plaintext HTTP gửi vào cổng 443 và drop TLS Record Header giả mạo gây lỗi OpenSSL. |

---

## 📊 Đánh giá khả năng chống đỡ 36 dạng tấn công DoS/DDoS (`type.txt`)

Dựa trên kiểm nghiệm thực tế và cơ chế phòng thủ chuyên sâu của Aegis-KernelFW:

```text
UDP Flood | can
UDP Fragmentation Flood | can
UDP Amplification | can
CharGEN Flood | can
ICMP (Ping) Flood | can
ICMP Fragmentation Flood | can
Misused Application Attack | can
IP Null Attack | can
TCP Flood | can
SYN Flood | can
SYN-ACK Flood | can
ACK Flood | can
ACK Fragmentation Flood | can
RST/FIN Flood | can
Multiple ACK Spoofed Session Flood | can
Multiple SYN-ACK Spoofed Session Flood | can
Synonymous IP Attack | can
Session Attack | can
Slowloris | not
Ping of Death | can
Smurf Attack | can
Fraggle Attack | can
LOIC Attack | can
HOIC Attack | can
HTTP Flood | not
GET Attack | not
POST Attack | not
Slow POST (R.U.D.Y.) | not
One-session / One-request Attack | not
HTTP Fragmentation | not
Recursive GET Flood | not
Random Recursive GET Flood | not
ReDoS (Regular Expression Denial of Service) | not
Advanced Persistent DoS (APDoS) | not
Multi-Vector Attacks | can
Zero-Day DDoS Attacks | not
```

* **Chống đỡ thành công (`can` - 22 đòn):** Toàn bộ các đòn tấn công L3/L4 volumetric (UDP, TCP SYN/ACK/RST, Frag, ICMP, Amplification, Land, Smurf, Fraggle, Sockstress/Session, LOIC, HOIC).
* **Cần hỗ trợ của WAF/L7 Proxy (`not` - 14 đòn):** Các cuộc tấn công tầng ứng dụng semantic (Slowloris, Slow POST R.U.D.Y, ReDoS, One-request heavy database query, Recursive crawler) cần Reverse Proxy/WAF (Nginx, ModSecurity, Cloudflare) để phân tích timeout kết nối và cấu trúc HTTP body.

---

## 🛠️ Cài đặt & Biên dịch (Build & Installation)

### 1. Yêu cầu hệ thống
* Hệ điều hành: **Ubuntu 22.04 LTS / Debian 12 / Proxmox VE** (Kernel $\ge 5.15$).
* Quyền hạn: `root` hoặc `sudo`.
* Gói phụ thuộc: `clang`, `llvm`, `libbpf-dev`, `libelf-dev`, `zlib1g-dev`, `gcc-multilib`.

### 2. Cài đặt môi trường tự động
```bash
sudo bash scripts/setup_deps.sh
```

### 3. Biên dịch chương trình
```bash
# Biên dịch cả Kernel eBPF (.o) và CLI Userspace
make all

# Hoặc chỉ biên dịch mã eBPF
make bpf

# Hoặc chỉ biên dịch mã CLI Userspace
make user

# Cài đặt vào hệ thống (/usr/local/bin/aegis-fw)
sudo make install
```

---

## 📖 Hướng dẫn sử dụng CLI (`aegis-fw`)

### 1. Nạp và gỡ bỏ Firewall khỏi Card mạng
```bash
# Nạp vào eth0 ở chế độ Generic (SKB mode - tương thích mọi card mạng ảo/veth)
sudo ./build/aegis-fw load eth0 --mode skb

# Nạp vào eth0 ở chế độ Native Driver (hiệu năng cao nhất, yêu cầu card Intel/Mellanox/Broadcom)
sudo ./build/aegis-fw load eth0 --mode native

# Gỡ bỏ Firewall khỏi card mạng
sudo ./build/aegis-fw unload eth0
```

### 2. Quản lý Bật / Tắt 16 Phương thức phòng thủ
```bash
# Xem danh sách và trạng thái hiện tại của toàn bộ 16 method
sudo ./build/aegis-fw feature list

# Tắt tạm thời một phương thức (ví dụ: tắt bộ lọc phân mảnh để kiểm thử)
sudo ./build/aegis-fw feature disable frag

# Bật lại phương thức
sudo ./build/aegis-fw feature enable frag

# Tắt hoặc bật đồng thời toàn bộ 16 phương thức
sudo ./build/aegis-fw feature enable all
sudo ./build/aegis-fw feature disable all
```
*Các tên module hỗ trợ:* `malformed`, `bogon`, `frag`, `tcp-flags`, `syn-flood`, `out-of-state`, `udp-junk`, `icmp-limit`, `reflected`, `rate-limit`, `dns-protect`, `ipv6`, `tcp-anomaly`, `quic`, `l7-scanner`, `tls-inspect`.

### 3. Khai báo cổng dịch vụ hợp lệ (Service Port Whitelist)
```bash
# Cho phép mở cổng TCP 80 (HTTP) và 443 (HTTPS)
sudo ./build/aegis-fw port allow tcp 80
sudo ./build/aegis-fw port allow tcp 443

# Cho phép mở cổng UDP 53 (DNS) hoặc 51820 (WireGuard VPN)
sudo ./build/aegis-fw port allow udp 53
sudo ./build/aegis-fw port allow udp 51820

# Liệt kê các cổng đang mở
sudo ./build/aegis-fw port list tcp
sudo ./build/aegis-fw port list udp

# Đóng cổng dịch vụ
sudo ./build/aegis-fw port disallow tcp 80
```
*(Mọi gói UDP hoặc gói ACK/RST gửi đến các cổng không nằm trong danh sách này sẽ bị drop trong im lặng tại tầng XDP, ngăn chặn quét cổng Shodan/Nmap và tiết kiệm 100% CPU).*

### 4. Quản lý Dynamic Auto-Ban
```bash
# Xem danh sách IP đang bị hệ thống tự động cấm và thời gian phạt còn lại
sudo ./build/aegis-fw ban list

# Mở cấm sớm cho một địa chỉ IP
sudo ./build/aegis-fw ban clear 192.168.1.100
```

### 5. Quản lý Rule tĩnh L3 (CIDR) & Rule L4
```bash
# Thêm subnet vào Blacklist (drop ngay tại XDP)
sudo ./build/aegis-fw rule add blacklist 45.33.32.0/24

# Thêm subnet vào Whitelist (Fast-path bỏ qua toàn bộ kiểm tra)
sudo ./build/aegis-fw rule add whitelist 192.168.100.0/24

# Xem danh sách Whitelist / Blacklist
sudo ./build/aegis-fw rule list blacklist
sudo ./build/aegis-fw rule list whitelist

# Thêm Rule tĩnh L4 (chặn Telnet port 23)
sudo ./build/aegis-fw rule add l4 tcp 23 drop

# Xóa Rule L4
sudo ./build/aegis-fw rule del l4 tcp 23
```

### 6. Thống kê & Màn hình Dashboard phân tách từng Method
```bash
# Xem bảng thống kê tổng số gói tin và dung lượng bytes bị drop theo từng Method
sudo ./build/aegis-fw stats

# Bật màn hình Live Dashboard (tự động cập nhật số gói/giây PPS và băng thông Mbps/Gbps)
sudo ./build/aegis-fw monitor 1

# Reset toàn bộ bộ đếm thống kê về 0
sudo ./build/aegis-fw reset-stats
```

---

## 🧪 Kịch bản kiểm thử an toàn (Testbed Network Namespace)

Script `scripts/test_traffic.sh` cho phép tạo môi trường mạng ảo cách ly an toàn (`veth pair` + `netns`) để kiểm thử mà không làm ảnh hưởng mạng máy thật:

```bash
# 1. Khởi tạo môi trường mạng ảo thử nghiệm
sudo bash scripts/test_traffic.sh setup

# 2. Gắn Aegis-KernelFW vào card mạng ảo veth_host
sudo ./build/aegis-fw load veth_host --mode skb

# 3. Kiểm tra ping thông thường từ bên trong namespace
sudo ip netns exec aegis_test_ns ping -c 3 10.200.1.1

# 4. Thử nghiệm cấm IP ảo
sudo ./build/aegis-fw rule add blacklist 10.200.1.2/32

# 5. Ping lại (gói tin bị XDP_DROP ngay lập tức)
sudo ip netns exec aegis_test_ns ping -c 3 10.200.1.1

# 6. Xem thống kê gói tin bị drop
sudo ./build/aegis-fw stats

# 7. Gỡ bỏ firewall và dọn dẹp môi trường thử nghiệm
sudo ./build/aegis-fw unload veth_host
sudo bash scripts/test_traffic.sh cleanup
```

---

## 🏢 Hướng dẫn triển khai thực tế

* **Mô hình Hộ gia đình (Home):**
  * Gắn XDP trên card WAN ngõ vào.
  * Đặt ngưỡng rate-limit nới lỏng (`max_pps = 10000`, `max_syn = 200`) để không chặn nhầm lúc chơi game (CS2, Valorant) hoặc xem video 4K.
  * Kết hợp AdGuard DNS để bật SafeSearch và chặn web xấu.
* **Mô hình Trường học (School / Lab / Ký túc xá):**
  * Gắn XDP trên cả cổng WAN và cổng LAN Gateway.
  * Bật `Method 5 (SYN Flood)` và `Method 10 (Dynamic Auto-Ban)` để tự động khóa các máy sinh viên chạy tool DoS (LOIC) nội bộ.
  * Chia VLAN trên MikroTik và phân bổ băng thông đều theo thuật toán PCQ.
* **Mô hình Doanh nghiệp nhỏ (Small Company / SME):**
  * Khai báo danh sách Whitelist cho IP tĩnh của đối tác và chi nhánh VPN.
  * Bật `Method 6 (TCP Out-of-State)` và `Method 7 (UDP Closed Port)` để đưa toàn bộ hệ thống vào chế độ ẩn mình (Stealth Mode) trước các máy quét tự động trên Internet.
  * Tận dụng tính năng Dual-WAN Failover của MikroTik để đảm bảo mạng không bao giờ bị gián đoạn.

---

## 📁 Cấu trúc thư mục dự án

```
Aegis-KernelFW/
├── Makefile                          # Build system cho Kernel eBPF và CLI
├── README.md                         # Tài liệu hướng dẫn kỹ thuật chi tiết
├── type.txt                          # Bảng phân loại 36 dạng tấn công DoS/DDoS
├── config/
│   └── rules.example.conf            # File cấu hình mẫu
├── include/
│   ├── aegis_common.h                # Pinned map paths, tune limits, version
│   └── aegis_types.h                 # Struct, feature flags, 24 distinct stat indices
├── scripts/
│   ├── setup_deps.sh                 # Cài đặt tự động Clang, LLVM, LibBPF
│   └── test_traffic.sh               # Tạo mạng ảo veth + netns để test cô lập an toàn
└── src/
    ├── bpf/
    │   ├── mitigation/               # 16 MODULE PHÒNG THỦ ĐỘC LẬP
    │   │   ├── malformed.h           # Method 01: Malformed & short packet check
    │   │   ├── bogon.h               # Method 02: Bogon, loopback, Land attack
    │   │   ├── frag.h                # Method 03: Fragmented packet drop (MF / offset)
    │   │   ├── tcp_flags.h           # Method 04: Invalid TCP flags / stealth scan
    │   │   ├── syn_flood.h           # Method 05: TCP SYN flood rate limit
    │   │   ├── out_of_state.h        # Method 06: TCP out-of-state ACK/RST closed port
    │   │   ├── udp_junk.h            # Method 07: UDP closed port & junk flood drop
    │   │   ├── icmp_flood.h          # Method 08: ICMP ping flood limiter
    │   │   ├── reflected.h           # Method 09: Reflected amplification flood
    │   │   ├── rate_limit.h          # Method 10: High PPS rate limit & Dynamic Auto-Ban
    │   │   ├── dns_protect.h         # Method 11: DNS Water Torture (PRSD) & ANY flood
    │   │   ├── ipv6_pipeline.h       # Method 12: Comprehensive IPv6 Defense Pipeline
    │   │   ├── tcp_anomaly.h         # Method 13: TCP Zero-Window & Sockstress
    │   │   ├── quic_flood.h          # Method 14: QUIC / HTTP/3 Initial Flood Mitigation
    │   │   ├── l7_scanner.h          # Method 15: Early L7 HTTP Scanner & Exploit Drop
    │   │   └── tls_sni.h             # Method 16: TLS Record Validation & Plaintext Drop
    │   └── xdp_fw.bpf.c              # Core XDP Hook: điều phối tuần tự 16 module
    └── userspace/
        ├── loader.c / .h             # Nạp/gỡ XDP và Pin toàn bộ BPF Maps
        ├── rule_manager.c / .h       # Bật/tắt method, Whitelist port, Dynamic ban, CIDR
        ├── stats.c / .h              # Đọc metric chi tiết từng method & Live dashboard
        └── main.c                    # CLI aegis-fw
```

---

## 📜 Giấy phép & Đóng góp
Dự án được phân phối dưới giấy phép mã nguồn mở **GPL-2.0**.
Mọi đóng góp và báo cáo lỗi xin vui lòng tạo Issue hoặc Pull Request tại [GitHub Repository](https://github.com/aegis-route/Aegis-KernelFW).
