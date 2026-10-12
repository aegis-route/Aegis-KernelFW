# 🛡️ Aegis-KernelFW

**Aegis-KernelFW** là hệ thống Firewall tốc độ cao hoạt động ở tầng nhân Linux (Linux Kernel Space) dựa trên công nghệ **XDP (eXpress Data Path)** và **eBPF (Extended Berkeley Packet Filter)**.

Dự án được thiết kế theo kiến trúc **Module hóa độc lập (Isolated Methods)**, cho phép nhận diện, phân loại, đếm metric riêng biệt và bật/tắt độc lập từng phương thức chống đỡ cho **10 kịch bản tấn công mạng phổ biến nhất**.

---

## ⚡ 10 Phương thức chống đỡ độc lập (Defense Methods)

Mỗi phương thức phòng thủ được tách thành một file header riêng biệt trong `src/bpf/mitigation/` và có bộ đếm Metric riêng biệt trong `map_stats`:

| Mã Method | Tên Module & File Header | Kịch bản tấn công | Cơ chế XDP xử lý |
|---|---|---|---|
| **Method 01** | `mitigation/malformed.h` | **Malformed Packets** | Kiểm tra độ dài IP/TCP/UDP header, `tot_len`, `ihl < 5` → `XDP_DROP` |
| **Method 02** | `mitigation/bogon.h` | **Bogon & Spoofed IP** | Chặn Land attack (`src == dst`), loopback `127.0.0.0/8`, multicast `224.0.0.0/4`, Class E |
| **Method 03** | `mitigation/frag.h` | **Fragmented Packets** | Bắt cờ `IP_MF` (More Fragments) hoặc `offset > 0` → `XDP_DROP` |
| **Method 04** | `mitigation/tcp_flags.h` | **Invalid TCP Flags / Scans** | Bắt các đòn quét cổng: Null scan, Xmas scan, SYN-FIN, SYN-RST, FIN không có ACK |
| **Method 05** | `mitigation/syn_flood.h` | **TCP SYN Flood** | Token Bucket trượt theo dõi tần suất cờ SYN per-IP → Drop khi vượt ngưỡng |
| **Method 06** | `mitigation/out_of_state.h` | **TCP Out-of-state ACK/RST** | Drop gói ACK/RST rác gửi đến cổng đóng để tránh kernel sinh gói RST phản hồi |
| **Method 07** | `mitigation/udp_junk.h` | **UDP Closed Port Flood** | Drop ngay lập tức mọi gói UDP gửi đến các port không mở trong `map_open_udp_ports` |
| **Method 08** | `mitigation/icmp_flood.h` | **ICMP Ping Flood** | Giới hạn tần suất gói Ping (Echo Request type 8) per-IP bằng sliding window |
| **Method 09** | `mitigation/reflected.h` | **Reflected Amplification** | Lọc gói phản hồi lạ từ DNS (53), NTP (123), SSDP (1900), Memcached (11211) |
| **Method 10** | `mitigation/rate_limit.h` | **High PPS & Dynamic Ban** | Token Bucket đo PPS per-IP; tự động ban IP vi phạm vào `map_dynamic_ban` (60s - 300s) |

---

## 📁 Cấu trúc thư mục Module

```
Aegis-KernelFW/
├── Makefile                          # Build system cho Kernel eBPF và CLI
├── README.md                         # Tài liệu hướng dẫn
├── config/
│   └── rules.example.conf            # Cấu hình mẫu
├── include/
│   ├── aegis_common.h                # Pinned map paths, tune limits
│   └── aegis_types.h                 # Struct, feature flags, 18 distinct stat indices
├── scripts/
│   ├── setup_deps.sh                 # Cài đặt Clang, LLVM, LibBPF
│   └── test_traffic.sh               # Tạo mạng ảo veth + netns để test cô lập an toàn
└── src/
    ├── bpf/
    │   ├── mitigation/               # 10 MODULE PHÒNG THỦ ĐỘC LẬP
    │   │   ├── malformed.h           # Method 01: Malformed & short packet
    │   │   ├── bogon.h               # Method 02: Bogon, loopback, Land attack
    │   │   ├── frag.h                # Method 03: Fragmented packet (MF / offset)
    │   │   ├── tcp_flags.h           # Method 04: Invalid TCP flags / stealth scan
    │   │   ├── syn_flood.h           # Method 05: TCP SYN flood rate limit
    │   │   ├── out_of_state.h        # Method 06: TCP out-of-state ACK/RST
    │   │   ├── udp_junk.h            # Method 07: UDP closed port junk
    │   │   ├── icmp_flood.h          # Method 08: ICMP ping flood limiter
    │   │   ├── reflected.h           # Method 09: Reflected amplification flood
    │   │   └── rate_limit.h          # Method 10: High PPS rate limit & Dynamic Ban
    │   └── xdp_fw.bpf.c              # Core XDP Hook: điều phối tuần tự 10 module
    └── userspace/
        ├── loader.c / .h             # Nạp/gỡ XDP và Pin toàn bộ BPF Maps
        ├── rule_manager.c / .h       # Bật/tắt method, Whitelist port, Dynamic ban, CIDR
        ├── stats.c / .h              # Đọc metric chi tiết từng method & Live dashboard
        └── main.c                    # CLI aegis-fw
```

---

## 📖 Hướng dẫn sử dụng CLI (`aegis-fw`)

### 1. Nạp và gỡ bỏ Firewall
```bash
# Nạp vào eth0 (chế độ generic / skb)
sudo ./build/aegis-fw load eth0 --mode skb

# Nạp vào eth0 (chế độ native/driver mode - hiệu năng cao nhất)
sudo ./build/aegis-fw load eth0 --mode native

# Gỡ bỏ khỏi eth0
sudo ./build/aegis-fw unload eth0
```

### 2. Quản lý Bật / Tắt từng phương thức phòng thủ (Feature Toggles)
```bash
# Xem danh sách trạng thái 10 phương thức
sudo ./build/aegis-fw feature list

# Tắt tạm thời một phương thức (ví dụ tắt chặn phân mảnh để test)
sudo ./build/aegis-fw feature disable frag

# Bật lại phương thức
sudo ./build/aegis-fw feature enable frag

# Tắt hoặc bật toàn bộ
sudo ./build/aegis-fw feature enable all
```

### 3. Khai báo cổng dịch vụ hợp lệ (Bảo vệ cổng đóng - Methods 6 & 7)
```bash
# Cho phép TCP port 80 (HTTP) và 443 (HTTPS)
sudo ./build/aegis-fw port allow tcp 80
sudo ./build/aegis-fw port allow tcp 443

# Cho phép UDP port 53 (DNS) hoặc 51820 (WireGuard)
sudo ./build/aegis-fw port allow udp 53

# Xem danh sách các cổng đang mở
sudo ./build/aegis-fw port list tcp
sudo ./build/aegis-fw port list udp
```
*(Mọi gói UDP hoặc gói ACK/RST gửi đến các cổng không nằm trong danh sách này sẽ bị drop ngay lập tức tại tầng XDP, giải phóng 100% CPU cho OS).*

### 4. Quản lý Dynamic Auto-Ban (Method 10)
```bash
# Xem danh sách các IP đang bị tự động cấm vì spam PPS cao
sudo ./build/aegis-fw ban list

# Mở cấm sớm cho một IP
sudo ./build/aegis-fw ban clear 192.168.1.100
```

### 5. Thống kê & Màn hình Dashboard phân tách từng Method
```bash
# Xem bảng thống kê chi tiết số gói bị drop bởi từng method
sudo ./build/aegis-fw stats

# Bật màn hình Live Dashboard (tự cập nhật PPS & Throughput mỗi 1 giây)
sudo ./build/aegis-fw monitor 1
```

---

## 📜 Giấy phép
Dự án được phân phối dưới giấy phép **GPL-2.0**.
