#!/usr/bin/env bash
# ==============================================================================
#  🛡️  AEGIS-CLI: BỘ ĐIỀU KHIỂN & QUẢN TRỊ TƯỜNG LỬA HẠT NHÂN (eBPF/XDP)
#  Sử dụng trực tiếp trên máy chủ Firewall Gateway (172.30.0.101 / VM 101)
# ==============================================================================
set -euo pipefail

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m'

AEGIS_BIN="/usr/local/bin/aegis-fw"
REPO_DIR="/home/minhmcpc/Aegis-KernelFW"
IFACE="ens18"

if [ ! -x "$AEGIS_BIN" ] && [ -f "${REPO_DIR}/build/aegis-fw" ]; then
    AEGIS_BIN="${REPO_DIR}/build/aegis-fw"
fi

banner() {
    clear 2>/dev/null || true
    echo -e "${CYAN}${BOLD}"
    echo "  █████╗ ███████╗ ██████╗ ██╗███████╗    ███████╗██╗    ██╗"
    echo " ██╔══██╗██╔════╝██╔════╝ ██║██╔════╝    ██╔════╝██║    ██║"
    echo " ███████║█████╗  ██║  ███╗██║███████╗    █████╗  ██║ █╗ ██║"
    echo " ██╔══██║██╔══╝  ██║   ██║██║╚════██║    ██╔══╝  ██║███╗██║"
    echo " ██║  ██║███████╗╚██████╔╝██║███████║    ██║     ╚███╔███╔╝"
    echo " ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝    ╚═╝      ╚══╝╚══╝ "
    echo -e "${NC}"
    echo -e "${YELLOW}  Aegis-KernelFW (XDP/eBPF Line-Rate Defense CLI Controller)${NC}"
    echo -e "${MAGENTA}  Interface: ${BOLD}${IFACE}${NC}${MAGENTA} | Systemd Service: ${BOLD}aegis-fw.service${NC}"
    echo "=========================================================================="
}

cmd_status() {
    banner
    echo -e "${BOLD}${CYAN}>>> TRẠNG THÁI HỆ THỐNG & XDP DRIVER HOOK:${NC}\n"
    if ip link show dev "$IFACE" | grep -q 'prog/xdp'; then
        echo -e "${GREEN}${BOLD}[✓] XDP HOOK: ĐANG HOẠT ĐỘNG TRÊN ${IFACE}${NC}"
        ip link show dev "$IFACE" | grep -E 'xdp|UP'
    else
        echo -e "${RED}${BOLD}[!] XDP HOOK: CHƯA GẮN VÀO ${IFACE}${NC}"
    fi

    echo -e "\n${BOLD}${CYAN}>>> TRẠNG THÁI SYSTEMD DAEMON:${NC}"
    systemctl status aegis-fw.service --no-pager -l || true

    echo -e "\n${BOLD}${CYAN}>>> TRẠNG THÁI 16 TÍNH NĂNG PHÒNG THỦ (eBPF BITMASK):${NC}"
    "$AEGIS_BIN" feature list || true
}

cmd_build() {
    banner
    echo -e "${BOLD}${YELLOW}[*] Bắt đầu Clean & Compile eBPF Kernel Firewall...${NC}\n"
    cd "$REPO_DIR"
    make clean
    make all
    sudo make install
    echo -e "\n${GREEN}${BOLD}[✓] BIÊN DỊCH VÀ CÀI ĐẶT THÀNH CÔNG VÀO HỆ THỐNG!${NC}"
    echo -e "    -> Binary: /usr/local/bin/aegis-fw"
    echo -e "    -> eBPF Object: /usr/local/lib/aegis/xdp_fw.bpf.o"
}

cmd_restart() {
    banner
    echo -e "${BOLD}${YELLOW}[*] Đang nạp lại dịch vụ Aegis-KernelFW...${NC}"
    sudo systemctl restart aegis-fw.service
    echo -e "${GREEN}${BOLD}[✓] Đã khởi động lại dịch vụ thành công!${NC}"
    cmd_status
}

cmd_stats() {
    "$AEGIS_BIN" stats
}

cmd_live() {
    banner
    echo -e "${BOLD}${GREEN}[*] Khởi chạy Live Telemetry Monitor (Bấm Ctrl+C để dừng)...${NC}\n"
    "$AEGIS_BIN" monitor 1
}

cmd_ban() {
    banner
    echo -e "${BOLD}${CYAN}>>> DANH SÁCH CÁC IP ĐANG BỊ AUTO-BAN (METHOD 10):${NC}\n"
    "$AEGIS_BIN" ban list || true
}

cmd_enable_all() {
    "$AEGIS_BIN" feature enable all
    echo -e "${GREEN}[✓] Đã kích hoạt toàn bộ 16 lớp phòng thủ eBPF!${NC}"
}

cmd_ports() {
    banner
    echo -e "${BOLD}${CYAN}>>> DANH SÁCH SERVICE PORT ĐANG BẢO VỆ (WHITELIST):${NC}\n"
    echo -e "${YELLOW}--- TCP Ports ---${NC}"
    "$AEGIS_BIN" port list tcp || true
    echo -e "\n${YELLOW}--- UDP Ports ---${NC}"
    "$AEGIS_BIN" port list udp || true
}

interactive_menu() {
    while true; do
        banner
        echo -e "${BOLD}CHỌN THAO TÁC QUẢN TRỊ TƯỜNG LỬA KERNEL:${NC}\n"
        echo -e "  ${GREEN}1.${NC} Kiểm tra trạng thái XDP & Systemd      (${CYAN}status${NC})"
        echo -e "  ${GREEN}2.${NC} Xem bảng thống kê gói tin & Drop       (${CYAN}stats${NC})"
        echo -e "  ${GREEN}3.${NC} Bật Live Telemetry Dashboard 1s       (${CYAN}live${NC})"
        echo -e "  ${GREEN}4.${NC} Xem danh sách IP đang bị Auto-Ban     (${CYAN}ban list${NC})"
        echo -e "  ${GREEN}5.${NC} Bật toàn bộ 16 Module phòng thủ       (${CYAN}feature enable all${NC})"
        echo -e "  ${GREEN}6.${NC} Xem Service Port đang bảo vệ (22, 53)  (${CYAN}ports${NC})"
        echo -e "  ${YELLOW}7.${NC} ${BOLD}Build lại Kernel từ Source code${NC}       (${YELLOW}make clean && make all${NC})"
        echo -e "  ${YELLOW}8.${NC} ${BOLD}Khởi động lại Aegis-KernelFW Systemd${NC} (${YELLOW}systemctl restart${NC})"
        echo -e "  ${MAGENTA}9.${NC} Reset toàn bộ bộ đếm về 0             (${MAGENTA}reset-stats${NC})"
        echo -e "  ${RED}0.${NC} Thoát\n"
        read -p "Nhập lựa chọn của bạn [0-9]: " choice

        case "$choice" in
            1) cmd_status ;;
            2) banner; cmd_stats ;;
            3) cmd_live ;;
            4) cmd_ban ;;
            5) banner; cmd_enable_all ;;
            6) cmd_ports ;;
            7) cmd_build ;;
            8) cmd_restart ;;
            9) banner; "$AEGIS_BIN" reset-stats; echo -e "\n${GREEN}[✓] Đã reset toàn bộ counter về 0!${NC}" ;;
            0|[qQ]) echo -e "\n${GREEN}[✓] Tạm biệt!${NC}"; exit 0 ;;
            *) echo -e "\n${RED}[!] Lựa chọn không hợp lệ.${NC}"; sleep 1 ;;
        esac
        echo ""
        read -p "Nhấn [Enter] để quay lại menu..." || true
    done
}

if [ $# -gt 0 ]; then
    case "$1" in
        status) cmd_status ;;
        stats) cmd_stats ;;
        live|monitor) cmd_live ;;
        build) cmd_build ;;
        restart|reload) cmd_restart ;;
        ban) cmd_ban ;;
        ports) cmd_ports ;;
        enable-all) cmd_enable_all ;;
        help|--help|-h)
            echo "Usage: aegis-cli [status|stats|live|build|restart|ban|ports|enable-all]"
            ;;
        *) "$AEGIS_BIN" "$@" ;;
    esac
else
    interactive_menu
fi
