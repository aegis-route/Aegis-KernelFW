#!/usr/bin/env bash
# ===============================================================
# Aegis-KernelFW: Isolated Network Namespace Test Script
# Sets up virtual ethernet (veth) pairs for safe XDP testing
# ===============================================================

set -euo pipefail

NS_NAME="aegis_test_ns"
VETH_HOST="veth_host"
VETH_NS="veth_peer"
HOST_IP="10.200.1.1/24"
PEER_IP="10.200.1.2/24"
PEER_RAW_IP="10.200.1.2"

if [ "$EUID" -ne 0 ]; then
    echo "[!] Please run as root (or use sudo)."
    exit 1
fi

ACTION="${1:-setup}"

case "$ACTION" in
    setup)
        echo "[*] Setting up isolated test network namespace..."
        ip netns add "$NS_NAME" 2>/dev/null || true
        ip link add "$VETH_HOST" type veth peer name "$VETH_NS" 2>/dev/null || true
        ip link set "$VETH_NS" netns "$NS_NAME"

        ip addr add "$HOST_IP" dev "$VETH_HOST" 2>/dev/null || true
        ip link set "$VETH_HOST" up

        ip netns exec "$NS_NAME" ip addr add "$PEER_IP" dev "$VETH_NS" 2>/dev/null || true
        ip netns exec "$NS_NAME" ip link set "$VETH_NS" up
        ip netns exec "$NS_NAME" ip link set lo up

        echo "[✓] Virtual network established!"
        echo "    Host interface:      $VETH_HOST ($HOST_IP)"
        echo "    Namespace interface: $VETH_NS ($PEER_IP) in netns '$NS_NAME'"
        echo ""
        echo "Next steps:"
        echo "  1. Attach firewall:  sudo ./build/aegis-fw load $VETH_HOST --mode skb"
        echo "  2. Test ping:        sudo ip netns exec $NS_NAME ping -c 3 10.200.1.1"
        echo "  3. Add drop rule:    sudo ./build/aegis-fw rule add blacklist $PEER_RAW_IP/32"
        echo "  4. Test ping again:  sudo ip netns exec $NS_NAME ping -c 3 10.200.1.1 (should be DROPPED)"
        echo "  5. Cleanup when done: sudo bash scripts/test_traffic.sh cleanup"
        ;;

    cleanup)
        echo "[*] Cleaning up virtual network and namespace..."
        ip link del "$VETH_HOST" 2>/dev/null || true
        ip netns del "$NS_NAME" 2>/dev/null || true
        echo "[✓] Cleaned up."
        ;;

    *)
        echo "Usage: sudo bash scripts/test_traffic.sh [setup|cleanup]"
        exit 1
        ;;
esac
