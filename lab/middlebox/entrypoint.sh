#!/bin/sh
set -e

CLIENT_IFACE=${CLIENT_IFACE:-eth0}
SERVER_IFACE=${SERVER_IFACE:-eth1}
LOG_DIR=${LOG_DIR:-/logs}

mkdir -p "$LOG_DIR/zeek" "$LOG_DIR/pcap"

echo "[middlebox] Enabling IP forwarding..."

# Allow all forwarding between the two lab interfaces
iptables -P FORWARD ACCEPT
iptables -F FORWARD

CLIENT_NET=$(ip -o -f inet addr show "$CLIENT_IFACE" | awk '{print $4}')
SERVER_NET=$(ip -o -f inet addr show "$SERVER_IFACE" | awk '{print $4}')
echo "[middlebox] $CLIENT_IFACE ($CLIENT_NET) <--> $SERVER_IFACE ($SERVER_NET)"

# ── tcpdump: rotate every 5 min, keep raw pcaps ───────────────────────────────
tcpdump -i "$CLIENT_IFACE" -s 0 \
    -w "$LOG_DIR/pcap/frontend_%Y%m%d_%H%M%S.pcap" \
    -G 300 -Z root \
    2>>"$LOG_DIR/tcpdump-frontend.log" &

tcpdump -i "$SERVER_IFACE" -s 0 \
    -w "$LOG_DIR/pcap/backend_%Y%m%d_%H%M%S.pcap" \
    -G 300 -Z root \
    2>>"$LOG_DIR/tcpdump-backend.log" &

echo "[middlebox] tcpdump started on both interfaces"

# ── Zeek: live analysis on the client-facing interface ────────────────────────
# Zeek on eth0 sees both directions of every forwarded flow:
#   client→server packets arrive on eth0
#   server→client reply packets leave on eth0
cd "$LOG_DIR/zeek" && \
    /opt/zeek/bin/zeek -i "$CLIENT_IFACE" \
        /opt/zeek/share/zeek/site/local.zeek \
        /opt/zeek/share/zeek/site/detect-yaler.zeek \
        2>>"$LOG_DIR/zeek.log" &

echo "[middlebox] Zeek started"
echo "[middlebox] Logs → $LOG_DIR"
echo ""
echo "  Live Zeek logs:    $LOG_DIR/zeek/"
echo "  Raw pcap files:    $LOG_DIR/pcap/"
echo "  JA3 analysis:      docker exec middlebox /analyze.sh"

wait
