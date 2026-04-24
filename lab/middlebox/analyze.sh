#!/bin/bash
# Post-capture JA3 / protocol analysis using tshark.
# Run inside the middlebox container:
#   docker exec -it middlebox /analyze.sh [pcap-file]

PCAP_DIR="/logs/pcap"
PCAP=${1:-$(ls -t "$PCAP_DIR"/frontend_*.pcap 2>/dev/null | head -1)}

if [[ -z "$PCAP" ]]; then
    echo "Usage: $0 [pcap-file]"
    echo "No pcap files found in $PCAP_DIR"
    exit 1
fi

echo "════════════════════════════════════════════════"
echo "  Analyzing: $PCAP"
echo "════════════════════════════════════════════════"
echo ""

# ── JA3 fingerprints from TLS ClientHello ─────────────────────────────────────
echo "── TLS Client Fingerprints (JA3) ──────────────"
echo "time_rel | src | dst:port | ja3 | sni"
tshark -r "$PCAP" \
    -Y "tls.handshake.type == 1" \
    -T fields \
    -e frame.time_relative \
    -e ip.src \
    -e ip.dst \
    -e tcp.dstport \
    -e tls.handshake.ja3 \
    -e tls.handshake.extensions_server_name \
    -E separator='|' \
    -E quote=d \
    2>/dev/null || true
echo ""

# ── WebSocket upgrade requests ─────────────────────────────────────────────────
echo "── WebSocket Upgrades ──────────────────────────"
echo "time_rel | src | dst | uri | user-agent"
tshark -r "$PCAP" \
    -Y 'http.connection contains "Upgrade" or http.upgrade' \
    -T fields \
    -e frame.time_relative \
    -e ip.src \
    -e ip.dst \
    -e http.request.uri \
    -e http.user_agent \
    -E separator='|' \
    2>/dev/null || true
echo ""

# ── TCP flow summary sorted by total bytes ────────────────────────────────────
echo "── Top TCP Flows by Bytes ──────────────────────"
tshark -r "$PCAP" -q -z "conv,tcp" 2>/dev/null \
    | awk 'NR>5 && /[0-9]/' \
    | sort -k3 -rn \
    | head -20 || true
echo ""

# ── TLS connections to port 443 grouped by JA3 ────────────────────────────────
echo "── JA3 Hit Count (port 443) ────────────────────"
echo "count | src | ja3"
tshark -r "$PCAP" \
    -Y "tcp.dstport == 443 and tls.handshake.type == 1" \
    -T fields \
    -e ip.src \
    -e tls.handshake.ja3 \
    -E separator='|' \
    2>/dev/null \
    | sort | uniq -c | sort -rn | head -20 || true
echo ""

# ── Connection duration for port 443 ──────────────────────────────────────────
echo "── Long-Lived TLS Connections (>10s) ───────────"
tshark -r "$PCAP" -q -z "conv,tcp" 2>/dev/null \
    | awk 'NR>5 && /\.443 / {
        split($0, f, " ")
        # Rough filter: last field > 10 means >10s
        # tshark conv output: <-> columns include duration
        print $0
    }' \
    | head -20 || true
