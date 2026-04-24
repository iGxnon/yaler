#!/bin/sh
# Scenario B — Tunnel traffic through yaler
#
# From the middlebox's perspective:
#   src: 10.1.0.10 (yaler-client, BoringSSL Chrome JA3)
#   dst: 10.2.0.10:443 (yaler-server)
#   protocol: TLS → WebSocket upgrade to /sw → binary relay frames
#
# The inner HTTP request to 10.2.0.11:80 is opaque to the middlebox (inside the tunnel).

N=${1:-5}
PROXY="socks5h://10.1.0.10:1080"   # yaler-client SOCKS5 listener
TARGET="http://10.2.0.11"          # inner destination (plain HTTP is fine)

echo "=== Tunnel traffic (Chrome JA3, WebSocket, long-lived) ==="
i=0
while [ $i -lt "$N" ]; do
    i=$((i+1))
    result=$(curl -s --proxy "$PROXY" "$TARGET/" \
        -o /dev/null \
        -w "%{http_code} time=%{time_total}s bytes=%{size_download}" \
        2>&1)
    echo "[$i/$N] SOCKS5→$TARGET → $result"
    sleep 1
done

echo ""
echo "=== Sustained tunnel (keeps connection alive for Zeek long-conn detection) ==="
echo "Downloading 1 MB through tunnel (5 iterations)..."
i=0
while [ $i -lt 5 ]; do
    i=$((i+1))
    curl -s --proxy "$PROXY" "$TARGET/" \
        -o /dev/null \
        -w "[$i/5] bytes=%{size_download} time=%{time_total}s\n" &
done
wait
