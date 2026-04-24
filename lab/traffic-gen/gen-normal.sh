#!/bin/sh
# Scenario A — Normal traffic (non-tunnel)
#
# From the middlebox's perspective:
#   src: 10.1.0.11 (traffic-gen, curl's TLS)
#   dst: 10.2.0.10:443 (yaler-server HTTPS)
#
# The server returns an nginx-like page for non-WS requests (active-probe defense).
# Middlebox will see: curl JA3, short-lived TLS, no WebSocket upgrade.

N=${1:-5}
TARGET_HTTPS="https://10.2.0.10"   # yaler-server's TLS endpoint
TARGET_HTTP="http://10.2.0.11"     # plain nginx target

echo "=== Normal HTTPS (curl JA3, no WebSocket) ==="
i=0
while [ $i -lt "$N" ]; do
    i=$((i+1))
    result=$(curl -sk "$TARGET_HTTPS/" \
        -o /dev/null \
        -w "%{http_code} time=%{time_total}s bytes=%{size_download}" \
        2>&1)
    echo "[$i/$N] HTTPS $TARGET_HTTPS → $result"
    sleep 1
done

echo ""
echo "=== Normal HTTP to target (plaintext, no TLS) ==="
i=0
while [ $i -lt "$N" ]; do
    i=$((i+1))
    result=$(curl -s "$TARGET_HTTP/" \
        -o /dev/null \
        -w "%{http_code} time=%{time_total}s bytes=%{size_download}" \
        2>&1)
    echo "[$i/$N] HTTP $TARGET_HTTP → $result"
    sleep 1
done
