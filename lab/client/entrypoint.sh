#!/bin/sh
# Add route so yaler-client reaches the backend network via middlebox.
# All yaler TLS/WS traffic will pass through 10.1.0.2 (middlebox) — captured by Zeek.
ip route add 10.2.0.0/24 via 10.1.0.2 2>/dev/null || true
exec "$@"
