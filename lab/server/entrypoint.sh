#!/bin/sh
# Add route so yaler-server can reach clients through middlebox.
# Return-path traffic (server → client) also passes through middlebox.
ip route add 10.1.0.0/24 via 10.2.0.2 2>/dev/null || true
exec "$@"
