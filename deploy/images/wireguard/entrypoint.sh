#!/usr/bin/env sh
set -eu

WG_INTERFACE="${WG_INTERFACE:-wg0}"
WG_CONFIG="${WG_CONFIG:-/etc/wireguard/wg0.conf}"
ENABLE_IP_FORWARD="${ENABLE_IP_FORWARD:-1}"

if [ ! -f "$WG_CONFIG" ]; then
  echo "WireGuard config not found: $WG_CONFIG" >&2
  exit 1
fi

if [ "$ENABLE_IP_FORWARD" = "1" ]; then
  sysctl -w net.ipv4.ip_forward=1 >/dev/null || true
fi

if ! ip link show "$WG_INTERFACE" >/dev/null 2>&1; then
  wg-quick up "$WG_CONFIG"
fi

cleanup() {
  wg-quick down "$WG_CONFIG" >/dev/null 2>&1 || true
}

trap cleanup INT TERM

tail -f /dev/null &
wait $!
