#!/usr/bin/env sh
set -eu

WG_INTERFACE="${WG_INTERFACE:-wg0}"
WG_CONFIG="${WG_CONFIG:-/etc/wireguard/wg0.conf}"
ENABLE_IP_FORWARD="${ENABLE_IP_FORWARD:-1}"
ENABLE_NAT="${ENABLE_NAT:-1}"
NAT_CIDR="${NAT_CIDR:-10.70.0.0/24}"
NAT_OUT_IF="${NAT_OUT_IF:-}"

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

detect_out_if() {
  if [ -n "$NAT_OUT_IF" ]; then
    echo "$NAT_OUT_IF"
    return 0
  fi
  ip route show default 0.0.0.0/0 2>/dev/null | awk 'NR==1{print $5; exit}'
}

iptables_add_once() {
  # $1: table (optional), rest: rule
  if [ "$1" = "-t" ]; then
    table="$2"
    shift 2
    if iptables -t "$table" -C "$@" >/dev/null 2>&1; then
      return 0
    fi
    iptables -t "$table" -A "$@" >/dev/null 2>&1 || echo "WARN: cannot add iptables -t $table rule: $*" >&2
    return 0
  fi
  if iptables -C "$@" >/dev/null 2>&1; then
    return 0
  fi
  iptables -A "$@" >/dev/null 2>&1 || echo "WARN: cannot add iptables rule: $*" >&2
}

iptables_del_if_exists() {
  if [ "$1" = "-t" ]; then
    table="$2"
    shift 2
    iptables -t "$table" -C "$@" >/dev/null 2>&1 || return 0
    iptables -t "$table" -D "$@" >/dev/null 2>&1 || true
    return 0
  fi
  iptables -C "$@" >/dev/null 2>&1 || return 0
  iptables -D "$@" >/dev/null 2>&1 || true
}

if [ "$ENABLE_NAT" = "1" ]; then
  OUT_IF="$(detect_out_if || true)"
  if [ -n "$OUT_IF" ]; then
    # Forward traffic between WireGuard and the public interface.
    iptables_add_once FORWARD -i "$WG_INTERFACE" -j ACCEPT
    iptables_add_once FORWARD -o "$WG_INTERFACE" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    # Masquerade WireGuard subnet to the internet.
    iptables_add_once -t nat POSTROUTING -s "$NAT_CIDR" -o "$OUT_IF" -j MASQUERADE
  else
    echo "WARN: cannot detect default route interface; NAT not installed" >&2
  fi
fi

cleanup() {
  if [ "$ENABLE_NAT" = "1" ]; then
    OUT_IF="$(detect_out_if || true)"
    if [ -n "$OUT_IF" ]; then
      iptables_del_if_exists FORWARD -i "$WG_INTERFACE" -j ACCEPT
      iptables_del_if_exists FORWARD -o "$WG_INTERFACE" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
      iptables_del_if_exists -t nat POSTROUTING -s "$NAT_CIDR" -o "$OUT_IF" -j MASQUERADE
    fi
  fi
  wg-quick down "$WG_CONFIG" >/dev/null 2>&1 || true
}

trap cleanup INT TERM

tail -f /dev/null &
wait $!
