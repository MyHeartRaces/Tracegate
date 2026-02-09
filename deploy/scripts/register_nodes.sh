#!/usr/bin/env bash
set -euo pipefail

API_URL=${1:-}
API_TOKEN=${2:-}
VPS_T_AGENT_BASE_URL=${3:-}
VPS_T_PUBLIC_IPV4=${4:-}
VPS_E_AGENT_BASE_URL=${5:-}
VPS_E_PUBLIC_IPV4=${6:-}

if [[ -z "$API_URL" || -z "$API_TOKEN" || -z "$VPS_T_AGENT_BASE_URL" || -z "$VPS_T_PUBLIC_IPV4" ]]; then
  echo "Usage: $0 <api-url> <api-token> <vps-t-agent-base-url> <vps-t-ip> [<vps-e-agent-base-url> <vps-e-ip>]" >&2
  exit 1
fi

api_post() {
  local payload="$1"
  curl -fsS -X POST "$API_URL/nodes" \
    -H "x-api-token: $API_TOKEN" \
    -H "Content-Type: application/json" \
    -d "$payload"
}

api_post "{\"role\":\"VPS_T\",\"name\":\"vps-t\",\"base_url\":\"$VPS_T_AGENT_BASE_URL\",\"public_ipv4\":\"$VPS_T_PUBLIC_IPV4\",\"active\":true}" || true

if [[ -n "$VPS_E_AGENT_BASE_URL" && -n "$VPS_E_PUBLIC_IPV4" ]]; then
  api_post "{\"role\":\"VPS_E\",\"name\":\"vps-e\",\"base_url\":\"$VPS_E_AGENT_BASE_URL\",\"public_ipv4\":\"$VPS_E_PUBLIC_IPV4\",\"active\":true}" || true
fi

echo "Done."
