#!/usr/bin/env bash
set -euo pipefail

API_URL=${1:-}
API_TOKEN=${2:-}

if [[ -z "$API_URL" || -z "$API_TOKEN" ]]; then
  echo "Usage: $0 <api-url> <api-token>" >&2
  exit 1
fi

curl -fsS -X POST "$API_URL/dispatch/reapply-base" \
  -H "x-api-token: $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}'

echo

curl -fsS -X POST "$API_URL/dispatch/reissue-current-revisions" \
  -H "x-api-token: $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}'

echo

echo "Reapply and reissue started."
