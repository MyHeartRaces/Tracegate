#!/usr/bin/env bash
set -euo pipefail

VPS_T_NODE=${1:-}
VPS_E_NODE=${2:-}

if [[ -z "$VPS_T_NODE" || -z "$VPS_E_NODE" ]]; then
  echo "Usage: $0 <vps-t-node-name> <vps-e-node-name>" >&2
  exit 1
fi

kubectl label node "$VPS_T_NODE" tracegate.role=vps-t --overwrite
kubectl label node "$VPS_E_NODE" tracegate.role=vps-e --overwrite

echo "Node labels updated."
