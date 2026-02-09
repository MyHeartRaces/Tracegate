#!/usr/bin/env bash
set -euo pipefail

RELEASE=${1:-tracegate}
NAMESPACE=${2:-tracegate}
VALUES_FILE=${3:-}

if ! command -v helm >/dev/null 2>&1; then
  echo "helm is required" >&2
  exit 1
fi
if ! command -v kubectl >/dev/null 2>&1; then
  echo "kubectl is required" >&2
  exit 1
fi

CHART_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../k3s/tracegate" && pwd)"

if [[ -n "$VALUES_FILE" ]]; then
  helm upgrade --install "$RELEASE" "$CHART_DIR" \
    --namespace "$NAMESPACE" \
    --create-namespace \
    -f "$VALUES_FILE"
else
  helm upgrade --install "$RELEASE" "$CHART_DIR" \
    --namespace "$NAMESPACE" \
    --create-namespace
fi

kubectl -n "$NAMESPACE" get pods
