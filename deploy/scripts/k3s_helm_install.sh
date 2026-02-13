#!/usr/bin/env bash
set -euo pipefail

RELEASE=${1:-tracegate}
NAMESPACE=${2:-tracegate}
shift 2 || true
VALUES_FILES=("$@")

if ! command -v helm >/dev/null 2>&1; then
  echo "helm is required" >&2
  exit 1
fi
if ! command -v kubectl >/dev/null 2>&1; then
  echo "kubectl is required" >&2
  exit 1
fi

CHART_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../k3s/tracegate" && pwd)"

HELM_ARGS=(
  upgrade
  --install
  "$RELEASE"
  "$CHART_DIR"
  --namespace
  "$NAMESPACE"
  --create-namespace
)

for f in "${VALUES_FILES[@]:-}"; do
  if [[ -n "$f" ]]; then
    HELM_ARGS+=(-f "$f")
  fi
done

helm "${HELM_ARGS[@]}"

kubectl -n "$NAMESPACE" get pods
