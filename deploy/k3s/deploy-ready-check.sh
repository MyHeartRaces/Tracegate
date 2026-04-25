#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"

CHART_DIR="${TRACEGATE_K3S_CHART_DIR:-${REPO_ROOT}/deploy/k3s/tracegate}"
PROD_VALUES="${TRACEGATE_K3S_PROD_VALUES:-${REPO_ROOT}/deploy/k3s/values-prod.example.yaml}"
NAMESPACE="${TRACEGATE_NAMESPACE:-tracegate}"
OUT_DIR="${TRACEGATE_DEPLOY_READY_OUT:-${TMPDIR:-/tmp}/tracegate-deploy-ready}"
STRICT_PROD="${TRACEGATE_STRICT_PROD:-0}"
CLUSTER_PREFLIGHT="${TRACEGATE_CLUSTER_PREFLIGHT:-0}"
SERVER_DRY_RUN="${TRACEGATE_KUBE_SERVER_DRY_RUN:-0}"
KUBECTL="${TRACEGATE_KUBECTL:-kubectl}"
KUBE_CONTEXT="${TRACEGATE_KUBE_CONTEXT:-}"

require_cmd() {
  local name="$1"
  if ! command -v "${name}" >/dev/null 2>&1; then
    echo "missing required command: ${name}" >&2
    exit 127
  fi
}

run() {
  echo "+ $*"
  "$@"
}

require_cmd python3
require_cmd helm
require_cmd git
if [ "${CLUSTER_PREFLIGHT}" = "1" ] || [ "${CLUSTER_PREFLIGHT}" = "true" ] || [ "${SERVER_DRY_RUN}" = "1" ] || [ "${SERVER_DRY_RUN}" = "true" ]; then
  require_cmd "${KUBECTL}"
fi

mkdir -p "${OUT_DIR}"
cd "${REPO_ROOT}"

run python3 -m ruff check .
run pytest -q
run helm lint "${CHART_DIR}"
if [ "${STRICT_PROD}" = "1" ] || [ "${STRICT_PROD}" = "true" ]; then
  run python3 deploy/k3s/prod-overlay-check.py --strict --chart-values "${CHART_DIR}/values.yaml" --values "${PROD_VALUES}" --expected-namespace "${NAMESPACE}"
fi
if [ "${CLUSTER_PREFLIGHT}" = "1" ] || [ "${CLUSTER_PREFLIGHT}" = "true" ]; then
  cluster_preflight_args=(
    python3 deploy/k3s/cluster-preflight-check.py
    --chart-values "${CHART_DIR}/values.yaml"
    --values "${PROD_VALUES}"
    --namespace "${NAMESPACE}"
    --kubectl "${KUBECTL}"
  )
  if [ -n "${KUBE_CONTEXT}" ]; then
    cluster_preflight_args+=(--context "${KUBE_CONTEXT}")
  fi
  run "${cluster_preflight_args[@]}"
fi
run sh -c "helm template tracegate '${CHART_DIR}' --namespace '${NAMESPACE}' > '${OUT_DIR}/tracegate-helm-default.yaml'"
run sh -c "helm template tracegate '${CHART_DIR}' --namespace '${NAMESPACE}' -f '${PROD_VALUES}' > '${OUT_DIR}/tracegate-helm-prod-example.yaml'"
if [ "${SERVER_DRY_RUN}" = "1" ] || [ "${SERVER_DRY_RUN}" = "true" ]; then
  kubectl_apply_args=("${KUBECTL}")
  if [ -n "${KUBE_CONTEXT}" ]; then
    kubectl_apply_args+=(--context "${KUBE_CONTEXT}")
  fi
  kubectl_apply_args+=(apply --dry-run=server -f "${OUT_DIR}/tracegate-helm-prod-example.yaml")
  run "${kubectl_apply_args[@]}"
fi
run git diff --check
run sh -c "python3 -m alembic heads | tee '${OUT_DIR}/alembic-heads.txt'"

echo "deploy-ready checks passed"
echo "rendered manifests: ${OUT_DIR}"
