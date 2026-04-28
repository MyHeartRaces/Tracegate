#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"

CHART_DIR="${TRACEGATE_K3S_CHART_DIR:-${REPO_ROOT}/deploy/k3s/tracegate}"
PROD_VALUES="${TRACEGATE_K3S_PROD_VALUES:-}"
RELEASE="${TRACEGATE_HELM_RELEASE:-tracegate}"
NAMESPACE="${TRACEGATE_NAMESPACE:-tracegate}"
TIMEOUT="${TRACEGATE_HELM_TIMEOUT:-15m}"
HISTORY_MAX="${TRACEGATE_HELM_HISTORY_MAX:-10}"
KUBECTL="${TRACEGATE_KUBECTL:-kubectl}"
KUBE_CONTEXT="${TRACEGATE_KUBE_CONTEXT:-}"
SKIP_PREFLIGHT="${TRACEGATE_SKIP_PREFLIGHT:-0}"
HELM_DRY_RUN="${TRACEGATE_HELM_DRY_RUN:-0}"
POST_DEPLOY_CHECKS="${TRACEGATE_POST_DEPLOY_CHECKS:-1}"
ROLLOUT_TIMEOUT="${TRACEGATE_ROLLOUT_TIMEOUT:-10m}"

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

if [ -z "${PROD_VALUES}" ]; then
  echo "TRACEGATE_K3S_PROD_VALUES must point at an ignored private production values file" >&2
  exit 2
fi

case "$(basename -- "${PROD_VALUES}")" in
  values-prod.example.yaml)
    echo "refusing to deploy values-prod.example.yaml; use an ignored private production values file" >&2
    exit 2
    ;;
esac

require_cmd helm
require_cmd python3
require_cmd "${KUBECTL}"

cd "${REPO_ROOT}"

if [ "${SKIP_PREFLIGHT}" != "1" ] && [ "${SKIP_PREFLIGHT}" != "true" ]; then
  (
    export TRACEGATE_STRICT_PROD=1
    export TRACEGATE_CLUSTER_PREFLIGHT=1
    export TRACEGATE_KUBE_SERVER_DRY_RUN=1
    export TRACEGATE_K3S_PROD_VALUES="${PROD_VALUES}"
    export TRACEGATE_K3S_CHART_DIR="${CHART_DIR}"
    export TRACEGATE_NAMESPACE="${NAMESPACE}"
    export TRACEGATE_KUBECTL="${KUBECTL}"
    export TRACEGATE_KUBE_CONTEXT="${KUBE_CONTEXT}"
    run "${SCRIPT_DIR}/deploy-ready-check.sh"
  )
fi

helm_args=(
  helm upgrade --install "${RELEASE}" "${CHART_DIR}"
  --namespace "${NAMESPACE}"
  --create-namespace
  -f "${PROD_VALUES}"
  --atomic
  --wait
  --timeout "${TIMEOUT}"
  --history-max "${HISTORY_MAX}"
)

if [ -n "${KUBE_CONTEXT}" ]; then
  helm_args+=(--kube-context "${KUBE_CONTEXT}")
fi

if [ "${HELM_DRY_RUN}" = "1" ] || [ "${HELM_DRY_RUN}" = "true" ]; then
  helm_args+=(--dry-run)
fi

run "${helm_args[@]}"

if [ "${HELM_DRY_RUN}" != "1" ] && [ "${HELM_DRY_RUN}" != "true" ] && [ "${POST_DEPLOY_CHECKS}" != "0" ] && [ "${POST_DEPLOY_CHECKS}" != "false" ]; then
  tracegate_selector="app.kubernetes.io/instance=${RELEASE},app.kubernetes.io/part-of=tracegate"
  kubectl_args=("${KUBECTL}")
  if [ -n "${KUBE_CONTEXT}" ]; then
    kubectl_args+=(--context "${KUBE_CONTEXT}")
  fi
  run "${kubectl_args[@]}" rollout status deployment -n "${NAMESPACE}" -l "${tracegate_selector}" --timeout="${ROLLOUT_TIMEOUT}"
  run "${kubectl_args[@]}" wait pod -n "${NAMESPACE}" -l "${tracegate_selector}" --for=condition=Ready --timeout="${ROLLOUT_TIMEOUT}"
  run "${kubectl_args[@]}" get pdb -n "${NAMESPACE}" -l "${tracegate_selector}"
fi
