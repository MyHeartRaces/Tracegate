#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INSTALL_DIR="${INSTALL_DIR:-/opt/tracegate}"
CONFIG_DIR="${CONFIG_DIR:-/etc/tracegate}"
TRACEGATE_ENV_FILE="${TRACEGATE_ENV_FILE:-${CONFIG_DIR}/tracegate.env}"
PYTHON_BIN="${PYTHON_BIN:-python3}"

load_env_file() {
  local file="$1"
  [[ -f "${file}" ]] || return 0

  eval "$("${PYTHON_BIN}" - "${file}" <<'PY'
from pathlib import Path
import re
import shlex
import sys

path = Path(sys.argv[1])
for raw_line in path.read_text(encoding="utf-8").splitlines():
    line = raw_line.strip()
    if not line or line.startswith("#") or "=" not in line:
        continue
    name, value = line.split("=", 1)
    name = name.strip()
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
        continue
    value = value.strip()
    if len(value) >= 2 and value[:1] == value[-1:] and value[:1] in {"'", '"'}:
        value = value[1:-1]
    print(f"export {name}={shlex.quote(value)}")
PY
)"
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

is_true() {
  local raw="${1:-}"
  raw="$(printf '%s' "${raw}" | tr '[:upper:]' '[:lower:]')"
  case "${raw}" in
    1|true|yes|on) return 0 ;;
    *) return 1 ;;
  esac
}

ensure_host_prereqs() {
  if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y --no-install-recommends ca-certificates curl rsync python3 python3-venv
    rm -rf /var/lib/apt/lists/*
  fi

  need_cmd curl
  need_cmd rsync
  need_cmd python3
}

wait_for_http_ok() {
  local url="$1"
  local attempts="${2:-30}"
  local delay="${3:-1}"

  for _ in $(seq 1 "${attempts}"); do
    if curl -fsS "${url}" >/dev/null 2>&1; then
      return 0
    fi
    sleep "${delay}"
  done

  echo "timed out waiting for HTTP endpoint: ${url}" >&2
  exit 1
}

wait_for_file() {
  local path="$1"
  local attempts="${2:-30}"
  local delay="${3:-1}"

  for _ in $(seq 1 "${attempts}"); do
    if [[ -s "${path}" ]]; then
      return 0
    fi
    sleep "${delay}"
  done

  echo "timed out waiting for file: ${path}" >&2
  exit 1
}

resolve_api_url() {
  if [[ -n "${TRACEGATE_REPLACE_API_URL:-}" ]]; then
    printf '%s\n' "${TRACEGATE_REPLACE_API_URL}"
    return 0
  fi

  local api_port="${API_PORT:-18080}"
  printf 'http://127.0.0.1:%s\n' "${api_port}"
}

enable_transit_runtime_units() {
  local -a units=(
    tracegate-agent-transit
    tracegate-haproxy@transit
    tracegate-nginx@transit
    tracegate-xray@transit
  )
  local private_unit=""

  for private_unit in tracegate-obfuscation@transit tracegate-fronting@transit tracegate-mtproto@transit; do
    if [[ -f "/etc/systemd/system/${private_unit%@transit}@.service" ]]; then
      units+=("${private_unit}")
    fi
  done

  systemctl enable --now "${units[@]}"
}

dispatch_post() {
  local path="$1"
  local payload="$2"
  curl -fsS \
    -H "x-api-token: ${TRACEGATE_REPLACE_API_TOKEN}" \
    -H "Content-Type: application/json" \
    -X POST \
    "${TRACEGATE_REPLACE_API_URL%/}${path}" \
    -d "${payload}" >/dev/null
}

if [[ "${EUID}" -ne 0 ]]; then
  echo "run as root" >&2
  exit 1
fi

if [[ ! -f "${TRACEGATE_ENV_FILE}" ]]; then
  echo "missing transit env file: ${TRACEGATE_ENV_FILE}" >&2
  exit 1
fi

ensure_host_prereqs
load_env_file "${TRACEGATE_ENV_FILE}"

TRACEGATE_INSTALL_ROLE="${TRACEGATE_INSTALL_ROLE:-transit}"
TRACEGATE_SINGLE_ENV_ONLY="${TRACEGATE_SINGLE_ENV_ONLY:-true}"
INSTALL_COMPONENTS="${INSTALL_COMPONENTS:-xray}"
INSTALL_PROXY_STACK="${INSTALL_PROXY_STACK:-true}"
PREFLIGHT_MODE="${PREFLIGHT_MODE:-transit}"
TRACEGATE_REPLACE_RENDER_MATERIALIZED="${TRACEGATE_REPLACE_RENDER_MATERIALIZED:-true}"
TRACEGATE_REPLACE_RENDER_PRIVATE_OVERLAYS="${TRACEGATE_REPLACE_RENDER_PRIVATE_OVERLAYS:-false}"
TRACEGATE_REPLACE_VALIDATE_RUNTIME="${TRACEGATE_REPLACE_VALIDATE_RUNTIME:-true}"
TRACEGATE_REPLACE_ENABLE_RUNTIME="${TRACEGATE_REPLACE_ENABLE_RUNTIME:-true}"
TRACEGATE_REPLACE_API_TOKEN="${TRACEGATE_REPLACE_API_TOKEN:-${API_INTERNAL_TOKEN:-}}"
TRACEGATE_REPLACE_REAPPLY_BASE="${TRACEGATE_REPLACE_REAPPLY_BASE:-true}"
TRACEGATE_REPLACE_REISSUE_CURRENT_REVISIONS="${TRACEGATE_REPLACE_REISSUE_CURRENT_REVISIONS:-true}"
TRACEGATE_REPLACE_RUNTIME_CONTRACT="${TRACEGATE_REPLACE_RUNTIME_CONTRACT:-${AGENT_DATA_ROOT:-/var/lib/tracegate/agent-transit}/runtime/runtime-contract.json}"
TRACEGATE_REPLACE_API_URL="$(resolve_api_url)"

TRACEGATE_INSTALL_ROLE="${TRACEGATE_INSTALL_ROLE}" \
TRACEGATE_SINGLE_ENV_ONLY="${TRACEGATE_SINGLE_ENV_ONLY}" \
PYTHON_BIN="${PYTHON_BIN}" \
  "${ROOT_DIR}/deploy/systemd/install.sh"

TRACEGATE_ENV_FILE="${TRACEGATE_ENV_FILE}" \
INSTALL_COMPONENTS="${INSTALL_COMPONENTS}" \
INSTALL_PROXY_STACK="${INSTALL_PROXY_STACK}" \
  "${INSTALL_DIR}/deploy/systemd/install-runtime.sh"

if is_true "${TRACEGATE_REPLACE_RENDER_MATERIALIZED}"; then
  "${INSTALL_DIR}/deploy/systemd/render-materialized-bundles.sh"
fi

if is_true "${TRACEGATE_REPLACE_RENDER_PRIVATE_OVERLAYS}"; then
  "${INSTALL_DIR}/deploy/systemd/render-xray-centric-overlays.sh"
fi

if is_true "${TRACEGATE_REPLACE_ENABLE_RUNTIME}"; then
  enable_transit_runtime_units
fi

if is_true "${TRACEGATE_REPLACE_REAPPLY_BASE}" || is_true "${TRACEGATE_REPLACE_REISSUE_CURRENT_REVISIONS}"; then
  if [[ -z "${TRACEGATE_REPLACE_API_TOKEN}" ]]; then
    echo "TRACEGATE_REPLACE_API_TOKEN or API_INTERNAL_TOKEN is required for dispatch operations" >&2
    exit 1
  fi

  wait_for_http_ok "${TRACEGATE_REPLACE_API_URL%/}/health" 60 1
fi

if is_true "${TRACEGATE_REPLACE_REAPPLY_BASE}"; then
  dispatch_post "/dispatch/reapply-base" '{"role":"TRANSIT"}'
fi

if is_true "${TRACEGATE_REPLACE_VALIDATE_RUNTIME}"; then
  wait_for_file "${TRACEGATE_REPLACE_RUNTIME_CONTRACT}" 60 1
  PREFLIGHT_MODE="${PREFLIGHT_MODE}" "${INSTALL_DIR}/deploy/systemd/validate-runtime-contracts.sh"
fi

if is_true "${TRACEGATE_REPLACE_REISSUE_CURRENT_REVISIONS}"; then
  dispatch_post "/dispatch/reissue-current-revisions" '{}'
fi

cat <<EOF
Tracegate Transit node replacement completed.

- env_file=${TRACEGATE_ENV_FILE}
- install_components=${INSTALL_COMPONENTS}
- render_materialized=${TRACEGATE_REPLACE_RENDER_MATERIALIZED}
- render_private_overlays=${TRACEGATE_REPLACE_RENDER_PRIVATE_OVERLAYS}
- validate_runtime=${TRACEGATE_REPLACE_VALIDATE_RUNTIME}
- enable_runtime=${TRACEGATE_REPLACE_ENABLE_RUNTIME}
- reapply_base=${TRACEGATE_REPLACE_REAPPLY_BASE}
- reissue_current_revisions=${TRACEGATE_REPLACE_REISSUE_CURRENT_REVISIONS}
EOF
