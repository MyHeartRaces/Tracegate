#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-/opt/tracegate}"
CONFIG_DIR="${CONFIG_DIR:-/etc/tracegate}"
PYTHON_BIN="${PYTHON_BIN:-${INSTALL_DIR}/.venv/bin/python}"
ENTRY_RUNTIME_CONTRACT="${ENTRY_RUNTIME_CONTRACT:-/var/lib/tracegate/agent-entry/runtime/runtime-contract.json}"
TRANSIT_RUNTIME_CONTRACT="${TRANSIT_RUNTIME_CONTRACT:-/var/lib/tracegate/agent-transit/runtime/runtime-contract.json}"
ZAPRET_PROFILE_ROOT="${ZAPRET_PROFILE_ROOT:-/etc/tracegate/private/zapret}"
PREFLIGHT_MODE="${PREFLIGHT_MODE:-auto}" # auto | pair | entry | transit

if [[ ! -x "${PYTHON_BIN}" ]]; then
  echo "python runtime not found: ${PYTHON_BIN}" >&2
  exit 1
fi

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

if [[ -f "${CONFIG_DIR}/tracegate.env" || -f "${CONFIG_DIR}/entry.env" || -f "${CONFIG_DIR}/transit.env" ]]; then
  load_env_file "${CONFIG_DIR}/tracegate.env"
  load_env_file "${CONFIG_DIR}/entry.env"
  load_env_file "${CONFIG_DIR}/transit.env"
fi

derive_private_runtime_root() {
  local contract_path="${1:-}"
  local runtime_dir=""
  local agent_dir=""
  local agent_name=""

  [[ -n "${contract_path}" ]] || return 1
  runtime_dir="$(dirname "${contract_path}")"
  agent_dir="$(dirname "${runtime_dir}")"
  agent_name="$(basename "${agent_dir}")"

  if [[ "${agent_name}" == agent-* ]]; then
    printf '%s/private\n' "$(dirname "${agent_dir}")"
    return 0
  fi
  return 1
}

PRIVATE_RUNTIME_ROOT="${PRIVATE_RUNTIME_ROOT:-}"
if [[ -z "${PRIVATE_RUNTIME_ROOT}" ]]; then
  PRIVATE_RUNTIME_ROOT="$(derive_private_runtime_root "${ENTRY_RUNTIME_CONTRACT}" || true)"
fi
if [[ -z "${PRIVATE_RUNTIME_ROOT}" ]]; then
  PRIVATE_RUNTIME_ROOT="$(derive_private_runtime_root "${TRANSIT_RUNTIME_CONTRACT}" || true)"
fi
PRIVATE_RUNTIME_ROOT="${PRIVATE_RUNTIME_ROOT:-/var/lib/tracegate/private}"

OBFUSCATION_STATE_ROOT="${OBFUSCATION_STATE_ROOT:-${PRIVATE_RUNTIME_ROOT}/obfuscation}"
OBFUSCATION_ENV="${OBFUSCATION_ENV:-/etc/tracegate/private/systemd/obfuscation.env}"
OBFUSCATION_UNIT="${OBFUSCATION_UNIT:-/etc/systemd/system/tracegate-obfuscation@.service}"
ENTRY_RUNTIME_STATE="${ENTRY_RUNTIME_STATE:-${OBFUSCATION_STATE_ROOT}/entry/runtime-state.json}"
TRANSIT_RUNTIME_STATE="${TRANSIT_RUNTIME_STATE:-${OBFUSCATION_STATE_ROOT}/transit/runtime-state.json}"
ENTRY_RUNTIME_ENV="${ENTRY_RUNTIME_ENV:-${OBFUSCATION_STATE_ROOT}/entry/runtime-state.env}"
TRANSIT_RUNTIME_ENV="${TRANSIT_RUNTIME_ENV:-${OBFUSCATION_STATE_ROOT}/transit/runtime-state.env}"
PROFILE_STATE_ROOT="${PROFILE_STATE_ROOT:-${PRIVATE_RUNTIME_ROOT}/profiles}"
ENTRY_PROFILE_STATE="${ENTRY_PROFILE_STATE:-${PROFILE_STATE_ROOT}/entry/desired-state.json}"
TRANSIT_PROFILE_STATE="${TRANSIT_PROFILE_STATE:-${PROFILE_STATE_ROOT}/transit/desired-state.json}"
ENTRY_PROFILE_ENV="${ENTRY_PROFILE_ENV:-${PROFILE_STATE_ROOT}/entry/desired-state.env}"
TRANSIT_PROFILE_ENV="${TRANSIT_PROFILE_ENV:-${PROFILE_STATE_ROOT}/transit/desired-state.env}"
PROFILES_UNIT="${PROFILES_UNIT:-/etc/systemd/system/tracegate-profiles@.service}"
LINK_CRYPTO_STATE_ROOT="${LINK_CRYPTO_STATE_ROOT:-${PRIVATE_RUNTIME_ROOT}/link-crypto}"
ENTRY_LINK_CRYPTO_STATE="${ENTRY_LINK_CRYPTO_STATE:-${LINK_CRYPTO_STATE_ROOT}/entry/desired-state.json}"
TRANSIT_LINK_CRYPTO_STATE="${TRANSIT_LINK_CRYPTO_STATE:-${LINK_CRYPTO_STATE_ROOT}/transit/desired-state.json}"
ENTRY_LINK_CRYPTO_ENV="${ENTRY_LINK_CRYPTO_ENV:-${LINK_CRYPTO_STATE_ROOT}/entry/desired-state.env}"
TRANSIT_LINK_CRYPTO_ENV="${TRANSIT_LINK_CRYPTO_ENV:-${LINK_CRYPTO_STATE_ROOT}/transit/desired-state.env}"
LINK_CRYPTO_UNIT="${LINK_CRYPTO_UNIT:-/etc/systemd/system/tracegate-link-crypto@.service}"
ROUTER_HANDOFF_STATE_ROOT="${ROUTER_HANDOFF_STATE_ROOT:-${PRIVATE_RUNTIME_ROOT}/router}"
ENTRY_ROUTER_STATE="${ENTRY_ROUTER_STATE:-${ROUTER_HANDOFF_STATE_ROOT}/entry/desired-state.json}"
TRANSIT_ROUTER_STATE="${TRANSIT_ROUTER_STATE:-${ROUTER_HANDOFF_STATE_ROOT}/transit/desired-state.json}"
ENTRY_ROUTER_ENV="${ENTRY_ROUTER_ENV:-${ROUTER_HANDOFF_STATE_ROOT}/entry/desired-state.env}"
TRANSIT_ROUTER_ENV="${TRANSIT_ROUTER_ENV:-${ROUTER_HANDOFF_STATE_ROOT}/transit/desired-state.env}"
ENTRY_ROUTER_CLIENT_BUNDLE="${ENTRY_ROUTER_CLIENT_BUNDLE:-${ROUTER_HANDOFF_STATE_ROOT}/entry/client-bundle.json}"
TRANSIT_ROUTER_CLIENT_BUNDLE="${TRANSIT_ROUTER_CLIENT_BUNDLE:-${ROUTER_HANDOFF_STATE_ROOT}/transit/client-bundle.json}"
ENTRY_ROUTER_CLIENT_ENV="${ENTRY_ROUTER_CLIENT_ENV:-${ROUTER_HANDOFF_STATE_ROOT}/entry/client-bundle.env}"
TRANSIT_ROUTER_CLIENT_ENV="${TRANSIT_ROUTER_CLIENT_ENV:-${ROUTER_HANDOFF_STATE_ROOT}/transit/client-bundle.env}"
FRONTING_STATE="${FRONTING_STATE:-${PRIVATE_RUNTIME_ROOT}/fronting/last-action.json}"
FRONTING_ENV="${FRONTING_ENV:-/etc/tracegate/private/fronting/fronting.env}"
FRONTING_UNIT="${FRONTING_UNIT:-/etc/systemd/system/tracegate-fronting@.service}"
MTPROTO_STATE="${MTPROTO_STATE:-${PRIVATE_RUNTIME_ROOT}/mtproto/last-action.json}"
MTPROTO_ENV="${MTPROTO_ENV:-/etc/tracegate/private/mtproto/mtproto.env}"
MTPROTO_UNIT="${MTPROTO_UNIT:-/etc/systemd/system/tracegate-mtproto@.service}"
MTPROTO_PUBLIC_PROFILE="${MTPROTO_PUBLIC_PROFILE:-${PRIVATE_RUNTIME_ROOT}/mtproto/public-profile.json}"

detect_preflight_mode() {
  case "${PREFLIGHT_MODE}" in
    pair|entry|transit)
      printf '%s\n' "${PREFLIGHT_MODE}"
      return 0
      ;;
    auto)
      if [[ -f "${ENTRY_RUNTIME_CONTRACT}" && -f "${TRANSIT_RUNTIME_CONTRACT}" ]]; then
        printf 'pair\n'
        return 0
      fi
      if [[ -f "${TRANSIT_RUNTIME_CONTRACT}" ]]; then
        printf 'transit\n'
        return 0
      fi
      if [[ -f "${ENTRY_RUNTIME_CONTRACT}" ]]; then
        printf 'entry\n'
        return 0
      fi
      echo "no runtime-contract.json found at ${ENTRY_RUNTIME_CONTRACT} or ${TRANSIT_RUNTIME_CONTRACT}" >&2
      return 1
      ;;
    *)
      echo "unsupported PREFLIGHT_MODE: ${PREFLIGHT_MODE}" >&2
      return 1
      ;;
  esac
}

PREFLIGHT_MODE_RESOLVED="$(detect_preflight_mode)"

args=(
  --mode "${PREFLIGHT_MODE_RESOLVED}"
)

case "${PREFLIGHT_MODE_RESOLVED}" in
  pair)
    args+=(--entry "${ENTRY_RUNTIME_CONTRACT}" --transit "${TRANSIT_RUNTIME_CONTRACT}")
    ;;
  entry)
    args+=(--entry "${ENTRY_RUNTIME_CONTRACT}")
    ;;
  transit)
    args+=(--transit "${TRANSIT_RUNTIME_CONTRACT}")
    ;;
esac

if [[ -d "${ZAPRET_PROFILE_ROOT}" ]]; then
  args+=(--zapret-root "${ZAPRET_PROFILE_ROOT}")
fi

if [[ -f "${OBFUSCATION_ENV}" ]]; then
  args+=(--obfuscation-env "${OBFUSCATION_ENV}")
fi

if [[ -f "${OBFUSCATION_UNIT}" ]]; then
  args+=(--obfuscation-unit "${OBFUSCATION_UNIT}")
fi

if [[ -f "${PROFILES_UNIT}" ]]; then
  args+=(--profiles-unit "${PROFILES_UNIT}")
fi

if [[ -f "${LINK_CRYPTO_UNIT}" ]]; then
  args+=(--link-crypto-unit "${LINK_CRYPTO_UNIT}")
fi

case "${PREFLIGHT_MODE_RESOLVED}" in
  pair)
    if [[ -f "${ENTRY_RUNTIME_STATE}" && -f "${TRANSIT_RUNTIME_STATE}" ]]; then
      args+=(--entry-runtime-state "${ENTRY_RUNTIME_STATE}" --transit-runtime-state "${TRANSIT_RUNTIME_STATE}")
    fi
    if [[ -f "${ENTRY_RUNTIME_ENV}" && -f "${TRANSIT_RUNTIME_ENV}" ]]; then
      args+=(--entry-runtime-env "${ENTRY_RUNTIME_ENV}" --transit-runtime-env "${TRANSIT_RUNTIME_ENV}")
    fi
    if [[ -f "${ENTRY_PROFILE_STATE}" && -f "${TRANSIT_PROFILE_STATE}" ]]; then
      args+=(--entry-profile-state "${ENTRY_PROFILE_STATE}" --transit-profile-state "${TRANSIT_PROFILE_STATE}")
    fi
    if [[ -f "${ENTRY_PROFILE_ENV}" && -f "${TRANSIT_PROFILE_ENV}" ]]; then
      args+=(--entry-profile-env "${ENTRY_PROFILE_ENV}" --transit-profile-env "${TRANSIT_PROFILE_ENV}")
    fi
    if [[ -f "${ENTRY_LINK_CRYPTO_STATE}" && -f "${TRANSIT_LINK_CRYPTO_STATE}" ]]; then
      args+=(--entry-link-crypto-state "${ENTRY_LINK_CRYPTO_STATE}" --transit-link-crypto-state "${TRANSIT_LINK_CRYPTO_STATE}")
    fi
    if [[ -f "${ENTRY_LINK_CRYPTO_ENV}" && -f "${TRANSIT_LINK_CRYPTO_ENV}" ]]; then
      args+=(--entry-link-crypto-env "${ENTRY_LINK_CRYPTO_ENV}" --transit-link-crypto-env "${TRANSIT_LINK_CRYPTO_ENV}")
    fi
    if [[ -f "${ENTRY_ROUTER_STATE}" && -f "${TRANSIT_ROUTER_STATE}" ]]; then
      args+=(--entry-router-state "${ENTRY_ROUTER_STATE}" --transit-router-state "${TRANSIT_ROUTER_STATE}")
    fi
    if [[ -f "${ENTRY_ROUTER_ENV}" && -f "${TRANSIT_ROUTER_ENV}" ]]; then
      args+=(--entry-router-env "${ENTRY_ROUTER_ENV}" --transit-router-env "${TRANSIT_ROUTER_ENV}")
    fi
    if [[ -f "${ENTRY_ROUTER_CLIENT_BUNDLE}" && -f "${TRANSIT_ROUTER_CLIENT_BUNDLE}" ]]; then
      args+=(--entry-router-client-bundle "${ENTRY_ROUTER_CLIENT_BUNDLE}" --transit-router-client-bundle "${TRANSIT_ROUTER_CLIENT_BUNDLE}")
    fi
    if [[ -f "${ENTRY_ROUTER_CLIENT_ENV}" && -f "${TRANSIT_ROUTER_CLIENT_ENV}" ]]; then
      args+=(--entry-router-client-env "${ENTRY_ROUTER_CLIENT_ENV}" --transit-router-client-env "${TRANSIT_ROUTER_CLIENT_ENV}")
    fi
    ;;
  entry)
    if [[ -f "${ENTRY_RUNTIME_STATE}" ]]; then
      args+=(--entry-runtime-state "${ENTRY_RUNTIME_STATE}")
    fi
    if [[ -f "${ENTRY_RUNTIME_ENV}" ]]; then
      args+=(--entry-runtime-env "${ENTRY_RUNTIME_ENV}")
    fi
    if [[ -f "${ENTRY_PROFILE_STATE}" ]]; then
      args+=(--entry-profile-state "${ENTRY_PROFILE_STATE}")
    fi
    if [[ -f "${ENTRY_PROFILE_ENV}" ]]; then
      args+=(--entry-profile-env "${ENTRY_PROFILE_ENV}")
    fi
    if [[ -f "${ENTRY_LINK_CRYPTO_STATE}" ]]; then
      args+=(--entry-link-crypto-state "${ENTRY_LINK_CRYPTO_STATE}")
    fi
    if [[ -f "${ENTRY_LINK_CRYPTO_ENV}" ]]; then
      args+=(--entry-link-crypto-env "${ENTRY_LINK_CRYPTO_ENV}")
    fi
    if [[ -f "${ENTRY_ROUTER_STATE}" ]]; then
      args+=(--entry-router-state "${ENTRY_ROUTER_STATE}")
    fi
    if [[ -f "${ENTRY_ROUTER_ENV}" ]]; then
      args+=(--entry-router-env "${ENTRY_ROUTER_ENV}")
    fi
    if [[ -f "${ENTRY_ROUTER_CLIENT_BUNDLE}" ]]; then
      args+=(--entry-router-client-bundle "${ENTRY_ROUTER_CLIENT_BUNDLE}")
    fi
    if [[ -f "${ENTRY_ROUTER_CLIENT_ENV}" ]]; then
      args+=(--entry-router-client-env "${ENTRY_ROUTER_CLIENT_ENV}")
    fi
    ;;
  transit)
    if [[ -f "${TRANSIT_RUNTIME_STATE}" ]]; then
      args+=(--transit-runtime-state "${TRANSIT_RUNTIME_STATE}")
    fi
    if [[ -f "${TRANSIT_RUNTIME_ENV}" ]]; then
      args+=(--transit-runtime-env "${TRANSIT_RUNTIME_ENV}")
    fi
    if [[ -f "${TRANSIT_PROFILE_STATE}" ]]; then
      args+=(--transit-profile-state "${TRANSIT_PROFILE_STATE}")
    fi
    if [[ -f "${TRANSIT_PROFILE_ENV}" ]]; then
      args+=(--transit-profile-env "${TRANSIT_PROFILE_ENV}")
    fi
    if [[ -f "${TRANSIT_LINK_CRYPTO_STATE}" ]]; then
      args+=(--transit-link-crypto-state "${TRANSIT_LINK_CRYPTO_STATE}")
    fi
    if [[ -f "${TRANSIT_LINK_CRYPTO_ENV}" ]]; then
      args+=(--transit-link-crypto-env "${TRANSIT_LINK_CRYPTO_ENV}")
    fi
    if [[ -f "${TRANSIT_ROUTER_STATE}" ]]; then
      args+=(--transit-router-state "${TRANSIT_ROUTER_STATE}")
    fi
    if [[ -f "${TRANSIT_ROUTER_ENV}" ]]; then
      args+=(--transit-router-env "${TRANSIT_ROUTER_ENV}")
    fi
    if [[ -f "${TRANSIT_ROUTER_CLIENT_BUNDLE}" ]]; then
      args+=(--transit-router-client-bundle "${TRANSIT_ROUTER_CLIENT_BUNDLE}")
    fi
    if [[ -f "${TRANSIT_ROUTER_CLIENT_ENV}" ]]; then
      args+=(--transit-router-client-env "${TRANSIT_ROUTER_CLIENT_ENV}")
    fi
    ;;
esac

if [[ -f "${FRONTING_STATE}" ]]; then
  args+=(--fronting-state "${FRONTING_STATE}")
fi

if [[ -f "${FRONTING_ENV}" ]]; then
  args+=(--fronting-env "${FRONTING_ENV}")
fi

if [[ -f "${FRONTING_UNIT}" ]]; then
  args+=(--fronting-unit "${FRONTING_UNIT}")
fi

if [[ -f "${MTPROTO_STATE}" ]]; then
  args+=(--mtproto-state "${MTPROTO_STATE}")
fi

if [[ -f "${MTPROTO_ENV}" ]]; then
  args+=(--mtproto-env "${MTPROTO_ENV}")
fi

if [[ -f "${MTPROTO_UNIT}" ]]; then
  args+=(--mtproto-unit "${MTPROTO_UNIT}")
fi

if [[ -f "${MTPROTO_PUBLIC_PROFILE}" ]]; then
  args+=(--mtproto-public-profile "${MTPROTO_PUBLIC_PROFILE}")
fi

exec "${PYTHON_BIN}" -m tracegate.cli.validate_runtime_contracts \
  "${args[@]}" \
  "$@"
