#!/usr/bin/env bash
set -euo pipefail

XRAY_VERSION="${XRAY_VERSION:-latest}"
XRAY_INSTALL_POLICY="${XRAY_INSTALL_POLICY:-if-missing}" # always | if-missing | skip
INSTALL_BIN_DIR="${INSTALL_BIN_DIR:-/usr/local/bin}"
TRACEGATE_ENV_FILE="${TRACEGATE_ENV_FILE:-/etc/tracegate/tracegate.env}"
INSTALL_COMPONENTS="${INSTALL_COMPONENTS:-auto}" # auto | xray | mtproto | xray,mtproto
INSTALL_PROXY_STACK="${INSTALL_PROXY_STACK:-true}"
MTPROTO_GIT_REPO="${MTPROTO_GIT_REPO:-https://github.com/TelegramMessenger/MTProxy.git}"
MTPROTO_GIT_REF="${MTPROTO_GIT_REF:-master}"
MTPROTO_INSTALL_POLICY="${MTPROTO_INSTALL_POLICY:-if-missing}" # always | if-missing | skip
MTPROTO_INSTALL_ROOT="${MTPROTO_INSTALL_ROOT:-/opt/MTProxy}"
MTPROTO_STATE_DIR="${MTPROTO_STATE_DIR:-/var/lib/tracegate/private/mtproto}"
MTPROTO_RUNTIME_DIR="${MTPROTO_RUNTIME_DIR:-${MTPROTO_STATE_DIR}/runtime}"
MTPROTO_SECRET_FILE="${MTPROTO_SECRET_FILE:-/etc/tracegate/private/mtproto/secret.txt}"
MTPROTO_ISSUED_STATE_FILE="${MTPROTO_ISSUED_STATE_FILE:-${MTPROTO_STATE_DIR}/issued.json}"
MTPROTO_PROXY_SECRET_FILE="${MTPROTO_PROXY_SECRET_FILE:-${MTPROTO_RUNTIME_DIR}/proxy-secret}"
MTPROTO_PROXY_CONFIG_FILE="${MTPROTO_PROXY_CONFIG_FILE:-${MTPROTO_RUNTIME_DIR}/proxy-multi.conf}"
MTPROTO_FETCH_SECRET_URL="${MTPROTO_FETCH_SECRET_URL:-https://core.telegram.org/getProxySecret}"
MTPROTO_FETCH_CONFIG_URL="${MTPROTO_FETCH_CONFIG_URL:-https://core.telegram.org/getProxyConfig}"
MTPROTO_REFRESH_BOOTSTRAP="${MTPROTO_REFRESH_BOOTSTRAP:-if-missing}" # always | if-missing | never

if [[ "${EUID}" -ne 0 ]]; then
  echo "run as root" >&2
  exit 1
fi

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

read_env_assignment() {
  local file="$1"
  local key="$2"

  [[ -f "${file}" ]] || return 0

  python3 - "$file" "$key" <<'PY'
from pathlib import Path
import sys

path, key = sys.argv[1:]
for raw_line in Path(path).read_text(encoding="utf-8").splitlines():
    line = raw_line.strip()
    if not line or line.startswith("#") or "=" not in line:
        continue
    name, value = line.split("=", 1)
    if name.strip() != key:
        continue
    value = value.strip()
    if len(value) >= 2 and value[:1] == value[-1:] and value[:1] in {"'", '"'}:
        value = value[1:-1]
    print(value)
    raise SystemExit(0)
PY
}

normalize_runtime_profile() {
  local raw="${1:-}"
  raw="$(printf '%s' "${raw}" | tr '[:upper:]' '[:lower:]')"
  raw="${raw#"${raw%%[![:space:]]*}"}"
  raw="${raw%"${raw##*[![:space:]]}"}"

  case "${raw}" in
    ""|default|xray-centric|xray-unified)
      echo "xray-centric"
      ;;
    split|xray-hysteria)
      echo "xray-centric"
      ;;
    *)
      echo "unsupported AGENT_RUNTIME_PROFILE value: ${raw}" >&2
      exit 1
      ;;
  esac
}

normalize_install_component() {
  local raw="${1:-}"
  raw="$(printf '%s' "${raw}" | tr '[:upper:]' '[:lower:]')"
  raw="${raw#"${raw%%[![:space:]]*}"}"
  raw="${raw%"${raw##*[![:space:]]}"}"

  case "${raw}" in
    xray|mtproto)
      echo "${raw}"
      ;;
    *)
      echo "unsupported runtime component: ${raw}" >&2
      exit 1
      ;;
  esac
}

normalize_install_policy() {
  local raw="${1:-}"
  raw="$(printf '%s' "${raw}" | tr '[:upper:]' '[:lower:]')"
  raw="${raw#"${raw%%[![:space:]]*}"}"
  raw="${raw%"${raw##*[![:space:]]}"}"

  case "${raw}" in
    ""|if-missing)
      echo "if-missing"
      ;;
    always|true|force)
      echo "always"
      ;;
    skip|false|never)
      echo "skip"
      ;;
    *)
      echo "unsupported install policy: ${raw}" >&2
      exit 1
      ;;
  esac
}

normalize_refresh_policy() {
  local raw="${1:-}"
  raw="$(printf '%s' "${raw}" | tr '[:upper:]' '[:lower:]')"
  raw="${raw#"${raw%%[![:space:]]*}"}"
  raw="${raw%"${raw##*[![:space:]]}"}"

  case "${raw}" in
    ""|if-missing)
      echo "if-missing"
      ;;
    always|true|force)
      echo "always"
      ;;
    never|false|skip)
      echo "never"
      ;;
    *)
      echo "unsupported bootstrap refresh policy: ${raw}" >&2
      exit 1
      ;;
  esac
}

resolve_install_components() {
  case "${INSTALL_COMPONENTS}" in
    auto)
      local runtime_profile="${AGENT_RUNTIME_PROFILE:-}"
      if [[ -z "${runtime_profile}" ]]; then
        runtime_profile="$(read_env_assignment "${TRACEGATE_ENV_FILE}" "AGENT_RUNTIME_PROFILE")"
      fi
      runtime_profile="$(normalize_runtime_profile "${runtime_profile}")"
      echo "xray"
      ;;
    *)
      local include_xray="false"
      local include_mtproto="false"
      local raw_component=""
      local normalized_component=""
      IFS=',' read -r -a raw_components <<<"${INSTALL_COMPONENTS}"
      for raw_component in "${raw_components[@]}"; do
        normalized_component="$(normalize_install_component "${raw_component}")"
        case "${normalized_component}" in
          xray) include_xray="true" ;;
          mtproto) include_mtproto="true" ;;
        esac
      done

      local resolved=()
      if [[ "${include_xray}" == "true" ]]; then
        resolved+=("xray")
      fi
      if [[ "${include_mtproto}" == "true" ]]; then
        resolved+=("mtproto")
      fi
      if [[ "${#resolved[@]}" -eq 0 ]]; then
        echo "unsupported INSTALL_COMPONENTS value: ${INSTALL_COMPONENTS}" >&2
        exit 1
      fi
      printf '%s\n' "${resolved[*]}"
      ;;
  esac
}

INSTALL_COMPONENTS_RESOLVED="$(resolve_install_components)"
XRAY_INSTALL_POLICY="$(normalize_install_policy "${XRAY_INSTALL_POLICY}")"
MTPROTO_INSTALL_POLICY="$(normalize_install_policy "${MTPROTO_INSTALL_POLICY}")"
MTPROTO_REFRESH_BOOTSTRAP="$(normalize_refresh_policy "${MTPROTO_REFRESH_BOOTSTRAP}")"

component_enabled() {
  local component="$1"
  case " ${INSTALL_COMPONENTS_RESOLVED} " in
    *" ${component} "*) return 0 ;;
    *) return 1 ;;
  esac
}

file_is_ready() {
  local path="$1"
  [[ -s "${path}" ]]
}

xray_artifacts_ready() {
  file_is_ready "${INSTALL_BIN_DIR}/xray" &&
    file_is_ready "${INSTALL_BIN_DIR}/geoip.dat" &&
    file_is_ready "${INSTALL_BIN_DIR}/geosite.dat"
}

mtproto_binary_ready() {
  [[ -x "${MTPROTO_INSTALL_ROOT}/objs/bin/mtproto-proxy" ]]
}

xray_install_required() {
  if ! component_enabled xray; then
    return 1
  fi

  case "${XRAY_INSTALL_POLICY}" in
    always)
      return 0
      ;;
    if-missing)
      ! xray_artifacts_ready
      return
      ;;
    skip)
      if xray_artifacts_ready; then
        return 1
      fi
      echo "XRAY_INSTALL_POLICY=skip but Xray is not installed under ${INSTALL_BIN_DIR}" >&2
      exit 1
      ;;
  esac
}

mtproto_install_required() {
  if ! component_enabled mtproto; then
    return 1
  fi

  case "${MTPROTO_INSTALL_POLICY}" in
    always)
      return 0
      ;;
    if-missing)
      ! mtproto_binary_ready
      return
      ;;
    skip)
      if mtproto_binary_ready; then
        return 1
      fi
      echo "MTPROTO_INSTALL_POLICY=skip but MTProxy is not installed under ${MTPROTO_INSTALL_ROOT}" >&2
      exit 1
      ;;
  esac
}

if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y --no-install-recommends ca-certificates curl unzip
  if [[ "${INSTALL_PROXY_STACK}" == "true" ]]; then
    apt-get install -y --no-install-recommends haproxy nginx
  fi
  if mtproto_install_required; then
    apt-get install -y --no-install-recommends git build-essential libssl-dev zlib1g-dev
  fi
  rm -rf /var/lib/apt/lists/*
fi

for cmd in curl python3 unzip sha256sum install mktemp; do
  need_cmd "${cmd}"
done

if mtproto_install_required; then
  for cmd in git make; do
    need_cmd "${cmd}"
  done
fi

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64) echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    *)
      echo "unsupported architecture: $(uname -m)" >&2
      exit 1
      ;;
  esac
}

ARCH="$(detect_arch)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

release_tag() {
  local repo="$1"
  local version="$2"
  if [[ "${version}" != "latest" ]]; then
    echo "${version}"
    return 0
  fi

  curl -fsSIL -o /dev/null -w '%{url_effective}' "https://github.com/${repo}/releases/latest" | python3 -c '
import sys
from urllib.parse import urlparse

path = urlparse(sys.stdin.read().strip()).path.rstrip("/")
tag = path.rsplit("/", 1)[-1]
if not tag:
    raise SystemExit("failed to resolve latest release tag")
print(tag)
'
}

release_asset_url() {
  local repo="$1"
  local version="$2"
  local asset_name="$3"

  if [[ "${version}" == "latest" ]]; then
    echo "https://github.com/${repo}/releases/latest/download/${asset_name}"
  else
    echo "https://github.com/${repo}/releases/download/${version}/${asset_name}"
  fi
}

install_xray() {
  local asset_name=""
  case "${ARCH}" in
    amd64) asset_name='Xray-linux-64.zip' ;;
    arm64) asset_name='Xray-linux-arm64-v8a.zip' ;;
  esac

  local tag
  tag="$(release_tag "XTLS/Xray-core" "${XRAY_VERSION}")"
  local zip_url
  zip_url="$(release_asset_url "XTLS/Xray-core" "${XRAY_VERSION}" "${asset_name}")"
  local dgst_url="${zip_url}.dgst"
  local zip_path="${TMP_DIR}/$(basename "${zip_url}")"
  local dgst_path="${zip_path}.dgst"
  local out_dir="${TMP_DIR}/xray"

  echo "installing Xray ${tag} (${ARCH})"
  curl -fsSL -o "${zip_path}" "${zip_url}"
  curl -fsSL -o "${dgst_path}" "${dgst_url}"

  local expected_sha
  expected_sha="$(grep '^SHA2-256=' "${dgst_path}" | awk '{print $2}')"
  if [[ -z "${expected_sha}" ]]; then
    echo "failed to parse Xray SHA2-256 digest" >&2
    exit 1
  fi
  echo "${expected_sha}  ${zip_path}" | sha256sum -c -

  mkdir -p "${out_dir}"
  unzip -j "${zip_path}" xray geoip.dat geosite.dat -d "${out_dir}" >/dev/null
  install -d -m 0755 "${INSTALL_BIN_DIR}"
  install -m 0755 "${out_dir}/xray" "${INSTALL_BIN_DIR}/xray"
  install -m 0644 "${out_dir}/geoip.dat" "${INSTALL_BIN_DIR}/geoip.dat"
  install -m 0644 "${out_dir}/geosite.dat" "${INSTALL_BIN_DIR}/geosite.dat"
}

ensure_xray_present() {
  if ! component_enabled xray; then
    return 0
  fi

  if ! xray_install_required; then
    echo "xray already present; skipping install"
    return 0
  fi

  install_xray
}

ensure_mtproto_secret_file() {
  local path="$1"
  python3 - "$path" <<'PY'
from pathlib import Path
import secrets
import sys

path = Path(sys.argv[1])
path.parent.mkdir(parents=True, exist_ok=True)
if path.is_file():
    raw = "".join(ch for ch in path.read_text(encoding="utf-8") if ch.lower() in "0123456789abcdef").lower()
    if len(raw) == 32:
        raise SystemExit(0)
path.write_text(secrets.token_hex(16) + "\n", encoding="utf-8")
path.chmod(0o600)
PY
}

ensure_mtproto_issued_state_file() {
  local path="$1"
  python3 - "$path" <<'PY'
from pathlib import Path
import json
import sys

path = Path(sys.argv[1])
path.parent.mkdir(parents=True, exist_ok=True)
if path.is_file() and path.stat().st_size > 0:
    raise SystemExit(0)
path.write_text(json.dumps({"entries": []}, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
path.chmod(0o600)
PY
}

refresh_mtproto_bootstrap() {
  local url="$1"
  local path="$2"

  python3 - "$url" "$path" <<'PY'
from pathlib import Path
import sys
from urllib.request import Request, urlopen

url = str(sys.argv[1]).strip()
path = Path(sys.argv[2])
path.parent.mkdir(parents=True, exist_ok=True)
request = Request(url, headers={"User-Agent": "Tracegate/2 install-runtime"})
with urlopen(request, timeout=15) as response:  # noqa: S310
    payload = response.read()
if not payload:
    raise SystemExit(f"empty MTProto bootstrap payload from {url}")
path.write_bytes(payload)
path.chmod(0o640)
PY
}

ensure_mtproto_bootstrap_file() {
  local url="$1"
  local path="$2"

  case "${MTPROTO_REFRESH_BOOTSTRAP}" in
    always)
      refresh_mtproto_bootstrap "${url}" "${path}"
      ;;
    if-missing)
      if file_is_ready "${path}"; then
        return 0
      fi
      refresh_mtproto_bootstrap "${url}" "${path}"
      ;;
    never)
      if file_is_ready "${path}"; then
        return 0
      fi
      echo "MTPROTO_REFRESH_BOOTSTRAP=never but missing bootstrap file: ${path}" >&2
      exit 1
      ;;
  esac
}

install_mtproto_binary() {
  local source_dir="${TMP_DIR}/mtproxy-source"
  local target_binary="${MTPROTO_INSTALL_ROOT}/objs/bin/mtproto-proxy"

  echo "installing official MTProxy (${MTPROTO_GIT_REF})"
  git clone --depth 1 "${MTPROTO_GIT_REPO}" "${source_dir}" >/dev/null 2>&1
  git -C "${source_dir}" fetch --depth 1 origin "${MTPROTO_GIT_REF}" >/dev/null 2>&1
  git -C "${source_dir}" checkout -q FETCH_HEAD
  make -C "${source_dir}" >/dev/null

  install -d -m 0755 "${MTPROTO_INSTALL_ROOT}/objs/bin"
  install -m 0755 "${source_dir}/objs/bin/mtproto-proxy" "${target_binary}"
}

install_mtproto() {
  local target_binary="${MTPROTO_INSTALL_ROOT}/objs/bin/mtproto-proxy"

  if mtproto_install_required; then
    install_mtproto_binary
  else
    echo "mtproto already present; skipping binary install"
  fi

  install -d -m 0750 \
    "${MTPROTO_STATE_DIR}" \
    "${MTPROTO_RUNTIME_DIR}" \
    "$(dirname "${MTPROTO_SECRET_FILE}")"
  ensure_mtproto_secret_file "${MTPROTO_SECRET_FILE}"
  ensure_mtproto_issued_state_file "${MTPROTO_ISSUED_STATE_FILE}"

  ensure_mtproto_bootstrap_file "${MTPROTO_FETCH_SECRET_URL}" "${MTPROTO_PROXY_SECRET_FILE}"
  ensure_mtproto_bootstrap_file "${MTPROTO_FETCH_CONFIG_URL}" "${MTPROTO_PROXY_CONFIG_FILE}"
}

if component_enabled xray; then
  ensure_xray_present
fi

if component_enabled mtproto; then
  install_mtproto
fi

echo "runtime binaries installed (components: ${INSTALL_COMPONENTS_RESOLVED})"
if component_enabled xray; then
  echo "xray_bin_dir=${INSTALL_BIN_DIR}"
fi
if component_enabled mtproto; then
  echo "mtproto_binary=${MTPROTO_INSTALL_ROOT}/objs/bin/mtproto-proxy"
  echo "mtproto_secret_file=${MTPROTO_SECRET_FILE}"
  echo "mtproto_issued_state_file=${MTPROTO_ISSUED_STATE_FILE}"
  echo "mtproto_proxy_secret_file=${MTPROTO_PROXY_SECRET_FILE}"
  echo "mtproto_proxy_config_file=${MTPROTO_PROXY_CONFIG_FILE}"
fi
