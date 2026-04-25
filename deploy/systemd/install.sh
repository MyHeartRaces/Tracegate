#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INSTALL_DIR="${INSTALL_DIR:-/opt/tracegate}"
CONFIG_DIR="${CONFIG_DIR:-/etc/tracegate}"
STATE_DIR="${STATE_DIR:-/var/lib/tracegate}"
LOG_DIR="${LOG_DIR:-/var/log/tracegate}"
RUN_USER="${RUN_USER:-tracegate}"
RUN_GROUP="${RUN_GROUP:-tracegate}"
PYTHON_BIN="${PYTHON_BIN:-python3}"
TRACEGATE_INSTALL_ROLE="${TRACEGATE_INSTALL_ROLE:-all}" # all | entry | transit
TRACEGATE_SINGLE_ENV_ONLY="${TRACEGATE_SINGLE_ENV_ONLY:-false}"

read_env_assignment() {
  local file="$1"
  local key="$2"

  [[ -f "${file}" ]] || return 0

  "${PYTHON_BIN}" - "$file" "$key" <<'PY'
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

normalize_install_role() {
  local raw="${1:-}"
  raw="$(printf '%s' "${raw}" | tr '[:upper:]' '[:lower:]')"
  raw="${raw#"${raw%%[![:space:]]*}"}"
  raw="${raw%"${raw##*[![:space:]]}"}"

  case "${raw}" in
    ""|all)
      echo "all"
      ;;
    entry)
      echo "entry"
      ;;
    transit)
      echo "transit"
      ;;
    *)
      echo "unsupported TRACEGATE_INSTALL_ROLE value: ${raw}" >&2
      exit 1
      ;;
  esac
}

is_true() {
  local raw="${1:-}"
  raw="$(printf '%s' "${raw}" | tr '[:upper:]' '[:lower:]')"
  case "${raw}" in
    1|true|yes|on) return 0 ;;
    *) return 1 ;;
  esac
}

seed_if_missing() {
  local source_file="$1"
  local target_file="$2"
  local mode="$3"
  local owner="${4:-root}"
  local group="${5:-${RUN_GROUP}}"

  if [[ -f "${source_file}" && ! -f "${target_file}" ]]; then
    install -m "${mode}" -o "${owner}" -g "${group}" "${source_file}" "${target_file}"
  fi
}

runtime_units_for_role() {
  local role="$1"
  echo "tracegate-haproxy@${role} tracegate-nginx@${role} tracegate-xray@${role}"
}

role_env_templates_for_install_role() {
  local role="$1"
  case "${role}" in
    all)
      echo "entry.env transit.env"
      ;;
    entry)
      echo "entry.env"
      ;;
    transit)
      echo "transit.env"
      ;;
  esac
}

if [[ "${EUID}" -ne 0 ]]; then
  echo "run as root" >&2
  exit 1
fi

TRACEGATE_INSTALL_ROLE="$(normalize_install_role "${TRACEGATE_INSTALL_ROLE}")"

if ! getent group "${RUN_GROUP}" >/dev/null 2>&1; then
  groupadd --system "${RUN_GROUP}"
fi

if ! id -u "${RUN_USER}" >/dev/null 2>&1; then
  useradd \
    --system \
    --gid "${RUN_GROUP}" \
    --home-dir "${STATE_DIR}" \
    --create-home \
    --shell /usr/sbin/nologin \
    "${RUN_USER}"
fi

install -d -m 0750 -o "${RUN_USER}" -g "${RUN_GROUP}" "${INSTALL_DIR}" "${CONFIG_DIR}" "${STATE_DIR}"
install -d -m 0755 -o root -g root "${LOG_DIR}"
install -d -m 0750 -o "${RUN_USER}" -g "${RUN_GROUP}" \
  "${STATE_DIR}/private" \
  "${STATE_DIR}/private/obfuscation" \
  "${STATE_DIR}/private/obfuscation/entry" \
  "${STATE_DIR}/private/obfuscation/transit" \
  "${STATE_DIR}/private/fronting" \
  "${STATE_DIR}/private/fronting/runtime" \
  "${STATE_DIR}/private/mtproto" \
  "${STATE_DIR}/private/mtproto/runtime" \
  "${STATE_DIR}/private/profiles" \
  "${STATE_DIR}/private/profiles/entry" \
  "${STATE_DIR}/private/profiles/transit" \
  "${STATE_DIR}/private/profiles/runtime" \
  "${STATE_DIR}/private/link-crypto" \
  "${STATE_DIR}/private/link-crypto/entry" \
  "${STATE_DIR}/private/link-crypto/transit" \
  "${STATE_DIR}/private/zapret"
install -d -m 0750 -o root -g root "${CONFIG_DIR}/tls"
install -d -m 0750 -o root -g "${RUN_GROUP}" \
  "${CONFIG_DIR}/private" \
  "${CONFIG_DIR}/private/overlays" \
  "${CONFIG_DIR}/private/systemd" \
  "${CONFIG_DIR}/private/fronting" \
  "${CONFIG_DIR}/private/profiles" \
  "${CONFIG_DIR}/private/mtproto" \
  "${CONFIG_DIR}/private/mieru" \
  "${CONFIG_DIR}/private/zapret" \
  "${CONFIG_DIR}/private/overlays/entry" \
  "${CONFIG_DIR}/private/overlays/transit"

if [[ ! -f "${CONFIG_DIR}/private/README.md" ]]; then
  install -m 0640 -o root -g "${RUN_GROUP}" \
    "${ROOT_DIR}/deploy/systemd/private-example/README.md" \
    "${CONFIG_DIR}/private/README.md"
fi

for role in entry transit; do
  target_dir="${CONFIG_DIR}/private/overlays/${role}"
  source_dir="${ROOT_DIR}/deploy/systemd/private-example/${role}"
  install -d -m 0750 -o root -g "${RUN_GROUP}" "${target_dir}"

  for sample in README.md xray.merge.json.example; do
    source_file="${source_dir}/${sample}"
    target_file="${target_dir}/${sample}"
    if [[ -f "${source_file}" && ! -f "${target_file}" ]]; then
      install -m 0640 -o root -g "${RUN_GROUP}" "${source_file}" "${target_file}"
    fi
  done
done

seed_if_missing \
  "${ROOT_DIR}/deploy/systemd/private-example/render-hook.sh.example" \
  "${CONFIG_DIR}/private/render-hook.sh.example" \
  0750 \
  root \
  "${RUN_GROUP}"
seed_if_missing \
  "${ROOT_DIR}/deploy/systemd/private-example/render-hook.sh.example" \
  "${CONFIG_DIR}/private/render-hook.sh" \
  0750 \
  root \
  "${RUN_GROUP}"

private_systemd_source_dir="${ROOT_DIR}/deploy/systemd/private-example/systemd"
private_systemd_target_dir="${CONFIG_DIR}/private/systemd"
install -d -m 0750 -o root -g "${RUN_GROUP}" "${private_systemd_target_dir}"

for sample in README.md obfuscation.env.example run-obfuscation.sh.example tracegate-obfuscation@.service.example; do
  source_file="${private_systemd_source_dir}/${sample}"
  target_file="${private_systemd_target_dir}/${sample}"
  if [[ -f "${source_file}" && ! -f "${target_file}" ]]; then
    mode="0640"
    if [[ "${sample}" == "run-obfuscation.sh.example" ]]; then
      mode="0750"
    fi
    install -m "${mode}" -o root -g "${RUN_GROUP}" "${source_file}" "${target_file}"
  fi
done
seed_if_missing \
  "${private_systemd_source_dir}/obfuscation.env.example" \
  "${private_systemd_target_dir}/obfuscation.env" \
  0640 \
  root \
  "${RUN_GROUP}"
seed_if_missing \
  "${private_systemd_source_dir}/run-obfuscation.sh.example" \
  "${private_systemd_target_dir}/run-obfuscation.sh" \
  0750 \
  root \
  "${RUN_GROUP}"
seed_if_missing \
  "${private_systemd_source_dir}/tracegate-obfuscation@.service.example" \
  "/etc/systemd/system/tracegate-obfuscation@.service" \
  0644 \
  root \
  root

private_zapret_source_dir="${ROOT_DIR}/deploy/systemd/private-example/zapret"
private_zapret_target_dir="${CONFIG_DIR}/private/zapret"
install -d -m 0750 -o root -g "${RUN_GROUP}" "${private_zapret_target_dir}"

for sample in README.md entry-lite.env.example transit-lite.env.example entry-transit-stealth.env.example mtproto-extra.env.example; do
  source_file="${private_zapret_source_dir}/${sample}"
  target_file="${private_zapret_target_dir}/${sample}"
  if [[ -f "${source_file}" && ! -f "${target_file}" ]]; then
    install -m 0640 -o root -g "${RUN_GROUP}" "${source_file}" "${target_file}"
  fi
done
seed_if_missing \
  "${private_zapret_source_dir}/entry-lite.env.example" \
  "${private_zapret_target_dir}/entry-lite.env" \
  0640 \
  root \
  "${RUN_GROUP}"
seed_if_missing \
  "${private_zapret_source_dir}/transit-lite.env.example" \
  "${private_zapret_target_dir}/transit-lite.env" \
  0640 \
  root \
  "${RUN_GROUP}"
seed_if_missing \
  "${private_zapret_source_dir}/entry-transit-stealth.env.example" \
  "${private_zapret_target_dir}/entry-transit-stealth.env" \
  0640 \
  root \
  "${RUN_GROUP}"
seed_if_missing \
  "${private_zapret_source_dir}/mtproto-extra.env.example" \
  "${private_zapret_target_dir}/mtproto-extra.env" \
  0640 \
  root \
  "${RUN_GROUP}"

private_link_crypto_source_dir="${ROOT_DIR}/deploy/systemd/private-example/link-crypto"
private_link_crypto_target_dir="${CONFIG_DIR}/private/link-crypto"
install -d -m 0750 -o root -g "${RUN_GROUP}" "${private_link_crypto_target_dir}"

for sample in README.md link-crypto.env.example run-link-crypto.sh.example tracegate-link-crypto@.service.example; do
  source_file="${private_link_crypto_source_dir}/${sample}"
  target_file="${private_link_crypto_target_dir}/${sample}"
  if [[ -f "${source_file}" && ! -f "${target_file}" ]]; then
    mode="0640"
    if [[ "${sample}" == "run-link-crypto.sh.example" ]]; then
      mode="0750"
    fi
    install -m "${mode}" -o root -g "${RUN_GROUP}" "${source_file}" "${target_file}"
  fi
done
seed_if_missing \
  "${private_link_crypto_source_dir}/link-crypto.env.example" \
  "${private_link_crypto_target_dir}/link-crypto.env" \
  0640 \
  root \
  "${RUN_GROUP}"
seed_if_missing \
  "${private_link_crypto_source_dir}/run-link-crypto.sh.example" \
  "${private_link_crypto_target_dir}/run-link-crypto.sh" \
  0750 \
  root \
  "${RUN_GROUP}"
seed_if_missing \
  "${private_link_crypto_source_dir}/tracegate-link-crypto@.service.example" \
  "/etc/systemd/system/tracegate-link-crypto@.service" \
  0644 \
  root \
  root

private_profiles_source_dir="${ROOT_DIR}/deploy/systemd/private-example/profiles"
private_profiles_target_dir="${CONFIG_DIR}/private/profiles"
install -d -m 0750 -o root -g "${RUN_GROUP}" "${private_profiles_target_dir}"

for sample in README.md profiles.env.example run-profiles.sh.example tracegate-profiles@.service.example; do
  source_file="${private_profiles_source_dir}/${sample}"
  target_file="${private_profiles_target_dir}/${sample}"
  if [[ -f "${source_file}" && ! -f "${target_file}" ]]; then
    mode="0640"
    if [[ "${sample}" == "run-profiles.sh.example" ]]; then
      mode="0750"
    fi
    install -m "${mode}" -o root -g "${RUN_GROUP}" "${source_file}" "${target_file}"
  fi
done
seed_if_missing \
  "${private_profiles_source_dir}/profiles.env.example" \
  "${private_profiles_target_dir}/profiles.env" \
  0640 \
  root \
  "${RUN_GROUP}"
seed_if_missing \
  "${private_profiles_source_dir}/run-profiles.sh.example" \
  "${private_profiles_target_dir}/run-profiles.sh" \
  0750 \
  root \
  "${RUN_GROUP}"
seed_if_missing \
  "${private_profiles_source_dir}/tracegate-profiles@.service.example" \
  "/etc/systemd/system/tracegate-profiles@.service" \
  0644 \
  root \
  root

private_mtproto_source_dir="${ROOT_DIR}/deploy/systemd/private-example/mtproto"
private_mtproto_target_dir="${CONFIG_DIR}/private/mtproto"
install -d -m 0750 -o root -g "${RUN_GROUP}" "${private_mtproto_target_dir}"

for sample in README.md mtproto.env.example fronting-transit.env.example run-mtproto.sh.example tracegate-mtproto@.service.example; do
  source_file="${private_mtproto_source_dir}/${sample}"
  target_file="${private_mtproto_target_dir}/${sample}"
  if [[ -f "${source_file}" && ! -f "${target_file}" ]]; then
    mode="0640"
    if [[ "${sample}" == "run-mtproto.sh.example" ]]; then
      mode="0750"
    fi
    install -m "${mode}" -o root -g "${RUN_GROUP}" "${source_file}" "${target_file}"
  fi
done
seed_if_missing \
  "${private_mtproto_source_dir}/mtproto.env.example" \
  "${private_mtproto_target_dir}/mtproto.env" \
  0640 \
  root \
  "${RUN_GROUP}"
seed_if_missing \
  "${private_mtproto_source_dir}/fronting-transit.env.example" \
  "${private_mtproto_target_dir}/fronting-transit.env" \
  0640 \
  root \
  "${RUN_GROUP}"
seed_if_missing \
  "${private_mtproto_source_dir}/run-mtproto.sh.example" \
  "${private_mtproto_target_dir}/run-mtproto.sh" \
  0750 \
  root \
  "${RUN_GROUP}"
seed_if_missing \
  "${private_mtproto_source_dir}/tracegate-mtproto@.service.example" \
  "/etc/systemd/system/tracegate-mtproto@.service" \
  0644 \
  root \
  root

private_fronting_source_dir="${ROOT_DIR}/deploy/systemd/private-example/fronting"
private_fronting_target_dir="${CONFIG_DIR}/private/fronting"
install -d -m 0750 -o root -g "${RUN_GROUP}" "${private_fronting_target_dir}"

for sample in README.md fronting.env.example run-fronting.sh.example tracegate-fronting@.service.example; do
  source_file="${private_fronting_source_dir}/${sample}"
  target_file="${private_fronting_target_dir}/${sample}"
  if [[ -f "${source_file}" && ! -f "${target_file}" ]]; then
    mode="0640"
    if [[ "${sample}" == "run-fronting.sh.example" ]]; then
      mode="0750"
    fi
    install -m "${mode}" -o root -g "${RUN_GROUP}" "${source_file}" "${target_file}"
  fi
done
seed_if_missing \
  "${private_fronting_source_dir}/fronting.env.example" \
  "${private_fronting_target_dir}/fronting.env" \
  0640 \
  root \
  "${RUN_GROUP}"
seed_if_missing \
  "${private_fronting_source_dir}/run-fronting.sh.example" \
  "${private_fronting_target_dir}/run-fronting.sh" \
  0750 \
  root \
  "${RUN_GROUP}"
seed_if_missing \
  "${private_fronting_source_dir}/tracegate-fronting@.service.example" \
  "/etc/systemd/system/tracegate-fronting@.service" \
  0644 \
  root \
  root

rsync -a \
  --delete \
  --exclude '.git' \
  --exclude '.venv' \
  --exclude '__pycache__' \
  --exclude '.pytest_cache' \
  "${ROOT_DIR}/" "${INSTALL_DIR}/"

"${PYTHON_BIN}" -m venv "${INSTALL_DIR}/.venv"
"${INSTALL_DIR}/.venv/bin/pip" install --upgrade pip
"${INSTALL_DIR}/.venv/bin/pip" install "${INSTALL_DIR}"

install -m 0644 "${ROOT_DIR}/deploy/systemd/"*.service /etc/systemd/system/

tracegate_env_source="${ROOT_DIR}/deploy/systemd/tracegate.env.example"
if [[ "${TRACEGATE_INSTALL_ROLE}" == "transit" ]] && is_true "${TRACEGATE_SINGLE_ENV_ONLY}"; then
  tracegate_env_source="${ROOT_DIR}/deploy/systemd/transit-single.env.example"
fi

if [[ ! -f "${CONFIG_DIR}/tracegate.env" ]]; then
  install -m 0640 -o root -g "${RUN_GROUP}" "${tracegate_env_source}" "${CONFIG_DIR}/tracegate.env"
fi

DECOY_ROOT="$(read_env_assignment "${CONFIG_DIR}/tracegate.env" "XRAY_CENTRIC_DECOY_DIR")"
DECOY_ROOT="${DECOY_ROOT:-/var/www/decoy}"
install -d -m 0755 -o root -g root "${DECOY_ROOT}"

if ! is_true "${TRACEGATE_SINGLE_ENV_ONLY}"; then
  for template in $(role_env_templates_for_install_role "${TRACEGATE_INSTALL_ROLE}"); do
    target="${CONFIG_DIR}/${template}"
    source_file="${ROOT_DIR}/deploy/systemd/${template}.example"
    if [[ ! -f "${target}" ]]; then
      install -m 0640 -o root -g "${RUN_GROUP}" "${source_file}" "${target}"
    fi
  done
fi

RUNTIME_PROFILE="$(normalize_runtime_profile "$(read_env_assignment "${CONFIG_DIR}/tracegate.env" "AGENT_RUNTIME_PROFILE")")"
ENTRY_RUNTIME_UNITS="$(runtime_units_for_role entry "${RUNTIME_PROFILE}")"
TRANSIT_RUNTIME_UNITS="$(runtime_units_for_role transit "${RUNTIME_PROFILE}")"

systemctl daemon-reload

cat <<EOF
Tracegate 2 install assets are in place.

Next steps:
1. Edit ${CONFIG_DIR}/tracegate.env$(if ! is_true "${TRACEGATE_SINGLE_ENV_ONLY}"; then
     case "${TRACEGATE_INSTALL_ROLE}" in
       all) printf ' and the role-specific env files' ;;
       entry) printf ' and %s/entry.env' "${CONFIG_DIR}" ;;
       transit) printf ' and %s/transit.env' "${CONFIG_DIR}" ;;
     esac
   else
     printf ' (single-file mode)'
   fi).
2. Install node runtime binaries on Entry / Transit hosts:
   ${INSTALL_DIR}/deploy/systemd/install-runtime.sh
   The default INSTALL_COMPONENTS=auto follows AGENT_RUNTIME_PROFILE=${RUNTIME_PROFILE}.
   For Transit MTProto testbeds, opt in explicitly:
   INSTALL_COMPONENTS=xray,mtproto ${INSTALL_DIR}/deploy/systemd/install-runtime.sh
3. Render materialized server bundles:
   ${INSTALL_DIR}/deploy/systemd/render-materialized-bundles.sh
4. Validate Entry / Transit runtime contracts on a testbed before promoting overlays:
   ${INSTALL_DIR}/deploy/systemd/validate-runtime-contracts.sh
5. Optionally generate xray-centric private overlays:
   ${INSTALL_DIR}/deploy/systemd/render-xray-centric-overlays.sh
6. Place private overlays or a private render hook under ${CONFIG_DIR}/private if needed.
   Host-local obfuscation service examples are seeded under ${CONFIG_DIR}/private/systemd.
   The runtime handoff state root is seeded under ${STATE_DIR}/private.
7. Add TLS material to ${CONFIG_DIR}/tls if agent mTLS is enabled.
8. Enable the required services, for example:
$(if [[ "${TRACEGATE_INSTALL_ROLE}" == "all" ]]; then
     cat <<EOEXAMPLE
   systemctl enable --now tracegate-api tracegate-dispatcher tracegate-bot
   systemctl enable --now tracegate-agent-entry
   systemctl enable --now tracegate-agent-transit
   systemctl enable --now ${ENTRY_RUNTIME_UNITS}
   systemctl enable --now ${TRANSIT_RUNTIME_UNITS}
EOEXAMPLE
   elif [[ "${TRACEGATE_INSTALL_ROLE}" == "entry" ]]; then
     cat <<EOEXAMPLE
   systemctl enable --now tracegate-agent-entry
   systemctl enable --now ${ENTRY_RUNTIME_UNITS}
EOEXAMPLE
   else
     cat <<EOEXAMPLE
   systemctl enable --now tracegate-agent-transit
   systemctl enable --now ${TRANSIT_RUNTIME_UNITS}
EOEXAMPLE
   fi)
EOF
