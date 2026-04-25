#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-/opt/tracegate}"
CONFIG_DIR="${CONFIG_DIR:-/etc/tracegate}"
BUNDLE_SOURCE_ROOT="${BUNDLE_SOURCE_ROOT:-${INSTALL_DIR}/bundles}"
BUNDLE_MATERIALIZED_ROOT="${BUNDLE_MATERIALIZED_ROOT:-/var/lib/tracegate/materialized-bundles}"
BUNDLE_PRIVATE_OVERLAY_ROOT="${BUNDLE_PRIVATE_OVERLAY_ROOT:-${CONFIG_DIR}/private/overlays}"
PYTHON_BIN="${PYTHON_BIN:-${INSTALL_DIR}/.venv/bin/python}"

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

export BUNDLE_SOURCE_ROOT
export BUNDLE_MATERIALIZED_ROOT
export BUNDLE_PRIVATE_OVERLAY_ROOT
"${PYTHON_BIN}" -m tracegate.cli.render_xray_centric_overlays
