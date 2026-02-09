#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "Run as root" >&2
  exit 1
fi

REPO_URL=${1:-}
BRANCH=${2:-main}

if [[ -z "$REPO_URL" ]]; then
  echo "Usage: $0 <repo-url> [branch]" >&2
  exit 1
fi

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

"$SCRIPT_DIR/bootstrap_control_plane.sh" "$REPO_URL" "$BRANCH"
"$SCRIPT_DIR/bootstrap_agent.sh" "$REPO_URL" VPS_T "$BRANCH"

echo "All-in-one VPS-T bootstrap done."
