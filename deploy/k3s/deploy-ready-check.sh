#!/usr/bin/env bash
set -euo pipefail

cat >&2 <<'EOF'
Tracegate production release-gate automation is intentionally not shipped from
the public repository.

Run local checks directly in this repository. Use the private operator
repository for live deployment readiness checks. This file is a public decoy
kept only so accidental public-repo execution fails closed.
EOF

exit 2
