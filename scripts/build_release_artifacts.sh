#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${PYTHON:-python3}"
PYTHON_BIN="$(command -v "${PYTHON}")"
VERSION="${1:-}"

if [ -z "${VERSION}" ]; then
  echo "usage: build_release_artifacts.sh VERSION" >&2
  exit 2
fi

PROJECT_VERSION="$(cd "${ROOT}" && "${PYTHON_BIN}" -c 'import pathlib,tomllib; print(tomllib.loads(pathlib.Path("pyproject.toml").read_text())["project"]["version"])')"
if [ "${VERSION}" != "${PROJECT_VERSION}" ]; then
  echo "requested version ${VERSION} does not match project version ${PROJECT_VERSION}" >&2
  exit 2
fi
if ! git -C "${ROOT}" diff --quiet --ignore-submodules -- || ! git -C "${ROOT}" diff --cached --quiet --ignore-submodules --; then
  echo "release artifacts require a clean tracked worktree" >&2
  exit 2
fi

OUT_DIR="${TRACEGATE_RELEASE_OUT:-${ROOT}/dist/release-v${VERSION}}"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT
SOURCE_DIR="${TMP_DIR}/source"
INSPECT_DIR="${TMP_DIR}/inspect"
mkdir -p "${SOURCE_DIR}" "${OUT_DIR}" "${INSPECT_DIR}"

git -C "${ROOT}" archive --format=tar HEAD | tar -xf - -C "${SOURCE_DIR}"
"${PYTHON_BIN}" "${SOURCE_DIR}/scripts/check_public_release.py" --root "${SOURCE_DIR}" --all-files

(
  cd "${SOURCE_DIR}"
  "${PYTHON_BIN}" -m build --outdir "${OUT_DIR}"
)
git -C "${ROOT}" archive \
  --format=tar.gz \
  --prefix="tracegate-host-runtime-${VERSION}/" \
  -o "${OUT_DIR}/tracegate-host-runtime-${VERSION}.tar.gz" \
  HEAD bundles deploy/systemd scripts/check_host_runtime.py

for archive in "${OUT_DIR}"/*.tar.gz; do
  target="${INSPECT_DIR}/$(basename "${archive}")"
  mkdir -p "${target}"
  tar -xf "${archive}" -C "${target}"
  "${PYTHON_BIN}" "${SOURCE_DIR}/scripts/check_public_release.py" --root "${target}" --all-files
done
for wheel in "${OUT_DIR}"/*.whl; do
  target="${INSPECT_DIR}/$(basename "${wheel}")"
  mkdir -p "${target}"
  unzip -q "${wheel}" -d "${target}"
  "${PYTHON_BIN}" "${SOURCE_DIR}/scripts/check_public_release.py" --root "${target}" --all-files
done

(
  cd "${OUT_DIR}"
  rm -f SHA256SUMS
  shasum -a 256 ./*.tar.gz ./*.whl > SHA256SUMS
)

printf 'release artifacts written to %s\n' "${OUT_DIR}"
find "${OUT_DIR}" -maxdepth 1 -type f -print | sort
