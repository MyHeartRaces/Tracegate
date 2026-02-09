#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "Run as root" >&2
  exit 1
fi

REPO_URL=${1:-}
BRANCH=${2:-main}
APP_DIR=${APP_DIR:-/opt/tracegate}
APP_USER=${APP_USER:-tracegate}
APP_GROUP=${APP_GROUP:-tracegate}

if [[ -z "$REPO_URL" ]]; then
  echo "Usage: $0 <repo-url> [branch]" >&2
  exit 1
fi

run_as_app_user() {
  su -s /bin/bash -c "$1" "$APP_USER"
}

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y git python3 python3-venv python3-pip curl ca-certificates

if ! getent group "$APP_GROUP" >/dev/null 2>&1; then
  groupadd --system "$APP_GROUP"
fi

if ! id -u "$APP_USER" >/dev/null 2>&1; then
  useradd --system --create-home --gid "$APP_GROUP" --shell /usr/sbin/nologin "$APP_USER"
fi

mkdir -p "$(dirname "$APP_DIR")"
install -d -m 755 -o "$APP_USER" -g "$APP_GROUP" "$APP_DIR"
if [[ ! -d "$APP_DIR/.git" ]]; then
  if [[ -n "$(find "$APP_DIR" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
    echo "Directory $APP_DIR is not empty and is not a git repository" >&2
    exit 1
  fi
  run_as_app_user "git clone --branch '$BRANCH' '$REPO_URL' '$APP_DIR'"
else
  run_as_app_user "cd '$APP_DIR' && git fetch --all --tags && git checkout '$BRANCH' && git pull --ff-only"
fi

chown -R "$APP_USER:$APP_GROUP" "$APP_DIR"
run_as_app_user "cd '$APP_DIR' && python3 -m venv .venv"
run_as_app_user "cd '$APP_DIR' && .venv/bin/pip install --upgrade pip wheel"
run_as_app_user "cd '$APP_DIR' && .venv/bin/pip install ."

install -d -m 750 -o root -g "$APP_GROUP" /etc/tracegate
if [[ ! -f /etc/tracegate/control-plane.env ]]; then
  install -m 640 -o root -g "$APP_GROUP" "$APP_DIR/deploy/env/control-plane.env.example" /etc/tracegate/control-plane.env
  echo "Created /etc/tracegate/control-plane.env (edit secrets before production use)"
fi

install -m 644 "$APP_DIR/deploy/systemd/tracegate-api.service" /etc/systemd/system/tracegate-api.service
install -m 644 "$APP_DIR/deploy/systemd/tracegate-dispatcher.service" /etc/systemd/system/tracegate-dispatcher.service

systemctl daemon-reload
systemctl enable --now tracegate-api.service tracegate-dispatcher.service

echo "Control-plane installed."
echo "1) Edit /etc/tracegate/control-plane.env"
echo "2) Run: systemctl restart tracegate-api tracegate-dispatcher"
echo "3) Run: /opt/tracegate/.venv/bin/tracegate-init-db"
