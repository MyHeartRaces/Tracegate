#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "Run as root" >&2
  exit 1
fi

REPO_URL=${1:-}
ROLE=${2:-}
BRANCH=${3:-main}
APP_DIR=${APP_DIR:-/opt/tracegate}
APP_USER=${APP_USER:-tracegate}
APP_GROUP=${APP_GROUP:-tracegate}

if [[ -z "$REPO_URL" || -z "$ROLE" ]]; then
  echo "Usage: $0 <repo-url> <VPS_T|VPS_E> [branch]" >&2
  exit 1
fi

if [[ "$ROLE" != "VPS_T" && "$ROLE" != "VPS_E" ]]; then
  echo "ROLE must be VPS_T or VPS_E" >&2
  exit 1
fi

run_as_app_user() {
  su -s /bin/bash -c "$1" "$APP_USER"
}

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y git python3 python3-venv python3-pip curl ca-certificates iproute2 nftables wireguard-tools

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
if [[ ! -f /etc/tracegate/agent.env ]]; then
  if [[ "$ROLE" == "VPS_T" ]]; then
    install -m 640 -o root -g "$APP_GROUP" "$APP_DIR/deploy/env/agent-vps-t.env.example" /etc/tracegate/agent.env
  else
    install -m 640 -o root -g "$APP_GROUP" "$APP_DIR/deploy/env/agent-vps-e.env.example" /etc/tracegate/agent.env
  fi
fi

sed -i "s/^AGENT_ROLE=.*/AGENT_ROLE=$ROLE/" /etc/tracegate/agent.env

install -d -m 750 -o "$APP_USER" -g "$APP_GROUP" /var/lib/tracegate-agent
install -m 644 "$APP_DIR/deploy/systemd/tracegate-agent.service" /etc/systemd/system/tracegate-agent.service

systemctl daemon-reload
systemctl enable --now tracegate-agent.service

echo "Agent installed for role=$ROLE"
echo "1) Edit /etc/tracegate/agent.env"
echo "2) Run: systemctl restart tracegate-agent"
