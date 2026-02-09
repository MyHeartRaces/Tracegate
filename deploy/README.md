# Production Deploy Assets

This folder contains production-oriented assets for VPS deployment.

## Files

- `systemd/tracegate-api.service`: control-plane API unit
- `systemd/tracegate-dispatcher.service`: outbox dispatcher unit
- `systemd/tracegate-agent.service`: node-agent unit (VPS-T/VPS-E)
- `systemd/tracegate-bot.service`: optional Telegram bot unit

- `env/control-plane.env.example`: API + dispatcher env template
- `env/agent-vps-t.env.example`: agent env template for VPS-T
- `env/agent-vps-e.env.example`: agent env template for VPS-E
- `env/bot.env.example`: bot env template

- `scripts/bootstrap_control_plane.sh`: install/update control-plane host
- `scripts/bootstrap_agent.sh`: install/update node-agent host
- `scripts/bootstrap_all_in_one_vps_t.sh`: install control-plane + VPS-T agent on one host
- `scripts/register_nodes.sh`: register VPS-T/VPS-E in control-plane
- `scripts/reapply_and_reissue.sh`: trigger base reapply and current revision reissue
- `scripts/k3s_label_nodes.sh`: assign k3s node roles (`tracegate.role=vps-t/vps-e`)
- `scripts/k3s_helm_install.sh`: install/upgrade Helm chart on k3s

- `k3s/tracegate/*`: Helm chart for k3s-native deployment
- `k3s/README.md`: k3s deployment guide
- `images/wireguard/*`: WireGuard container build context

## Notes

- Run bootstrap scripts as root.
- Set all secrets in `/etc/tracegate/*.env` before opening public access.
- Agent auth and API auth are operational security credentials, not payment/coins features.
- For k3s mode, prefer the Helm chart under `deploy/k3s/tracegate` instead of host-level systemd.
