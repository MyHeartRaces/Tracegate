# Tracegate on k3s

This chart deploys:
- control-plane (`api`, `dispatcher`, optional `bot`, optional `postgres`)
- gateway on VPS-T (`xray`, `hysteria2`, `wireguard`, `agent`) in one pod
- gateway on VPS-E (`xray`, `agent`) in one pod
- optional observability stack (`prometheus`, `grafana`)

## Prerequisites

- k3s cluster with two nodes (recommended):
  - one node for `vps-t`
  - one node for `vps-e`
- `kubectl` and `helm`
- container images pushed to GHCR/Docker registry:
  - app: `tracegate`
  - wireguard sidecar: `tracegate-wireguard`
  - build context for WG image: `deploy/images/wireguard`

## 1) Label nodes by role

```bash
./deploy/scripts/k3s_label_nodes.sh <vps-t-node-name> <vps-e-node-name>
```

## 2) Prepare values override

Create `deploy/k3s/values-prod.yaml` and override at minimum:
- `controlPlane.image.repository`
- `gateway.agentImage.repository`
- `gateway.vpsT.wireguard.image`
- auth tokens
- `gateway.vpsT.publicIPv4` / `gateway.vpsE.publicIPv4`
- `controlPlane.env.defaultVpsTHost` / `defaultVpsEHost`
- xray/hysteria/wireguard configs (stored as Kubernetes Secrets by the chart)

Start from:

```bash
cp deploy/k3s/values-prod.example.yaml deploy/k3s/values-prod.yaml
```

## 3) Deploy

```bash
./deploy/scripts/k3s_helm_install.sh tracegate tracegate deploy/k3s/values-prod.yaml
```

## 4) Verify

```bash
kubectl -n tracegate get pods -o wide
kubectl -n tracegate logs deploy/tracegate-api
kubectl -n tracegate logs deploy/tracegate-gateway-vps-t -c agent
kubectl -n tracegate get job
```

## Notes

- Pods use `hostNetwork: true` for data-plane ports (`443/tcp`, `443/udp`, `51820/udp`).
- For `wireguard` container, privileged mode and `NET_ADMIN/SYS_MODULE` are enabled.
- `registration` job auto-registers node endpoints into control-plane and runs reapply/reissue.
- The gateway uses a hostPath (`/var/lib/tracegate-agent`) for runtime configs. The init container seeds files only if they are missing.
  If you change the embedded base configs in Helm values, you may need to delete the corresponding runtime file on the node
  (for example `/var/lib/tracegate-agent/runtime/hysteria/config.yaml`) and restart the gateway pod.

### Observability (optional)

Set `observability.enabled=true` to deploy Prometheus + Grafana.

- Prometheus scrapes:
  - control-plane `/metrics` (internal token)
  - agents `/metrics` (agent token)
  - node-exporter + cadvisor for node/container metrics
- Grafana is reachable only via the control-plane reverse proxy: `https://<control-plane>/grafana/`
  (login is via Telegram OTP issued by the bot).

### Namespace behavior

The chart does not create a `Namespace` resource. The install script uses `helm ... --create-namespace`.
