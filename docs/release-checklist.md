# Release Checklist

Use this checklist before pushing a public Tracegate release.

## Public Repository

- `git status` contains only intentional changes.
- Public docs do not include live domains, live addresses, exact production
  ports or deployment-specific topology.
- Public examples use placeholders or reserved documentation values.
- Decoy sites and raw client exports are absent.
- Secrets are referenced through external Secret names, not inline values.

## Validation

```bash
python3 -m ruff check .
pytest -q
git diff --check
python3 scripts/check_public_release.py
```

For chart changes:

```bash
helm lint ./deploy/k3s/tracegate
helm template tracegate ./deploy/k3s/tracegate
python3 deploy/k3s/prod-overlay-check.py --strict \
  --chart-values deploy/k3s/tracegate/values.yaml \
  --values deploy/k3s/values-prod.yaml
```

Production promotion gates run from the operator environment.

Build release assets only through `scripts/build_release_artifacts.sh`. It
exports a clean tracked tree, scans the source and every unpacked artifact,
then produces Python, Helm and generic bundle packages plus `SHA256SUMS`.

## Endpoint First

- Confirm Endpoint has four distinct IPv4 addresses: one service/egress and
  three ingress shards.
- Confirm only `gateway-endpoint` renders in `endpoint-first`.
- Run `pod-runtime-readiness.py` and confirm WGWS, MTG and all Endpoint
  runtimes are pod containers.
- Confirm gateway state is PVC-backed and no Endpoint gateway volume uses
  hostPath.
- Confirm Endpoint nftables blocks client ports on service/egress IP.
- Validate sustained payload for Direct and every Backup profile.
- Confirm the service/egress IP is the only observed client egress identity.

## Full Backhaul

- Render and apply both Universal Entry nftables policies.
- Verify sustained authenticated payload through the SS2022/ShadowTLS primary.
- Verify the Xray observatory switches away from a failed ShadowTLS primary
  without parallel dial bursts.
- Verify Hysteria2/Gecko fallback transfers TCP and UDP after the ShadowTLS
  primary is unavailable.
- Confirm Entry has no direct user-traffic egress during every failure test.

## MTProto

- Confirm Telemt runs only in the Endpoint gateway pod and its native health
  checks pass.
- Confirm Entry TCP/443 routes the configured FakeTLS SNI to Endpoint TCP/443.
- Confirm Endpoint TCP/443 accepts that MTProto SNI only from Entry source
  addresses.
- Confirm the public profile uses the DNS-only Entry hostname, TLS transport,
  a validated decoy domain and per-user secrets.
- Confirm `front-g.example.net` and `splitter.front-m.example.net` are absent from active SNI fields.
- Test sustained Telegram traffic through the Endpoint egress path.

## Private Repository

- Private values are updated when chart inputs change.
- Encrypted Secrets are current.
- Decoy assets are stored only in the private repository and mounted through
  the production ConfigMap/PVC expected by the private overlay.
- MTProto and backhaul image pins are present before promotion.
- Any operational notes that reveal live layout stay private.
- In `entry-endpoint` mode, cluster preflight reports no legacy Transit or
  chain-Transit nodes.

## Recovery

- Confirm the PostgreSQL backup CronJob completed against an off-node encrypted
  Restic repository.
- Confirm the latest scheduled restore-check completed in a disposable
  PostgreSQL instance.
- Confirm repository credentials exist only in an encrypted external Secret.
