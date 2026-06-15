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

## Universal Entry Backhaul

- Render and apply both Universal Entry nftables policies.
- Verify every XHTTP shard transfers sustained authenticated payload through
  its own SNI, REALITY destination and path.
- Verify Xray observatory removes a failed XHTTP shard without parallel dial
  bursts.
- Verify Hysteria2/Salamander fallback transfers TCP and UDP after all XHTTP
  shards are unavailable.
- Confirm Endpoint backhaul UDP/443 accepts only configured Entry source
  addresses.
- Confirm private legacy link-crypto remains isolated on UDP/4443.
- Confirm Entry has no direct user-traffic egress during every failure test.

## MTProto

- Confirm Telemt runs only on Endpoint and is loopback-bound.
- Confirm Entry TCP/443 routes only the validated FakeTLS SNI to the local
  MTProto tunnel inbound.
- Confirm Endpoint has no public MTProto frontend in tunnel mode.
- Confirm Telemt renders `proxy_protocol = false` in tunnel mode.
- Confirm the public address hostname differs from the FakeTLS SNI.
- Confirm `yandex.ru` and `splitter.wb.ru` are absent from active SNI fields.
- Test sustained Telegram traffic through the Endpoint egress path.

## Private Repository

- Private values are updated when chart inputs change.
- Encrypted Secrets are current.
- Decoy assets are stored only in the private repository or on the production
  host storage expected by the private overlay.
- Telemt and backhaul image pins are present before promotion.
- Any operational notes that reveal live layout stay private.
- In `entry-endpoint` mode, cluster preflight reports no legacy Transit or
  chain-Transit nodes.
