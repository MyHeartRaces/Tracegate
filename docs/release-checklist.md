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

## NaiveProxy V4

- Build and push `deploy/images/naiveproxy-caddy/Dockerfile`.
- Verify `caddy list-modules` contains `http.handlers.forward_proxy`.
- Pin `gateway.images.naiveproxy.digest` in the private production overlay.
- Confirm the V4 auth hostname, TLS Secret, `naiveproxy.tcpExposure=demux`,
  Transit node selector, `tcp/11443` backend and `udp/443` ownership in the
  private overlay.
- Confirm Transit HAProxy demuxes the configured auth hostname from public
  `tcp/443` to `127.0.0.1:11443`.
- Confirm Hysteria remains on `udp/4443`.

## Private Repository

- Private values are updated when chart inputs change.
- Encrypted Secrets are current.
- Decoy assets are stored only in the private repository or on the production
  host storage expected by the private overlay.
- The NaiveProxy auth-domain TLS Secret and digest-pinned Caddy image are
  present before promotion.
- Any operational notes that reveal live layout stay private.
