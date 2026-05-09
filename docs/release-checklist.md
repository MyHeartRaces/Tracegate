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
- Confirm V4 fronting, TLS material, node placement and port ownership against
  the private operator runbook.
- Keep client endpoint details and import instructions out of public release
  notes.

## Private Repository

- Private values are updated when chart inputs change.
- Encrypted Secrets are current.
- Decoy assets are stored only in the private repository or on the production
  host storage expected by the private overlay.
- V4 TLS material and digest-pinned runtime images are present before
  promotion.
- Any operational notes that reveal live layout stay private.
