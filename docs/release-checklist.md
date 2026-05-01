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
deploy/k3s/deploy-ready-check.sh
```

For production promotion, run the strict gate with private values from the
operator environment.

## Private Repository

- Private values are updated when chart inputs change.
- Encrypted Secrets are current.
- Decoy assets are stored only in the private repository or on the production
  host storage expected by the private overlay.
- Any operational notes that reveal live layout stay private.
