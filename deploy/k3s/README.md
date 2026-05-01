# Tracegate k3s Chart

`deploy/k3s/tracegate` is the public Helm chart for the current Tracegate 2.2
runtime. It contains safe defaults, placeholder values and validation logic. It
does not contain production values, live hostnames, live addresses, decoy pages
or decrypted secret material.

## Boundary

Keep these items outside the public repository:

- real production values;
- decrypted Kubernetes Secrets;
- node inventory and host policy;
- exact public endpoint layout;
- decoy site assets;
- generated client exports;
- rendered manifests from a live production overlay.

The public chart may define generic settings and validation rules. The private
overlay supplies the actual deployment-specific values.

## Chart Inputs

Safe public inputs live in:

- `tracegate/values.yaml` for chart defaults;
- `values-prod.example.yaml` for a placeholder production shape.

Private inputs should live in an ignored file outside this repository, then be
passed with `-f /path/to/private-values.yaml`.

## Render

Use Helm rendering for local validation:

```bash
helm template tracegate ./deploy/k3s/tracegate --namespace tracegate
```

For production-like validation, point the release gate at an ignored private
values file:

```bash
TRACEGATE_K3S_PROD_VALUES=/path/to/private-values.yaml \
deploy/k3s/deploy-ready-check.sh
```

Strict mode is for the operator environment. It validates that the private
overlay satisfies production safety rules without printing secret values:

```bash
TRACEGATE_STRICT_PROD=1 \
TRACEGATE_CLUSTER_PREFLIGHT=1 \
TRACEGATE_K3S_PROD_VALUES=/path/to/private-values.yaml \
deploy/k3s/deploy-ready-check.sh
```

## Deploy

Use the deploy wrapper for real promotions:

```bash
TRACEGATE_K3S_PROD_VALUES=/path/to/private-values.yaml \
deploy/k3s/deploy-prod.sh
```

The wrapper runs the release gate, verifies namespace consistency, performs a
Helm upgrade with rollback semantics and checks Kubernetes rollout health.
Set `TRACEGATE_HELM_DRY_RUN=1` to inspect the upgrade path without applying it.
`TRACEGATE_POST_DEPLOY_CHECKS=0` disables only the final smoke checks for an
operator-controlled emergency rerun. The rendered chart namespace matches `TRACEGATE_NAMESPACE`
before promotion continues.

## Operational Rules

- Keep user and connection mutations on live APIs or narrow reload hooks.
- Keep private profile material in external Secrets.
- Keep bot copy in external Secrets or private runtime storage.
- Production decoy sites must stay outside the chart. The chart does not ship a built-in decoy page.
  Decoy content must be mounted from private storage.
- Keep production images pinned by version tag or digest.
- Keep rollout and preflight guards enabled for production.
- Keep generated runtime state out of Git.
- Keep observability tuning in the private overlay when it reveals deployment
  details.

## Release Gate

The public release gate runs formatting checks, tests, Helm lint/render checks,
database migration checks and Git whitespace validation:

```bash
deploy/k3s/deploy-ready-check.sh
```

When real production values are used, the scripts validate configuration shape
and required external resources without decoding or logging secret values.
