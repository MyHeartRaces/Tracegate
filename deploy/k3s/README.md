# Tracegate k3s Chart

`deploy/k3s/tracegate` is the public Helm chart for Tracegate. It is suitable
for local rendering, review and validation with placeholder inputs. It is not a
complete production deployment repository.

## Public Scope

This directory may contain:

- generic chart templates;
- safe default values;
- placeholder production-shaped examples;
- validation code that rejects unsafe overlays;
- public notes about required external resources.

This directory must not contain:

- live hostnames, addresses, node inventory or provider metadata;
- exact public endpoint layout;
- rendered manifests from a real environment;
- decrypted Secrets or plaintext disk encryption keys;
- decoy content;
- generated client artifacts;
- live deployment automation.

The shell wrappers in this directory are decoys that fail closed. Production promotion scripts live with the operator material.

## Chart Validation

For public review, render the chart with placeholder values:

```bash
helm lint ./deploy/k3s/tracegate
helm template tracegate ./deploy/k3s/tracegate
python3 deploy/k3s/prod-overlay-check.py \
  --chart-values deploy/k3s/tracegate/values.yaml \
  --values deploy/k3s/values-prod.example.yaml
```

Strict checks and cluster preflight are designed to run from the operator
environment with private overlays. They validate shape and prerequisites without
printing secret material.
The operator overlay supplies the actual deployment-specific values; public
examples keep placeholders.

## Required External Inputs

Real deployments must provide these inputs outside the public repository:

- control-plane secrets and database credentials;
- private profile material for gateway roles;
- TLS material and decoy content;
- node labels, annotations and host policy;
- production image pins;
- encrypted Entry and Transit runtime storage.

Entry traffic shaping and chain-client limits are enabled in public values as
guardrails. The real Entry network interface must be set in the operator
overlay.

Entry and Transit runtime directories must be provisioned on encrypted storage
before scheduling those roles. See
[docs/node-encryption-runbook.md](../../docs/node-encryption-runbook.md) for
the generic procedure.

## Operational Notes

- Keep user and connection mutations on the API or narrow reload hooks.
- Keep private profile material in external Secrets.
- Production decoy sites must stay outside the chart; the chart does not ship a built-in decoy page.
- Keep bot copy and decoy surfaces outside the public chart.
- Keep generated runtime state out of Git.
- Keep rollout and preflight guards enabled in operator gates.
- Keep observability endpoints and alert routing in operator-managed values.
- Keep public examples generic enough that they cannot identify a live
  deployment.
