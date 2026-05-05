# Operator Workflow

This document is intentionally high level. Live deployment material stays
outside the public source tree.

## Local Work

1. Update application code, chart templates or tests in the public repository.
2. Keep placeholders in public examples.
3. Run local checks:

```bash
python3 -m ruff check .
pytest -q
```

## Operator Overlay Work

1. Update encrypted secrets or ignored operator values.
2. Keep raw secret files untracked unless they are encrypted.
3. Keep decoy assets and generated client artifacts private.
4. Before scheduling Entry or Transit, provision encrypted runtime storage with
   `docs/node-encryption-runbook.md` and annotate only verified nodes.
5. Run the strict deployment gate from the operator environment.

## Promotion

1. Render the chart with operator values.
2. Run the operator release gate.
3. Deploy with operator automation.
4. Verify bot, API, gateway health and Grafana OTP flow.
5. Watch alert delivery long enough to catch noisy or missing signals.

## Cleanup

Routine cleanup should remove stale bot message references, expired one-time
tokens, failed outbox rows that are no longer actionable, revoked connection
material and old Kubernetes rollout artifacts. Keep only the retention window
needed for rollback and incident review.
