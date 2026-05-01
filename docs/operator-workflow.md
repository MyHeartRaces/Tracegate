# Operator Workflow

This document is intentionally high level. Concrete production values, live
endpoint names, host policy and decoy content belong to the private deployment
repository.

## Local Work

1. Update application code, chart templates or tests in the public repository.
2. Keep placeholders in public examples.
3. Run local checks:

```bash
python3 -m ruff check .
pytest -q
```

## Private Overlay Work

1. Update encrypted secrets or ignored private values in the private repository.
2. Keep raw secret files untracked unless they are encrypted.
3. Keep decoy assets and generated client artifacts private.
4. Run the strict deployment gate from the operator environment.

## Promotion

1. Render the chart with private values.
2. Run the release gate.
3. Deploy with the wrapper.
4. Verify bot, API, gateway health and Grafana OTP flow.
5. Watch alert delivery long enough to catch noisy or missing signals.

## Cleanup

Routine cleanup should remove stale bot message references, expired one-time
tokens, failed outbox rows that are no longer actionable, revoked connection
material and old Kubernetes rollout artifacts. Keep only the retention window
needed for rollback and incident review.
