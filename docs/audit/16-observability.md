# Observability

Metrics, health, alerting, and the Grafana handoff. Observability is built to give
operators visibility without leaking user identity (pseudonymous labels) or
becoming an attack surface.

## 1. HTTP metrics

`src/tracegate/observability.py` installs a middleware on every FastAPI app
(`install_http_observability(app, component=...)`) exporting Prometheus:

- `*_http_requests_total` (Counter) — by component, method, route label, status.
- `*_http_request_duration_seconds` (Histogram) — request latency.

Route labels are normalised (`_route_label`) so cardinality stays bounded.
`configure_logging(level)` sets structured logging from `log_level`.

## 2. Per-component metrics

- **Dispatcher** (`dispatcher_metrics_*`, default `:9091`) — outbox processing,
  delivery outcomes, retries.
- **Bot** (`bot_metrics_*`, default `:9092`).
- **Agent** (`agent/metrics.py`) — reconcile outcomes, health-check results.
- **Hysteria2** — traffic stats API on loopback `:9999`, secret-protected; the
  agent verifies the stats secret as a health check
  (`check_hysteria_stats_secret`).
- **Xray** — StatsService via the gRPC API (per-user up/down link counters), used
  for live usage without restarts.

## 3. Health checks (runtime contract)

`agent/system.py::gather_health_checks` validates the runtime contract for the
role: expected ports are listening, **forbidden ports are not** (e.g. the
forbidden public TCP/8443), required processes are running, and the Hysteria
stats API authenticates. Port checks are deliberately strict (separate TCP/UDP
`ss` queries, `/proc/net` fallback) to avoid false positives. The agent serves
`/v1/health` (readiness) and `/v1/live` (liveness) consumed by the k3s probes.

DPI-aware health philosophy (`docs/dpi-research-notes.md`): a check must transfer
**sustained authenticated payload**, because some filtering modes allow a
handshake then freeze the flow — a handshake-only probe would report false health.

## 4. Alerting

The dispatcher runs periodic ops checks (`dispatcher_ops_alerts_*`): disk
threshold, dead-outbox threshold, and a Prometheus query path, delivering Telegram
alerts to admins/superadmins with repeat/suppress/resolved semantics. Grafana
Alerting can post to an internal webhook (`grafana_alerts_webhook_*`) → Tracegate
API → Telegram.

## 5. Grafana handoff

Grafana is optional (`grafana_enabled`). Users/operators reach it via a
**signed, expiring OTP handoff** rather than shared credentials: `GrafanaOtp`
rows + HMAC-signed handoff URLs (`api/routers/grafana.py`, `compare_digest`
verify), with pseudonymous login IDs derived from the pseudonym secret so Grafana
never sees raw Telegram IDs. nginx proxies `/grafana/` on the TLS vhost; sessions
use a TTL.

## 6. Privacy posture

Metric labels and Grafana logins are **pseudonymous** (HMAC-derived), never raw
connection or Telegram IDs (`services/pseudonym.py`). This keeps operational
visibility from becoming a de-anonymisation vector — consistent with the project's
"separation, not anonymity" stance.
