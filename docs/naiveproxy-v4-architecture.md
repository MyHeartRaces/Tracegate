# V4 NaiveProxy Architecture

Tracegate V4 is a dedicated NaiveProxy profile for high-stealth direct access.
It runs as a separate managed runtime surface. Public endpoint placement,
fronting and port ownership are operator-runbook details and must not be
duplicated in public user-facing copy.

## Public Contract

- Profile key: `v4direct`
- Profile label: `v4-direct-naiveproxy`
- Display label: `V4-Direct-NaiveProxy`
- Protocol enum: `NAIVEPROXY`
- Delivery role: `NAIVEPROXY`
- Runtime profile: `tracegate-naiveproxy-v4`
- Public endpoint coordinates are supplied only by the private operator overlay.
- Client-facing transport details must not be printed in chat instructions,
  public README files or release notes.

## Pod Model

The k3s chart renders a dedicated `naiveproxy` Deployment. The pod contains:

- `agent`: receives only `NAIVEPROXY` role artifacts and writes the live Caddyfile.
- `caddy`: a Caddy build with the Naive forwardproxy module; it watches the
  generated Caddyfile and reloads in-process.

The production fronting mode is validated by chart guards and private
operator checks. Exact listener mapping stays in the private runbook.

## Stealth Defaults

- Client credentials are connection-scoped HTTP Basic auth values.
- Unauthenticated HTTP requests receive auth/OIDC-shaped decoy responses.
- Caddy forwardproxy is rendered with `hide_ip`, `hide_via`, and
  `probe_resistance`.
- Client exports must avoid printing transport endpoints in chat or public
  documentation; user-specific connection material is delivered only as a
  generated client artifact.

## Image Requirement

The chart image `gateway.images.naiveproxy` must point to a Caddy build that
contains the Naive forwardproxy module:

```bash
docker build -f deploy/images/naiveproxy-caddy/Dockerfile -t tracegate-naiveproxy-caddy:local .
docker run --rm tracegate-naiveproxy-caddy:local caddy list-modules | grep -Fx http.handlers.forward_proxy
```

The image Dockerfile runs the same module check during build. Production
overlays must pin the operator-built image digest.
