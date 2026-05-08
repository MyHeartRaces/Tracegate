# V4 NaiveProxy Architecture

Tracegate V4 is a dedicated NaiveProxy profile for high-stealth direct access.
It is intentionally separate from the existing Transit/Entry gateway pod so it
can own `tcp/443` and `udp/443` without sharing the Hysteria2 or HAProxy surface.

## Public Contract

- Profile key: `v4direct`
- Profile label: `v4-direct-naiveproxy`
- Display label: `V4-Direct-NaiveProxy`
- Protocol enum: `NAIVEPROXY`
- Delivery role: `NAIVEPROXY`
- Runtime profile: `tracegate-naiveproxy-v4`
- Public domain: the configured auth-shaped NaiveProxy hostname.
- Public ports: `tcp/443` for HTTPS fallback and `udp/443` for HTTP/3/QUIC
- Hysteria2 public UDP remains `udp/4443`

## Pod Model

The k3s chart renders a dedicated `naiveproxy` Deployment with `hostNetwork`
enabled and a required node selector. The pod contains:

- `agent`: receives only `NAIVEPROXY` role artifacts and writes the live Caddyfile.
- `caddy`: a Caddy build with the Naive forwardproxy module; it watches the
  generated Caddyfile and reloads in-process.

This keeps V4 away from the Transit HAProxy TCP demux and avoids the impossible
case of Caddy and HAProxy both binding `tcp/443` in the same network namespace.

## Stealth Defaults

- The public hostname is an auth-shaped domain.
- Client credentials are connection-scoped HTTP Basic auth values.
- Unauthenticated HTTP requests receive auth/OIDC-shaped decoy responses:
  `/auth/login`, `/auth/session`, `/auth/token`, `/oauth2/authorize`,
  `/oauth2/token`, and `/.well-known/openid-configuration`.
- Caddy forwardproxy is rendered with `hide_ip`, `hide_via`, and
  `probe_resistance`.
- Client exports prefer a `quic://user:pass@<auth-host>` endpoint and include an
  `https://` fallback JSON for clients where QUIC performs worse.

## Image Requirement

The chart image `gateway.images.naiveproxy` must point to a Caddy build that
contains the Naive forwardproxy module:

```bash
docker build -f deploy/images/naiveproxy-caddy/Dockerfile -t tracegate-naiveproxy-caddy:local .
docker run --rm tracegate-naiveproxy-caddy:local caddy list-modules | grep -Fx http.handlers.forward_proxy
```

The image Dockerfile runs the same module check during build. Production
overlays must pin the operator-built image digest.
