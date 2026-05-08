# Tracegate NaiveProxy Caddy Image

This image is the Caddy runtime used by the V4 NaiveProxy gateway pod. It is a
standard Caddy image rebuilt with the Naive forward_proxy module.

Build locally:

```bash
docker build \
  -f deploy/images/naiveproxy-caddy/Dockerfile \
  --build-arg VCS_REF="$(git rev-parse HEAD)" \
  -t tracegate-naiveproxy-caddy:local \
  .
```

Verify the module:

```bash
docker run --rm tracegate-naiveproxy-caddy:local caddy list-modules | grep -Fx http.handlers.forward_proxy
```

Production values must reference a registry-pushed image by immutable digest.
