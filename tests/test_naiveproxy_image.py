from pathlib import Path


def test_naiveproxy_caddy_image_builds_with_naive_forwardproxy_module() -> None:
    dockerfile = (Path(__file__).resolve().parents[1] / "deploy/images/naiveproxy-caddy/Dockerfile").read_text(encoding="utf-8")

    assert "ARG CADDY_VERSION=2.9" in dockerfile
    assert "github.com/caddyserver/forwardproxy=github.com/klzgrad/forwardproxy@${FORWARDPROXY_REF}" in dockerfile
    assert "grep -Fx http.handlers.forward_proxy" in dockerfile
    assert 'org.opencontainers.image.title="tracegate-naiveproxy-caddy"' in dockerfile
