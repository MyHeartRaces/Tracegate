from tracegate.client_export.v2rayn import export_v2rayn


def test_export_vless_reality_uri() -> None:
    effective = {
        "protocol": "vless",
        "server": "t.example.com",
        "port": 443,
        "uuid": "11111111-2222-3333-4444-555555555555",
        "sni": "google.com",
        "reality": {"public_key": "PUBKEY", "short_id": "abcd"},
        "profile": "B1-stealth-direct",
    }
    out = export_v2rayn(effective)
    assert out.kind == "uri"
    assert out.content.startswith("vless://11111111-2222-3333-4444-555555555555@t.example.com:443?")
    assert "security=reality" in out.content
    assert "sni=google.com" in out.content
    assert "pbk=PUBKEY" in out.content
    assert "sid=abcd" in out.content


def test_export_hysteria2_uri() -> None:
    effective = {
        "protocol": "hysteria2",
        "server": "t.example.com",
        "port": 443,
        "auth": {"type": "userpass", "username": "u", "password": "p"},
        "profile": "B3-h3-mimic-direct",
    }
    out = export_v2rayn(effective)
    assert out.kind == "uri"
    assert out.content.startswith("hysteria2://u:p@t.example.com:443/")
    assert "insecure=1" in out.content


def test_export_vless_ws_tls_uri() -> None:
    effective = {
        "protocol": "vless",
        "transport": "ws_tls",
        "server": "t.example.com",
        "port": 443,
        "uuid": "11111111-2222-3333-4444-555555555555",
        "sni": "t.example.com",
        "ws": {"path": "/ws", "host": "t.example.com"},
        "tls": {"server_name": "t.example.com", "insecure": True},
        "profile": "B1-https-ws-direct",
    }
    out = export_v2rayn(effective)
    assert out.kind == "uri"
    assert out.content.startswith("vless://11111111-2222-3333-4444-555555555555@t.example.com:443?")
    assert "security=tls" in out.content
    assert "type=ws" in out.content
    assert "alpn=" not in out.content
    assert "fp=" not in out.content
    assert "path=/ws" in out.content
    assert "host=t.example.com" in out.content
    assert "allowInsecure=1" in out.content


def test_export_wireguard_conf() -> None:
    effective = {
        "protocol": "wireguard",
        "endpoint": "t.example.com:51820",
        "interface": {"addresses": ["10.70.0.2/32"], "private_key": "PRIV", "dns": ["1.1.1.1"], "mtu": 1420},
        "peer": {"public_key": "PUB", "allowed_ips": ["0.0.0.0/0"], "persistent_keepalive": 25},
        "profile": "B5-gaming-direct",
    }
    out = export_v2rayn(effective)
    assert out.kind == "wg_conf"
    assert "[Interface]" in out.content
    assert "Endpoint = t.example.com:51820" in out.content
