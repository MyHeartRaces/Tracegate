from pathlib import Path


def test_entry_opens_udp_8443_for_hysteria_chain_ingress() -> None:
    conf = Path("bundles/base-entry/nftables.conf").read_text(encoding="utf-8")
    assert "udp dport 8443 accept" in conf
    assert "tcp dport 8070 accept" in conf
    assert "udp dport 443 drop" in conf
    assert "tcp dport 8443 drop" in conf


def test_tracegate2_firewalls_do_not_depend_on_k3s_or_wireguard() -> None:
    conf_t = Path("bundles/base-transit/nftables.conf").read_text(encoding="utf-8")
    conf_e = Path("bundles/base-entry/nftables.conf").read_text(encoding="utf-8")
    for conf in (conf_t, conf_e):
        assert "10.42.0.0/16" not in conf
        assert "51821" not in conf
        assert "wg0" not in conf
        assert "k3s" not in conf


def test_transit_accepts_public_80_and_443_only_for_data_plane() -> None:
    conf_t = Path("bundles/base-transit/nftables.conf").read_text(encoding="utf-8")
    assert "tcp dport { 80, 443 } accept" in conf_t
    assert "udp dport 8443 accept" in conf_t
    assert "udp dport 443 drop" in conf_t
    assert "tcp dport 8443 drop" in conf_t


def test_firewalls_explicitly_drop_crossed_hysteria_ports_before_accept_rules() -> None:
    for path in ("bundles/base-entry/nftables.conf", "bundles/base-transit/nftables.conf"):
        conf = Path(path).read_text(encoding="utf-8")
        tcp_accept = "tcp dport 443 accept" if "tcp dport 443 accept" in conf else "tcp dport { 80, 443 } accept"
        assert conf.index("udp dport 443 drop") < conf.index("udp dport 8443 accept")
        assert conf.index("tcp dport 8443 drop") < conf.index(tcp_accept)


def test_entry_and_transit_bundles_define_proxy_fronting_stack() -> None:
    entry_haproxy = Path("bundles/base-entry/haproxy.cfg").read_text(encoding="utf-8")
    entry_nginx = Path("bundles/base-entry/nginx.conf").read_text(encoding="utf-8")
    transit_haproxy = Path("bundles/base-transit/haproxy.cfg").read_text(encoding="utf-8")
    transit_nginx = Path("bundles/base-transit/nginx.conf").read_text(encoding="utf-8")

    for haproxy_conf in (entry_haproxy, transit_haproxy):
        assert "bind :443" in haproxy_conf
        assert "127.0.0.1:2443" in haproxy_conf
        assert "127.0.0.1:4443" in haproxy_conf
        assert "timeout client 5m" in haproxy_conf
        assert "timeout server 5m" in haproxy_conf
        assert "timeout tunnel 1h" in haproxy_conf
        assert "REPLACE_TLS_SERVER_NAME" in haproxy_conf
        assert "REPLACE_REALITY_ACLS" in haproxy_conf
        assert "REPLACE_REALITY_ROUTES" in haproxy_conf
        assert "REPLACE_REALITY_BACKENDS" in haproxy_conf

    assert "REPLACE_MTPROTO_ACL" in transit_haproxy
    assert "REPLACE_MTPROTO_ROUTE" in transit_haproxy
    assert "REPLACE_MTPROTO_BACKEND" in transit_haproxy

    for nginx_conf in (entry_nginx, transit_nginx):
        assert "listen 127.0.0.1:4443 ssl http2;" in nginx_conf
        assert "proxy_pass http://127.0.0.1:10000;" in nginx_conf
        assert "proxy_connect_timeout 5s;" in nginx_conf
        assert "proxy_read_timeout 5m;" in nginx_conf
        assert "proxy_send_timeout 5m;" in nginx_conf
        assert "/etc/tracegate/tls/ws.crt" in nginx_conf

    assert "listen 80;" in transit_nginx
    assert "location ^~ /grafana/" in transit_nginx
    assert "proxy_pass http://127.0.0.1:18080;" in transit_nginx
    assert "location ^~ /v1/decoy/" not in entry_nginx
    assert "location = /vault/mtproto" not in entry_nginx
    assert "proxy_pass https://tracegate.su/vault/mtproto/" not in entry_nginx
