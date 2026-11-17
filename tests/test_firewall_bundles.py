from pathlib import Path


def test_entry_opens_only_the_udp_4443_interconnect() -> None:
    conf = Path("bundles/base-entry/nftables.conf").read_text(encoding="utf-8")
    # Entry Hysteria was retired in 4.1.2: public UDP/443 is no longer accepted
    # on Entry (the default drop policy covers it); UDP/4443 stays the
    # Entry<->Endpoint interconnect.
    assert "udp dport 4443 accept" in conf
    assert "udp dport { 443, 4443 } accept" not in conf
    assert not [line for line in conf.splitlines() if "udp dport" in line and "443" in line.replace("4443", "").replace("8443", "")]
    assert "tcp dport 443 accept" in conf
    assert "tcp dport { 4443, 8443 } drop" in conf
    assert "tcp dport 8070 accept" in conf
    assert "udp dport 443 drop" not in conf
    assert "udp dport 8443 drop" in conf


def test_entry_haproxy_does_not_claim_loopback_443() -> None:
    conf = Path("bundles/base-entry/haproxy.cfg").read_text(encoding="utf-8")
    assert "bind REPLACE_ENTRY_BIND_HOST:443" in conf
    assert "bind :443" not in conf


def test_tracegate2_firewalls_do_not_depend_on_cluster_runtime_or_wireguard() -> None:
    conf_t = Path("bundles/base-transit/nftables.conf").read_text(encoding="utf-8")
    conf_e = Path("bundles/base-entry/nftables.conf").read_text(encoding="utf-8")
    for conf in (conf_t, conf_e):
        assert "10.42.0.0/16" not in conf
        assert "51821" not in conf
        assert "wg0" not in conf
        assert "KUBE-" not in conf


def test_transit_accepts_public_hysteria_and_interconnect_udp_ports() -> None:
    conf_t = Path("bundles/base-transit/nftables.conf").read_text(encoding="utf-8")
    # Endpoint TCP/8443 is a declared public HAProxy listener; UDP/8443 stays dropped.
    assert "tcp dport { 80, 443, 8443 } accept" in conf_t
    assert "tcp dport 4443 drop" in conf_t
    assert "tcp dport { 4443, 8443 } drop" not in conf_t
    assert "udp dport { 443, 4443, 8444 } accept" in conf_t
    assert "udp dport 443 drop" not in conf_t
    assert "udp dport 8443 drop" in conf_t


def test_interserver_tcp_links_are_materialized_as_source_gated() -> None:
    entry = Path("bundles/base-entry/nftables.conf").read_text(encoding="utf-8")
    transit = Path("bundles/base-transit/nftables.conf").read_text(encoding="utf-8")

    assert "BEGIN tracegate-managed-mtproto-mask-firewall" in entry
    assert "tcp dport 10444 drop" in entry
    assert "BEGIN tracegate-managed-entry-link-firewall" in transit
    assert "tcp dport { 9443, 9444, 9445, 9446 } drop" in transit


def test_firewalls_explicitly_drop_crossed_hysteria_ports_before_accept_rules() -> None:
    for path in ("bundles/base-entry/nftables.conf", "bundles/base-transit/nftables.conf"):
        conf = Path(path).read_text(encoding="utf-8")
        tcp_accept = "tcp dport 443 accept" if "tcp dport 443 accept" in conf else "tcp dport { 80, 443, 8443 } accept"
        tcp_drop = "tcp dport { 4443, 8443 } drop" if "base-entry" in path else "tcp dport 4443 drop"
        udp_accept = (
            "udp dport { 443, 4443, 8444 } accept"
            if "base-transit" in path
            else "udp dport 4443 accept"
        )
        assert conf.index("udp dport 8443 drop") < conf.index(udp_accept)
        assert conf.index(tcp_drop) < conf.index(tcp_accept)


def test_entry_and_transit_bundles_define_proxy_fronting_stack() -> None:
    entry_haproxy = Path("bundles/base-entry/haproxy.cfg").read_text(encoding="utf-8")
    entry_nginx = Path("bundles/base-entry/nginx.conf").read_text(encoding="utf-8")
    transit_haproxy = Path("bundles/base-transit/haproxy.cfg").read_text(encoding="utf-8")
    transit_nginx = Path("bundles/base-transit/nginx.conf").read_text(encoding="utf-8")

    for haproxy_conf in (entry_haproxy, transit_haproxy):
        assert "127.0.0.1:2443" in haproxy_conf
        assert "127.0.0.1:10443" in haproxy_conf
        assert "timeout client 5m" in haproxy_conf
        assert "timeout server 5m" in haproxy_conf
        assert "timeout tunnel 1h" in haproxy_conf
        assert "REPLACE_TLS_SERVER_NAME" in haproxy_conf
        assert "REPLACE_REALITY_ACLS" in haproxy_conf
        assert "REPLACE_REALITY_ROUTES" in haproxy_conf
        assert "REPLACE_REALITY_BACKENDS" in haproxy_conf

    assert "bind REPLACE_ENTRY_BIND_HOST:443" in entry_haproxy
    assert "bind :443" in transit_haproxy
    assert "bind :8443" in transit_haproxy
    assert ":8443" not in entry_haproxy

    assert "REPLACE_MTPROTO_ACL" in transit_haproxy
    assert "REPLACE_MTPROTO_ROUTE" in transit_haproxy
    assert "REPLACE_MTPROTO_BACKEND" in transit_haproxy

    for nginx_conf in (entry_nginx, transit_nginx):
        assert "listen 127.0.0.1:10443 ssl;" in nginx_conf
        assert "/etc/tracegate/tls/ws.crt" in nginx_conf
        assert "root /var/www/decoy;" in nginx_conf
        # Unknown paths answer 404 from the cover site instead of the home page.
        assert "try_files $uri $uri/ =404;" in nginx_conf
        assert "/index.html;" not in nginx_conf
        assert "error_page 404 /404.html;" in nginx_conf
        # The client VLESS gRPC-TLS surface was retired in 4.1.1.
        assert "grpc_pass" not in nginx_conf
        assert "location /tracegate.v1.Edge/" not in nginx_conf

    # Entry no longer proxies client VLESS WS; Endpoint keeps /ws only as the
    # MTProto entry-local-endpoint-egress carrier.
    assert "location /ws" not in entry_nginx
    assert "127.0.0.1:10000" not in entry_nginx
    assert "proxy_pass http://127.0.0.1:10000;" in transit_nginx
    assert "proxy_connect_timeout 5s;" in transit_nginx
    assert "proxy_read_timeout 5m;" in transit_nginx
    assert "proxy_send_timeout 5m;" in transit_nginx

    assert "listen 80;" in transit_nginx
    assert "location ^~ /grafana/" in transit_nginx
    assert "location /wgws" not in transit_nginx
    assert "127.0.0.1:51821" not in transit_nginx
    assert "proxy_pass http://127.0.0.1:18080;" in transit_nginx
    assert "location ^~ /v1/decoy/" not in entry_nginx
    assert "location ^~ /api/account/" not in entry_nginx
    # The cover-site sign-in has a neutral public path on Endpoint that is
    # rewritten to the existing agent handlers; the old path stays.
    assert "location ^~ /api/account/" in transit_nginx
    assert "rewrite ^/api/account/(.*)$ /v1/decoy/$1 break;" in transit_nginx
    assert "location ^~ /v1/decoy/" in transit_nginx
    assert transit_nginx.count("proxy_pass REPLACE_TRANSIT_DECOY_UPSTREAM;") == 2
    assert "location = /vault/mtproto" not in entry_nginx
    assert "proxy_pass https://tracegate.test/vault/mtproto/" not in entry_nginx
    assert "listen 127.0.0.1:443 ssl;" in entry_nginx


def test_nginx_templates_enable_http2_per_server_not_on_listen() -> None:
    root = Path(__file__).resolve().parents[1]
    for name in ("base-entry", "base-transit"):
        nginx_conf = (root / "bundles" / name / "nginx.conf").read_text(encoding="utf-8")
        assert " ssl http2;" not in nginx_conf
        assert "http2 on;" in nginx_conf
