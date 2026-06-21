from __future__ import annotations

import argparse
import logging

from tracegate.observability import configure_logging
from tracegate.udp_tcp_tunnel import UdpOverTcpClient, UdpOverTcpServer


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="tracegate-udp-tcp-tunnel")
    parser.add_argument("--log-level", default="INFO")
    subparsers = parser.add_subparsers(dest="mode", required=True)

    server = subparsers.add_parser("server")
    server.add_argument("--tcp-bind-host", required=True)
    server.add_argument("--tcp-bind-port", required=True, type=int)
    server.add_argument("--udp-target-host", required=True)
    server.add_argument("--udp-target-port", required=True, type=int)
    server.add_argument("--tls-cert-file")
    server.add_argument("--tls-key-file")
    server.add_argument("--tls-handshake-timeout-seconds", type=float, default=5.0)
    server.add_argument("--idle-timeout-seconds", type=float, default=300.0)

    client = subparsers.add_parser("client")
    client.add_argument("--udp-bind-host", required=True)
    client.add_argument("--udp-bind-port", required=True, type=int)
    client.add_argument("--tcp-connect-host", required=True)
    client.add_argument("--tcp-connect-port", required=True, type=int)
    client.add_argument("--tls-server-name")
    client.add_argument("--tls-ca-file")
    client.add_argument("--tls-insecure-skip-verify", action="store_true")
    client.add_argument("--tls-handshake-timeout-seconds", type=float, default=5.0)
    client.add_argument("--connect-timeout-seconds", type=float, default=5.0)
    client.add_argument("--reconnect-delay-seconds", type=float, default=1.0)
    return parser


def main() -> None:
    parser = _parser()
    args = parser.parse_args()
    configure_logging(str(args.log_level))

    if args.mode == "server":
        UdpOverTcpServer(
            tcp_bind_host=args.tcp_bind_host,
            tcp_bind_port=int(args.tcp_bind_port),
            udp_target_host=args.udp_target_host,
            udp_target_port=int(args.udp_target_port),
            tls_cert_file=args.tls_cert_file,
            tls_key_file=args.tls_key_file,
            tls_handshake_timeout_seconds=float(args.tls_handshake_timeout_seconds),
            idle_timeout_seconds=float(args.idle_timeout_seconds),
            logger=logging.getLogger("tracegate.udp_tcp_tunnel.server"),
        ).run_forever()
        return

    UdpOverTcpClient(
        udp_bind_host=args.udp_bind_host,
        udp_bind_port=int(args.udp_bind_port),
        tcp_connect_host=args.tcp_connect_host,
        tcp_connect_port=int(args.tcp_connect_port),
        tls_server_name=args.tls_server_name,
        tls_ca_file=args.tls_ca_file,
        tls_insecure_skip_verify=bool(args.tls_insecure_skip_verify),
        tls_handshake_timeout_seconds=float(args.tls_handshake_timeout_seconds),
        connect_timeout_seconds=float(args.connect_timeout_seconds),
        reconnect_delay_seconds=float(args.reconnect_delay_seconds),
        logger=logging.getLogger("tracegate.udp_tcp_tunnel.client"),
    ).run_forever()
