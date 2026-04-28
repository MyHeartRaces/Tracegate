import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path

from tracegate.udp_tcp_tunnel import UdpOverTcpClient, UdpOverTcpServer


def _free_port(*, sock_type: int) -> int:
    with socket.socket(socket.AF_INET, sock_type) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def test_udp_over_tcp_roundtrip() -> None:
    backend_port = _free_port(sock_type=socket.SOCK_DGRAM)
    server_port = _free_port(sock_type=socket.SOCK_STREAM)
    client_port = _free_port(sock_type=socket.SOCK_DGRAM)
    stop_backend = threading.Event()

    def _udp_echo() -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(("127.0.0.1", backend_port))
            sock.settimeout(0.2)
            while not stop_backend.is_set():
                try:
                    payload, addr = sock.recvfrom(65535)
                except TimeoutError:
                    continue
                sock.sendto(b"echo:" + payload, addr)

    backend_thread = threading.Thread(target=_udp_echo, daemon=True)
    backend_thread.start()

    server = UdpOverTcpServer(
        tcp_bind_host="127.0.0.1",
        tcp_bind_port=server_port,
        udp_target_host="127.0.0.1",
        udp_target_port=backend_port,
        idle_timeout_seconds=30.0,
    )
    server_thread = threading.Thread(target=server.run_forever, daemon=True)
    server_thread.start()

    client = UdpOverTcpClient(
        udp_bind_host="127.0.0.1",
        udp_bind_port=client_port,
        tcp_connect_host="127.0.0.1",
        tcp_connect_port=server_port,
        connect_timeout_seconds=1.0,
        reconnect_delay_seconds=0.1,
    )
    client_thread = threading.Thread(target=client.run_forever, daemon=True)
    client_thread.start()

    time.sleep(0.3)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        sock.settimeout(5)
        sock.sendto(b"hello", ("127.0.0.1", client_port))
        payload, _ = sock.recvfrom(65535)

    client.stop()
    server.stop()
    stop_backend.set()
    client_thread.join(timeout=2)
    server_thread.join(timeout=2)
    backend_thread.join(timeout=2)

    assert payload == b"echo:hello"


def test_udp_over_tcp_roundtrip_with_tls() -> None:
    backend_port = _free_port(sock_type=socket.SOCK_DGRAM)
    server_port = _free_port(sock_type=socket.SOCK_STREAM)
    client_port = _free_port(sock_type=socket.SOCK_DGRAM)
    stop_backend = threading.Event()

    def _udp_echo() -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(("127.0.0.1", backend_port))
            sock.settimeout(0.2)
            while not stop_backend.is_set():
                try:
                    payload, addr = sock.recvfrom(65535)
                except TimeoutError:
                    continue
                sock.sendto(b"tls:" + payload, addr)

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        cert_path = tmp_path / "tls.crt"
        key_path = tmp_path / "tls.key"
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-keyout",
                str(key_path),
                "-out",
                str(cert_path),
                "-days",
                "1",
                "-nodes",
                "-subj",
                "/CN=localhost",
            ],
            check=True,
            capture_output=True,
            text=True,
        )

        backend_thread = threading.Thread(target=_udp_echo, daemon=True)
        backend_thread.start()

        server = UdpOverTcpServer(
            tcp_bind_host="127.0.0.1",
            tcp_bind_port=server_port,
            udp_target_host="127.0.0.1",
            udp_target_port=backend_port,
            tls_cert_file=str(cert_path),
            tls_key_file=str(key_path),
            tls_handshake_timeout_seconds=1.0,
            idle_timeout_seconds=30.0,
        )
        server_thread = threading.Thread(target=server.run_forever, daemon=True)
        server_thread.start()

        client = UdpOverTcpClient(
            udp_bind_host="127.0.0.1",
            udp_bind_port=client_port,
            tcp_connect_host="127.0.0.1",
            tcp_connect_port=server_port,
            tls_server_name="localhost",
            tls_ca_file=str(cert_path),
            tls_handshake_timeout_seconds=1.0,
            connect_timeout_seconds=1.0,
            reconnect_delay_seconds=0.1,
        )
        client_thread = threading.Thread(target=client.run_forever, daemon=True)
        client_thread.start()

        time.sleep(0.3)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(("127.0.0.1", 0))
            sock.settimeout(5)
            sock.sendto(b"hello", ("127.0.0.1", client_port))
            payload, _ = sock.recvfrom(65535)

        client.stop()
        server.stop()
        stop_backend.set()
        client_thread.join(timeout=2)
        server_thread.join(timeout=2)
        backend_thread.join(timeout=2)

    assert payload == b"tls:hello"
