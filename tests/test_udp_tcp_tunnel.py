import socket
import tempfile
import threading
import time
from pathlib import Path

from tracegate.udp_tcp_tunnel import UdpOverTcpClient, UdpOverTcpServer

_TLS_CERT_PEM = """-----BEGIN CERTIFICATE-----
MIIC8zCCAdugAwIBAgIULiD5r26di0YFVZ0B0ejKKPqTNJ4wDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDQwMzIxMjYzM1oXDTM2MDMz
MTIxMjYzM1owFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAotsSIVdWq2Fh3Cn3p6lKFubAmToX8Ahce7IlYqHeMMUE
PNHksY5t5/hx6ZmliTAuZc+cSdEUyj7RDJfostEstvwtLgWOYIaWXTLm01SfWXip
TysjQGyUQfuCbrW5hux6jsCMTVTHPLftQmn6DfVudwhb4Vgv1kxut5QQiqCAQqRl
1tv7c6G/cQbdbx9HhNLvrKhel5ggQMDOJ0m/0vzVlpKtp8IxSynxA9R55uYGbLbP
aCTWr3XgTIR5J7BgQ6SiMcYzXdQoIicw6BXc/CXQ7hXwNtw3hpxhPMRxOwaMHQUD
5Sbe9xL9q6QLmm6dm4vrdYQcQo7JO8yGcSPhhTOFdwIDAQABoz0wOzAaBgNVHREE
EzARgglsb2NhbGhvc3SHBH8AAAEwHQYDVR0OBBYEFNxiw4MT52lyHa0zNqnOx6H5
oxOQMA0GCSqGSIb3DQEBCwUAA4IBAQCfje5EPNPKdVo2L2jn4lw2fAdwa4y26fGY
+mquoAfWasmY+ZUM/BSp2KJoPhHmweoGm3KB5vj9WFs8H/L2dsC5lY4x+ASR+bzb
rO6ejjgc9kKxa0u096/QERdIf+szpPMzVZvcM8nVdooeHaDFnjNXfrv+KW0AO6hb
zm0ENZn9n+LInhvXh3r5E+dxzZmTyOlAFF5AmhHW8FMXwTQmXllTq70+VQl/qlcc
nPp8ugkHkBbGQlHrwHEaJ6u8HDsqVTpbv9d21uPM3/k8bvJAiUtr95W6Z7PMQpB2
TOSeoRxroWdd2SItwfGwt2c/OO/HsPcvwRPzKpA9kfE2VW0eZ9WH
-----END CERTIFICATE-----
"""

_TLS_KEY_PEM = """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCi2xIhV1arYWHc
KfenqUoW5sCZOhfwCFx7siViod4wxQQ80eSxjm3n+HHpmaWJMC5lz5xJ0RTKPtEM
l+iy0Sy2/C0uBY5ghpZdMubTVJ9ZeKlPKyNAbJRB+4JutbmG7HqOwIxNVMc8t+1C
afoN9W53CFvhWC/WTG63lBCKoIBCpGXW2/tzob9xBt1vH0eE0u+sqF6XmCBAwM4n
Sb/S/NWWkq2nwjFLKfED1Hnm5gZsts9oJNavdeBMhHknsGBDpKIxxjNd1CgiJzDo
Fdz8JdDuFfA23DeGnGE8xHE7BowdBQPlJt73Ev2rpAuabp2bi+t1hBxCjsk7zIZx
I+GFM4V3AgMBAAECggEABSLXmDRC8tKEiD/psn0TNOKVRU4Snk4+Fx0MT3WUwsga
/6nTaicGrhwzHUh6j1sRbVCSqmBtCIoTEqHv2Qr+dHfQ4koEytYXWT/JDaC9X5dx
fb7PNLGbgZ2qksApyfbjwit1T4hguf+AUhSO4v6zrWQIiq1JGkY1fetY2xgqiLaU
1BxxWVIIz/wi7bx/bLNcjqLVAEaphCAUAiGOltWbDrgRNHioURA33JySZTCbiqJA
y1k/NKnHqNJXsLBDrhfU2ZnlQMqF6vr4F8heH2hERQ+PO9wnK+DiSvAKJ6NOJ7RI
f+vyK+CAv/X4UcWZzbFUA+HBgXEl4zh+vK0NkdLiAQKBgQDQYv+S6EQpB7bp7u8D
bGqXHSi0WK2eg8b4MKksawjBprC3r49cKeHGcZzvD46KMEkfyh0umUuFIyZtcJR9
dx8WFwbdaqclijVeCkmvcLW8atqrRTxr1oSxcWZ85qz2MMm4GRT9dJrKhYV6prRZ
vV4Vuog+GD6eaPLqLHvUU/cXgQKBgQDIEN13U5iOCq15cqmq+A1ceB+76p/cMcFQ
CJliqvM144zdw6wkmT9aqasu6cvSJkwRS0KnfgBQi6ClMtWnfuHUCisRk/iESu7U
ChThW9sT/Yqcn9gQfmetcw5+wnwnXywa6rQtjXpoGkAAJzUL/8+L7TA2LRExaUaj
TpBEmXfY9wKBgFCCbwtrASp4+IpY7a787BGGCnvi5vEfKHgrFLE8iR2IMS5GfbS1
2ay5qFAUSpXJIfdONwgR4cOGWQpfPH9czn3SV6yj0AAI7aVvhBhsC0rIXcNd9IIV
Vx7XGSmYVaqoHscpqZpiuosUGwXP8k3Zg8gRUSHsbAT3tyISHaVi60wBAoGAKt3C
NgEJXNXY2X7B78n6QufSFNdurSVUACv3gXaTaeZ5lkKIrcbQFkLoVMLvUvW1srbn
by/GLXvdTcgYkyzSgjYziC6mPuI3TeNjGe4ugJgAjRKKnu4WlMlkP7C4HU99Cb9k
H6aCpa+KKv47lXiYJakKfXEmj+m4ouEAdFJVpX0CgYEAuQxn3hjBR88nm3dVFKie
L07v3xjJ6i4cOtN5R++0ZqnJ2Dh9W4eSPr9ReB6/zMEQtA4IHyoxlrkD1lVk547F
slDjqJbB2EBuoMd9sFWxyZpG1xGfLURxe6/RNzX/VjmxkC2ijFRTp6ZrDdtvxffH
++eapMZNQGilYvsfo+4ntLA=
-----END PRIVATE KEY-----
"""


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
        cert_path.write_text(_TLS_CERT_PEM, encoding="utf-8")
        key_path.write_text(_TLS_KEY_PEM, encoding="utf-8")

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
