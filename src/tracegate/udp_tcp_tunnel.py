from __future__ import annotations

import logging
import select
import socket
import struct
import time
from dataclasses import dataclass, field
from threading import Event

_FRAME_HEADER = struct.Struct("!H")
_MAX_DATAGRAM_SIZE = 65535


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError("unexpected EOF")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _recv_frame(sock: socket.socket) -> bytes:
    header = _recv_exact(sock, _FRAME_HEADER.size)
    (size,) = _FRAME_HEADER.unpack(header)
    return _recv_exact(sock, size)


def _send_frame(sock: socket.socket, payload: bytes) -> None:
    if len(payload) > _MAX_DATAGRAM_SIZE:
        raise ValueError("payload too large for framed UDP-over-TCP tunnel")
    sock.sendall(_FRAME_HEADER.pack(len(payload)) + payload)


@dataclass(slots=True)
class UdpOverTcpServer:
    tcp_bind_host: str
    tcp_bind_port: int
    udp_target_host: str
    udp_target_port: int
    idle_timeout_seconds: float = 300.0
    accept_timeout_seconds: float = 1.0
    logger: logging.Logger = field(default_factory=lambda: logging.getLogger("tracegate.udp_tcp_tunnel.server"))
    _stop_event: Event = field(default_factory=Event, init=False, repr=False)

    def stop(self) -> None:
        self._stop_event.set()

    def run_forever(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((self.tcp_bind_host, self.tcp_bind_port))
            listener.listen(8)
            listener.settimeout(self.accept_timeout_seconds)
            self.logger.info(
                "udp_tcp_tunnel_server_started tcp_bind=%s:%s udp_target=%s:%s",
                self.tcp_bind_host,
                self.tcp_bind_port,
                self.udp_target_host,
                self.udp_target_port,
            )
            while not self._stop_event.is_set():
                try:
                    conn, addr = listener.accept()
                except TimeoutError:
                    continue
                except OSError:
                    if self._stop_event.is_set():
                        break
                    raise

                try:
                    self._handle_connection(conn, addr)
                finally:
                    try:
                        conn.close()
                    except OSError:
                        pass

    def _handle_connection(self, conn: socket.socket, addr: tuple[str, int]) -> None:
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.logger.info("udp_tcp_tunnel_server_client_connected peer=%s:%s", addr[0], addr[1])
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_sock:
            udp_sock.connect((self.udp_target_host, self.udp_target_port))
            last_activity = time.monotonic()
            while not self._stop_event.is_set():
                idle_left = self.idle_timeout_seconds - (time.monotonic() - last_activity)
                if idle_left <= 0:
                    self.logger.warning(
                        "udp_tcp_tunnel_server_idle_timeout peer=%s:%s idle_timeout_seconds=%.1f",
                        addr[0],
                        addr[1],
                        self.idle_timeout_seconds,
                    )
                    return
                readable, _, _ = select.select([conn, udp_sock], [], [], min(idle_left, 1.0))
                if not readable:
                    continue
                if conn in readable:
                    payload = _recv_frame(conn)
                    udp_sock.send(payload)
                    last_activity = time.monotonic()
                if udp_sock in readable:
                    payload = udp_sock.recv(_MAX_DATAGRAM_SIZE)
                    _send_frame(conn, payload)
                    last_activity = time.monotonic()


@dataclass(slots=True)
class UdpOverTcpClient:
    udp_bind_host: str
    udp_bind_port: int
    tcp_connect_host: str
    tcp_connect_port: int
    reconnect_delay_seconds: float = 1.0
    connect_timeout_seconds: float = 5.0
    logger: logging.Logger = field(default_factory=lambda: logging.getLogger("tracegate.udp_tcp_tunnel.client"))
    _stop_event: Event = field(default_factory=Event, init=False, repr=False)

    def stop(self) -> None:
        self._stop_event.set()

    def run_forever(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_sock:
            udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            udp_sock.bind((self.udp_bind_host, self.udp_bind_port))
            self.logger.info(
                "udp_tcp_tunnel_client_started udp_bind=%s:%s tcp_connect=%s:%s",
                self.udp_bind_host,
                self.udp_bind_port,
                self.tcp_connect_host,
                self.tcp_connect_port,
            )
            current_udp_peer: tuple[str, int] | None = None

            while not self._stop_event.is_set():
                try:
                    tcp_sock = socket.create_connection(
                        (self.tcp_connect_host, self.tcp_connect_port),
                        timeout=self.connect_timeout_seconds,
                    )
                except OSError as exc:
                    self.logger.warning(
                        "udp_tcp_tunnel_client_connect_failed tcp_connect=%s:%s error=%s",
                        self.tcp_connect_host,
                        self.tcp_connect_port,
                        exc,
                    )
                    time.sleep(self.reconnect_delay_seconds)
                    continue

                with tcp_sock:
                    tcp_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    self.logger.info(
                        "udp_tcp_tunnel_client_connected tcp_connect=%s:%s",
                        self.tcp_connect_host,
                        self.tcp_connect_port,
                    )
                    try:
                        while not self._stop_event.is_set():
                            readable, _, _ = select.select([udp_sock, tcp_sock], [], [], 1.0)
                            if not readable:
                                continue
                            if udp_sock in readable:
                                payload, addr = udp_sock.recvfrom(_MAX_DATAGRAM_SIZE)
                                current_udp_peer = addr
                                _send_frame(tcp_sock, payload)
                            if tcp_sock in readable:
                                payload = _recv_frame(tcp_sock)
                                if current_udp_peer is None:
                                    self.logger.warning(
                                        "udp_tcp_tunnel_client_drop_no_peer bytes=%s",
                                        len(payload),
                                    )
                                    continue
                                udp_sock.sendto(payload, current_udp_peer)
                    except OSError as exc:
                        self.logger.warning(
                            "udp_tcp_tunnel_client_connection_lost tcp_connect=%s:%s error=%s",
                            self.tcp_connect_host,
                            self.tcp_connect_port,
                            exc,
                        )
                    except ConnectionError as exc:
                        self.logger.warning(
                            "udp_tcp_tunnel_client_connection_closed tcp_connect=%s:%s error=%s",
                            self.tcp_connect_host,
                            self.tcp_connect_port,
                            exc,
                        )
                    time.sleep(self.reconnect_delay_seconds)
