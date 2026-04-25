from __future__ import annotations

import logging
import select
import socket
import ssl
import struct
import time
from dataclasses import dataclass, field
from threading import Event, Lock, Thread

_FRAME_HEADER = struct.Struct("!H")
_MAX_DATAGRAM_SIZE = 65535


def _close_quietly(sock: socket.socket) -> None:
    try:
        sock.close()
    except OSError:
        pass


def _shutdown_quietly(sock: socket.socket) -> None:
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass


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
    tls_cert_file: str | None = None
    tls_key_file: str | None = None
    tls_handshake_timeout_seconds: float = 5.0
    idle_timeout_seconds: float = 300.0
    accept_timeout_seconds: float = 1.0
    logger: logging.Logger = field(default_factory=lambda: logging.getLogger("tracegate.udp_tcp_tunnel.server"))
    _stop_event: Event = field(default_factory=Event, init=False, repr=False)

    def stop(self) -> None:
        self._stop_event.set()

    def run_forever(self) -> None:
        tls_context = self._build_server_tls_context()
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

                self._handle_connection(conn, addr, tls_context)

    def _build_server_tls_context(self) -> ssl.SSLContext | None:
        if not self.tls_cert_file and not self.tls_key_file:
            return None
        if not self.tls_cert_file or not self.tls_key_file:
            raise ValueError("server TLS requires both cert and key files")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=self.tls_cert_file, keyfile=self.tls_key_file)
        return context

    def _wrap_server_connection(
        self,
        conn: socket.socket,
        tls_context: ssl.SSLContext | None,
    ) -> socket.socket:
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if tls_context is None:
            return conn
        conn.settimeout(self.tls_handshake_timeout_seconds)
        try:
            wrapped = tls_context.wrap_socket(conn, server_side=True)
        except Exception:
            conn.settimeout(None)
            raise
        wrapped.settimeout(None)
        return wrapped

    def _handle_connection(
        self,
        conn: socket.socket,
        addr: tuple[str, int],
        tls_context: ssl.SSLContext | None,
    ) -> None:
        try:
            managed_conn = self._wrap_server_connection(conn, tls_context)
        except OSError as exc:
            self.logger.warning(
                "udp_tcp_tunnel_server_tls_failed peer=%s:%s error=%s",
                addr[0],
                addr[1],
                exc,
            )
            try:
                conn.close()
            except OSError:
                pass
            return

        self.logger.info("udp_tcp_tunnel_server_client_connected peer=%s:%s", addr[0], addr[1])
        with managed_conn:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_sock:
                udp_sock.connect((self.udp_target_host, self.udp_target_port))
                last_activity = time.monotonic()
                last_activity_lock = Lock()
                connection_closed = Event()

                def _touch() -> None:
                    nonlocal last_activity
                    with last_activity_lock:
                        last_activity = time.monotonic()

                def _tcp_to_udp() -> None:
                    try:
                        while not self._stop_event.is_set() and not connection_closed.is_set():
                            payload = _recv_frame(managed_conn)
                            self.logger.debug(
                                "udp_tcp_tunnel_server_rx_tcp peer=%s:%s bytes=%s",
                                addr[0],
                                addr[1],
                                len(payload),
                            )
                            udp_sock.send(payload)
                            _touch()
                    except (ConnectionError, OSError) as exc:
                        if not connection_closed.is_set() and not self._stop_event.is_set():
                            self.logger.warning(
                                "udp_tcp_tunnel_server_connection_lost peer=%s:%s error=%s",
                                addr[0],
                                addr[1],
                                exc,
                            )
                    finally:
                        connection_closed.set()

                def _udp_to_tcp() -> None:
                    try:
                        while not self._stop_event.is_set() and not connection_closed.is_set():
                            readable, _, _ = select.select([udp_sock], [], [], 1.0)
                            if udp_sock not in readable:
                                continue
                            payload = udp_sock.recv(_MAX_DATAGRAM_SIZE)
                            self.logger.debug(
                                "udp_tcp_tunnel_server_rx_udp peer=%s:%s bytes=%s",
                                addr[0],
                                addr[1],
                                len(payload),
                            )
                            _send_frame(managed_conn, payload)
                            _touch()
                    except OSError as exc:
                        if not connection_closed.is_set() and not self._stop_event.is_set():
                            self.logger.warning(
                                "udp_tcp_tunnel_server_udp_error peer=%s:%s error=%s",
                                addr[0],
                                addr[1],
                                exc,
                            )
                    finally:
                        connection_closed.set()

                tcp_thread = Thread(target=_tcp_to_udp, daemon=True)
                udp_thread = Thread(target=_udp_to_tcp, daemon=True)
                tcp_thread.start()
                udp_thread.start()

                while not self._stop_event.is_set() and not connection_closed.is_set():
                    with last_activity_lock:
                        idle_left = self.idle_timeout_seconds - (time.monotonic() - last_activity)
                    if idle_left <= 0:
                        self.logger.warning(
                            "udp_tcp_tunnel_server_idle_timeout peer=%s:%s idle_timeout_seconds=%.1f",
                            addr[0],
                            addr[1],
                            self.idle_timeout_seconds,
                        )
                        connection_closed.set()
                        break
                    time.sleep(min(idle_left, 0.5))

                _shutdown_quietly(managed_conn)
                _close_quietly(udp_sock)
                tcp_thread.join(timeout=1.0)
                udp_thread.join(timeout=1.0)


@dataclass(slots=True)
class UdpOverTcpClient:
    udp_bind_host: str
    udp_bind_port: int
    tcp_connect_host: str
    tcp_connect_port: int
    tls_server_name: str | None = None
    tls_ca_file: str | None = None
    tls_insecure_skip_verify: bool = False
    tls_handshake_timeout_seconds: float = 5.0
    reconnect_delay_seconds: float = 1.0
    connect_timeout_seconds: float = 5.0
    logger: logging.Logger = field(default_factory=lambda: logging.getLogger("tracegate.udp_tcp_tunnel.client"))
    _stop_event: Event = field(default_factory=Event, init=False, repr=False)

    def stop(self) -> None:
        self._stop_event.set()

    def run_forever(self) -> None:
        tls_context = self._build_client_tls_context()
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
                    raw_sock = socket.create_connection(
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

                try:
                    tcp_sock = self._wrap_client_connection(raw_sock, tls_context)
                except OSError as exc:
                    self.logger.warning(
                        "udp_tcp_tunnel_client_tls_failed tcp_connect=%s:%s error=%s",
                        self.tcp_connect_host,
                        self.tcp_connect_port,
                        exc,
                    )
                    try:
                        raw_sock.close()
                    except OSError:
                        pass
                    time.sleep(self.reconnect_delay_seconds)
                    continue

                with tcp_sock:
                    self.logger.info(
                        "udp_tcp_tunnel_client_connected tcp_connect=%s:%s",
                        self.tcp_connect_host,
                        self.tcp_connect_port,
                    )
                    connection_closed = Event()
                    current_udp_peer_lock = Lock()

                    def _udp_to_tcp() -> None:
                        nonlocal current_udp_peer
                        try:
                            while not self._stop_event.is_set() and not connection_closed.is_set():
                                readable, _, _ = select.select([udp_sock], [], [], 1.0)
                                if udp_sock not in readable:
                                    continue
                                payload, addr = udp_sock.recvfrom(_MAX_DATAGRAM_SIZE)
                                with current_udp_peer_lock:
                                    current_udp_peer = addr
                                self.logger.debug(
                                    "udp_tcp_tunnel_client_rx_udp peer=%s:%s bytes=%s",
                                    addr[0],
                                    addr[1],
                                    len(payload),
                                )
                                _send_frame(tcp_sock, payload)
                        except OSError as exc:
                            if not connection_closed.is_set() and not self._stop_event.is_set():
                                self.logger.warning(
                                    "udp_tcp_tunnel_client_connection_lost tcp_connect=%s:%s error=%s",
                                    self.tcp_connect_host,
                                    self.tcp_connect_port,
                                    exc,
                                )
                        finally:
                            connection_closed.set()

                    def _tcp_to_udp() -> None:
                        nonlocal current_udp_peer
                        try:
                            while not self._stop_event.is_set() and not connection_closed.is_set():
                                payload = _recv_frame(tcp_sock)
                                with current_udp_peer_lock:
                                    udp_peer = current_udp_peer
                                self.logger.debug(
                                    "udp_tcp_tunnel_client_rx_tcp bytes=%s has_peer=%s",
                                    len(payload),
                                    udp_peer is not None,
                                )
                                if udp_peer is None:
                                    self.logger.warning(
                                        "udp_tcp_tunnel_client_drop_no_peer bytes=%s",
                                        len(payload),
                                    )
                                    continue
                                udp_sock.sendto(payload, udp_peer)
                        except ConnectionError as exc:
                            if not connection_closed.is_set() and not self._stop_event.is_set():
                                self.logger.warning(
                                    "udp_tcp_tunnel_client_connection_closed tcp_connect=%s:%s error=%s",
                                    self.tcp_connect_host,
                                    self.tcp_connect_port,
                                    exc,
                                )
                        except OSError as exc:
                            if not connection_closed.is_set() and not self._stop_event.is_set():
                                self.logger.warning(
                                    "udp_tcp_tunnel_client_connection_lost tcp_connect=%s:%s error=%s",
                                    self.tcp_connect_host,
                                    self.tcp_connect_port,
                                    exc,
                                )
                        finally:
                            connection_closed.set()

                    udp_thread = Thread(target=_udp_to_tcp, daemon=True)
                    tcp_thread = Thread(target=_tcp_to_udp, daemon=True)
                    udp_thread.start()
                    tcp_thread.start()
                    while not self._stop_event.is_set() and not connection_closed.is_set():
                        time.sleep(0.2)
                    connection_closed.set()
                    _shutdown_quietly(tcp_sock)
                    udp_thread.join(timeout=1.0)
                    tcp_thread.join(timeout=1.0)
                    time.sleep(self.reconnect_delay_seconds)

    def _build_client_tls_context(self) -> ssl.SSLContext | None:
        if not self.tls_server_name and not self.tls_ca_file and not self.tls_insecure_skip_verify:
            return None
        context = ssl.create_default_context()
        if self.tls_ca_file:
            context.load_verify_locations(cafile=self.tls_ca_file)
        if self.tls_insecure_skip_verify:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        elif not self.tls_server_name:
            raise ValueError("client TLS verification requires tls_server_name")
        return context

    def _wrap_client_connection(
        self,
        conn: socket.socket,
        tls_context: ssl.SSLContext | None,
    ) -> socket.socket:
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if tls_context is None:
            return conn
        conn.settimeout(self.tls_handshake_timeout_seconds)
        try:
            wrapped = tls_context.wrap_socket(conn, server_hostname=self.tls_server_name)
        except Exception:
            conn.settimeout(None)
            raise
        wrapped.settimeout(None)
        return wrapped
