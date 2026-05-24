"""
Client-side HTTP proxy (STEPS.md §3.5).

UserAuthn starts a small TCP listener on ``127.0.0.1:18080`` while it waits
for the OAuth Device Flow to complete. Each browser connection is wrapped
in a fresh Noise-IK tunnel to SrvAuthn, with ``{"service": "proxy"}`` as
the first message; raw bytes then flow both directions until either side
closes.

There is no HTTP awareness here — we just shuttle bytes. The server-side
egress (``server/proxy.py``) connects to the IdP on the gateway host's
loopback and the bytes pass through unmodified.
"""

import json
import logging
import os
import socket
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from client import tunnel as tunnel_mod

log = logging.getLogger("userauthn.proxy")


class ProxyServer:
    """Background thread accepting TCP connections and tunneling each."""

    def __init__(self, listen_host: str, listen_port: int,
                 srv_address: str, srv_auth_port: int, server_pubkey: str):
        self.listen_host  = listen_host
        self.listen_port  = listen_port
        self.srv_address  = srv_address
        self.srv_auth_port = srv_auth_port
        self.server_pubkey = server_pubkey
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    def start(self) -> None:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.listen_host, self.listen_port))
        s.listen(32)
        s.settimeout(0.5)
        self._sock = s
        self._thread = threading.Thread(target=self._accept_loop,
                                         daemon=True, name="proxy-accept")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._sock is not None:
            try: self._sock.close()
            except OSError: pass
            self._sock = None

    # ── internals ───────────────────────────────────────────────────────────

    def _accept_loop(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                conn, addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            t = threading.Thread(
                target=self._handle, args=(conn, addr), daemon=True,
                name=f"proxy-conn-{addr[1]}",
            )
            t.start()

    def _handle(self, browser_sock: socket.socket, addr: tuple) -> None:
        log.info(f"proxy: browser connection from {addr}")
        session = None
        try:
            session = tunnel_mod.connect(
                self.srv_address, self.srv_auth_port, self.server_pubkey,
            )
            # Service select
            session.send(json.dumps({"service": "proxy"}).encode())
            ack = json.loads(session.recv().decode())
            if ack.get("status") != "ok":
                log.warning(f"proxy: server refused: {ack}")
                return

            t1 = threading.Thread(target=_pump_sock_to_tunnel,
                                  args=(browser_sock, session), daemon=True)
            t2 = threading.Thread(target=_pump_tunnel_to_sock,
                                  args=(session, browser_sock), daemon=True)
            t1.start(); t2.start()
            t1.join(); t2.join()
        except Exception as e:
            log.debug(f"proxy: connection from {addr} ended: {e}")
        finally:
            if session is not None:
                session.close()
            try: browser_sock.close()
            except OSError: pass


def _pump_sock_to_tunnel(sock: socket.socket, session) -> None:
    try:
        while True:
            data = sock.recv(16 * 1024)
            if not data:
                break
            session.send(data)
    except Exception:
        pass
    finally:
        try: session.send(b"")
        except Exception: pass


def _pump_tunnel_to_sock(session, sock: socket.socket) -> None:
    try:
        while True:
            data = session.recv()
            if not data:
                break
            sock.sendall(data)
    except Exception:
        pass
    finally:
        try: sock.shutdown(socket.SHUT_WR)
        except OSError: pass


def start(listen_host: str, listen_port: int,
          srv_address: str, srv_auth_port: int,
          server_pubkey: str) -> ProxyServer:
    server = ProxyServer(listen_host, listen_port,
                         srv_address, srv_auth_port, server_pubkey)
    server.start()
    return server
