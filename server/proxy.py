"""
Server-side proxy egress (STEPS.md §3.6).

When a tunnel session opens with ``{"service": "proxy"}`` as its first
message, control transfers here. We:

  1. Open a TCP connection to the IdP (default ``localhost:8080``).
  2. ACK the client with ``{"status": "ok"}``.
  3. Bidirectionally pipe bytes between the encrypted tunnel and the
     plaintext IdP socket until one side closes.

There is no service-side multiplexing; one tunnel == one upstream
connection. The browser opens a fresh tunnel for every HTTP request that
keep-alive doesn't reuse — that's fine. Noise-IK handshakes are cheap.
"""

import configparser
import json
import logging
import socket
import threading

log = logging.getLogger("srvauthn.proxy")


def _send_json(session, obj):
    session.send(json.dumps(obj).encode())


def _send_err(session, msg):
    _send_json(session, {"error": msg})


def _pump_tunnel_to_socket(session, sock: socket.socket, name: str):
    """Read encrypted frames from the tunnel, write plaintext to sock."""
    try:
        while True:
            data = session.recv()
            if not data:
                break
            sock.sendall(data)
    except Exception as e:
        log.debug(f"[{name}] tunnel→sock pump stopped: {e}")
    finally:
        try: sock.shutdown(socket.SHUT_WR)
        except OSError: pass


def _pump_socket_to_tunnel(sock: socket.socket, session, name: str):
    """Read plaintext from sock, send encrypted frames into the tunnel."""
    try:
        while True:
            data = sock.recv(16 * 1024)
            if not data:
                break
            session.send(data)
    except Exception as e:
        log.debug(f"[{name}] sock→tunnel pump stopped: {e}")
    finally:
        # Signal EOF to the peer with an empty frame.
        try: session.send(b"")
        except Exception: pass


def handle_proxy(session, cfg: configparser.ConfigParser) -> None:
    target = cfg.get("server", "proxy_target",
                     fallback="localhost:8080")
    host, _, port = target.partition(":")
    port = int(port or "8080")

    try:
        upstream = socket.create_connection((host, port), timeout=10)
    except OSError as e:
        log.error(f"proxy: cannot reach {target}: {e}")
        _send_err(session, "upstream_unreachable")
        return

    _send_json(session, {"status": "ok"})
    log.info(f"proxy: piping tunnel ↔ {target} (peer={session.peer[0]})")

    t1 = threading.Thread(target=_pump_tunnel_to_socket,
                          args=(session, upstream, "t→u"), daemon=True)
    t2 = threading.Thread(target=_pump_socket_to_tunnel,
                          args=(upstream, session, "u→t"), daemon=True)
    t1.start(); t2.start()
    t1.join(); t2.join()

    try: upstream.close()
    except OSError: pass
    log.info(f"proxy: closed (peer={session.peer[0]})")
