"""
Server-side Noise-IK tunnel (STEPS.md §3.3).

:func:`accept_handshake` runs the responder side of the Noise-IK handshake
on a freshly accepted TCP socket and returns:

  - a :class:`TunnelSession` wrapping the connection (post-handshake);
  - the initial payload bytes the initiator stuffed into message 1.

The caller (``server/srvauthn.py``) decides what to do with that initial
payload: dispatch to the auth handler, the proxy handler, etc.
"""

import base64
import os
import socket
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from common import framing
from common.noise import NoiseHandshake, CipherState


SESSION_TIMEOUT = 660


class TunnelSession:
    def __init__(self, sock: socket.socket,
                 send_cipher: CipherState, recv_cipher: CipherState,
                 peer_addr: tuple):
        self._sock = sock
        self._send = send_cipher
        self._recv = recv_cipher
        self.peer  = peer_addr
        self.remote_static = None   # filled in by accept_handshake

    def send(self, payload: bytes) -> None:
        ct = self._send.encrypt(b"", payload)
        framing.send_frame(self._sock, ct)

    def recv(self) -> bytes:
        ct = framing.recv_frame(self._sock)
        return self._recv.decrypt(b"", ct)

    def settimeout(self, seconds: float) -> None:
        self._sock.settimeout(seconds)

    @property
    def raw_socket(self) -> socket.socket:
        return self._sock

    def close(self) -> None:
        try:
            self._sock.close()
        except OSError:
            pass


def accept_handshake(sock: socket.socket, peer_addr: tuple,
                     local_static_priv_b64: str,
                     responder_payload: bytes = b"") -> tuple[TunnelSession, bytes]:
    """
    Run the responder side of a Noise-IK handshake on ``sock``.

    ``local_static_priv_b64`` is the server's long-lived WireGuard private
    key in base64 (the same value SrvAuthn already loads from
    ``/etc/wireguard/privatekey-server`` at startup, §1.2).

    Returns ``(session, initial_payload)``. ``initial_payload`` is whatever
    the initiator placed inside message 1.
    """
    priv = base64.b64decode(local_static_priv_b64, validate=True)
    if len(priv) != 32:
        raise ValueError("local static private key must be 32 bytes")

    handshake = NoiseHandshake.responder(priv)

    # Message 1: read e, es, s, ss + initial payload
    msg1 = framing.recv_frame(sock)
    initial_payload = handshake.read_message(msg1)

    # Message 2: write e, ee, se + (optional) responder payload
    msg2 = handshake.write_message(responder_payload)
    framing.send_frame(sock, msg2)

    cs_send, cs_recv = handshake.finalize()
    sock.settimeout(SESSION_TIMEOUT)
    session = TunnelSession(sock, cs_send, cs_recv, peer_addr)
    session.remote_static = handshake.rs
    return session, initial_payload
