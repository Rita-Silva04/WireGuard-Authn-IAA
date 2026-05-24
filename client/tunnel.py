"""
Client-side Noise-IK tunnel (STEPS.md §3.3).

A :class:`TunnelSession` wraps a TCP connection that has completed a
Noise-IK handshake against the SrvAuthn responder. It exposes ``send`` /
``recv`` taking/returning plaintext bytes; framing and AEAD encryption are
handled internally.
"""

import base64
import os
import socket
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from common import framing
from common.noise import NoiseHandshake, CipherState


CONNECT_TIMEOUT = 30      # seconds for TCP connect + handshake
SESSION_TIMEOUT = 660     # generous post-handshake timeout (user can take time)


class TunnelSession:
    """A bidirectional, encrypted, framed message stream."""

    def __init__(self, sock: socket.socket,
                 send_cipher: CipherState, recv_cipher: CipherState):
        self._sock = sock
        self._send = send_cipher
        self._recv = recv_cipher

    def send(self, payload: bytes) -> None:
        ct = self._send.encrypt(b"", payload)
        framing.send_frame(self._sock, ct)

    def recv(self) -> bytes:
        ct = framing.recv_frame(self._sock)
        return self._recv.decrypt(b"", ct)

    def settimeout(self, seconds: float) -> None:
        self._sock.settimeout(seconds)

    def close(self) -> None:
        try:
            self._sock.close()
        except OSError:
            pass

    # Context-manager sugar so the caller can ``with tunnel.connect(...)``.
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()


def connect(host: str, port: int, server_static_pub_b64: str,
            initial_payload: bytes = b"") -> TunnelSession:
    """
    Open a TCP connection to ``(host, port)``, run a Noise-IK handshake
    against the server's static key (passed as base64, matching the
    on-disk ``publickey-server`` and ``base.conf:public_key``), and return
    a :class:`TunnelSession` ready for transport-mode traffic.

    ``initial_payload`` is sent inside the *first* handshake message, so it
    arrives at the server only after the responder has verified message 1.
    The responder may piggy-back an initial payload on message 2, which we
    surface to the caller as the session's first :meth:`recv`.
    """
    server_static_pub = base64.b64decode(server_static_pub_b64, validate=True)
    if len(server_static_pub) != 32:
        raise ValueError("server static public key must be 32 bytes")

    sock = socket.create_connection((host, port), timeout=CONNECT_TIMEOUT)
    try:
        handshake = NoiseHandshake.initiator(server_static_pub)

        # Message 1: e, es, s, ss + initial_payload  (handshake bytes are
        # length-prefixed framed so the server can recv a discrete unit).
        msg1 = handshake.write_message(initial_payload)
        framing.send_frame(sock, msg1)

        # Message 2: e, ee, se + optional payload (we ignore it for now;
        # callers can recv() it as the first transport message if they
        # extend the protocol).
        msg2 = framing.recv_frame(sock)
        handshake.read_message(msg2)

        cs_send, cs_recv = handshake.finalize()
        sock.settimeout(SESSION_TIMEOUT)
        return TunnelSession(sock, cs_send, cs_recv)
    except Exception:
        sock.close()
        raise
