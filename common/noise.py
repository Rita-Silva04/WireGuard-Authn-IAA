"""
Noise-IK (Curve25519 + ChaCha20-Poly1305 + BLAKE2s) — STEPS.md §3.2.

Implemented from the Noise spec (revision 34) §5 / §7 / §13, on top of
``cryptography.hazmat`` primitives only. No third-party Noise library.

Pattern IK
==========
::

    IK:
      <- s              (responder's static key known to initiator a priori)
      ...
      -> e, es, s, ss   (message 1, initiator → responder)
      <- e, ee, se      (message 2, responder → initiator)

The initiator must know the responder's static public key ``rs`` (which in
our deployment is the server's WireGuard public key). Per spec §7.5 IK
provides: identity-hiding for the initiator's static, mutual authentication,
KCI resistance, and forward secrecy after message 2.

Public surface
--------------
``NoiseHandshake.initiator(rs_bytes)`` and ``NoiseHandshake.responder(s_priv_bytes)``
create handshake objects whose ``write_message(payload)`` and
``read_message(data)`` methods drive the protocol. After the last message,
``finalize()`` returns ``(send_cipher, recv_cipher)`` — a pair of
:class:`CipherState` objects for the post-handshake transport.

Transport
---------
:class:`CipherState` exposes ``encrypt(ad, plaintext)`` and
``decrypt(ad, ciphertext)`` using ChaCha20-Poly1305. Per Noise spec §5.1,
transport messages use an empty ``ad`` by default; we expose ``ad`` here so
callers may bind a frame to a header if they want extra protection.
"""

import hmac
import hashlib
import os
import struct
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


# Constants from the Noise spec
HASHLEN  = 32   # BLAKE2s output size
DHLEN    = 32   # X25519 output size
KEYLEN   = 32   # ChaCha20 key size
TAGLEN   = 16   # Poly1305 tag size

# Sentinel value the spec uses for "max nonce reached / cipher exhausted".
NONCE_MAX = 2 ** 64 - 1

PROTOCOL_NAME = "Noise_IK_25519_ChaChaPoly_BLAKE2s"


# ── HMAC / HKDF over BLAKE2s ─────────────────────────────────────────────────

def _hmac(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.blake2s).digest()


def _hkdf(chaining_key: bytes, ikm: bytes, num_outputs: int) -> tuple[bytes, ...]:
    """
    Noise's HKDF wrapper (spec §4.3). Returns ``num_outputs`` 32-byte values.
    """
    assert num_outputs in (2, 3), "Noise HKDF only used with 2 or 3 outputs"
    temp_key = _hmac(chaining_key, ikm)
    out1 = _hmac(temp_key, b"\x01")
    out2 = _hmac(temp_key, out1 + b"\x02")
    if num_outputs == 2:
        return (out1, out2)
    out3 = _hmac(temp_key, out2 + b"\x03")
    return (out1, out2, out3)


# ── DH helpers ───────────────────────────────────────────────────────────────

def _dh(priv: X25519PrivateKey, pub_bytes: bytes) -> bytes:
    """Curve25519 X25519. Returns 32-byte shared secret."""
    pub = X25519PublicKey.from_public_bytes(pub_bytes)
    return priv.exchange(pub)


def _gen_keypair() -> tuple[X25519PrivateKey, bytes]:
    """Return (priv, pub_bytes) for a fresh X25519 keypair."""
    priv = X25519PrivateKey.generate()
    pub  = priv.public_key().public_bytes_raw()
    return priv, pub


# ── Cipher / Symmetric state ─────────────────────────────────────────────────

class CipherState:
    """
    Per-direction transport-mode cipher (Noise spec §5.1).

    Each CipherState carries a 32-byte symmetric key and a 64-bit nonce
    counter that is incremented after every encrypt/decrypt. Nonces are
    serialised as 4 zero bytes + 8 little-endian bytes for the counter
    (ChaCha20-Poly1305 wants a 12-byte nonce; the high 4 bytes are zero
    per spec).
    """

    def __init__(self, key: Optional[bytes] = None):
        if key is not None and len(key) != KEYLEN:
            raise ValueError("CipherState key must be 32 bytes")
        self.k: Optional[bytes] = key
        self.n: int             = 0

    def has_key(self) -> bool:
        return self.k is not None

    def _nonce(self) -> bytes:
        if self.n >= NONCE_MAX:
            raise OverflowError("Noise nonce exhausted")
        return b"\x00\x00\x00\x00" + struct.pack("<Q", self.n)

    def encrypt(self, ad: bytes, plaintext: bytes) -> bytes:
        """Encrypt with the current key/nonce; increment nonce on success."""
        if not self.has_key():
            # Spec §5.1: with no key, encryption is the identity function.
            return plaintext
        out = ChaCha20Poly1305(self.k).encrypt(self._nonce(), plaintext, ad)
        self.n += 1
        return out

    def decrypt(self, ad: bytes, ciphertext: bytes) -> bytes:
        if not self.has_key():
            return ciphertext
        out = ChaCha20Poly1305(self.k).decrypt(self._nonce(), ciphertext, ad)
        self.n += 1
        return out

    def rekey(self) -> None:
        """Spec §11.3 — derive a new key from the current one."""
        if not self.has_key():
            return
        # REKEY(k) = ENCRYPT(k, max_nonce, zerolen, zeros(32))
        nonce = b"\xff" * 4 + b"\xff" * 8
        new_k = ChaCha20Poly1305(self.k).encrypt(nonce, b"\x00" * 32, b"")[:KEYLEN]
        self.k = new_k
        self.n = 0


class _SymmetricState:
    """
    Internal — combined handshake hash + chaining key + transient cipher
    (Noise spec §5.2). Driven by the public NoiseHandshake below.
    """

    def __init__(self, protocol_name: str):
        name = protocol_name.encode()
        if len(name) <= HASHLEN:
            self.h = name + b"\x00" * (HASHLEN - len(name))
        else:
            self.h = hashlib.blake2s(name).digest()
        self.ck = self.h
        self.cipher = CipherState()

    def mix_hash(self, data: bytes) -> None:
        self.h = hashlib.blake2s(self.h + data).digest()

    def mix_key(self, input_key_material: bytes) -> None:
        new_ck, temp_k = _hkdf(self.ck, input_key_material, 2)
        self.ck = new_ck
        self.cipher = CipherState(temp_k)

    def encrypt_and_hash(self, plaintext: bytes) -> bytes:
        ct = self.cipher.encrypt(self.h, plaintext)
        self.mix_hash(ct)
        return ct

    def decrypt_and_hash(self, ciphertext: bytes) -> bytes:
        pt = self.cipher.decrypt(self.h, ciphertext)
        self.mix_hash(ciphertext)
        return pt

    def split(self) -> tuple[CipherState, CipherState]:
        k1, k2 = _hkdf(self.ck, b"", 2)
        return CipherState(k1), CipherState(k2)


# ── Public handshake ─────────────────────────────────────────────────────────

class NoiseHandshake:
    """
    Drive a Noise-IK handshake.

    Two message exchanges:
      msg1: initiator → responder    e, es, s, ss + payload
      msg2: responder → initiator    e, ee, se    + payload

    Use :func:`initiator` or :func:`responder` to construct, then alternate
    ``write_message``/``read_message`` as appropriate for your role. After
    the handshake completes (``handshake_done`` becomes True), call
    :meth:`finalize` to get the transport ciphers.
    """

    # ----- construction -----

    def __init__(self, role: str, s_priv: X25519PrivateKey,
                 s_pub: bytes, rs: Optional[bytes]):
        assert role in ("initiator", "responder")
        self.role = role
        self.s_priv = s_priv
        self.s_pub  = s_pub
        self.rs:    Optional[bytes]             = rs
        self.e:     Optional[X25519PrivateKey]  = None
        self.e_pub: Optional[bytes]             = None
        self.re:    Optional[bytes]             = None
        self.sym  = _SymmetricState(PROTOCOL_NAME)
        # Empty prologue
        self.sym.mix_hash(b"")
        # Pre-message: responder's static is known to the initiator
        if role == "initiator":
            assert self.rs is not None, "IK initiator needs rs"
            self.sym.mix_hash(self.rs)
        else:
            self.sym.mix_hash(self.s_pub)
        self._msg_idx = 0
        self.handshake_done = False
        self._cs_send: Optional[CipherState] = None
        self._cs_recv: Optional[CipherState] = None

    @classmethod
    def initiator(cls, server_static_pub: bytes,
                   client_static: Optional[X25519PrivateKey] = None) -> "NoiseHandshake":
        """
        Build an initiator. The client static key may be supplied; if not,
        a fresh per-session keypair is generated (which is fine — IK uses
        the initiator's static only to provide identity-hiding, not to
        bind a persistent identity in our use case).
        """
        if client_static is None:
            client_static, _ = _gen_keypair()
        s_pub = client_static.public_key().public_bytes_raw()
        return cls("initiator", client_static, s_pub, server_static_pub)

    @classmethod
    def responder(cls, local_static_priv_bytes: bytes) -> "NoiseHandshake":
        s_priv = X25519PrivateKey.from_private_bytes(local_static_priv_bytes)
        s_pub  = s_priv.public_key().public_bytes_raw()
        return cls("responder", s_priv, s_pub, rs=None)

    # ----- message driver -----

    def write_message(self, payload: bytes = b"") -> bytes:
        if self.handshake_done:
            raise RuntimeError("handshake already complete")

        if self._msg_idx == 0:
            if self.role != "initiator":
                raise RuntimeError("responder cannot write message 0")
            return self._write_msg1(payload)

        if self._msg_idx == 1:
            if self.role != "responder":
                raise RuntimeError("initiator cannot write message 1")
            return self._write_msg2(payload)

        raise RuntimeError("no more handshake messages")

    def read_message(self, data: bytes) -> bytes:
        if self.handshake_done:
            raise RuntimeError("handshake already complete")

        if self._msg_idx == 0:
            if self.role != "responder":
                raise RuntimeError("initiator cannot read message 0")
            return self._read_msg1(data)

        if self._msg_idx == 1:
            if self.role != "initiator":
                raise RuntimeError("responder cannot read message 1")
            return self._read_msg2(data)

        raise RuntimeError("no more handshake messages")

    # ----- message 1: initiator → responder, tokens e, es, s, ss -----

    def _write_msg1(self, payload: bytes) -> bytes:
        # e
        self.e, self.e_pub = _gen_keypair()
        out = bytearray(self.e_pub)
        self.sym.mix_hash(self.e_pub)
        # es
        self.sym.mix_key(_dh(self.e, self.rs))
        # s  (encrypted)
        out += self.sym.encrypt_and_hash(self.s_pub)
        # ss
        self.sym.mix_key(_dh(self.s_priv, self.rs))
        # payload
        out += self.sym.encrypt_and_hash(payload)
        self._msg_idx = 1
        return bytes(out)

    def _read_msg1(self, data: bytes) -> bytes:
        view = memoryview(data)
        # e
        if len(view) < DHLEN:
            raise ValueError("msg1 truncated: missing e")
        self.re = bytes(view[:DHLEN])
        view = view[DHLEN:]
        self.sym.mix_hash(self.re)
        # es
        self.sym.mix_key(_dh(self.s_priv, self.re))
        # s
        s_enc_len = DHLEN + TAGLEN
        if len(view) < s_enc_len:
            raise ValueError("msg1 truncated: missing encrypted s")
        self.rs = self.sym.decrypt_and_hash(bytes(view[:s_enc_len]))
        view = view[s_enc_len:]
        # ss
        self.sym.mix_key(_dh(self.s_priv, self.rs))
        # payload
        payload = self.sym.decrypt_and_hash(bytes(view))
        self._msg_idx = 1
        return payload

    # ----- message 2: responder → initiator, tokens e, ee, se -----

    def _write_msg2(self, payload: bytes) -> bytes:
        # e
        self.e, self.e_pub = _gen_keypair()
        out = bytearray(self.e_pub)
        self.sym.mix_hash(self.e_pub)
        # ee
        self.sym.mix_key(_dh(self.e, self.re))
        # se   — DH(initiator's static, responder's ephemeral)
        #        responder side: DH(rs, e_priv)
        self.sym.mix_key(_dh(self.e, self.rs))
        # payload
        out += self.sym.encrypt_and_hash(payload)
        self._cs_recv, self._cs_send = self.sym.split()
        self.handshake_done = True
        self._msg_idx = 2
        return bytes(out)

    def _read_msg2(self, data: bytes) -> bytes:
        view = memoryview(data)
        # e
        if len(view) < DHLEN:
            raise ValueError("msg2 truncated: missing e")
        self.re = bytes(view[:DHLEN])
        view = view[DHLEN:]
        self.sym.mix_hash(self.re)
        # ee
        self.sym.mix_key(_dh(self.e, self.re))
        # se   — initiator side: DH(s_priv, re)
        self.sym.mix_key(_dh(self.s_priv, self.re))
        # payload
        payload = self.sym.decrypt_and_hash(bytes(view))
        # Initiator-side split: c1 (init→resp) goes "send", c2 (resp→init) "recv"
        self._cs_send, self._cs_recv = self.sym.split()
        self.handshake_done = True
        self._msg_idx = 2
        return payload

    # ----- finalize -----

    def finalize(self) -> tuple[CipherState, CipherState]:
        if not self.handshake_done:
            raise RuntimeError("handshake not finished")
        return self._cs_send, self._cs_recv

    @property
    def remote_static(self) -> Optional[bytes]:
        """The peer's static public key as observed during the handshake."""
        return self.rs if self.role == "responder" else None

    @property
    def handshake_hash(self) -> bytes:
        """The transcript hash after the final message — useful for binding."""
        return self.sym.h


__all__ = [
    "NoiseHandshake", "CipherState",
    "DHLEN", "KEYLEN", "TAGLEN", "PROTOCOL_NAME",
]
