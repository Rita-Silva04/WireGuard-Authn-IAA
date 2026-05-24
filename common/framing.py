"""
Length-prefixed framing for the Noise-IK tunnel (STEPS.md §3.1).

Wire format:
    [4-byte big-endian length N] [N bytes payload]

The cap of 64 KiB matches the largest single Noise transport message in our
deployment and keeps a single read() bounded against accidental or hostile
peers. Frames larger than the cap raise FrameError; partial reads are looped
until the expected number of bytes arrive or the connection closes.
"""

import socket
import struct

MAX_FRAME_LEN = 64 * 1024   # bytes, payload only (not including the length prefix)


class FrameError(IOError):
    """Raised for malformed frames or short reads."""


def send_frame(sock: socket.socket, payload: bytes) -> None:
    """Send a single framed payload. Raises FrameError if it exceeds the cap."""
    if len(payload) > MAX_FRAME_LEN:
        raise FrameError(f"frame too large: {len(payload)} > {MAX_FRAME_LEN}")
    header = struct.pack(">I", len(payload))
    sock.sendall(header + payload)


def recv_frame(sock: socket.socket) -> bytes:
    """
    Read one frame from `sock`. Returns the payload bytes (without the
    length prefix). Raises FrameError on EOF mid-frame or on a length that
    exceeds the cap.
    """
    header = _recv_exact(sock, 4)
    (length,) = struct.unpack(">I", header)
    if length > MAX_FRAME_LEN:
        raise FrameError(f"declared frame length {length} > {MAX_FRAME_LEN}")
    if length == 0:
        return b""
    return _recv_exact(sock, length)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    """Read exactly n bytes from sock or raise FrameError on EOF."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise FrameError(
                f"connection closed mid-frame "
                f"(have {len(buf)} bytes, want {n})"
            )
        buf.extend(chunk)
    return bytes(buf)
