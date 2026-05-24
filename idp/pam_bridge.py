"""
PAM bridge — drives ``pam_authenticate("iaa-vpn", …)`` from inside the IdP
process and coordinates with Flask HTTP handlers via threading primitives.
(STEPS.md §2.2, §2.3, §2.7.)

Conversation contract
=====================

The PAM module (``pam_vpnmfa.so``) talks to this bridge through the PAM
conversation function. We use only two message styles:

  ``PAM_PROMPT_ECHO_OFF``
      The module wants a factor outcome. The ``msg`` payload starts with
      one of:

        ``FACTOR:password``   — the bridge must verify the password factor
                                and respond with "OK" / "FAIL" / "UNAVAILABLE".
        ``FACTOR:totp``       — same, for TOTP.
        ``FACTOR:fido2``      — same, for FIDO2.

      The bridge's response is a plain string. Anything other than "OK" is
      treated as failure by the C module; "UNAVAILABLE" maps to
      ``PAM_AUTHINFO_UNAVAIL``, any other non-OK to ``PAM_AUTH_ERR``.

  ``PAM_TEXT_INFO``
      The module is reporting status (e.g. ``INFO:risk_level=L2``). No
      response is expected; the bridge ack with an empty string.

Threading model
===============

``start_authentication`` spawns one worker thread per MFA session. The
thread calls :func:`PamHandle.authenticate`. Inside ``pam_authenticate`` the
C module calls our conv callback once per required factor. Each call:

  1. parks itself on ``Session.response_event``,
  2. stashes the prompt in ``Session.pending_prompt`` and sets
     ``Session.prompt_event`` so the Flask side wakes up,
  3. waits for the HTTP handler to deliver a result via
     :func:`submit_factor_result`, then returns the stored response.

The Flask side never blocks on PAM directly; instead it polls
:func:`wait_for_prompt` and :func:`get_result` with a short timeout, so a
hung PAM thread cannot stall a request worker indefinitely.
"""

import logging
import os
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from common import libpam
from common.libpam import (
    PamHandle, PamError,
    PAM_PROMPT_ECHO_OFF, PAM_PROMPT_ECHO_ON, PAM_TEXT_INFO, PAM_ERROR_MSG,
    PAM_SUCCESS, PAM_AUTHINFO_UNAVAIL, PAM_RHOST,
)

log = logging.getLogger("pam_bridge")

PAM_SERVICE_NAME = "iaa-vpn"

# Maximum time we let a single factor sit pending before assuming the user has
# walked away and aborting the PAM thread.
FACTOR_TIMEOUT = 300.0


# ── Session state ────────────────────────────────────────────────────────────

@dataclass
class _Session:
    sid:             str
    username:        str
    ip:              str
    risk_score:      int

    # Cross-thread signalling.
    prompt_event:    threading.Event = field(default_factory=threading.Event)
    response_event:  threading.Event = field(default_factory=threading.Event)

    pending_prompt:  Optional[str] = None       # "FACTOR:password", etc.
    pending_style:   Optional[int] = None
    pending_info:    list[str]     = field(default_factory=list)

    factor_result:   Optional[str] = None       # "OK" / "FAIL" / "UNAVAILABLE"

    result:          Optional[bool] = None      # True/False once auth ends
    error:           Optional[str]  = None

    thread:          Optional[threading.Thread] = None
    done:            threading.Event = field(default_factory=threading.Event)


_sessions: dict[str, _Session] = {}
_lock = threading.RLock()


# ── Public API ───────────────────────────────────────────────────────────────

def start_authentication(sid: str, username: str, ip: str,
                         risk_score: int) -> None:
    """
    Start a background PAM authentication for ``sid``. Idempotent — calling
    twice with the same ``sid`` returns immediately.

    ``risk_score`` is the integer 0-100 score produced by
    :func:`idp.rba.compute_risk` (§2.7). It is passed to the PAM module via
    the ``IAA_RISK_SCORE`` PAM environment variable.
    """
    with _lock:
        if sid in _sessions:
            return
        sess = _Session(sid=sid, username=username, ip=ip,
                        risk_score=int(risk_score))
        _sessions[sid] = sess

    t = threading.Thread(target=_run_pam, args=(sess,), daemon=True,
                         name=f"pam-{sid[:8]}")
    sess.thread = t
    t.start()


def wait_for_prompt(sid: str, timeout: float = 5.0) -> Optional[tuple[str, int]]:
    """
    Return (prompt, style) for the next factor the PAM module wants the
    Flask side to handle. ``prompt`` is the raw message payload — usually
    ``FACTOR:<name>``. Returns ``None`` if no prompt is pending within
    ``timeout`` seconds.

    The prompt remains "current" until :func:`submit_factor_result` is
    called; repeated calls within that window return the same prompt
    (idempotent on the HTTP side).
    """
    sess = _sessions.get(sid)
    if not sess:
        return None
    if sess.done.is_set():
        return None
    sess.prompt_event.wait(timeout)
    if sess.pending_prompt is None:
        return None
    return (sess.pending_prompt, sess.pending_style or PAM_TEXT_INFO)


def submit_factor_result(sid: str, outcome: str, payload: str = "") -> bool:
    """
    Deliver an "OK"/"FAIL"/"UNAVAILABLE" outcome for the currently-pending
    factor. Returns True if there *was* a pending prompt to consume; False
    if the session is unknown, already finished, or has no pending prompt.
    """
    if outcome not in ("OK", "FAIL", "UNAVAILABLE"):
        raise ValueError(f"bad outcome {outcome!r}")
    sess = _sessions.get(sid)
    if not sess or sess.done.is_set():
        return False
    if sess.pending_prompt is None:
        return False
    sess.factor_result = outcome
    sess.pending_prompt = None
    sess.prompt_event.clear()
    sess.response_event.set()
    return True


def get_result(sid: str, timeout: float = 0.0) -> Optional[bool]:
    """
    True if PAM has finished and authentication succeeded, False if it
    finished and failed, ``None`` if it is still running (or unknown sid).

    A non-zero ``timeout`` waits up to that many seconds for the PAM thread
    to finish.
    """
    sess = _sessions.get(sid)
    if not sess:
        return None
    if timeout > 0:
        sess.done.wait(timeout)
    return sess.result


def cleanup(sid: str) -> None:
    """Drop the session record after the device-code is fully approved."""
    with _lock:
        _sessions.pop(sid, None)


def pending_info(sid: str) -> list[str]:
    """Return the list of INFO:… messages the PAM module has emitted so far."""
    sess = _sessions.get(sid)
    if not sess:
        return []
    return list(sess.pending_info)


# ── Internals ────────────────────────────────────────────────────────────────

def _make_conv(sess: _Session):
    """Build a Python conv callback bound to a particular session."""

    def conv(prompts):
        out = []
        for style, msg in prompts:
            if style in (PAM_TEXT_INFO, PAM_ERROR_MSG):
                # Informational — no response expected.
                if msg:
                    sess.pending_info.append(msg)
                    log.info("[%s] PAM info: %s", sess.sid, msg)
                out.append(None)
                continue

            if style not in (PAM_PROMPT_ECHO_OFF, PAM_PROMPT_ECHO_ON):
                log.warning("[%s] unknown PAM msg_style=%d msg=%r",
                            sess.sid, style, msg)
                out.append("FAIL")
                continue

            # A factor prompt. Stash and wait for the Flask side.
            sess.pending_prompt = msg
            sess.pending_style  = style
            sess.factor_result  = None
            sess.response_event.clear()
            sess.prompt_event.set()

            log.info("[%s] PAM asked for: %s", sess.sid, msg)

            ready = sess.response_event.wait(FACTOR_TIMEOUT)
            if not ready or sess.factor_result is None:
                log.warning("[%s] factor %s timed out", sess.sid, msg)
                out.append("FAIL")
                continue

            log.info("[%s] %s → %s", sess.sid, msg, sess.factor_result)
            out.append(sess.factor_result)

        return out

    return conv


def _run_pam(sess: _Session):
    """Worker thread body: drives one PAM authentication to completion."""
    try:
        with PamHandle(PAM_SERVICE_NAME, sess.username, _make_conv(sess)) as h:
            if sess.ip:
                try:
                    h.set_item(PAM_RHOST, sess.ip)
                except PamError as e:
                    log.warning("[%s] pam_set_item(PAM_RHOST) failed: %s",
                                sess.sid, e)
            h.putenv("IAA_RISK_SCORE", str(sess.risk_score))

            rc = h.authenticate(flags=0)
            sess.result = (rc == PAM_SUCCESS)
            if rc != PAM_SUCCESS:
                sess.error = h.strerror(rc)
                log.info("[%s] PAM auth failed: %s", sess.sid, sess.error)
            else:
                log.info("[%s] PAM auth succeeded", sess.sid)
    except Exception as e:
        log.exception("[%s] PAM thread crashed", sess.sid)
        sess.result = False
        sess.error  = str(e)
    finally:
        # Wake anyone parked on wait_for_prompt or get_result.
        sess.pending_prompt = None
        sess.prompt_event.set()
        sess.done.set()
