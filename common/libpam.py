"""
Minimal ctypes wrapper around libpam (STEPS.md §2.1).

Exposes just enough of the libpam C API for the IdP to call
``pam_authenticate("iaa-vpn", username, conv=…)`` from Python.

Why not use a PyPI package?
  - ``python-pam`` doesn't expose a custom conversation function — it only does
    "give me a password" style synchronous auth.
  - ``pamela`` would work, but pulling a dependency for the ~80 lines of
    ctypes glue we actually need adds opaque code to our trust surface for
    no real win.

Memory model for the conversation callback
------------------------------------------
PAM's contract (`man 3 pam_conv`):

  * The library allocates the ``msg`` array and frees it; the callback must
    treat it as read-only and must not free it.
  * The callback allocates the ``resp`` array (with ``malloc``) and each
    response string (also ``malloc``); the library will ``free`` them after
    the conversation completes.

This module satisfies both. We use ``libc.malloc`` / ``libc.strdup`` so the
allocations are compatible with PAM's later ``free`` calls.
"""

import ctypes
import ctypes.util
from ctypes import (
    CFUNCTYPE, POINTER, Structure,
    c_char, c_char_p, c_int, c_void_p, c_size_t,
)


# ── Library handles ──────────────────────────────────────────────────────────

_libpam_path = ctypes.util.find_library("pam") or "libpam.so.0"
libpam = ctypes.CDLL(_libpam_path, use_errno=True)

_libc_path = ctypes.util.find_library("c") or "libc.so.6"
libc = ctypes.CDLL(_libc_path)
libc.malloc.argtypes  = [c_size_t]
libc.malloc.restype   = c_void_p
libc.free.argtypes    = [c_void_p]
libc.free.restype     = None
libc.strdup.argtypes  = [c_char_p]
libc.strdup.restype   = c_void_p
libc.memset.argtypes  = [c_void_p, c_int, c_size_t]
libc.memset.restype   = c_void_p


# ── Constants (from <security/_pam_types.h>) ─────────────────────────────────

PAM_SUCCESS              = 0
PAM_OPEN_ERR             = 1
PAM_SYMBOL_ERR           = 2
PAM_SERVICE_ERR          = 3
PAM_SYSTEM_ERR           = 4
PAM_BUF_ERR              = 5
PAM_PERM_DENIED          = 6
PAM_AUTH_ERR             = 7
PAM_CRED_INSUFFICIENT    = 8
PAM_AUTHINFO_UNAVAIL     = 9
PAM_USER_UNKNOWN         = 10
PAM_MAXTRIES             = 11
PAM_ABORT                = 26
PAM_CONV_ERR             = 19

# Message styles
PAM_PROMPT_ECHO_OFF      = 1
PAM_PROMPT_ECHO_ON       = 2
PAM_ERROR_MSG            = 3
PAM_TEXT_INFO            = 4

# Items
PAM_SERVICE              = 1
PAM_USER                 = 2
PAM_TTY                  = 3
PAM_RHOST                = 4
PAM_CONV                 = 5
PAM_AUTHTOK              = 6
PAM_USER_PROMPT          = 9


# ── PAM structs ──────────────────────────────────────────────────────────────

class PamMessage(Structure):
    _fields_ = [
        ("msg_style", c_int),
        ("msg",       c_char_p),
    ]


class PamResponse(Structure):
    _fields_ = [
        ("resp",         c_char_p),
        ("resp_retcode", c_int),
    ]


CONV_FUNC = CFUNCTYPE(
    c_int,
    c_int,
    POINTER(POINTER(PamMessage)),
    POINTER(POINTER(PamResponse)),
    c_void_p,
)


class PamConv(Structure):
    _fields_ = [
        ("conv",         CONV_FUNC),
        ("appdata_ptr",  c_void_p),
    ]


# ── libpam prototypes ────────────────────────────────────────────────────────

libpam.pam_start.argtypes        = [c_char_p, c_char_p, POINTER(PamConv),
                                    POINTER(c_void_p)]
libpam.pam_start.restype         = c_int

libpam.pam_end.argtypes          = [c_void_p, c_int]
libpam.pam_end.restype           = c_int

libpam.pam_authenticate.argtypes = [c_void_p, c_int]
libpam.pam_authenticate.restype  = c_int

libpam.pam_acct_mgmt.argtypes    = [c_void_p, c_int]
libpam.pam_acct_mgmt.restype     = c_int

libpam.pam_set_item.argtypes     = [c_void_p, c_int, c_void_p]
libpam.pam_set_item.restype      = c_int

libpam.pam_get_item.argtypes     = [c_void_p, c_int, POINTER(c_void_p)]
libpam.pam_get_item.restype      = c_int

libpam.pam_putenv.argtypes       = [c_void_p, c_char_p]
libpam.pam_putenv.restype        = c_int

libpam.pam_getenv.argtypes       = [c_void_p, c_char_p]
libpam.pam_getenv.restype        = c_char_p

libpam.pam_strerror.argtypes     = [c_void_p, c_int]
libpam.pam_strerror.restype      = c_char_p


# ── Pythonic helper ──────────────────────────────────────────────────────────

class PamError(RuntimeError):
    def __init__(self, code: int, msg: str = ""):
        self.code = code
        super().__init__(f"PAM error {code}: {msg}")


def _check(pamh, rc, op):
    if rc != PAM_SUCCESS:
        msg = libpam.pam_strerror(pamh, rc) or b""
        raise PamError(rc, f"{op}: {msg.decode(errors='replace')}")


def _alloc_response_array(num_msg: int) -> int:
    """malloc a struct pam_response[num_msg] zero-filled. Return ptr as int."""
    total = ctypes.sizeof(PamResponse) * num_msg
    p = libc.malloc(total)
    if not p:
        raise MemoryError("malloc(pam_response array) failed")
    libc.memset(p, 0, total)
    return p


class PamHandle:
    """
    Context manager around a libpam authentication session.

    Usage:
        with PamHandle("iaa-vpn", "alice", conv_fn) as h:
            h.putenv("IAA_RISK_SCORE", "42")
            h.set_item(PAM_RHOST, "10.0.0.5")
            h.authenticate()
    """

    def __init__(self, service: str, user: str, conv: callable):
        self.service = service
        self.user    = user
        # Keep references so the CFUNCTYPE closure & struct survive the
        # whole conversation.
        self._py_conv     = conv
        self._conv_cb     = CONV_FUNC(self._dispatch)
        self._pam_conv    = PamConv(self._conv_cb, None)
        self._pamh        = c_void_p()

    # ── conv plumbing ────────────────────────────────────────────────────────

    def _dispatch(self, num_msg, msg_ptr, resp_ptr, appdata_ptr):
        """Translate the C-side conv call into a Python call, then re-pack."""
        try:
            prompts = []
            for i in range(num_msg):
                m = msg_ptr[i].contents
                prompts.append((m.msg_style,
                                m.msg.decode(errors='replace') if m.msg else ""))

            answers = self._py_conv(prompts)
            if answers is None or len(answers) != num_msg:
                return PAM_CONV_ERR

            arr_p = _alloc_response_array(num_msg)
            arr   = (PamResponse * num_msg).from_address(arr_p)
            for i, ans in enumerate(answers):
                if ans is None:
                    arr[i].resp = None
                else:
                    raw = libc.strdup(ans.encode())
                    if not raw:
                        return PAM_BUF_ERR
                    arr[i].resp = ctypes.cast(raw, c_char_p)
                arr[i].resp_retcode = 0
            resp_ptr[0] = ctypes.cast(arr_p, POINTER(PamResponse))
            return PAM_SUCCESS
        except Exception:
            import traceback, sys
            traceback.print_exc(file=sys.stderr)
            return PAM_CONV_ERR

    # ── lifecycle ────────────────────────────────────────────────────────────

    def __enter__(self):
        rc = libpam.pam_start(self.service.encode(),
                              self.user.encode(),
                              ctypes.byref(self._pam_conv),
                              ctypes.byref(self._pamh))
        _check(self._pamh, rc, "pam_start")
        return self

    def __exit__(self, exc_type, exc, tb):
        if self._pamh:
            libpam.pam_end(self._pamh, PAM_SUCCESS)
            self._pamh = c_void_p()

    # ── API ──────────────────────────────────────────────────────────────────

    def putenv(self, key: str, value: str):
        rc = libpam.pam_putenv(self._pamh, f"{key}={value}".encode())
        _check(self._pamh, rc, f"pam_putenv({key})")

    def set_item(self, item_type: int, value: str):
        # PAM keeps its own copy of the string; passing a bytes pointer is OK.
        b = value.encode() if isinstance(value, str) else value
        rc = libpam.pam_set_item(self._pamh, item_type, c_char_p(b))
        _check(self._pamh, rc, f"pam_set_item({item_type})")

    def authenticate(self, flags: int = 0) -> int:
        """Run pam_authenticate; return the raw PAM code (PAM_SUCCESS == 0)."""
        return libpam.pam_authenticate(self._pamh, flags)

    def strerror(self, code: int) -> str:
        s = libpam.pam_strerror(self._pamh, code) or b""
        return s.decode(errors='replace')
