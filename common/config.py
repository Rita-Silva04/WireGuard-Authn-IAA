"""
Shared fail-closed configuration loader (§1.12).

Every service (IdP, Helpdesk, SrvAuthn) calls require_env() at process start.
If a required environment variable is missing, empty, or still set to a
placeholder/sentinel, the process logs a clear error and exits non-zero so
the deployment cannot silently boot with known-weak secrets.
"""

import sys

# Substrings that mark an unset/placeholder value. If the env var contains any
# of these (case-insensitive) the value is treated as missing.
PLACEHOLDER_MARKERS = (
    "change-me",
    "change_me",
    "changeme",
    "replace-me",
    "replace_me",
    "replace_or",
    "replace_with",
    "your-secret",
    "your_secret",
    "todo",
    "placeholder",
)


def _looks_like_placeholder(value: str) -> bool:
    if not value:
        return True
    low = value.strip().lower()
    return any(marker in low for marker in PLACEHOLDER_MARKERS)


def require_env(name: str, env: dict | None = None) -> str:
    """
    Return env[name] if it is set and non-empty and not a placeholder.

    On failure, print a clear error to stderr and exit with status 78
    (EX_CONFIG from sysexits.h). Never returns a placeholder value.
    """
    import os
    src = env if env is not None else os.environ
    value = src.get(name, "")
    if _looks_like_placeholder(value):
        sys.stderr.write(
            f"[config] FATAL: required environment variable {name!r} is missing "
            f"or set to a placeholder ({value!r}).\n"
            f"[config] Refusing to start with an insecure configuration.\n"
        )
        sys.exit(78)
    return value


def require_envs(*names: str) -> dict[str, str]:
    """Validate several env vars at once and return a dict of their values."""
    return {n: require_env(n) for n in names}


def require_master_key() -> str:
    """
    Validate IAA_MASTER_KEY at startup (§4.6). The variable holds a base64
    string that must decode to exactly 32 bytes for AES-256-GCM. We refuse
    to start if it is missing, a placeholder, or the wrong length.
    """
    import base64
    raw = require_env("IAA_MASTER_KEY")
    try:
        key = base64.b64decode(raw, validate=True)
    except Exception as e:
        sys.stderr.write(
            f"[config] FATAL: IAA_MASTER_KEY is not valid base64: {e}\n"
        )
        sys.exit(78)
    if len(key) != 32:
        sys.stderr.write(
            f"[config] FATAL: IAA_MASTER_KEY must decode to 32 bytes "
            f"(got {len(key)} bytes). Generate one with:\n"
            f"  python3 -c \"import os, base64; "
            f"print(base64.b64encode(os.urandom(32)).decode())\"\n"
        )
        sys.exit(78)
    return raw
