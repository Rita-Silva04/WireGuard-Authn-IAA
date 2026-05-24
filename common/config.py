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
