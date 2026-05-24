"""
Risk-Based Authentication (RBA) Engine.

Computes a risk score and decides which MFA factors are required.

§1.5 — ASN/country signals removed. The previous implementation called
ip-api.com synchronously, which introduced an external dependency, leaked the
client IP, and broke offline demos. Justification: see JUSTIFICATIONS.md §2.

Risk indicators (current set):
  - New IP address for this user          (+0.20)
  - Recent authentication failures        (+0.10 per failure, max +0.40)
  - Unusual time of day                   (+0.20)
  - First ever login (no history)         (+0.30)

§1.4 — Strict tiering with no fallback:
  L1 (score < THRESHOLD_LOW)  → require password
  L2 (score < THRESHOLD_MED)  → require password + TOTP
  L3 (otherwise)              → require password + TOTP + FIDO2

If the user is missing a required factor at the chosen tier, compute_risk()
returns factors=None plus a human-readable reason. The IdP renders an error
page directing the user to contact the helpdesk.
"""

import ipaddress
from datetime import datetime, timezone

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from common import db as database


FACTOR_PASSWORD = "password"
FACTOR_TOTP     = "totp"
FACTOR_FIDO2    = "fido2"

# Thresholds
THRESHOLD_LOW  = 0.30   # below → password only
THRESHOLD_MED  = 0.60   # below → password + TOTP


def _is_private_or_loopback(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback
    except ValueError:
        return False


def _is_unusual_hour(hour: int) -> bool:
    """Consider 0–6 AM unusual."""
    return 0 <= hour < 6


def _required_factors_for(score: float) -> list[str]:
    """Map a numeric risk score to the strict factor list demanded by §1.4."""
    if score < THRESHOLD_LOW:
        return [FACTOR_PASSWORD]
    if score < THRESHOLD_MED:
        return [FACTOR_PASSWORD, FACTOR_TOTP]
    return [FACTOR_PASSWORD, FACTOR_TOTP, FACTOR_FIDO2]


def _missing_factors(user_id: int, required: list[str]) -> list[str]:
    """Return the subset of `required` the user is NOT enrolled for."""
    missing: list[str] = []
    if FACTOR_PASSWORD in required and not database.has_password(user_id):
        missing.append(FACTOR_PASSWORD)
    if FACTOR_TOTP in required:
        row = database.get_totp_secret(user_id)
        if not row or not row["confirmed"]:
            missing.append(FACTOR_TOTP)
    if FACTOR_FIDO2 in required:
        if not database.get_fido2_credentials(user_id):
            missing.append(FACTOR_FIDO2)
    return missing


def compute_risk(username: str, ip_address: str, user_agent: str = "") -> dict:
    """
    Compute the risk score for an authentication attempt.

    Returns:
        {
            "score":   float,            # 0.0 – 1.0
            "level":   "LOW"|"MED"|"HIGH",
            "factors": list[str] | None, # None if the user lacks a required factor
            "reasons": list[str],        # human-readable risk signals
            "missing": list[str],        # factors the user must enrol to log in
            "asn":     "" ,              # kept for log compatibility, always empty
        }
    """
    score   = 0.0
    reasons = []

    user = database.get_user(username)
    if not user:
        # Unknown user — pin to highest tier so the caller surfaces nothing useful.
        return {
            "score":   1.0,
            "level":   "HIGH",
            "factors": None,
            "reasons": ["Unknown user"],
            "missing": [FACTOR_PASSWORD, FACTOR_TOTP, FACTOR_FIDO2],
            "asn":     "",
        }

    user_id = user["id"]

    # ── IP history ────────────────────────────────────────────────────────────
    history = database.get_ip_history(user_id)
    if not history:
        score += 0.30
        reasons.append("First ever login — no IP history")
    else:
        known_ips = {row["ip_address"] for row in history}
        if ip_address not in known_ips:
            score += 0.20
            reasons.append(f"New IP address: {ip_address}")

    # ── Recent failures ───────────────────────────────────────────────────────
    failures = database.get_recent_failures(username, minutes=30)
    if failures > 0:
        penalty = min(failures * 0.10, 0.40)
        score  += penalty
        reasons.append(f"{failures} failed attempt(s) in last 30 min")

    # ── Time of day ───────────────────────────────────────────────────────────
    now  = datetime.now(timezone.utc)
    hour = now.hour
    if _is_unusual_hour(hour):
        score += 0.20
        reasons.append(f"Unusual hour: {hour:02d}:00 UTC")

    # Clamp
    score = min(score, 1.0)

    # ── §1.4: strict factor decision (no enrolment-based fallback) ────────────
    required = _required_factors_for(score)
    missing  = _missing_factors(user_id, required)

    # ── Update IP history (no ASN under §1.5) ─────────────────────────────────
    database.upsert_ip_history(user_id, ip_address, asn=None)

    return {
        "score":   round(score, 3),
        "level":   risk_label(score),
        "factors": None if missing else required,
        "reasons": reasons,
        "missing": missing,
        "asn":     "",
    }


def risk_label(score: float) -> str:
    if score < THRESHOLD_LOW:  return "LOW"
    if score < THRESHOLD_MED:  return "MED"
    return "HIGH"
