"""
Risk-Based Authentication (RBA) Engine.

Computes a risk score and decides which MFA factors are required.

§1.5 — ASN is resolved only from a local GeoIP database. No external API is
called during login, so the demo remains offline and the client IP is not
shared with third parties.

Risk indicators (current set):
  - New IP address for this user          (+0.20)
  - New ASN for this user                 (+0.15)
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
import os
from datetime import datetime, timezone

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from common import db as database


FACTOR_PASSWORD = "password"
FACTOR_TOTP     = "totp"
FACTOR_FIDO2    = "fido2"

# Thresholds — kept on the float 0.0–1.0 axis for the existing math but
# also exposed on the 0–100 axis for PAM (the C module reads IAA_RISK_SCORE
# as a small integer per §2.7).
THRESHOLD_LOW  = 0.30   # below → password only
THRESHOLD_MED  = 0.60   # below → password + TOTP
SCORE_SCALE    = 100    # internal float 0.0–1.0 → wire integer 0–100
ASN_DB_PATH    = os.environ.get("GEOIP_ASN_DB_PATH", "/geoip/dbip-asn-lite-2026-05.mmdb")


def _is_private_or_loopback(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback
    except ValueError:
        return False


def _lookup_asn(ip: str) -> str:
    """Resolve an IP to AS number/name using a local GeoIP ASN database."""
    if _is_private_or_loopback(ip) or not ASN_DB_PATH or not os.path.exists(ASN_DB_PATH):
        return ""
    try:
        import maxminddb
        from geoip2.errors import AddressNotFoundError
    except Exception:
        return ""

    try:
        with maxminddb.open_database(ASN_DB_PATH) as reader:
            result = reader.get(ip) or {}
    except (AddressNotFoundError, OSError, ValueError):
        return ""

    number = (
        result.get("autonomous_system_number")
        or result.get("asn")
        or result.get("as_number")
    )
    org = (
        result.get("autonomous_system_organization")
        or result.get("as_name")
        or result.get("organization")
        or result.get("isp")
        or ""
    )
    if number and org:
        return f"AS{number} {org}"
    if number:
        return f"AS{number}"
    return org


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
    asn = _lookup_asn(ip_address)

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

        known_asns = {row["asn"] for row in history if row["asn"]}
        if asn and known_asns and asn not in known_asns:
            score += 0.15
            reasons.append(f"New ASN: {asn}")

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

    return {
        "score":     round(score, 3),
        "score_int": int(round(score * SCORE_SCALE)),  # §2.7 — for PAM
        "level":     risk_label(score),
        "factors":   None if missing else required,
        "reasons":   reasons,
        "missing":   missing,
        "asn":       asn,
    }


def risk_label(score: float) -> str:
    if score < THRESHOLD_LOW:  return "LOW"
    if score < THRESHOLD_MED:  return "MED"
    return "HIGH"
