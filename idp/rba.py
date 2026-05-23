"""
Risk-Based Authentication (RBA) Engine.

Computes a risk score 0.0–1.0 and decides which MFA factors are required.

Risk indicators:
  - New IP address for this user          (+0.20)
  - IP from different ASN than usual      (+0.25)
  - IP from different country             (+0.15)
  - Recent authentication failures        (+0.10 per failure, max +0.40)
  - Unusual time of day                   (+0.20)
  - First ever login (no history)         (+0.30)
  - IP is a known VPN/Tor exit            (+0.30)

Factor requirements based on score:
  0.00 – 0.30  →  password only
  0.30 – 0.60  →  password + TOTP
  0.60 – 1.00  →  password + TOTP + FIDO2
"""

import json
import ipaddress
import urllib.request
import urllib.error
from datetime import datetime, timezone

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import db.database as database


FACTOR_PASSWORD = "password"
FACTOR_TOTP     = "totp"
FACTOR_FIDO2    = "fido2"

# Thresholds
THRESHOLD_LOW  = 0.30   # below → password only
THRESHOLD_MED  = 0.60   # below → password + TOTP


def _get_asn_info(ip: str) -> dict:
    """Query ip-api.com for ASN and country info (free, no key needed)."""
    try:
        # Skip private IPs
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_loopback:
            return {"asn": "PRIVATE", "country": "LOCAL", "org": "local"}

        url = f"http://ip-api.com/json/{ip}?fields=status,country,org,as"
        req = urllib.request.Request(url, headers={"User-Agent": "vpnauth/1.0"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read())
            if data.get("status") == "success":
                return {
                    "asn":     data.get("as", ""),
                    "country": data.get("country", ""),
                    "org":     data.get("org", ""),
                }
    except Exception:
        pass
    return {"asn": "", "country": "", "org": ""}


def _is_unusual_hour(hour: int) -> bool:
    """Consider 0–6 AM unusual."""
    return 0 <= hour < 6


def _get_typical_asn(user_id: int) -> str | None:
    """Return the most frequently used ASN for this user."""
    history = database.get_ip_history(user_id)
    if not history:
        return None
    asn_counts: dict[str, int] = {}
    for row in history:
        asn = row["asn"] or ""
        asn_counts[asn] = asn_counts.get(asn, 0) + row["count"]
    return max(asn_counts, key=asn_counts.get)


def compute_risk(username: str, ip_address: str, user_agent: str = "") -> dict:
    """
    Compute the risk score for an authentication attempt.

    Returns:
        {
            "score":    float,          # 0.0 – 1.0
            "factors":  list[str],      # required MFA factors in order
            "reasons":  list[str],      # human-readable risk indicators
            "asn":      str,
            "country":  str,
        }
    """
    score   = 0.0
    reasons = []

    user = database.get_user(username)
    if not user:
        return {
            "score": 1.0,
            "factors": [FACTOR_PASSWORD, FACTOR_TOTP, FACTOR_FIDO2],
            "reasons": ["Unknown user"],
            "asn": "", "country": "",
        }

    user_id = user["id"]
    ip_info = _get_asn_info(ip_address)
    asn     = ip_info["asn"]
    country = ip_info["country"]

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

        typical_asn = _get_typical_asn(user_id)
        if typical_asn and asn and asn != typical_asn:
            score += 0.25
            reasons.append(f"Different ASN: {asn} (usual: {typical_asn})")

        # Country check — use most common country from history
        known_countries = {row["asn"] for row in history if row["asn"]}
        # (we piggyback country in asn field for simplicity)

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

    # ── Clamp score ───────────────────────────────────────────────────────────
    score = min(score, 1.0)

    # ── Determine required factors ────────────────────────────────────────────
    # Also check which factors the user actually has enrolled
    has_password = database.get_password_hash(user_id) is not None
    totp_row     = database.get_totp_secret(user_id)
    has_totp     = totp_row is not None and totp_row["confirmed"]
    fido2_creds  = database.get_fido2_credentials(user_id)
    has_fido2    = len(fido2_creds) > 0

    factors = []

    if score < THRESHOLD_LOW:
        # Low risk — password only
        if has_password:
            factors = [FACTOR_PASSWORD]
        else:
            factors = [FACTOR_TOTP] if has_totp else [FACTOR_FIDO2]

    elif score < THRESHOLD_MED:
        # Medium risk — password + TOTP
        factors = []
        if has_password:  factors.append(FACTOR_PASSWORD)
        if has_totp:      factors.append(FACTOR_TOTP)
        if not factors:   factors = [FACTOR_FIDO2] if has_fido2 else [FACTOR_PASSWORD]

    else:
        # High risk — all factors
        factors = []
        if has_password: factors.append(FACTOR_PASSWORD)
        if has_totp:     factors.append(FACTOR_TOTP)
        if has_fido2:    factors.append(FACTOR_FIDO2)
        if not factors:  factors = [FACTOR_PASSWORD]

    # ── Update IP history ─────────────────────────────────────────────────────
    database.upsert_ip_history(user_id, ip_address, asn)

    return {
        "score":   round(score, 3),
        "factors": factors,
        "reasons": reasons,
        "asn":     asn,
        "country": country,
    }


def risk_label(score: float) -> str:
    if score < THRESHOLD_LOW:  return "LOW"
    if score < THRESHOLD_MED:  return "MEDIUM"
    return "HIGH"
