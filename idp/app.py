"""
OAuth 2.0 Authorization Server — Device Authorization Grant (RFC 8628)

Endpoints:
  POST /oauth/device/code          - start device flow, get device_code + user_code
  GET  /oauth/device               - browser: enter user_code
  POST /oauth/device/verify        - browser: submit user_code → MFA flow
  GET  /oauth/mfa/<session_id>     - browser: MFA challenge page
  GET  /oauth/mfa/<session_id>/password/challenge
                                   - issue a fresh challenge {salt, nonce} (§1.6)
  POST /oauth/mfa/<session_id>/password
                                   - submit HMAC proof (§1.6)
  POST /oauth/mfa/<session_id>/totp
  GET  /oauth/mfa/<session_id>/fido2/start
  POST /oauth/mfa/<session_id>/fido2/finish
  POST /oauth/token                - poll for token (by SrvAuthn)
  GET  /oauth/userinfo             - validate token, return user info (single-use, §1.8)
"""

import os
import sys
import json
import hmac
import logging
import secrets
import hashlib
import base64
from datetime import datetime, timezone, timedelta

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
)
log_rba = logging.getLogger("rba")

from flask import (Flask, request, jsonify, render_template,
                   redirect, url_for, session, Response)
import pyotp
from webauthn import (
    generate_authentication_options,
    verify_authentication_response,
    options_to_json,
)
from webauthn.helpers.structs import (
    AuthenticatorTransport,
    PublicKeyCredentialDescriptor,
    UserVerificationRequirement,
)

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from common import db as database
from common.config import require_env, require_master_key
from idp.rba import compute_risk, risk_label
from idp import pam_bridge

# §1.12 + §4.6: refuse to start with missing/placeholder secrets.
require_env("SECRET_KEY")
require_env("OAUTH_CLIENT_SECRET")
require_master_key()

app = Flask(__name__)
app.secret_key = os.environ["SECRET_KEY"]

RP_ID    = os.environ.get("RP_ID", "localhost")
ORIGIN   = os.environ.get("ORIGIN", "http://localhost")
DEV_CODE_TTL    = 600   # seconds
TOKEN_TTL       = 60    # §1.8 — short-lived OAuth access tokens
MFA_SESSION_TTL = 300   # seconds

GENERIC_AUTH_ERROR = "Authentication failed. Check your credentials and try again later."
GENERIC_AUTH_UNAVAILABLE = "Authentication is temporarily unavailable. Try again later."

# §1.6 — scrypt parameters for the password verifier.
SCRYPT_N      = 2 ** 14
SCRYPT_R      = 8
SCRYPT_P      = 1
SCRYPT_DKLEN  = 32
SCRYPT_MAXMEM = 64 * 1024 * 1024   # 64 MiB headroom for hashlib.scrypt


# ── helpers ────────────────────────────────────────────────────────────────────

def _now_iso():
    return datetime.now(timezone.utc).isoformat()

def _expires_iso(seconds):
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat()

def _is_expired(iso_str):
    dt = datetime.fromisoformat(iso_str)
    return datetime.now(timezone.utc) > dt

def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def _b64url_decode(s: str) -> bytes:
    s = s.replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s)

def _credential_descriptor(cred_id: str, transports_json: str):
    transports = []
    for t in json.loads(transports_json or "[]"):
        try:
            transports.append(AuthenticatorTransport(t))
        except ValueError:
            pass
    return PublicKeyCredentialDescriptor(
        id=_b64url_decode(cred_id),
        transports=transports or None,
    )

def _user_code() -> str:
    """Generate a human-readable 8-char user code like ABCD-EFGH."""
    chars = "BCDFGHJKLMNPQRSTVWXZ"   # no vowels, no ambiguous chars
    a = "".join(secrets.choice(chars) for _ in range(4))
    b = "".join(secrets.choice(chars) for _ in range(4))
    return f"{a}-{b}"


def _lockout_message(seconds: int) -> str:
    if seconds <= 0:
        seconds = database.LOCKOUT_DURATION
    minutes = max(1, (seconds + 59) // 60)
    unit = "minute" if minutes == 1 else "minutes"
    return (f"Too many failed authentication attempts. "
            f"Try again in about {minutes} {unit}.")


def _lockout_seconds(user=None, username: str = None) -> int:
    if user:
        return database.auth_lockout_seconds_remaining(
            username or user["username"], user["id"]
        )
    return database.auth_lockout_seconds_remaining(username or "")


def _lockout_response(user=None, session_id=None, factor=None,
                      username: str = None):
    """Return the same lockout message for known and unknown identifiers."""
    return render_template(
        "error.html",
        error=_lockout_message(_lockout_seconds(user, username)),
    ), 429


def _lockout_json(user=None, username: str = None):
    return jsonify({
        "error": "locked_out",
        "message": _lockout_message(_lockout_seconds(user, username)),
    }), 429


def _request_ip() -> str:
    return request.remote_addr or "0.0.0.0"


def _request_user_agent() -> str:
    return request.headers.get("User-Agent", "")


def _session_rba_context(session_id: str):
    return database.get_rba_context(session_id)


def _ctx_value(ctx, key: str, fallback):
    return ctx[key] if ctx and ctx[key] is not None else fallback


def _client_secret_valid(client, supplied_secret: str) -> bool:
    expected = client["client_secret"]
    return bool(supplied_secret) and hmac.compare_digest(
        str(expected), str(supplied_secret)
    )


# ── Device Authorization Grant ─────────────────────────────────────────────────

@app.route("/oauth/device/code", methods=["POST"])
def device_code():
    """RFC 8628 §3.1 — Device Authorization Request."""
    payload = request.get_json(silent=True) or {}
    client_id = request.form.get("client_id") or payload.get("client_id", "")
    client_secret = (
        request.form.get("client_secret")
        or payload.get("client_secret")
        or ""
    )
    scope     = request.form.get("scope", "vpn")
    requested_username = (
        request.form.get("requested_username")
        or request.form.get("login_hint")
        or payload.get("requested_username")
        or payload.get("login_hint")
        or ""
    ).strip()
    client_ip = (
        request.form.get("client_ip")
        or payload.get("client_ip")
        or request.remote_addr
        or "0.0.0.0"
    ).strip()

    client = database.get_oauth_client(client_id)
    if not client or not _client_secret_valid(client, client_secret):
        return jsonify({"error": "invalid_client"}), 401

    dev_code  = secrets.token_urlsafe(32)
    user_code = _user_code()
    expires   = _expires_iso(DEV_CODE_TTL)

    database.create_device_code(
        dev_code, user_code, client_id, scope, expires,
        requested_username or None,
        client_ip or None,
    )

    verification_uri = f"{ORIGIN}/oauth/device"
    return jsonify({
        "device_code":               dev_code,
        "user_code":                 user_code,
        "verification_uri":          verification_uri,
        "verification_uri_complete": f"{verification_uri}?code={user_code}",
        "expires_in":                DEV_CODE_TTL,
        "interval":                  5,
    })


@app.route("/oauth/device", methods=["GET"])
def device_page():
    """Browser landing page — user enters user_code."""
    prefill = request.args.get("code", "")
    requested_username = ""
    if prefill:
        row = database.get_device_code_by_user_code(prefill.strip().upper())
        if row:
            requested_username = row["requested_username"] or ""
    return render_template("device.html",
                           prefill=prefill,
                           requested_username=requested_username)


@app.route("/oauth/device/verify", methods=["POST"])
def device_verify():
    """Browser submits user_code → start MFA."""
    user_code = request.form.get("user_code", "").strip().upper()
    username  = request.form.get("username", "").strip()

    row = database.get_device_code_by_user_code(user_code)
    if not row or _is_expired(row["expires_at"]):
        return render_template("device.html", error="Invalid or expired code.", prefill="")

    if row["status"] != "pending":
        return render_template("device.html", error="Code already used.", prefill="")

    requested_username = row["requested_username"] or ""
    user = database.get_user(username)
    if not user:
        return render_template("device.html",
                               error="Unknown username.",
                               prefill=user_code,
                               requested_username=requested_username)

    # §1.10 — refuse to start an MFA session for a locked-out user.
    if database.is_auth_locked(username, user["id"]):
        return _lockout_response(user=user, username=username)

    # RBA — compute risk and required factors (§1.4)
    ip  = row["client_ip"] or _request_ip()
    ua  = _request_user_agent()
    rba = compute_risk(username, ip, ua)
    log_rba.info("user=%s score=%.2f signals=%s tier=%s",
                 username, rba["score"], rba["signals"], rba["tier"])

    # §1.4 — strict policy: reject if the user lacks a required factor.
    if rba["factors"] is None:
        missing = ", ".join(rba["missing"]) or "additional factors"
        msg = (f"Risk level {rba['level']} requires factors you have not "
               f"enrolled ({missing}). Contact your helpdesk to enrol.")
        database.log_rba_event(
            username    = username,
            event_type  = "auth_blocked_missing_factor",
            success     = False,
            ip_address  = ip,
            asn         = rba["asn"],
            risk_score  = rba["score"],
            risk_reasons= json.dumps(rba["reasons"]),
            factors_used= json.dumps(rba.get("missing", [])),
            user_agent  = ua,
        )
        return render_template("error.html", error=msg), 403

    # Create MFA session
    mfa_sid = secrets.token_urlsafe(24)
    database.create_mfa_session(
        session_id      = mfa_sid,
        user_id         = user["id"],
        device_code     = row["device_code"],
        required_factors= json.dumps(rba["factors"]),
        expires_at      = _expires_iso(MFA_SESSION_TTL),
    )

    database.log_rba_event(
        username    = username,
        event_type  = "auth_start",
        success     = True,
        ip_address  = ip,
        asn         = rba["asn"],
        risk_score  = rba["score"],
        risk_reasons= json.dumps(rba["reasons"]),
        factors_used= json.dumps(rba["factors"]),
        user_agent  = ua,
        session_id  = mfa_sid,
    )

    # §2.3/2.7 — kick off the PAM thread; it will start asking for factors
    # via the conversation function. The bridge runs `pam_authenticate` in
    # a background thread and exposes pending prompts + final outcome here.
    pam_bridge.start_authentication(
        sid        = mfa_sid,
        username   = username,
        ip         = ip,
        risk_score = rba["score_int"],
    )

    return redirect(url_for("mfa_page", session_id=mfa_sid))


# ── MFA orchestration ──────────────────────────────────────────────────────────

_PROMPT_TO_FACTOR = {
    "FACTOR:password": "password",
    "FACTOR:totp":     "totp",
    "FACTOR:fido2":    "fido2",
}


def _factor_from_prompt(prompt: str | None) -> str | None:
    if not prompt:
        return None
    # tolerate extra trailing whitespace from C string handling
    return _PROMPT_TO_FACTOR.get(prompt.strip())


@app.route("/oauth/mfa/<session_id>", methods=["GET"])
def mfa_page(session_id):
    """
    Render whichever factor the PAM module is currently asking for. The
    sequencing of factors lives entirely in the PAM module (§2.4/§2.6);
    this handler only consumes the bridge's pending prompt and renders
    the matching template.
    """
    mfa = database.get_mfa_session(session_id)
    if not mfa or _is_expired(mfa["expires_at"]):
        return render_template("error.html", error=GENERIC_AUTH_ERROR), 400

    user = database.get_user_by_id(mfa["user_id"])

    # §1.10 — lockout check at the top of every factor route.
    if database.is_auth_locked(user["username"], user["id"]):
        # Make sure no PAM thread is still parked on a response.
        pam_bridge.submit_factor_result(session_id, "FAIL")
        return _lockout_response(user=user, session_id=session_id, factor=None)

    # If PAM has already finished, route to success/failure terminal page.
    final = pam_bridge.get_result(session_id)
    if final is True:
        return _complete_auth(mfa, session_id)
    if final is False:
        return render_template("error.html",
                               error=GENERIC_AUTH_ERROR), 401

    # Otherwise block briefly waiting for the next PAM prompt.
    prompt = pam_bridge.wait_for_prompt(session_id, timeout=5.0)
    if prompt is None:
        # PAM may have just finished between our two checks above; re-check.
        final = pam_bridge.get_result(session_id)
        if final is True:
            return _complete_auth(mfa, session_id)
        if final is False:
            return render_template("error.html",
                                   error=GENERIC_AUTH_ERROR), 401
        # Still pending — ask the browser to refresh.
        return render_template("error.html",
                               error="Authentication is still in progress. "
                                     "Please reload the page."), 503

    factor = _factor_from_prompt(prompt[0])
    if factor is None:
        return render_template("error.html",
                               error=GENERIC_AUTH_UNAVAILABLE), 500

    required = json.loads(mfa["required_factors"])
    return render_template("mfa.html",
                           session_id=session_id,
                           factor=factor,
                           username=user["username"],
                           required=required,
                           password_ok=mfa["password_ok"],
                           totp_ok=mfa["totp_ok"],
                           fido2_ok=mfa["fido2_ok"])


# ── §1.6 — Password challenge-response ────────────────────────────────────────

@app.route("/oauth/mfa/<session_id>/password/challenge", methods=["GET"])
def mfa_password_challenge(session_id):
    """
    Issue a fresh nonce and return (salt, nonce) so the browser can compute
    proof = HMAC-SHA256(scrypt(password, salt), nonce). The nonce is stored
    in the MFA session and marked unconsumed; it is invalidated on the next
    proof submission (success or failure) so each challenge is single-use.
    """
    mfa = database.get_mfa_session(session_id)
    if not mfa or _is_expired(mfa["expires_at"]):
        return jsonify({"error": "authentication_unavailable"}), 400

    user = database.get_user_by_id(mfa["user_id"])
    if database.is_auth_locked(user["username"], user["id"]):
        return _lockout_json(user=user)

    verifier = database.get_password_verifier(user["id"])
    if not verifier:
        return jsonify({"error": "authentication_unavailable"}), 400

    salt, _ = verifier
    nonce = secrets.token_bytes(32)
    database.issue_password_nonce(session_id, nonce)

    return jsonify({
        "salt_b64":  base64.b64encode(salt).decode(),
        "nonce_b64": base64.b64encode(nonce).decode(),
        "scrypt": {"N": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P,
                   "dkLen": SCRYPT_DKLEN},
    })


@app.route("/oauth/mfa/<session_id>/password", methods=["POST"])
def mfa_password(session_id):
    """Verify proof = HMAC-SHA256(verifier, nonce) — replay-rejected (§1.6)."""
    mfa = database.get_mfa_session(session_id)
    if not mfa or _is_expired(mfa["expires_at"]):
        return jsonify({"error": "authentication_unavailable"}), 400

    user = database.get_user_by_id(mfa["user_id"])

    if database.is_auth_locked(user["username"], user["id"]):
        return _lockout_response(user=user, session_id=session_id,
                                 factor="password")

    proof_b64 = request.form.get("proof", "")
    try:
        proof = base64.b64decode(proof_b64, validate=True)
    except Exception:
        proof = b""

    # Atomically consume the nonce — a second POST with the same nonce will
    # find it consumed and be rejected as replay.
    nonce = database.consume_password_nonce(session_id)
    verifier = database.get_password_verifier(user["id"])
    valid    = False
    if nonce and verifier and len(proof) == 32:
        _, verifier_bytes = verifier
        expected = hmac.new(verifier_bytes, nonce, hashlib.sha256).digest()
        valid = hmac.compare_digest(expected, proof)

    if not valid:
        ctx = _session_rba_context(session_id)
        database.record_auth_failure(user["username"], user["id"])
        database.log_rba_event(
            user["username"], "password_fail", False,
            ip_address  = _ctx_value(ctx, "ip_address", _request_ip()),
            user_agent  = _ctx_value(ctx, "user_agent", _request_user_agent()),
            session_id  = session_id,
            risk_score  = _ctx_value(ctx, "risk_score", 0.0),
            risk_reasons= _ctx_value(ctx, "risk_reasons", "[]"),
            factors_used= _ctx_value(ctx, "factors_used", "[]"),
        )
        # If this failure triggered the lockout, tear down the PAM thread so
        # it doesn't sit blocked on response_event for FACTOR_TIMEOUT.
        if database.is_auth_locked(user["username"], user["id"]):
            pam_bridge.submit_factor_result(session_id, "FAIL")
            return _lockout_response(user=user, session_id=session_id,
                                     factor="password")
        return render_template("mfa.html",
                               session_id=session_id,
                               factor="password",
                               error=GENERIC_AUTH_ERROR,
                               username=user["username"],
                               required=json.loads(mfa["required_factors"]),
                               password_ok=0, totp_ok=mfa["totp_ok"],
                               fido2_ok=mfa["fido2_ok"])

    database.update_mfa_session(session_id, password_ok=1)
    pam_bridge.submit_factor_result(session_id, "OK")
    return redirect(url_for("mfa_page", session_id=session_id))


@app.route("/oauth/mfa/<session_id>/totp", methods=["POST"])
def mfa_totp(session_id):
    mfa = database.get_mfa_session(session_id)
    if not mfa or _is_expired(mfa["expires_at"]):
        return jsonify({"error": "authentication_unavailable"}), 400

    user = database.get_user_by_id(mfa["user_id"])

    if database.is_auth_locked(user["username"], user["id"]):
        return _lockout_response(user=user, session_id=session_id,
                                 factor="totp")

    code  = request.form.get("code", "").strip()
    totp_row = database.get_totp_secret(user["id"])

    valid = False
    if totp_row and totp_row["confirmed"]:
        totp  = pyotp.TOTP(totp_row["secret"])
        valid = totp.verify(code, valid_window=1)

    if not valid:
        ctx = _session_rba_context(session_id)
        database.record_auth_failure(user["username"], user["id"])
        database.log_rba_event(
            user["username"], "totp_fail", False,
            ip_address  = _ctx_value(ctx, "ip_address", _request_ip()),
            user_agent  = _ctx_value(ctx, "user_agent", _request_user_agent()),
            session_id  = session_id,
            risk_score  = _ctx_value(ctx, "risk_score", 0.0),
            risk_reasons= _ctx_value(ctx, "risk_reasons", "[]"),
            factors_used= _ctx_value(ctx, "factors_used", "[]"),
        )
        if database.is_auth_locked(user["username"], user["id"]):
            pam_bridge.submit_factor_result(session_id, "FAIL")
            return _lockout_response(user=user, session_id=session_id,
                                     factor="totp")
        return render_template("mfa.html",
                               session_id=session_id,
                               factor="totp",
                               error=GENERIC_AUTH_ERROR,
                               username=user["username"],
                               required=json.loads(mfa["required_factors"]),
                               password_ok=mfa["password_ok"], totp_ok=0,
                               fido2_ok=mfa["fido2_ok"])

    database.update_mfa_session(session_id, totp_ok=1)
    pam_bridge.submit_factor_result(session_id, "OK")
    return redirect(url_for("mfa_page", session_id=session_id))


@app.route("/oauth/mfa/<session_id>/fido2/start", methods=["GET"])
def mfa_fido2_start(session_id):
    mfa = database.get_mfa_session(session_id)
    if not mfa or _is_expired(mfa["expires_at"]):
        return jsonify({"error": "authentication_unavailable"}), 400

    user = database.get_user_by_id(mfa["user_id"])
    if database.is_auth_locked(user["username"], user["id"]):
        return _lockout_json(user=user)

    creds = database.get_fido2_credentials(mfa["user_id"])
    allow_creds = [
        _credential_descriptor(c["cred_id"], c["transports"])
        for c in creds
    ]

    options = generate_authentication_options(
        rp_id             = RP_ID,
        allow_credentials = allow_creds,
        user_verification = UserVerificationRequirement.REQUIRED,   # §1.9
    )
    session[f"fido2_challenge_{session_id}"] = _b64url_encode(options.challenge)
    return Response(options_to_json(options), mimetype="application/json")


@app.route("/oauth/mfa/<session_id>/fido2/finish", methods=["POST"])
def mfa_fido2_finish(session_id):
    mfa = database.get_mfa_session(session_id)
    if not mfa or _is_expired(mfa["expires_at"]):
        return jsonify({"error": "authentication_unavailable"}), 400

    user = database.get_user_by_id(mfa["user_id"])
    if database.is_auth_locked(user["username"], user["id"]):
        return _lockout_json(user=user)

    challenge_b64 = session.get(f"fido2_challenge_{session_id}")
    if not challenge_b64:
        return jsonify({"error": "authentication_unavailable"}), 400

    body    = request.get_json()
    cred_id = body.get("id", "")

    cred_id_norm = cred_id.replace("+", "-").replace("/", "_").rstrip("=")
    cred_row = database.get_fido2_credential_by_id(cred_id_norm)
    if not cred_row or cred_row["user_id"] != mfa["user_id"]:
        ctx = _session_rba_context(session_id)
        database.record_auth_failure(user["username"], user["id"])
        database.log_rba_event(
            user["username"], "fido2_fail", False,
            ip_address  = _ctx_value(ctx, "ip_address", _request_ip()),
            user_agent  = _ctx_value(ctx, "user_agent", _request_user_agent()),
            session_id  = session_id,
            risk_score  = _ctx_value(ctx, "risk_score", 0.0),
            risk_reasons= _ctx_value(ctx, "risk_reasons", "[]"),
            factors_used= _ctx_value(ctx, "factors_used", "[]"),
        )
        if database.is_auth_locked(user["username"], user["id"]):
            pam_bridge.submit_factor_result(session_id, "FAIL")
            return _lockout_json(user=user)
        return jsonify({"error": "authentication_failed"}), 401

    def b64url_to_bytes(s):
        s = s.replace("-", "+").replace("_", "/")
        s += "=" * (-len(s) % 4)
        return base64.b64decode(s)

    try:
        verification = verify_authentication_response(
            credential             = body,
            expected_challenge     = b64url_to_bytes(challenge_b64),
            expected_rp_id        = RP_ID,
            expected_origin       = ORIGIN,
            credential_public_key = b64url_to_bytes(cred_row["public_key"]),
            credential_current_sign_count = cred_row["sign_count"],
            require_user_verification = True,   # §1.9
        )
    except Exception as e:
        ctx = _session_rba_context(session_id)
        database.record_auth_failure(user["username"], user["id"])
        database.log_rba_event(
            user["username"], "fido2_fail", False,
            ip_address  = _ctx_value(ctx, "ip_address", _request_ip()),
            user_agent  = _ctx_value(ctx, "user_agent", _request_user_agent()),
            session_id  = session_id,
            risk_score  = _ctx_value(ctx, "risk_score", 0.0),
            risk_reasons= _ctx_value(ctx, "risk_reasons", "[]"),
            factors_used= _ctx_value(ctx, "factors_used", "[]"),
        )
        if database.is_auth_locked(user["username"], user["id"]):
            pam_bridge.submit_factor_result(session_id, "FAIL")
            return _lockout_json(user=user)
        return jsonify({"error": "authentication_failed"}), 401

    database.update_fido2_sign_count(cred_id_norm, verification.new_sign_count)
    database.update_mfa_session(session_id, fido2_ok=1)
    pam_bridge.submit_factor_result(session_id, "OK")
    return jsonify({"status": "ok"})


def _complete_auth(mfa, session_id):
    """All factors passed — approve device code and reset failure counters."""
    database.approve_device_code(mfa["device_code"], mfa["user_id"])
    user = database.get_user_by_id(mfa["user_id"])
    database.reset_auth_failures(user["username"], mfa["user_id"])   # §1.10
    pam_bridge.cleanup(session_id)
    ctx = _session_rba_context(session_id)
    ip = _ctx_value(ctx, "ip_address", _request_ip())
    asn = _ctx_value(ctx, "asn", None)
    database.upsert_ip_history(user["id"], ip, asn=asn)
    database.log_rba_event(
        username     = user["username"],
        event_type   = "auth_success",
        success      = True,
        ip_address   = ip,
        asn          = asn,
        user_agent   = _ctx_value(ctx, "user_agent", _request_user_agent()),
        session_id   = session_id,
        risk_score   = _ctx_value(ctx, "risk_score", 0.0),
        risk_reasons = _ctx_value(ctx, "risk_reasons", "[]"),
        factors_used = _ctx_value(ctx, "factors_used", mfa["required_factors"]),
    )
    return render_template("success.html", username=user["username"])


# ── Token endpoint (§1.8 — short TTL, hashed at rest) ─────────────────────────

@app.route("/oauth/token", methods=["POST"])
def token():
    """RFC 8628 §3.5 — Device Access Token Request (polled by SrvAuthn)."""
    grant_type  = request.form.get("grant_type", "")
    device_code = request.form.get("device_code", "")
    client_id   = request.form.get("client_id", "")
    client_secret = request.form.get("client_secret", "")

    if grant_type != "urn:ietf:params:oauth:grant-type:device_code":
        return jsonify({"error": "unsupported_grant_type"}), 400

    client = database.get_oauth_client(client_id)
    if not client or not _client_secret_valid(client, client_secret):
        return jsonify({"error": "invalid_client"}), 401

    row = database.get_device_code(device_code)
    if not row:
        return jsonify({"error": "invalid_grant"}), 400
    if _is_expired(row["expires_at"]):
        return jsonify({"error": "expired_token"}), 400
    if row["status"] == "pending":
        return jsonify({"error": "authorization_pending"}), 400
    if row["status"] == "denied":
        return jsonify({"error": "access_denied"}), 400

    # Issue access token — stored as SHA-256 hash, never plaintext (§1.8).
    access_token = secrets.token_urlsafe(48)
    expires      = _expires_iso(TOKEN_TTL)
    database.create_access_token(access_token, row["user_id"],
                                  client_id, row["scope"], expires)

    user = database.get_user_by_id(row["user_id"])
    return jsonify({
        "access_token": access_token,
        "token_type":   "Bearer",
        "expires_in":   TOKEN_TTL,
        "username":     user["username"],
    })


# ── Userinfo endpoint (§1.8 — single-use) ─────────────────────────────────────

@app.route("/oauth/userinfo", methods=["GET"])
def userinfo():
    """
    Called by SrvAuthn after token obtained — returns user info. The token
    is marked used on first successful call; subsequent calls return 401
    even within the TTL window (§1.8).
    """
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error": "unauthorized"}), 401

    token_str = auth[7:]
    tok = database.get_access_token(token_str)
    if not tok or _is_expired(tok["expires_at"]):
        return jsonify({"error": "invalid_token"}), 401

    if tok["used_at"] is not None:
        return jsonify({"error": "invalid_token"}), 401

    # Mark used *before* returning the body — a concurrent retry will lose
    # the UPDATE race and see used_at != NULL.
    if not database.mark_token_used(token_str):
        return jsonify({"error": "invalid_token"}), 401

    user = database.get_user_by_id(tok["user_id"])
    iface = request.args.get("interface", "wg0")
    peer  = database.get_wg_peer(tok["user_id"], iface)

    return jsonify({
        "sub":         str(user["id"]),
        "username":    user["username"],
        "wg_peer": {
            "client_ip":  peer["client_ip"]  if peer else None,
            "psk":        peer["psk"]         if peer else None,
            "client_pubkey": peer["client_pubkey"] if peer else None,
        } if peer else None,
    })


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    database.init_db()
    database.ensure_default_client()
    app.run(host="0.0.0.0", port=int(os.environ.get("IDP_PORT", 8080)),
            debug=False)
