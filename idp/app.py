"""
OAuth 2.0 Authorization Server — Device Authorization Grant (RFC 8628)

Endpoints:
  POST /oauth/device/code          - start device flow, get device_code + user_code
  GET  /oauth/device               - browser: enter user_code
  POST /oauth/device/verify        - browser: submit user_code → MFA flow
  GET  /oauth/mfa/<session_id>     - browser: MFA challenge page
  POST /oauth/mfa/<session_id>/password
  POST /oauth/mfa/<session_id>/totp
  GET  /oauth/mfa/<session_id>/fido2/start
  POST /oauth/mfa/<session_id>/fido2/finish
  POST /oauth/token                - poll for token (by SrvAuthn)
  GET  /oauth/userinfo             - validate token, return user info + WG params
"""

import os
import sys
import json
import secrets
import hashlib
import base64
from datetime import datetime, timezone, timedelta

from flask import (Flask, request, jsonify, render_template,
                   redirect, url_for, session, Response)
import bcrypt
import pyotp
from webauthn import (
    generate_authentication_options,
    verify_authentication_response,
    options_to_json,
)
from webauthn.helpers.structs import UserVerificationRequirement

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import db.database as database
from rba.engine import compute_risk, risk_label

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "idp-secret-change-me")

RP_ID    = os.environ.get("RP_ID", "localhost")
ORIGIN   = os.environ.get("ORIGIN", "http://localhost")
DEV_CODE_TTL   = 600   # seconds
TOKEN_TTL      = 3600  # seconds
MFA_SESSION_TTL = 300  # seconds


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

def _user_code() -> str:
    """Generate a human-readable 8-char user code like ABCD-EFGH."""
    chars = "BCDFGHJKLMNPQRSTVWXZ"   # no vowels, no ambiguous chars
    a = "".join(secrets.choice(chars) for _ in range(4))
    b = "".join(secrets.choice(chars) for _ in range(4))
    return f"{a}-{b}"


# ── Device Authorization Grant ─────────────────────────────────────────────────

@app.route("/oauth/device/code", methods=["POST"])
def device_code():
    """RFC 8628 §3.1 — Device Authorization Request."""
    client_id = request.form.get("client_id") or request.json.get("client_id", "")
    scope     = request.form.get("scope", "vpn")

    client = database.get_oauth_client(client_id)
    if not client:
        return jsonify({"error": "invalid_client"}), 401

    dev_code  = secrets.token_urlsafe(32)
    user_code = _user_code()
    expires   = _expires_iso(DEV_CODE_TTL)

    database.create_device_code(dev_code, user_code, client_id, scope, expires)

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
    return render_template("device.html", prefill=prefill)


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

    user = database.get_user(username)
    if not user:
        return render_template("device.html",
                               error="Unknown username.", prefill=user_code)

    # RBA — compute risk and required factors
    ip  = request.remote_addr or "0.0.0.0"
    ua  = request.headers.get("User-Agent", "")
    rba = compute_risk(username, ip, ua)

    # Create MFA session
    mfa_sid = secrets.token_urlsafe(24)
    database.create_mfa_session(
        session_id      = mfa_sid,
        user_id         = user["id"],
        device_code     = row["device_code"],
        required_factors= json.dumps(rba["factors"]),
        expires_at      = _expires_iso(MFA_SESSION_TTL),
    )

    # Log RBA event (pending)
    database.log_rba_event(
        username    = username,
        event_type  = "auth_start",
        success     = False,
        ip_address  = ip,
        asn         = rba["asn"],
        risk_score  = rba["score"],
        factors_used= json.dumps(rba["factors"]),
        user_agent  = ua,
    )

    return redirect(url_for("mfa_page", session_id=mfa_sid))


# ── MFA orchestration ──────────────────────────────────────────────────────────

def _mfa_next_factor(mfa_session):
    """Return the next incomplete required factor, or None if all done."""
    required = json.loads(mfa_session["required_factors"])
    for factor in required:
        if factor == "password" and not mfa_session["password_ok"]:
            return "password"
        if factor == "totp"     and not mfa_session["totp_ok"]:
            return "totp"
        if factor == "fido2"    and not mfa_session["fido2_ok"]:
            return "fido2"
    return None   # all done


@app.route("/oauth/mfa/<session_id>", methods=["GET"])
def mfa_page(session_id):
    mfa = database.get_mfa_session(session_id)
    if not mfa or _is_expired(mfa["expires_at"]):
        return render_template("error.html", error="MFA session expired."), 400

    factor = _mfa_next_factor(mfa)
    if factor is None:
        return _complete_auth(mfa, session_id)

    user = database.get_user_by_id(mfa["user_id"])
    required = json.loads(mfa["required_factors"])
    return render_template("mfa.html",
                           session_id=session_id,
                           factor=factor,
                           username=user["username"],
                           required=required,
                           password_ok=mfa["password_ok"],
                           totp_ok=mfa["totp_ok"],
                           fido2_ok=mfa["fido2_ok"])


@app.route("/oauth/mfa/<session_id>/password", methods=["POST"])
def mfa_password(session_id):
    mfa = database.get_mfa_session(session_id)
    if not mfa or _is_expired(mfa["expires_at"]):
        return jsonify({"error": "Session expired"}), 400

    password = request.form.get("password", "")
    user     = database.get_user_by_id(mfa["user_id"])
    pw_hash  = database.get_password_hash(mfa["user_id"])

    if not pw_hash or not bcrypt.checkpw(password.encode(), pw_hash.encode()):
        database.log_rba_event(user["username"], "password_fail", False,
                                request.remote_addr)
        return render_template("mfa.html",
                               session_id=session_id,
                               factor="password",
                               error="Incorrect password.",
                               username=user["username"],
                               required=json.loads(mfa["required_factors"]),
                               password_ok=0, totp_ok=mfa["totp_ok"],
                               fido2_ok=mfa["fido2_ok"])

    database.update_mfa_session(session_id, password_ok=1)
    return redirect(url_for("mfa_page", session_id=session_id))


@app.route("/oauth/mfa/<session_id>/totp", methods=["POST"])
def mfa_totp(session_id):
    mfa = database.get_mfa_session(session_id)
    if not mfa or _is_expired(mfa["expires_at"]):
        return jsonify({"error": "Session expired"}), 400

    code  = request.form.get("code", "").strip()
    user  = database.get_user_by_id(mfa["user_id"])
    totp_row = database.get_totp_secret(mfa["user_id"])

    valid = False
    if totp_row and totp_row["confirmed"]:
        totp  = pyotp.TOTP(totp_row["secret"])
        valid = totp.verify(code, valid_window=1)

    if not valid:
        database.log_rba_event(user["username"], "totp_fail", False,
                                request.remote_addr)
        return render_template("mfa.html",
                               session_id=session_id,
                               factor="totp",
                               error="Invalid TOTP code.",
                               username=user["username"],
                               required=json.loads(mfa["required_factors"]),
                               password_ok=mfa["password_ok"], totp_ok=0,
                               fido2_ok=mfa["fido2_ok"])

    database.update_mfa_session(session_id, totp_ok=1)
    return redirect(url_for("mfa_page", session_id=session_id))


@app.route("/oauth/mfa/<session_id>/fido2/start", methods=["GET"])
def mfa_fido2_start(session_id):
    mfa = database.get_mfa_session(session_id)
    if not mfa or _is_expired(mfa["expires_at"]):
        return jsonify({"error": "Session expired"}), 400

    creds = database.get_fido2_credentials(mfa["user_id"])
    allow_creds = [{"id": _b64url_decode(c["cred_id"]),
                    "transports": json.loads(c["transports"])}
                   for c in creds]

    options = generate_authentication_options(
        rp_id             = RP_ID,
        allow_credentials = allow_creds,
        user_verification = UserVerificationRequirement.PREFERRED,
    )
    session[f"fido2_challenge_{session_id}"] = _b64url_encode(options.challenge)
    return Response(options_to_json(options), mimetype="application/json")


@app.route("/oauth/mfa/<session_id>/fido2/finish", methods=["POST"])
def mfa_fido2_finish(session_id):
    mfa = database.get_mfa_session(session_id)
    if not mfa or _is_expired(mfa["expires_at"]):
        return jsonify({"error": "Session expired"}), 400

    challenge_b64 = session.get(f"fido2_challenge_{session_id}")
    if not challenge_b64:
        return jsonify({"error": "No FIDO2 challenge in session"}), 400

    body    = request.get_json()
    cred_id = body.get("id", "")

    # Normalise to base64url
    cred_id_norm = cred_id.replace("+", "-").replace("/", "_").rstrip("=")
    cred_row = database.get_fido2_credential_by_id(cred_id_norm)
    if not cred_row or cred_row["user_id"] != mfa["user_id"]:
        return jsonify({"error": "Credential not found"}), 401

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
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 401

    database.update_fido2_sign_count(cred_id_norm, verification.new_sign_count)
    database.update_mfa_session(session_id, fido2_ok=1)
    return jsonify({"status": "ok"})


def _complete_auth(mfa, session_id):
    """All factors passed — approve device code."""
    database.approve_device_code(mfa["device_code"], mfa["user_id"])
    user = database.get_user_by_id(mfa["user_id"])
    database.log_rba_event(
        username     = user["username"],
        event_type   = "auth_success",
        success      = True,
        ip_address   = request.remote_addr,
        factors_used = mfa["required_factors"],
    )
    return render_template("success.html", username=user["username"])


# ── Token endpoint ─────────────────────────────────────────────────────────────

@app.route("/oauth/token", methods=["POST"])
def token():
    """RFC 8628 §3.5 — Device Access Token Request (polled by SrvAuthn)."""
    grant_type  = request.form.get("grant_type", "")
    device_code = request.form.get("device_code", "")
    client_id   = request.form.get("client_id", "")

    if grant_type != "urn:ietf:params:oauth:grant-type:device_code":
        return jsonify({"error": "unsupported_grant_type"}), 400

    client = database.get_oauth_client(client_id)
    if not client:
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

    # Issue access token
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


# ── Userinfo endpoint ──────────────────────────────────────────────────────────

@app.route("/oauth/userinfo", methods=["GET"])
def userinfo():
    """Called by SrvAuthn after token obtained — returns user + WG peer info."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error": "unauthorized"}), 401

    token_str = auth[7:]
    tok = database.get_access_token(token_str)
    if not tok or _is_expired(tok["expires_at"]):
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


# ── PAM blueprint ──────────────────────────────────────────────────────────────
from idp.pam_routes import pam_bp
app.register_blueprint(pam_bp)
