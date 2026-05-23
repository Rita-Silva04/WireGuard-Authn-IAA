"""
PAM-facing endpoints — added to the IdP Flask app.
The PAM module calls these to get required factors and verify credentials.

Mount this as a blueprint into idp/app.py.
"""

import json
import os
import sys

import bcrypt
import pyotp
from flask import Blueprint, jsonify, request

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import db.database as database

pam_bp = Blueprint("pam", __name__, url_prefix="/pam")


@pam_bp.route("/factors", methods=["GET"])
def pam_factors():
    """
    Called by pam_vpnmfa.so to get required factors for a user+session.
    Returns: {"factors": ["password", "totp", "fido2"]}
    """
    username   = request.args.get("username", "")
    session_id = request.args.get("session_id", "")

    # If there's an active MFA session, use its required_factors
    if session_id:
        mfa = database.get_mfa_session(session_id)
        if mfa:
            factors = json.loads(mfa["required_factors"])
            return jsonify({"factors": factors, "source": "mfa_session"})

    # Fallback: return all factors the user has enrolled
    user = database.get_user(username)
    if not user:
        return jsonify({"factors": [], "error": "unknown_user"}), 404

    factors = []
    if database.get_password_hash(user["id"]):
        factors.append("password")
    totp_row = database.get_totp_secret(user["id"])
    if totp_row and totp_row["confirmed"]:
        factors.append("totp")
    if database.get_fido2_credentials(user["id"]):
        factors.append("fido2")

    return jsonify({"factors": factors, "source": "enrolled"})


@pam_bp.route("/verify", methods=["POST"])
def pam_verify():
    """
    Called by pam_vpnmfa.so with collected credentials.
    Verifies password + TOTP. FIDO2 is verified via browser flow.
    Returns: {"status": "ok"} or {"status": "fail", "reason": "..."}
    """
    username   = request.form.get("username", "")
    password   = request.form.get("password", "")
    totp_code  = request.form.get("totp", "")
    session_id = request.form.get("session_id", "")

    user = database.get_user(username)
    if not user:
        return jsonify({"status": "fail", "reason": "unknown_user"}), 401

    mfa = database.get_mfa_session(session_id) if session_id else None
    required = json.loads(mfa["required_factors"]) if mfa else []

    # ── Verify password ──────────────────────────────────────────────────────
    if "password" in required or (not required and password):
        pw_hash = database.get_password_hash(user["id"])
        if not pw_hash:
            return jsonify({"status": "fail", "reason": "no_password_set"}), 401
        if not bcrypt.checkpw(password.encode(), pw_hash.encode()):
            database.log_rba_event(username, "pam_password_fail", False,
                                    request.remote_addr)
            return jsonify({"status": "fail", "reason": "wrong_password"}), 401
        if mfa:
            database.update_mfa_session(session_id, password_ok=1)

    # ── Verify TOTP ──────────────────────────────────────────────────────────
    if "totp" in required and totp_code:
        totp_row = database.get_totp_secret(user["id"])
        if not totp_row or not totp_row["confirmed"]:
            return jsonify({"status": "fail", "reason": "totp_not_enrolled"}), 401
        totp = pyotp.TOTP(totp_row["secret"])
        if not totp.verify(totp_code, valid_window=1):
            database.log_rba_event(username, "pam_totp_fail", False,
                                    request.remote_addr)
            return jsonify({"status": "fail", "reason": "wrong_totp"}), 401
        if mfa:
            database.update_mfa_session(session_id, totp_ok=1)

    # ── FIDO2 check — trust browser session ─────────────────────────────────
    if "fido2" in required:
        if mfa and not mfa["fido2_ok"]:
            return jsonify({"status": "fail", "reason": "fido2_pending"}), 401

    database.log_rba_event(username, "pam_verify_success", True,
                            request.remote_addr)
    return jsonify({"status": "ok"})
