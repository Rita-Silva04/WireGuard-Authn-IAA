"""
Helpdesk UI — Internal enrolment and credential management.

§1.7 — bound to 127.0.0.1 only. The spec marks the helpdesk as internal and
exclusive; we refuse to listen on any other interface.

Routes:
  GET  /                          - user list
  GET  /user/<username>           - user detail + credential status
  POST /user/create               - create user
  POST /user/<username>/password  - set password (stored as scrypt verifier, §1.6)
  POST /user/<username>/totp      - generate/reset TOTP secret
  GET  /user/<username>/totp/qr   - TOTP QR code image
  POST /user/<username>/fido2/start   - start FIDO2 registration
  POST /user/<username>/fido2/finish  - finish FIDO2 registration
  DELETE /user/<username>/fido2/<cred_id> - remove FIDO2 credential
"""

import os
import sys
import json
import base64
import hashlib
import io
import secrets

import pyotp
import qrcode
from flask import (Flask, render_template, request, jsonify,
                   redirect, url_for, send_file, Response)
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    options_to_json,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    AuthenticatorTransport,
    PublicKeyCredentialDescriptor,
    UserVerificationRequirement,
    ResidentKeyRequirement,
)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from common import db as database
from common.config import require_env, require_master_key

# §1.12 + §4.6 — refuse to start without real secrets.
require_env("SECRET_KEY")
require_env("OAUTH_CLIENT_SECRET")
require_master_key()

app = Flask(__name__)
app.secret_key = os.environ["SECRET_KEY"]

RP_ID  = os.environ.get("RP_ID",  "localhost")
ORIGIN = os.environ.get("ORIGIN", "http://localhost")

# §1.6 — scrypt parameters (must match idp/app.py).
SCRYPT_N      = 2 ** 14
SCRYPT_R      = 8
SCRYPT_P      = 1
SCRYPT_DKLEN  = 32
SCRYPT_MAXMEM = 64 * 1024 * 1024

# In-memory challenge store (helpdesk is single-user internal tool)
_challenges: dict[str, str] = {}


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


def _derive_password_verifier(password: str, salt: bytes) -> bytes:
    """scrypt(password, salt, N=2^14, r=8, p=1) → 32 bytes (§1.6)."""
    return hashlib.scrypt(
        password.encode(), salt=salt,
        n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P,
        dklen=SCRYPT_DKLEN, maxmem=SCRYPT_MAXMEM,
    )


# ── Pages ──────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    users = database.list_users()
    return render_template("index.html", users=users)


@app.route("/user/<username>")
def user_detail(username):
    user = database.get_user(username)
    if not user:
        return render_template("error.html", error=f"User '{username}' not found"), 404

    has_pw   = database.has_password(user["id"])
    totp_row = database.get_totp_secret(user["id"])
    fido2s   = database.get_fido2_credentials(user["id"])

    return render_template("user.html",
                           user=user,
                           has_password=has_pw,
                           totp=totp_row,
                           fido2_creds=fido2s)


# ── User management ────────────────────────────────────────────────────────────

@app.route("/user/create", methods=["POST"])
def create_user():
    username     = request.form.get("username", "").strip()
    display_name = request.form.get("display_name", "").strip()
    if not username:
        return redirect(url_for("index"))
    database.create_user(username, display_name or username)
    return redirect(url_for("user_detail", username=username))


# ── Password management (§1.6 — scrypt verifier) ──────────────────────────────

@app.route("/user/<username>/password", methods=["POST"])
def set_password(username):
    user = database.get_user(username)
    if not user:
        return jsonify({"error": "User not found"}), 404

    password = request.form.get("password", "")
    if len(password) < 8:
        return render_template("user.html",
                               user=user,
                               error="Password must be at least 8 characters.",
                               has_password=database.has_password(user["id"]),
                               totp=database.get_totp_secret(user["id"]),
                               fido2_creds=database.get_fido2_credentials(user["id"]))

    salt     = secrets.token_bytes(16)
    verifier = _derive_password_verifier(password, salt)
    database.set_password_verifier(user["id"], salt, verifier)
    return redirect(url_for("user_detail", username=username))


# ── TOTP management ────────────────────────────────────────────────────────────

@app.route("/user/<username>/totp", methods=["POST"])
def reset_totp(username):
    user = database.get_user(username)
    if not user:
        return jsonify({"error": "User not found"}), 404

    secret = pyotp.random_base32()
    database.set_totp_secret(user["id"], secret, confirmed=False)
    return redirect(url_for("user_detail", username=username))


@app.route("/user/<username>/totp/confirm", methods=["POST"])
def confirm_totp(username):
    user = database.get_user(username)
    if not user:
        return jsonify({"error": "User not found"}), 404

    code     = request.form.get("code", "").strip()
    totp_row = database.get_totp_secret(user["id"])
    if not totp_row:
        return redirect(url_for("user_detail", username=username))

    totp  = pyotp.TOTP(totp_row["secret"])
    if totp.verify(code, valid_window=1):
        database.set_totp_secret(user["id"], totp_row["secret"], confirmed=True)

    return redirect(url_for("user_detail", username=username))


@app.route("/user/<username>/totp/qr")
def totp_qr(username):
    user = database.get_user(username)
    if not user:
        return jsonify({"error": "User not found"}), 404

    totp_row = database.get_totp_secret(user["id"])
    if not totp_row:
        return jsonify({"error": "No TOTP secret"}), 404

    issuer = "VPNAuth"
    uri    = pyotp.TOTP(totp_row["secret"]).provisioning_uri(
        name=username, issuer_name=issuer
    )
    img    = qrcode.make(uri)
    buf    = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return send_file(buf, mimetype="image/png")


# ── FIDO2 management (§1.9 — user verification REQUIRED) ──────────────────────

@app.route("/user/<username>/fido2/start", methods=["POST"])
def fido2_register_start(username):
    user = database.get_user(username)
    if not user:
        return jsonify({"error": "User not found"}), 404

    existing = database.get_fido2_credentials(user["id"])
    exclude = [
        _credential_descriptor(c["cred_id"], c["transports"])
        for c in existing
    ]

    options = generate_registration_options(
        rp_id          = RP_ID,
        rp_name        = "VPNAuth Helpdesk",
        user_name      = username,
        user_id        = str(user["id"]).encode(),
        exclude_credentials = exclude,
        authenticator_selection = AuthenticatorSelectionCriteria(
            user_verification = UserVerificationRequirement.REQUIRED,   # §1.9
            resident_key      = ResidentKeyRequirement.PREFERRED,
        ),
    )
    _challenges[username] = _b64url_encode(options.challenge)
    return Response(options_to_json(options), mimetype="application/json")


@app.route("/user/<username>/fido2/finish", methods=["POST"])
def fido2_register_finish(username):
    user = database.get_user(username)
    if not user:
        return jsonify({"error": "User not found"}), 404

    challenge_b64 = _challenges.pop(username, None)
    if not challenge_b64:
        return jsonify({"error": "No challenge in progress"}), 400

    body = request.get_json()
    try:
        verification = verify_registration_response(
            credential         = body,
            expected_challenge = _b64url_decode(challenge_b64),
            expected_rp_id    = RP_ID,
            expected_origin   = ORIGIN,
            require_user_verification = True,   # §1.9
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 400

    cred_id = _b64url_encode(verification.credential_id)
    pub_key = _b64url_encode(verification.credential_public_key)
    transports = json.dumps(body.get("response", {}).get("transports", []))
    key_name = request.args.get("name", "YubiKey")

    database.add_fido2_credential(
        user["id"], cred_id, pub_key,
        verification.sign_count, transports, key_name
    )
    return jsonify({"status": "ok", "message": "Security key registered"})


@app.route("/user/<username>/fido2/<cred_id>/delete", methods=["POST"])
def fido2_delete(username, cred_id):
    user = database.get_user(username)
    if not user:
        return jsonify({"error": "User not found"}), 404
    with database.db() as conn:
        conn.execute(
            "DELETE FROM fido2_credentials WHERE cred_id=? AND user_id=?",
            (cred_id, user["id"])
        )
    return redirect(url_for("user_detail", username=username))


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    database.init_db()
    # §1.7 — listen on the loopback interface only.
    app.run(host="127.0.0.1",
            port=int(os.environ.get("HELPDESK_PORT", 8081)),
            debug=False)
