#!/usr/bin/env python3
"""
One-command setup for the WireGuard-Authn stack.

Usage:
    python3 scripts/setup.py [--user alice] [--password TestPass123] [--force]

What it does (idempotent — safe to re-run):
  1. Check prerequisites (docker, wg)
  2. Generate .env with real secrets
  3. Generate the WireGuard server keypair
  4. Generate server/srvauthn.conf
  5. Prepare runtime data directory
  6. Build and start the Docker stack
  7. Enrol a test user (default: alice) with password + TOTP

After this script succeeds, run:
    python3 scripts/test_e2e.py
"""

import argparse
import os
import re
import secrets
import shutil
import subprocess
import sys
import time
import urllib.parse
import urllib.request

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ── Helpers ───────────────────────────────────────────────────────────────────

def step(n, msg):
    print(f"\n{'─'*60}\nStep {n}: {msg}\n{'─'*60}")

def ok(msg):   print(f"  ✓  {msg}")
def info(msg): print(f"  →  {msg}")
def warn(msg): print(f"  ⚠  {msg}")

def fail(msg):
    print(f"\n  ✗  FAIL: {msg}\n")
    sys.exit(1)

def shell(cmd, capture=True, check=True):
    return subprocess.run(
        cmd, shell=True, text=True, cwd=PROJECT_ROOT,
        capture_output=capture, check=check,
    )

def exists(*parts):
    return os.path.exists(os.path.join(PROJECT_ROOT, *parts))

def read(*parts):
    with open(os.path.join(PROJECT_ROOT, *parts)) as f:
        return f.read().strip()

def write(content, *parts):
    path = os.path.join(PROJECT_ROOT, *parts)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(content)

def container_python(code):
    r = subprocess.run(
        ["docker", "exec", "vpn-idp", "python3", "-c", code],
        capture_output=True, text=True,
    )
    return r.stdout.strip()

# ── Steps ─────────────────────────────────────────────────────────────────────

def check_prerequisites():
    step(1, "Check prerequisites")
    missing = []
    for tool in ("docker", "wg"):
        if not shutil.which(tool):
            missing.append(tool)
        else:
            ok(f"{tool} found")
    if missing:
        fail(f"Missing tools: {', '.join(missing)}\n"
             f"  Install with: sudo apt install {' '.join(missing).replace('docker', 'docker.io').replace('wg', 'wireguard-tools')}")

    r = shell("docker compose version", check=False)
    if r.returncode != 0:
        fail("'docker compose' (v2) not found. Install Docker Compose v2.")
    ok("docker compose v2 found")

    r = shell("docker info", check=False)
    if r.returncode != 0:
        fail("Docker daemon is not running or current user can't reach it.\n"
             "  Try: sudo systemctl start docker  OR  add yourself to the docker group.")
    ok("Docker daemon reachable")


def generate_env(force):
    step(2, "Environment file (.env)")

    if exists(".env") and not force:
        # Check if it still has placeholder values
        content = read(".env")
        if "change-me" in content or "REPLACE_OR" in content:
            warn(".env exists but has placeholder values — overwriting")
        else:
            ok(".env already configured — skipping")
            return

    import base64 as _b64
    secret_key      = secrets.token_hex(32)
    oauth_secret    = secrets.token_hex(32)
    iaa_master_key  = _b64.b64encode(secrets.token_bytes(32)).decode()

    template = read(".env.example")
    content  = template
    # Replace placeholder values
    content  = re.sub(r"SECRET_KEY=.*",          f"SECRET_KEY={secret_key}",   content)
    content  = re.sub(r"OAUTH_CLIENT_SECRET=.*", f"OAUTH_CLIENT_SECRET={oauth_secret}", content)
    content  = re.sub(r"IAA_MASTER_KEY=.*",      f"IAA_MASTER_KEY={iaa_master_key}", content)
    content  = re.sub(r"RP_ID=.*",               "RP_ID=localhost", content)
    content  = re.sub(r"ORIGIN=.*",              "ORIGIN=http://localhost:18080", content)
    content  = re.sub(r"HELPDESK_ORIGIN=.*",     "HELPDESK_ORIGIN=http://localhost:8081", content)
    # SERVER_PUBKEY will be filled in after WG key generation
    write(content, ".env")
    ok(".env written with fresh secrets (incl. IAA_MASTER_KEY for §4.6)")


def generate_wg_keys(force):
    step(3, "WireGuard server keypair")

    if exists("wireguard", "privatekey-server") and not force:
        ok("WireGuard keys already exist — skipping")
        pubkey = read("wireguard", "publickey-server")
    else:
        r = shell("bash scripts/init-wg.sh", check=False)
        if r.returncode != 0:
            # Already exists error from the script
            if "already exists" in r.stdout:
                ok("WireGuard keys already exist — skipping")
                pubkey = read("wireguard", "publickey-server")
            else:
                fail(f"init-wg.sh failed:\n{r.stdout}\n{r.stderr}")
        else:
            pubkey = read("wireguard", "publickey-server")
            ok(f"WireGuard keypair generated")

    ok(f"Server public key: {pubkey}")

    # Patch SERVER_PUBKEY into .env
    env = read(".env")
    env = re.sub(r"SERVER_PUBKEY=.*", f"SERVER_PUBKEY={pubkey}", env)
    write(env, ".env")
    ok("SERVER_PUBKEY written to .env")
    return pubkey


def generate_srvauthn_conf(pubkey, force):
    step(4, "SrvAuthn config (server/srvauthn.conf)")

    if exists("server", "srvauthn.conf") and not force:
        ok("srvauthn.conf already exists — skipping")
        return

    oauth_secret = ""
    for line in read(".env").splitlines():
        if line.startswith("OAUTH_CLIENT_SECRET="):
            oauth_secret = line.split("=", 1)[1]

    template = read("server", "srvauthn.conf.example")
    content  = re.sub(r"wg_public_key\s*=.*",
                      f"wg_public_key   = {pubkey}", template)
    content  = re.sub(r"oauth_client_secret\s*=.*",
                      f"oauth_client_secret = {oauth_secret}", content)
    write(content, "server", "srvauthn.conf")
    ok("server/srvauthn.conf written")


def generate_base_conf(pubkey, force):
    step("4b", "Client base config (client/base.conf)")

    if exists("client", "base.conf") and not force:
        ok("client/base.conf already exists — skipping")
        return

    content = f"""[server]
public_key  = {pubkey}
address     = host.docker.internal
port        = 51820
auth_port   = 9999
allowed_ips = 10.10.10.0/24
"""
    write(content, "client", "base.conf")
    ok("client/base.conf written")


def prepare_data_dir():
    step("4c", "Runtime data directory (data/)")
    path = os.path.join(PROJECT_ROOT, "data")
    os.makedirs(path, exist_ok=True)

    # Docker bind-mounts this directory as /data. On hosts using user namespace
    # remapping, container-created files can appear as nobody:nogroup; keeping
    # the directory host-owned and writable avoids reset/delete failures.
    os.chmod(path, 0o777)
    ok("data/ ready for Docker bind mount")


def start_stack(force):
    step(5, "Build and start Docker stack")

    # Check if all three containers are already running
    r = shell("docker compose ps -q --status running 2>/dev/null | wc -l", check=False)
    running = int(r.stdout.strip()) if r.returncode == 0 else 0

    if running >= 3 and not force:
        ok("Stack is already running — skipping build")
    else:
        info("Building images (first time takes 1–2 minutes)...")
        r = shell("docker compose up -d --build", capture=False, check=False)
        if r.returncode != 0:
            fail("docker compose up failed — check output above")

    # Wait for all three services to be ready
    info("Waiting for services to be ready...")
    deadline = time.time() + 60
    while time.time() < deadline:
        r = shell("docker compose logs --no-log-prefix 2>&1", check=False)
        logs = r.stdout
        idp_up      = "Running on" in logs and "8080" in logs
        helpdesk_up = "Running on" in logs and "8081" in logs
        srv_up      = "listening on port 9999" in logs
        if idp_up and helpdesk_up and srv_up:
            break
        time.sleep(2)
    else:
        fail("Services did not become ready within 60 s.\n"
             "  Check with: docker compose logs")

    ok("vpn-idp      ready on :8080")
    ok("vpn-helpdesk ready on :8081")
    ok("vpn-srvauthn ready on :9999 (Noise-IK)")

    # Verify wg0
    r = subprocess.run(
        ["docker", "exec", "vpn-srvauthn", "wg", "show", "wg0"],
        capture_output=True, text=True,
    )
    if r.returncode != 0 or "listening port" not in r.stdout:
        fail("wg0 is not up inside the container.\n"
             "  Check: docker compose logs srvauthn")
    ok("wg0 up and listening on UDP 51820")


def enrol_user(username, password, force):
    step(6, f"Enrol test user '{username}'")

    base = "http://localhost:8081"

    def post(path, data):
        body = urllib.parse.urlencode(data).encode()
        req  = urllib.request.Request(f"{base}{path}", data=body, method="POST")
        opener = urllib.request.build_opener(urllib.request.HTTPRedirectHandler())
        return opener.open(req, timeout=10)

    # Check if already enrolled
    r = subprocess.run(
        ["docker", "exec", "vpn-idp", "python3", "-c",
         f"import sqlite3; conn=sqlite3.connect('/data/vpnauth.db'); "
         f"r=conn.execute(\"SELECT id FROM users WHERE username='{username}'\").fetchone(); "
         f"print('exists' if r else 'missing')"],
        capture_output=True, text=True,
    )
    already_exists = r.stdout.strip() == "exists"

    if already_exists and not force:
        # Check if fully enrolled (password + totp)
        enrolled = container_python(
            f"import sqlite3; conn=sqlite3.connect('/data/vpnauth.db'); "
            f"u=conn.execute(\"SELECT id FROM users WHERE username='{username}'\").fetchone(); "
            f"uid=u[0] if u else None; "
            f"pw=conn.execute('SELECT 1 FROM passwords WHERE user_id=?',(uid,)).fetchone() if uid else None; "
            f"tp=conn.execute('SELECT 1 FROM totp_secrets WHERE user_id=? AND confirmed=1',(uid,)).fetchone() if uid else None; "
            f"print('full' if pw and tp else 'partial')"
        )
        if enrolled == "full":
            ok(f"'{username}' already fully enrolled — skipping")
            return
        info(f"'{username}' exists but enrolment is incomplete — continuing")

    # Create user (ignore error if already exists)
    try:
        post(f"/user/create", {"username": username})
        ok(f"User '{username}' created")
    except Exception:
        info(f"User '{username}' already exists — continuing")

    # Set password
    try:
        post(f"/user/{username}/password", {"password": password})
        ok(f"Password set")
    except Exception as e:
        fail(f"Setting password failed: {e}")

    # Generate TOTP secret
    try:
        post(f"/user/{username}/totp", {})
        ok("TOTP secret generated")
    except Exception as e:
        fail(f"Generating TOTP failed: {e}")

    # Read the secret from the DB and confirm it. Since §4.6 the column
    # holds AES-256-GCM ciphertext; route through common.db so the master
    # key in the container env decrypts it correctly.
    totp_secret = container_python(
        f"import sys; sys.path.insert(0,'/app'); "
        f"from common import db as d; "
        f"u=d.get_user('{username}'); "
        f"row=d.get_totp_secret(u['id']) if u else None; "
        f"print(row['secret'] if row else '')"
    )
    if not totp_secret:
        fail(f"Could not read pending TOTP secret for '{username}' from DB")

    totp_code = container_python(
        f"import pyotp; print(pyotp.TOTP('{totp_secret}').now())"
    )

    try:
        post(f"/user/{username}/totp/confirm", {"code": totp_code})
        ok(f"TOTP confirmed (code={totp_code})")
    except Exception as e:
        fail(f"TOTP confirmation failed: {e}")

    # Final check
    enrolled = container_python(
        f"import sqlite3; conn=sqlite3.connect('/data/vpnauth.db'); "
        f"u=conn.execute(\"SELECT id FROM users WHERE username='{username}'\").fetchone(); "
        f"uid=u[0] if u else None; "
        f"pw=conn.execute('SELECT 1 FROM passwords WHERE user_id=?',(uid,)).fetchone() if uid else None; "
        f"tp=conn.execute('SELECT 1 FROM totp_secrets WHERE user_id=? AND confirmed=1',(uid,)).fetchone() if uid else None; "
        f"print('full' if pw and tp else 'partial')"
    )
    if enrolled != "full":
        fail(f"Enrolment check failed — something is missing")

    ok(f"'{username}' fully enrolled: password ✓  TOTP ✓")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="One-command setup for the WireGuard-Authn stack"
    )
    parser.add_argument("--user",     default="alice",       help="Test username to enrol (default: alice)")
    parser.add_argument("--password", default="TestPass123", help="Password for the test user")
    parser.add_argument("--force",    action="store_true",   help="Overwrite existing keys/config/enrolment")
    args = parser.parse_args()

    print("\n" + "═"*60)
    print("  WireGuard-Authn — Stack Setup")
    print("═"*60)

    check_prerequisites()
    generate_env(args.force)
    pubkey = generate_wg_keys(args.force)
    generate_srvauthn_conf(pubkey, args.force)
    generate_base_conf(pubkey, args.force)
    prepare_data_dir()
    start_stack(args.force)
    enrol_user(args.username if hasattr(args, "username") else args.user,
               args.password, args.force)

    print("\n" + "═"*60)
    print("  Setup complete!")
    print("═"*60)
    print(f"""
  Services:
    IdP       →  http://localhost:8080
    Helpdesk  →  http://localhost:8081
    SrvAuthn  →  port 9999 (Noise-IK)
    WireGuard →  UDP 51820

  Test user:  {args.user}  /  {args.password}

  Next step — run the full end-to-end test:
    python3 scripts/test_e2e.py
""")


if __name__ == "__main__":
    main()
