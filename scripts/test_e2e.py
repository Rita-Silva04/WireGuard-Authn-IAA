#!/usr/bin/env python3
"""
End-to-end integration test — fully automated.

Covers the whole stack at its current state: as of Phase 1 this exercises
server-generated WG keypair (§1.1), scrypt+HMAC password challenge-response
(§1.6), single-use OAuth tokens (§1.8), race-safe IP leasing (§1.11), and the
end-to-end VPN bring-up + ping.

What this script does:
  1. Ensures the Multipass VM 'vpn-client' exists and is running
  2. Discovers the gateway IP from the VM's perspective
  3. Regenerates the TLS cert with the correct IP SAN if needed
  4. Mounts the repo into the VM and installs dependencies
  5. Writes client/base.conf with the correct gateway address
  6. Runs userauthn.py inside the VM (via multipass exec)
  7. Simultaneously completes the OAuth Device Flow programmatically:
       - GET  /oauth/mfa/<sid>/password/challenge → {salt, nonce}
       - scrypt(password, salt) → verifier; HMAC-SHA256(verifier, nonce) → proof
       - POST /oauth/mfa/<sid>/password with proof
       - POST /oauth/mfa/<sid>/totp with the current code
  8. Verifies wg0 is up on the client, the peer appears on the server,
     and ping 10.10.10.1 succeeds from inside the VM

Usage:
    python3 scripts/test_e2e.py

Prerequisites:
    - docker compose stack is already up (docker compose up -d)
    - User 'alice' is enrolled in the helpdesk (password + TOTP)
    - multipass is installed (snap install multipass)
"""

import base64
import hashlib
import hmac
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request

# ── Config ────────────────────────────────────────────────────────────────────

PROJECT_ROOT    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VM_NAME         = "vpn-client"
WGPROJECT_IN_VM = "/home/ubuntu/wgproject"
USERNAME        = "alice"
PASSWORD        = "TestPass123"
IDP_URL         = "http://localhost:8080"

# ── Helpers ───────────────────────────────────────────────────────────────────

def step(n, msg):
    print(f"\n{'─'*60}\nStep {n}: {msg}\n{'─'*60}")

def ok(msg):
    print(f"  ✓  {msg}")

def fail(msg):
    print(f"\n  ✗  FAIL: {msg}\n")
    sys.exit(1)

def shell(cmd, capture=True, cwd=PROJECT_ROOT):
    r = subprocess.run(cmd, shell=True, text=True, cwd=cwd,
                       capture_output=capture)
    return r

def multipass(*args, capture=True):
    r = subprocess.run(["multipass"] + list(args),
                       capture_output=capture, text=True)
    return r

def vm_exec(*args, capture=True):
    r = subprocess.run(["multipass", "exec", VM_NAME, "--"] + list(args),
                       capture_output=capture, text=True)
    return r

def container_python(code):
    r = subprocess.run(
        ["docker", "exec", "vpn-idp", "python3", "-c", code],
        capture_output=True, text=True,
    )
    return r.stdout.strip()

# ── Steps ─────────────────────────────────────────────────────────────────────

def reset_state():
    """Remove stale WireGuard peers and auth DB rows so every run starts clean."""
    step(0, "Reset state from previous runs")

    # Remove all live peers from wg0
    r = subprocess.run(
        ["docker", "exec", "vpn-srvauthn", "wg", "show", "wg0"],
        capture_output=True, text=True,
    )
    peers = re.findall(r"peer: (\S+)", r.stdout)
    for p in peers:
        subprocess.run(
            ["docker", "exec", "vpn-srvauthn", "wg", "set", "wg0", "peer", p, "remove"],
            capture_output=True,
        )
    if peers:
        print(f"  Removed {len(peers)} stale peer(s) from wg0")

    # Truncate the [Peer] sections from wg0.conf so restarts stay clean
    conf_path = os.path.join(PROJECT_ROOT, "wireguard/wg0.conf")
    if os.path.exists(conf_path):
        with open(conf_path) as f:
            lines = f.readlines()
        clean = []
        in_peer = False
        for line in lines:
            if line.strip().startswith("[Peer]"):
                in_peer = True
            elif line.strip().startswith("[") and in_peer:
                in_peer = False
            if not in_peer:
                clean.append(line)
        with open(conf_path, "w") as f:
            f.writelines(clean)

    # Clear auth-related DB tables (keep users + credentials) and unlock
    # any account that may have hit the failure threshold in a prior run.
    container_python(
        "import sqlite3\n"
        "conn = sqlite3.connect('/data/vpnauth.db')\n"
        "for t in ('wg_peers','oauth_tokens','device_codes','mfa_sessions','rba_events','rba_ip_history'):\n"
        "    conn.execute(f'DELETE FROM {t}')\n"
        "conn.execute('UPDATE users SET failed_attempts=0, locked_until=0, last_failure_at=0')\n"
        "conn.commit()\n"
        "print('DB auth tables cleared, users unlocked')"
    )
    ok("State reset complete")


def ensure_vm():
    step(1, f"Ensure VM '{VM_NAME}' is running")
    r = multipass("info", VM_NAME)
    if r.returncode != 0:
        print(f"  VM not found — launching (takes 1–3 minutes)...")
        multipass("launch", "--name", VM_NAME, "24.04", capture=False)
    else:
        m = re.search(r"State:\s+(\w+)", r.stdout)
        state = m.group(1) if m else "unknown"
        if state != "Running":
            print(f"  VM is '{state}' — starting...")
            multipass("start", VM_NAME, capture=False)
        else:
            print(f"  VM already running")
    ok("VM is running")


def find_gateway_ip():
    step(2, "Find gateway IP (as seen from inside the VM)")
    r = vm_exec("ip", "route", "show", "default")
    m = re.search(r"default via (\S+)", r.stdout)
    if not m:
        fail(f"Could not parse gateway IP from: '{r.stdout.strip()}'")
    ip = m.group(1)
    ok(f"Gateway IP: {ip}")
    return ip


def ensure_cert(gateway_ip):
    step(3, "TLS certificate")
    cert = os.path.join(PROJECT_ROOT, "certs/srv.crt")
    key  = os.path.join(PROJECT_ROOT, "certs/srv.key")
    need_regen = True

    if os.path.exists(cert):
        r = shell(f"openssl x509 -noout -text -in certs/srv.crt")
        has_ip_san = f"IP Address:{gateway_ip}" in r.stdout
        if has_ip_san:
            print(f"  Cert already has IP SAN for {gateway_ip}")
            need_regen = False
        else:
            print(f"  Cert missing IP SAN for {gateway_ip} — regenerating")
            os.unlink(cert)
            os.unlink(key)

    if need_regen:
        r = shell(f"bash scripts/init-certs.sh {gateway_ip}")
        if r.returncode != 0:
            fail(f"init-certs.sh failed:\n{r.stderr}")
        ok(f"Cert regenerated (CN={gateway_ip}, SAN includes IP:{gateway_ip})")

        print("  Restarting srvauthn to pick up new cert...")
        shell("docker compose restart srvauthn")
        for _ in range(30):
            time.sleep(1)
            r = shell("docker compose logs srvauthn --no-log-prefix 2>&1 | tail -3")
            if "listening on port 9999" in r.stdout:
                break
        else:
            fail("SrvAuthn did not restart in time")
        ok("SrvAuthn restarted with new cert")
    else:
        ok("Cert is valid — no restart needed")


def mount_and_install(gateway_ip):
    step(4, "Mount repo into VM and install dependencies")

    multipass("mount", PROJECT_ROOT, f"{VM_NAME}:{WGPROJECT_IN_VM}")
    time.sleep(1)

    r = vm_exec("ls", f"{WGPROJECT_IN_VM}/client/userauthn.py")
    if r.returncode != 0:
        fail(f"Repo not visible at {WGPROJECT_IN_VM} inside VM")
    ok("Repo mounted")

    r = vm_exec("which", "wg")
    if r.returncode != 0:
        print("  Installing wireguard-tools and python3...")
        vm_exec("sudo", "apt-get", "update", "-qq")
        r = vm_exec("sudo", "apt-get", "install", "-y", "-qq",
                    "wireguard-tools", "python3")
        if r.returncode != 0:
            fail(f"apt install failed:\n{r.stderr}")
    ok("Dependencies installed")


def write_base_conf(gateway_ip):
    step(5, "Write client/base.conf")
    pubkey = open(os.path.join(PROJECT_ROOT, "wireguard/publickey-server")).read().strip()
    conf = (
        "[server]\n"
        f"public_key  = {pubkey}\n"
        f"address     = {gateway_ip}\n"
        "port        = 51820\n"
        "auth_port   = 9999\n"
        f"tls_cert    = {WGPROJECT_IN_VM}/certs/srv.crt\n"
    )
    path = os.path.join(PROJECT_ROOT, "client/base.conf")
    with open(path, "w") as f:
        f.write(conf)
    ok(f"Written client/base.conf (address={gateway_ip})")


def get_totp_secret():
    step(6, "Fetch TOTP secret for automated OAuth")
    secret = container_python(
        "import sqlite3\n"
        "conn = sqlite3.connect('/data/vpnauth.db')\n"
        "row = conn.execute("
        "  \"SELECT ts.secret FROM totp_secrets ts\"\n"
        "  \" JOIN users u ON u.id=ts.user_id\"\n"
        "  \" WHERE u.username='alice' AND ts.confirmed=1\"\n"
        ").fetchone()\n"
        "print(row[0] if row else '')"
    )
    if not secret:
        fail("No confirmed TOTP secret for 'alice'. "
             "Run the helpdesk enrolment steps first.")
    ok(f"TOTP secret found (length={len(secret)})")
    return secret


def get_totp_code(secret):
    return container_python(
        f"import pyotp; print(pyotp.TOTP('{secret}').now())"
    )


def complete_oauth(user_code, totp_secret, result):
    """Run in a thread — simulate the browser completing password + TOTP."""
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(),
        urllib.request.HTTPRedirectHandler(),
    )
    try:
        # POST /oauth/device/verify
        data = urllib.parse.urlencode(
            {"user_code": user_code, "username": USERNAME}
        ).encode()
        resp = opener.open(
            urllib.request.Request(
                f"{IDP_URL}/oauth/device/verify", data=data, method="POST"
            ), timeout=15
        )
        sid = resp.url.rstrip("/").split("/")[-1]
        print(f"  [oauth] Session: {sid}")

        time.sleep(0.3)

        # ── Password challenge-response (§1.6) ─────────────────────────────
        # 1. Fetch (salt, nonce) from the challenge endpoint.
        chresp = opener.open(
            f"{IDP_URL}/oauth/mfa/{sid}/password/challenge", timeout=15
        )
        challenge = json.loads(chresp.read())
        salt  = base64.b64decode(challenge["salt_b64"])
        nonce = base64.b64decode(challenge["nonce_b64"])
        sc    = challenge["scrypt"]

        # 2. Derive verifier = scrypt(password, salt, …) — same params as server.
        verifier = hashlib.scrypt(
            PASSWORD.encode(), salt=salt,
            n=sc["N"], r=sc["r"], p=sc["p"], dklen=sc["dkLen"],
            maxmem=64 * 1024 * 1024,
        )

        # 3. proof = HMAC-SHA256(verifier, nonce)
        proof = hmac.new(verifier, nonce, hashlib.sha256).digest()
        proof_b64 = base64.b64encode(proof).decode()

        # 4. POST only the proof — the raw password never leaves the client.
        data = urllib.parse.urlencode({"proof": proof_b64}).encode()
        opener.open(
            urllib.request.Request(
                f"{IDP_URL}/oauth/mfa/{sid}/password", data=data, method="POST"
            ), timeout=30
        )
        print(f"  [oauth] Password proof accepted (scrypt+HMAC)")

        time.sleep(0.3)

        # POST TOTP
        code = get_totp_code(totp_secret)
        data = urllib.parse.urlencode({"code": code}).encode()
        opener.open(
            urllib.request.Request(
                f"{IDP_URL}/oauth/mfa/{sid}/totp", data=data, method="POST"
            ), timeout=15
        )
        print(f"  [oauth] TOTP accepted (code={code})")
        result["oauth_ok"] = True

    except Exception as e:
        result["oauth_error"] = str(e)
        print(f"  [oauth] ERROR: {e}")


def run_userauthn_and_verify(totp_secret):
    step(7, "Run userauthn.py inside the VM + complete OAuth automatically")

    cmd = [
        "multipass", "exec", VM_NAME, "--",
        "sudo", "python3", "-u",   # -u disables stdout buffering in pipes
        f"{WGPROJECT_IN_VM}/client/userauthn.py",
        "--interface", "wg0",
        "--username", USERNAME,
        "--config", f"{WGPROJECT_IN_VM}/client/base.conf",
    ]

    result = {}
    oauth_thread = None
    output = []

    print("  Starting userauthn.py in VM...")
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, encoding="utf-8", errors="replace",
    )

    for line in proc.stdout:
        print(f"    {line}", end="")
        output.append(line)

        # Capture user_code and kick off OAuth thread
        if "Your code:" in line and oauth_thread is None:
            m = re.search(r"Your code[:\s│]+([A-Z0-9]{4}-[A-Z0-9]{4})", line)
            if m:
                user_code = m.group(1)
                print(f"\n  [test] Captured user_code={user_code}, starting OAuth...\n")
                oauth_thread = threading.Thread(
                    target=complete_oauth,
                    args=(user_code, totp_secret, result),
                    daemon=True,
                )
                oauth_thread.start()

    try:
        proc.wait(timeout=120)
    except subprocess.TimeoutExpired:
        proc.kill()
        fail("userauthn.py timed out after 120 s")

    if oauth_thread:
        oauth_thread.join(timeout=30)

    if "oauth_error" in result:
        fail(f"OAuth completion failed: {result['oauth_error']}")

    full_output = "".join(output)
    if proc.returncode != 0 or "VPN Connected" not in full_output:
        fail(f"userauthn.py failed (exit={proc.returncode}). "
             f"Last lines:\n{''.join(output[-10:])}")

    ok("userauthn.py completed — VPN Connected")
    return result


def verify_tunnel():
    step(8, "Verify the WireGuard tunnel")

    time.sleep(2)

    # wg show on client
    r = vm_exec("sudo", "wg", "show", "wg0")
    print(f"  wg show wg0 (client VM):\n{r.stdout}")
    if "peer:" not in r.stdout:
        fail("No peer in client wg0")
    ok("Client wg0 has server as peer")

    # wg show on server
    r = subprocess.run(
        ["docker", "exec", "vpn-srvauthn", "wg", "show", "wg0"],
        capture_output=True, text=True,
    )
    print(f"  wg show wg0 (server):\n{r.stdout}")
    if "peer:" not in r.stdout:
        fail("No peer in server wg0")
    ok("Server wg0 has client as peer")

    # ping
    print("  Pinging 10.10.10.1 from the VM...")
    r = vm_exec("ping", "-c", "3", "-W", "5", "10.10.10.1")
    print(r.stdout)
    if r.returncode != 0 or "0 received" in r.stdout:
        fail(f"Ping failed:\n{r.stdout}\n{r.stderr}")
    ok("ping 10.10.10.1 succeeded — tunnel is up!")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print("\n" + "═"*60)
    print("  End-to-end VM Integration Test")
    print("═"*60)

    reset_state()
    ensure_vm()
    gateway_ip  = find_gateway_ip()
    ensure_cert(gateway_ip)
    mount_and_install(gateway_ip)
    write_base_conf(gateway_ip)
    totp_secret = get_totp_secret()
    run_userauthn_and_verify(totp_secret)
    verify_tunnel()

    print("\n" + "═"*60)
    print("  ALL CHECKS PASSED — stack verified end-to-end!")
    print("═"*60 + "\n")


if __name__ == "__main__":
    main()
