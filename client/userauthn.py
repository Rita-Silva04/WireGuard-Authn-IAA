#!/usr/bin/env python3
"""
UserAuthn — Client-side Authentication Application

Usage:
    userauthn.py --interface wg0 --username alice --config base.conf [--port 9999]

base.conf:
    [server]
    public_key  = <wireguard server pubkey base64>
    address     = 192.168.1.79
    port        = 51820
    auth_port   = 9999
    tls_cert    = /path/to/srv.crt   # server TLS cert for verification

Flow (spec §3 — server-driven keypair):
  1. Generate a fresh PSK locally (§1.1, parameter 6)
  2. Connect to SrvAuthn via TLS (verify server cert — no fallback, §1.3)
  3. Send hello: {username, psk, interface}
  4. Receive: {user_code, verification_uri}
  5. Open browser at verification_uri
  6. Wait for SrvAuthn to send the WG config — including the *server-generated*
     client keypair (parameter 1) and the server-allocated private IP
     (parameter 2)
  7. Apply WireGuard interface
"""

import argparse
import base64
import configparser
import json
import os
import socket
import ssl
import subprocess
import sys
import webbrowser
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [UserAuthn] %(levelname)s %(message)s",
)
log = logging.getLogger("userauthn")


# ── Config ────────────────────────────────────────────────────────────────────

def load_config(path: str) -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    if not os.path.exists(path):
        log.error(f"Config file not found: {path}")
        sys.exit(1)
    cfg.read(path)
    return cfg


# ── WireGuard key helpers ─────────────────────────────────────────────────────

def is_valid_wg_key(value: str) -> bool:
    """Base64 string decoding to exactly 32 bytes — the WG key shape."""
    if not isinstance(value, str) or not value:
        return False
    try:
        raw = base64.b64decode(value, validate=True)
    except Exception:
        return False
    return len(raw) == 32


def generate_psk() -> str:
    """Generate a fresh WireGuard pre-shared key (parameter 6, §1.1)."""
    return subprocess.check_output(["wg", "genpsk"]).decode().strip()


# ── TLS connect (§1.3 — no silent CERT_NONE fallback) ─────────────────────────

def connect_to_srvauthn(address: str, auth_port: int,
                        tls_cert: str | None) -> ssl.SSLSocket:
    """
    Open a TLS connection to SrvAuthn, verifying server identity against the
    pinned self-signed certificate. If `tls_cert` is missing or unreadable we
    refuse to connect — there is no insecure fallback path (§1.3).
    """
    if not tls_cert:
        log.error("No tls_cert configured — refusing to connect. "
                  "Set tls_cert in base.conf to the server's pinned certificate.")
        sys.exit(1)
    if not os.path.exists(tls_cert):
        log.error(f"Server TLS certificate not found at {tls_cert} — "
                  f"refusing to connect.")
        sys.exit(1)
    if not os.access(tls_cert, os.R_OK):
        log.error(f"Server TLS certificate at {tls_cert} is not readable — "
                  f"refusing to connect.")
        sys.exit(1)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(tls_cert)
    ctx.verify_mode = ssl.CERT_REQUIRED
    log.info(f"TLS: verifying against {tls_cert}")

    raw = socket.create_connection((address, auth_port), timeout=30)
    return ctx.wrap_socket(raw, server_hostname=address)


def send_json(sock: ssl.SSLSocket, data: dict):
    sock.sendall(json.dumps(data).encode() + b"\n")


def recv_json(sock: ssl.SSLSocket) -> dict:
    raw = b""
    while not raw.endswith(b"\n"):
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("Connection closed by server")
        raw += chunk
    return json.loads(raw.strip())


# ── WireGuard interface bring-up ──────────────────────────────────────────────

def apply_wireguard_interface(interface: str, private_key: str, client_ip: str,
                              server_pubkey: str, server_address: str,
                              server_port: int, psk: str, dns: str = "1.1.1.1"):
    """Write and apply a WireGuard interface configuration."""
    config = f"""[Interface]
PrivateKey = {private_key}
Address = {client_ip}/24
DNS = {dns}

[Peer]
PublicKey = {server_pubkey}
PresharedKey = {psk}
Endpoint = {server_address}:{server_port}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
"""
    conf_path = f"/etc/wireguard/{interface}.conf"

    with open(conf_path, "w") as f:
        f.write(config)
    os.chmod(conf_path, 0o600)
    log.info(f"Written {conf_path}")

    # Bring down if already up
    subprocess.run(["wg-quick", "down", interface], capture_output=True)

    # Bring up
    result = subprocess.run(["wg-quick", "up", interface],
                            capture_output=True, text=True)
    if result.returncode != 0:
        log.error(f"wg-quick up failed:\n{result.stderr}")
        return False

    log.info(f"Interface {interface} is up — IP: {client_ip}")
    return True


def print_banner():
    print("""
╔══════════════════════════════════════════════════╗
║          UserAuthn — VPN Authentication          ║
║       WireGuard + FIDO2/TOTP/Password MFA        ║
╚══════════════════════════════════════════════════╝
""")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="UserAuthn — Client-side VPN Authentication"
    )
    parser.add_argument("--interface", required=True,  help="WireGuard interface name (e.g. wg0)")
    parser.add_argument("--username",  required=True,  help="Your username")
    parser.add_argument("--config",    required=True,  help="Base config file path")
    parser.add_argument("--port",      type=int,       help="Override SrvAuthn TLS port")
    args = parser.parse_args()

    print_banner()

    cfg = load_config(args.config)
    if not cfg.has_section("server"):
        log.error("Config file must have a [server] section")
        sys.exit(1)

    srv_address  = cfg.get("server", "address")
    srv_wg_port  = cfg.getint("server", "port",      fallback=51820)
    auth_port    = args.port or cfg.getint("server", "auth_port", fallback=9999)
    tls_cert     = cfg.get("server", "tls_cert",     fallback=None)
    server_pubkey= cfg.get("server", "public_key",   fallback="")

    # ── Step 1: Generate PSK only (server now generates the keypair, §1.1) ────
    log.info("Generating WireGuard PSK…")
    psk = generate_psk()
    log.info(f"PSK generated (length={len(base64.b64decode(psk))} bytes)")

    # ── Step 2: Connect to SrvAuthn ───────────────────────────────────────────
    log.info(f"Connecting to SrvAuthn at {srv_address}:{auth_port}…")
    try:
        sock = connect_to_srvauthn(srv_address, auth_port, tls_cert)
    except Exception as e:
        log.error(f"Cannot connect to SrvAuthn: {e}")
        sys.exit(1)

    log.info("TLS connection established")
    # The 30 s timeout was only for the initial connect.
    # The auth poll can take up to POLL_TIMEOUT seconds on the server side.
    sock.settimeout(660)

    try:
        # ── Step 3: Send hello (username + PSK; no client_pubkey, §1.1) ──────
        send_json(sock, {
            "username":  args.username,
            "psk":       psk,
            "interface": args.interface,
        })

        # ── Step 4: Receive auth instructions ─────────────────────────────────
        log.info("Waiting for server response…")
        resp = recv_json(sock)

        if resp.get("error"):
            log.error(f"Server error: {resp['error']}")
            sys.exit(1)

        if resp.get("status") == "pending":
            user_code        = resp["user_code"]
            verification_uri = resp["verification_uri"]

            print(f"""
┌─────────────────────────────────────────────────┐
│  Open this URL in your browser to authenticate:  │
│                                                   │
│  {verification_uri:<47} │
│                                                   │
│  Your code: {user_code:<36} │
└─────────────────────────────────────────────────┘
""")
            try:
                webbrowser.open(verification_uri)
                log.info("Browser opened automatically")
            except Exception:
                log.info("Could not open browser automatically — open URL manually")

            print("Waiting for authentication to complete…")

        # ── Step 5: Wait for WireGuard config ─────────────────────────────────
        result = recv_json(sock)

        if result.get("error"):
            log.error(f"Authentication failed: {result['error']}")
            sys.exit(1)

        if result.get("status") != "success":
            log.error(f"Unexpected response: {result}")
            sys.exit(1)

        client_ip    = result["client_ip"]
        srv_pub      = result.get("server_pubkey", server_pubkey)
        psk_back     = result.get("psk", psk)
        client_priv  = result.get("client_wg_private_key", "")
        client_pub   = result.get("client_wg_public_key", "")
        username     = result.get("username", args.username)

        # ── §1.1 validation: server must have sent a 32-byte private key ─────
        if not is_valid_wg_key(client_priv) or not is_valid_wg_key(client_pub):
            log.error("Server response missing or malformed client WG keypair "
                      "(expected base64-encoded 32-byte keys).")
            sys.exit(1)

        if psk_back != psk:
            # Server is required to echo back the same PSK; mismatch means
            # the server changed our PSK which violates the spec.
            log.error("Server echoed back a different PSK — refusing to apply.")
            sys.exit(1)

        log.info(f"Auth success for {username} — allocated IP: {client_ip}")

        # ── Step 6: Apply WireGuard interface ─────────────────────────────────
        log.info(f"Applying WireGuard interface {args.interface}…")
        ok = apply_wireguard_interface(
            interface     = args.interface,
            private_key   = client_priv,
            client_ip     = client_ip,
            server_pubkey = srv_pub,
            server_address= srv_address,
            server_port   = srv_wg_port,
            psk           = psk,
        )

        if ok:
            print(f"""
╔══════════════════════════════════════════════════╗
║              ✅  VPN Connected!                  ║
║                                                   ║
║  User:      {username:<36} ║
║  Interface: {args.interface:<36} ║
║  IP:        {client_ip:<36} ║
╚══════════════════════════════════════════════════╝
""")
        else:
            print("\n❌ WireGuard interface failed to come up. Check logs above.\n")
            sys.exit(1)

    finally:
        sock.close()


if __name__ == "__main__":
    main()
