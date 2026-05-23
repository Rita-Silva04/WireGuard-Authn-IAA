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

Flow:
  1. Generate a fresh WireGuard keypair
  2. Connect to SrvAuthn via TLS (verify server cert)
  3. Send hello: {username, client_pubkey, interface}
  4. Receive: {user_code, verification_uri}
  5. Open browser at verification_uri
  6. Wait for SrvAuthn to send WireGuard config
  7. Apply WireGuard interface
"""

import argparse
import configparser
import json
import os
import platform
import socket
import ssl
import subprocess
import sys
import tempfile
import webbrowser
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [UserAuthn] %(levelname)s %(message)s",
)
log = logging.getLogger("userauthn")


def load_config(path: str) -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    if not os.path.exists(path):
        log.error(f"Config file not found: {path}")
        sys.exit(1)
    cfg.read(path)
    return cfg


def generate_wg_keypair() -> tuple[str, str]:
    """Generate a WireGuard private/public key pair. Returns (private, public)."""
    private = subprocess.check_output(["wg", "genkey"]).decode().strip()
    public  = subprocess.check_output(
        ["wg", "pubkey"], input=private.encode()
    ).decode().strip()
    return private, public


def connect_to_srvauthn(address: str, auth_port: int,
                          tls_cert: str | None) -> ssl.SSLSocket:
    """Open a TLS connection to SrvAuthn, verifying server identity."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    if tls_cert and os.path.exists(tls_cert):
        # Pin to the server's self-signed cert
        ctx.load_verify_locations(tls_cert)
        ctx.verify_mode = ssl.CERT_REQUIRED
        log.info(f"TLS: verifying against {tls_cert}")
    else:
        # In development, allow without cert verification
        # Production deployments MUST provide a cert
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        log.warning("TLS: certificate verification disabled (development mode)")

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

    # Write config
    with open(conf_path, "w") as f:
        f.write(config)
    os.chmod(conf_path, 0o600)

    log.info(f"Written {conf_path}")

    # Bring down if already up
    subprocess.run(["wg-quick", "down", interface],
                   capture_output=True)

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

    # ── Step 1: Generate WireGuard keypair ────────────────────────────────────
    log.info("Generating WireGuard keypair…")
    private_key, public_key = generate_wg_keypair()
    log.info(f"Client public key: {public_key}")

    # ── Step 2: Connect to SrvAuthn ───────────────────────────────────────────
    log.info(f"Connecting to SrvAuthn at {srv_address}:{auth_port}…")
    try:
        sock = connect_to_srvauthn(srv_address, auth_port, tls_cert)
    except Exception as e:
        log.error(f"Cannot connect to SrvAuthn: {e}")
        sys.exit(1)

    log.info("TLS connection established")

    try:
        # ── Step 3: Send hello ────────────────────────────────────────────────
        send_json(sock, {
            "username":     args.username,
            "client_pubkey": public_key,
            "interface":    args.interface,
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
            # Auto-open browser
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
        psk          = result["psk"]
        username     = result.get("username", args.username)

        log.info(f"Auth success for {username} — allocated IP: {client_ip}")

        # ── Step 6: Apply WireGuard interface ─────────────────────────────────
        log.info(f"Applying WireGuard interface {args.interface}…")
        ok = apply_wireguard_interface(
            interface     = args.interface,
            private_key   = private_key,
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
