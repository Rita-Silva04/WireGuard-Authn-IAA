#!/usr/bin/env python3
"""
UserAuthn — Client-side Authentication Application

Usage:
    userauthn.py --interface wg0 --username alice --config base.conf [--port 9999]

base.conf:
    [server]
    public_key  = <wireguard server pubkey base64>      # also the Noise-IK static
    address     = 192.168.1.79
    port        = 51820
    auth_port   = 9999

Flow (spec §3 — server-driven keypair, Noise-IK tunnel):
  1. Generate a fresh PSK locally (§1.1, parameter 6)
  2. Open a Noise-IK tunnel to SrvAuthn, keyed on the server's WG public
     key (which doubles as the responder's Noise static key — see
     JUSTIFICATIONS.md §5). No TLS, no certificates.
  3. Send hello: {service: "auth", username, psk, interface}
  4. Receive: {user_code, verification_uri}
  5. Open browser at verification_uri (in deployments with the local HTTP
     proxy this resolves to 127.0.0.1:18080 — see proxy.py).
  6. Wait for SrvAuthn to send the WG config — including the
     server-generated client keypair (parameter 1) and the server-allocated
     private IP (parameter 2).
  7. Apply WireGuard interface; optionally start the proxy listener for the
     OAuth browser flow.
"""

import argparse
import base64
import configparser
import json
import os
import subprocess
import sys
import threading
import webbrowser
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [UserAuthn] %(levelname)s %(message)s",
)
log = logging.getLogger("userauthn")

# Make ``common`` and sibling ``client`` packages importable when this file
# is run directly (e.g. ``sudo python3 client/userauthn.py …``) as well as
# via ``python -m client.userauthn``.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from client import tunnel as tunnel_mod
from client import proxy  as proxy_mod


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
    if not isinstance(value, str) or not value:
        return False
    try:
        raw = base64.b64decode(value, validate=True)
    except Exception:
        return False
    return len(raw) == 32


def generate_psk() -> str:
    return subprocess.check_output(["wg", "genpsk"]).decode().strip()


# ── Tunnel JSON helpers ───────────────────────────────────────────────────────

def send_json(session, obj: dict) -> None:
    session.send(json.dumps(obj).encode())


def recv_json(session) -> dict:
    raw = session.recv()
    return json.loads(raw.decode())


# ── WireGuard interface bring-up ──────────────────────────────────────────────

def apply_wireguard_interface(interface: str, private_key: str, client_ip: str,
                              server_pubkey: str, server_address: str,
                              server_port: int, psk: str,
                              allowed_ips: str = "10.10.10.0/24",
                              dns: str = "1.1.1.1"):
    config = f"""[Interface]
PrivateKey = {private_key}
Address = {client_ip}/24
DNS = {dns}

[Peer]
PublicKey = {server_pubkey}
PresharedKey = {psk}
Endpoint = {server_address}:{server_port}
AllowedIPs = {allowed_ips}
PersistentKeepalive = 25
"""
    conf_path = f"/etc/wireguard/{interface}.conf"

    with open(conf_path, "w") as f:
        f.write(config)
    os.chmod(conf_path, 0o600)
    log.info(f"Written {conf_path}")

    subprocess.run(["wg-quick", "down", interface], capture_output=True)
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
    parser.add_argument("--port",      type=int,       help="Override SrvAuthn tunnel port")
    parser.add_argument("--proxy-host", default="127.0.0.1",
                        help="Local HTTP proxy bind address (default 127.0.0.1). "
                             "Use 0.0.0.0 inside a Docker client container "
                             "when publishing the port to the host.")
    parser.add_argument("--proxy-port", type=int, default=18080,
                        help="Local HTTP proxy port (default 18080). "
                             "Set to 0 to disable the proxy.")
    args = parser.parse_args()

    print_banner()

    cfg = load_config(args.config)
    if not cfg.has_section("server"):
        log.error("Config file must have a [server] section")
        sys.exit(1)

    srv_address  = cfg.get("server", "address")
    srv_wg_port  = cfg.getint("server", "port",      fallback=51820)
    auth_port    = args.port or cfg.getint("server", "auth_port", fallback=9999)
    server_pubkey= cfg.get("server", "public_key",   fallback="")
    allowed_ips  = cfg.get("server", "allowed_ips",  fallback="10.10.10.0/24")

    if not is_valid_wg_key(server_pubkey):
        log.error("base.conf:public_key is not a valid 32-byte base64 key")
        sys.exit(1)

    # Step 1: PSK only (server generates the keypair, §1.1)
    log.info("Generating WireGuard PSK…")
    psk = generate_psk()
    log.info(f"PSK generated (length={len(base64.b64decode(psk))} bytes)")

    # Step 2: Optionally start the local HTTP proxy so the browser flow
    # rides over the same Noise-IK tunnel infrastructure (§3.5).
    proxy_server = None
    if args.proxy_port:
        try:
            proxy_server = proxy_mod.start(
                listen_host  = args.proxy_host,
                listen_port  = args.proxy_port,
                srv_address  = srv_address,
                srv_auth_port= auth_port,
                server_pubkey= server_pubkey,
            )
            log.info(f"Local proxy listening on {args.proxy_host}:{args.proxy_port} "
                     f"→ tunnel to {srv_address}:{auth_port}")
        except Exception as e:
            log.warning(f"Could not start local proxy on :{args.proxy_port}: {e}. "
                        f"Browser will need to hit the IdP directly.")

    # Step 3: Open the Noise-IK tunnel to SrvAuthn for the auth protocol.
    log.info(f"Opening Noise-IK tunnel to SrvAuthn at {srv_address}:{auth_port}…")
    try:
        session = tunnel_mod.connect(srv_address, auth_port, server_pubkey)
    except Exception as e:
        log.error(f"Cannot reach SrvAuthn: {e}")
        sys.exit(1)
    log.info("Noise-IK tunnel established")

    try:
        # Step 4: Send hello
        send_json(session, {
            "service":   "auth",
            "username":  args.username,
            "psk":       psk,
            "interface": args.interface,
        })

        log.info("Waiting for server response…")
        resp = recv_json(session)

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

        # Step 5: Wait for WireGuard config
        result = recv_json(session)

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

        if not is_valid_wg_key(client_priv) or not is_valid_wg_key(client_pub):
            log.error("Server response missing or malformed client WG keypair.")
            sys.exit(1)
        if psk_back != psk:
            log.error("Server echoed back a different PSK — refusing to apply.")
            sys.exit(1)

        log.info(f"Auth success for {username} — allocated IP: {client_ip}")

        # Step 6: Apply WireGuard interface
        log.info(f"Applying WireGuard interface {args.interface}…")
        ok = apply_wireguard_interface(
            interface     = args.interface,
            private_key   = client_priv,
            client_ip     = client_ip,
            server_pubkey = srv_pub,
            server_address= srv_address,
            server_port   = srv_wg_port,
            psk           = psk,
            allowed_ips   = allowed_ips,
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
        session.close()
        if proxy_server is not None:
            proxy_server.stop()


if __name__ == "__main__":
    main()
