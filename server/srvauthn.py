#!/usr/bin/env python3
"""
SrvAuthn — Server-side Authentication Application

Usage:
    srvauthn.py --interface wg0 --config srvauthn.conf [--port 9999]

Config file (srvauthn.conf) — see srvauthn.conf.example.

SrvAuthn listens on a TLS port for UserAuthn connections.
For each connection it:
  1. Reads the hello: {username, client_pubkey, psk, interface}
  2. Validates client_pubkey (base64 → 32 bytes) and psk (§1.13)
  3. Starts the OAuth Device Grant flow with the IdP
  4. Returns user_code + verification_uri to UserAuthn
  5. Polls the IdP until the user completes MFA in browser
  6. On success: leases a WireGuard IP atomically (§1.11)
                generates the client's WG keypair (§1.1)
  7. Sends (client_ip, server_pubkey, client_wg_private_key,
            client_wg_public_key) to UserAuthn — the client receives its
     keypair from the server per spec §3.
  8. Registers the peer in the live WireGuard interface
"""

import argparse
import base64
import configparser
import hashlib
import json
import logging
import os
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [SrvAuthn] %(levelname)s %(message)s",
)
log = logging.getLogger("srvauthn")

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from common import db as database
from common.config import require_env

DEFAULT_PORT     = 9999
POLL_INTERVAL    = 5    # seconds between IdP token polls
POLL_TIMEOUT     = 600  # seconds max wait for user


def load_config(path: str) -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    cfg.read(path)
    return cfg


def _http_post(url: str, data: dict, token: str = None) -> dict:
    body    = urllib.parse.urlencode(data).encode()
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())


def _http_get(url: str, token: str = None) -> dict:
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())


# ── WireGuard key helpers (§1.13) ─────────────────────────────────────────────

def is_valid_wg_key(value: str) -> bool:
    """Return True if value is a base64 string decoding to exactly 32 bytes."""
    if not isinstance(value, str) or not value:
        return False
    try:
        raw = base64.b64decode(value, validate=True)
    except Exception:
        return False
    return len(raw) == 32


def wg_keypair() -> tuple[str, str]:
    """Generate a fresh WireGuard keypair server-side (§1.1)."""
    priv = subprocess.check_output(["wg", "genkey"]).decode().strip()
    pub  = subprocess.check_output(
        ["wg", "pubkey"], input=priv.encode()
    ).decode().strip()
    return priv, pub


def fingerprint(value: str, n: int = 12) -> str:
    """Short SHA-256 fingerprint of a key — for logging only."""
    digest = hashlib.sha256(value.encode()).hexdigest()
    return digest[:n]


# ── WireGuard peer registration ───────────────────────────────────────────────

def register_wg_peer(interface: str, pubkey: str, client_ip: str, psk: str):
    """Add peer to the live WireGuard interface and persist to wg0.conf."""
    try:
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.psk', delete=False) as f:
            f.write(psk)
            psk_file = f.name

        subprocess.run([
            "wg", "set", interface,
            "peer", pubkey,
            "preshared-key", psk_file,
            "allowed-ips", f"{client_ip}/32",
            "persistent-keepalive", "25",
        ], check=True)
        os.unlink(psk_file)

        # Persist to config file
        wg_conf = f"/etc/wireguard/{interface}.conf"
        if os.path.exists(wg_conf):
            with open(wg_conf, "a") as f:
                f.write(f"\n[Peer]\n"
                        f"PublicKey = {pubkey}\n"
                        f"PresharedKey = {psk}\n"
                        f"AllowedIPs = {client_ip}/32\n"
                        f"PersistentKeepalive = 25\n")
        log.info(f"Registered peer {client_ip} (pub fp={fingerprint(pubkey)})")
    except subprocess.CalledProcessError as e:
        log.error(f"wg set failed: {e}")


# ── Connection handler ───────────────────────────────────────────────────────

def _send_err(conn, msg):
    conn.sendall(json.dumps({"error": msg}).encode() + b"\n")


def handle_client(conn: ssl.SSLSocket, addr, cfg: configparser.ConfigParser):
    """Handle one UserAuthn connection."""
    peer_ip = addr[0]
    log.info(f"Connection from {peer_ip}")
    try:
        # ── 1. Read hello from UserAuthn ──────────────────────────────────────
        raw = b""
        while not raw.endswith(b"\n"):
            chunk = conn.recv(4096)
            if not chunk:
                return
            raw += chunk
        hello = json.loads(raw.strip())

        username   = hello.get("username", "")
        client_psk = hello.get("psk", "")
        interface  = hello.get("interface",
                               cfg.get("server", "wg_interface", fallback="wg0"))

        if not username:
            _send_err(conn, "missing_username")
            return

        # ── §1.1 + §1.13: PSK comes from the client and must be a valid
        # 32-byte base64 WireGuard key. The client no longer sends a public
        # key — the server now generates the client's WG keypair below.
        if not client_psk:
            _send_err(conn, "missing_psk")
            return
        if not is_valid_wg_key(client_psk):
            log.warning(f"Rejecting hello from {peer_ip}: invalid psk")
            _send_err(conn, "invalid_psk")
            return

        log.info(f"Auth request: user={username} interface={interface}")

        # ── 2. Start OAuth Device Grant flow ──────────────────────────────────
        idp_url   = cfg.get("server", "idp_url", fallback="http://localhost:8080")
        client_id = cfg.get("server", "oauth_client_id", fallback="srvauthn")
        # OAuth secret is read at startup; not used in /oauth/device/code today

        try:
            dev_resp = _http_post(f"{idp_url}/oauth/device/code", {
                "client_id": client_id,
                "scope":     "vpn",
            })
        except Exception as e:
            log.error(f"IdP device/code failed: {e}")
            _send_err(conn, "IdP unreachable")
            return

        device_code      = dev_resp["device_code"]
        verification_uri = dev_resp["verification_uri_complete"]
        user_code        = dev_resp["user_code"]

        # ── 3. Send verification info to UserAuthn ────────────────────────────
        conn.sendall(json.dumps({
            "status":           "pending",
            "user_code":        user_code,
            "verification_uri": verification_uri,
        }).encode() + b"\n")

        # ── 4. Poll IdP for token ─────────────────────────────────────────────
        access_token = None
        deadline     = time.time() + POLL_TIMEOUT

        while time.time() < deadline:
            time.sleep(POLL_INTERVAL)
            try:
                tok_resp = _http_post(f"{idp_url}/oauth/token", {
                    "grant_type":  "urn:ietf:params:oauth:grant-type:device_code",
                    "device_code": device_code,
                    "client_id":   client_id,
                })
                access_token = tok_resp["access_token"]
                log.info(f"Token obtained for user={username}")
                break
            except urllib.error.HTTPError as e:
                body = json.loads(e.read())
                err  = body.get("error", "")
                if err == "authorization_pending":
                    continue
                elif err == "access_denied":
                    _send_err(conn, "access_denied")
                    return
                elif err == "expired_token":
                    _send_err(conn, "code_expired")
                    return
                else:
                    log.error(f"Token poll error: {body}")
                    break
            except Exception as e:
                log.error(f"Token poll exception: {e}")
                break

        if not access_token:
            _send_err(conn, "auth_timeout")
            return

        # ── 5. Get userinfo from IdP ──────────────────────────────────────────
        try:
            info = _http_get(
                f"{idp_url}/oauth/userinfo?interface={interface}",
                token=access_token,
            )
        except Exception as e:
            log.error(f"Userinfo failed: {e}")
            _send_err(conn, "userinfo_failed")
            return

        # ── 6. Server generates the client's WG keypair (§1.1) ───────────────
        client_wg_priv, client_wg_pub = wg_keypair()
        log.info(f"Generated client WG keypair (pub fp={fingerprint(client_wg_pub)})")

        # ── 7. Atomically lease an IP for this peer (§1.11) ──────────────────
        subnet  = cfg.get("server", "internal_subnet", fallback="10.10.10.0/24")
        srv_pub = cfg.get("server", "wg_public_key", fallback="")

        user = database.get_user(username)
        if not user:
            _send_err(conn, "unknown_user")
            return

        try:
            client_ip = database.lease_next_ip(
                interface     = interface,
                subnet        = subnet,
                user_id       = user["id"],
                client_pubkey = client_wg_pub,
                psk           = client_psk,
            )
        except database.NoFreeIPError:
            log.error(f"Subnet {subnet} exhausted while leasing for {username}")
            _send_err(conn, "subnet_exhausted")
            return

        # ── 8. Send WG config to UserAuthn (incl. server-generated keypair) ──
        conn.sendall(json.dumps({
            "status":                  "success",
            "client_ip":               client_ip,
            "server_pubkey":           srv_pub,
            "client_wg_private_key":   client_wg_priv,
            "client_wg_public_key":    client_wg_pub,
            "psk":                     client_psk,
            "username":                info.get("username", username),
        }).encode() + b"\n")

        # ── 9. Register peer in live WireGuard ────────────────────────────────
        register_wg_peer(interface, client_wg_pub, client_ip, client_psk)

    except Exception as e:
        log.exception(f"Error handling client {addr}: {e}")
    finally:
        conn.close()
        log.info(f"Connection from {peer_ip} closed")


def _load_server_wg_private_key(cfg: configparser.ConfigParser):
    """
    Read the server's WG private key from the file referenced by the config
    (§1.2). The key is stored in `cfg["server"]["wg_private_key"]` so later
    phases (Noise-IK) can consume it. Aborts on any error.
    """
    path = cfg.get("server", "wg_private_key_file",
                   fallback="/etc/wireguard/privatekey-server")
    if not os.path.exists(path):
        log.error(f"Server WG private key not found at {path} — refusing to start")
        sys.exit(78)
    try:
        with open(path) as f:
            priv = f.read().strip()
    except OSError as e:
        log.error(f"Cannot read server WG private key {path}: {e}")
        sys.exit(78)
    if not is_valid_wg_key(priv):
        log.error(f"Server WG private key in {path} is not a valid WG key")
        sys.exit(78)
    cfg.set("server", "wg_private_key", priv)
    log.info(f"Loaded server WG private key from {path} "
             f"(fingerprint: {fingerprint(priv)})")


def run_server(cfg: configparser.ConfigParser, port: int):
    database.init_db()
    database.ensure_default_client()

    # §1.2: load the server's WG private key at startup
    _load_server_wg_private_key(cfg)

    tls_cert = cfg.get("server", "tls_cert", fallback="/certs/srv.crt")
    tls_key  = cfg.get("server", "tls_key",  fallback="/certs/srv.key")

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(tls_cert, tls_key)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", port))
        sock.listen(10)
        log.info(f"SrvAuthn listening on port {port} (TLS)")

        with ctx.wrap_socket(sock, server_side=True) as tls_sock:
            while True:
                try:
                    conn, addr = tls_sock.accept()
                    t = threading.Thread(
                        target=handle_client, args=(conn, addr, cfg), daemon=True
                    )
                    t.start()
                except KeyboardInterrupt:
                    log.info("Shutting down.")
                    break
                except Exception as e:
                    log.error(f"Accept error: {e}")


def main():
    parser = argparse.ArgumentParser(description="SrvAuthn — VPN Authentication Server")
    parser.add_argument("--interface", default="wg0",    help="WireGuard interface")
    parser.add_argument("--config",    default="srvauthn.conf", help="Config file path")
    parser.add_argument("--port",      type=int, default=DEFAULT_PORT, help="TLS listen port")
    args = parser.parse_args()

    # §1.12: fail-closed env var check.
    require_env("OAUTH_CLIENT_SECRET")

    cfg = load_config(args.config)
    if not cfg.has_section("server"):
        cfg.add_section("server")
    cfg.set("server", "wg_interface", args.interface)

    run_server(cfg, args.port)


if __name__ == "__main__":
    main()
