#!/usr/bin/env python3
"""
SrvAuthn — Server-side Authentication Application

Usage:
    srvauthn.py --interface wg0 --config srvauthn.conf [--port 9999]

Config file (srvauthn.conf) — see srvauthn.conf.example.

SrvAuthn listens on a TCP port for UserAuthn connections. Each connection
performs a Noise-IK handshake (responder side) keyed on the server's
long-lived WireGuard private key (STEPS.md §3, JUSTIFICATIONS.md §5).

After the handshake the first frame carries either:

  * ``{"service": "auth", ...}``  — the auth protocol (default if absent).
  * ``{"service": "proxy"}``      — the HTTP proxy egress (§3.6).

The auth protocol then:
  1. Validates the PSK (§1.1, §1.13).
  2. Starts the OAuth Device Grant flow with the IdP.
  3. Returns user_code + verification_uri to UserAuthn.
  4. Polls the IdP until the user completes MFA in the browser.
  5. On success: leases an IP (§1.11) and generates the client's WG
     keypair server-side (§1.1).
  6. Sends the WG config down the tunnel and registers the peer in wg0.
"""

import argparse
import base64
import configparser
import hashlib
import json
import logging
import os
import socket
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
from server import tunnel as tunnel_mod
from server import proxy as proxy_mod
from server.leases import LeaseSweeper

DEFAULT_PORT     = 9999
POLL_INTERVAL    = 5    # seconds between IdP token polls
POLL_TIMEOUT     = 600  # seconds max wait for user

# Default lease lifetime in srvauthn.conf. The sweeper enforces it (§4.1/§4.2).
DEFAULT_LEASE_TTL = 24 * 60 * 60        # 24 hours
DEFAULT_SWEEPER_POLL = 60               # seconds


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


# ── Tunnel-based connection handler ──────────────────────────────────────────

def _send_json(session, obj: dict) -> None:
    session.send(json.dumps(obj).encode())


def _recv_json(session) -> dict:
    raw = session.recv()
    return json.loads(raw.decode())


def _send_err(session, msg: str) -> None:
    _send_json(session, {"error": msg})


def handle_auth(session, hello: dict, cfg: configparser.ConfigParser):
    """Auth protocol over an already-established Noise tunnel."""
    peer_ip = session.peer[0]

    username   = hello.get("username", "")
    client_psk = hello.get("psk", "")
    interface  = hello.get("interface",
                           cfg.get("server", "wg_interface", fallback="wg0"))

    if not username:
        _send_err(session, "missing_username")
        return

    if not client_psk:
        _send_err(session, "missing_psk")
        return
    if not is_valid_wg_key(client_psk):
        log.warning(f"Rejecting hello from {peer_ip}: invalid psk")
        _send_err(session, "invalid_psk")
        return

    log.info(f"Auth request: user={username} interface={interface}")

    idp_url   = cfg.get("server", "idp_url", fallback="http://localhost:8080")
    client_id = cfg.get("server", "oauth_client_id", fallback="srvauthn")
    client_secret = cfg.get(
        "server", "oauth_client_secret",
        fallback=os.environ.get("OAUTH_CLIENT_SECRET", ""),
    )

    try:
        dev_resp = _http_post(f"{idp_url}/oauth/device/code", {
            "client_id": client_id,
            "client_secret": client_secret,
            "scope":     "vpn",
            "requested_username": username,
            "client_ip": peer_ip,
        })
    except Exception as e:
        log.error(f"IdP device/code failed: {e}")
        _send_err(session, "IdP unreachable")
        return

    device_code      = dev_resp["device_code"]
    verification_uri = dev_resp["verification_uri_complete"]
    user_code        = dev_resp["user_code"]

    _send_json(session, {
        "status":           "pending",
        "user_code":        user_code,
        "verification_uri": verification_uri,
    })

    # Poll IdP for token
    access_token = None
    deadline     = time.time() + POLL_TIMEOUT
    while time.time() < deadline:
        time.sleep(POLL_INTERVAL)
        try:
            tok_resp = _http_post(f"{idp_url}/oauth/token", {
                "grant_type":  "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": device_code,
                "client_id":   client_id,
                "client_secret": client_secret,
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
                _send_err(session, "access_denied"); return
            elif err == "expired_token":
                _send_err(session, "code_expired"); return
            log.error(f"Token poll error: {body}")
            break
        except Exception as e:
            log.error(f"Token poll exception: {e}")
            break

    if not access_token:
        _send_err(session, "auth_timeout")
        return

    try:
        info = _http_get(
            f"{idp_url}/oauth/userinfo?interface={interface}",
            token=access_token,
        )
    except Exception as e:
        log.error(f"Userinfo failed: {e}")
        _send_err(session, "userinfo_failed")
        return

    authenticated_username = info.get("username", "").strip()
    if not authenticated_username:
        log.error("Userinfo response did not include a username")
        _send_err(session, "userinfo_missing_username")
        return
    if authenticated_username != username:
        log.info(
            "UserAuthn requested user=%s; IdP authenticated user=%s. "
            "Using IdP identity for provisioning.",
            username, authenticated_username,
        )

    # Server generates the client's WG keypair (§1.1)
    client_wg_priv, client_wg_pub = wg_keypair()
    log.info(f"Generated client WG keypair (pub fp={fingerprint(client_wg_pub)})")

    subnet  = cfg.get("server", "internal_subnet", fallback="10.10.10.0/24")
    srv_pub = cfg.get("server", "wg_public_key", fallback="")

    user = database.get_user(authenticated_username)
    if not user:
        _send_err(session, "unknown_user")
        return

    lease_ttl = cfg.getint("server", "lease_ttl_seconds",
                            fallback=DEFAULT_LEASE_TTL)
    try:
        client_ip = database.lease_next_ip(
            interface         = interface,
            subnet            = subnet,
            user_id           = user["id"],
            client_pubkey     = client_wg_pub,
            psk               = client_psk,
            lease_ttl_seconds = lease_ttl,
        )
    except database.NoFreeIPError:
        log.error(f"Subnet {subnet} exhausted while leasing for {username}")
        _send_err(session, "subnet_exhausted")
        return

    _send_json(session, {
        "status":                "success",
        "client_ip":             client_ip,
        "server_pubkey":         srv_pub,
        "client_wg_private_key": client_wg_priv,
        "client_wg_public_key":  client_wg_pub,
        "psk":                   client_psk,
        "username":              authenticated_username,
    })

    register_wg_peer(interface, client_wg_pub, client_ip, client_psk)


def handle_connection(sock: socket.socket, addr: tuple,
                       cfg: configparser.ConfigParser):
    """
    Per-connection entry point: run the Noise responder handshake, then
    dispatch based on the first decrypted frame's "service" field.
    """
    peer_ip = addr[0]
    log.info(f"Connection from {peer_ip}")
    session = None
    try:
        priv_b64 = cfg.get("server", "wg_private_key")
        session, _ = tunnel_mod.accept_handshake(sock, addr, priv_b64)
        log.info(f"Noise handshake completed with {peer_ip}")

        first = _recv_json(session)
        service = first.get("service", "auth")

        if service == "auth":
            handle_auth(session, first, cfg)
        elif service == "proxy":
            proxy_mod.handle_proxy(session, cfg)
        else:
            _send_err(session, f"unknown_service:{service}")

    except Exception as e:
        log.exception(f"Error handling {addr}: {e}")
    finally:
        if session is not None:
            session.close()
        else:
            try: sock.close()
            except OSError: pass
        log.info(f"Connection from {peer_ip} closed")


def _load_server_wg_private_key(cfg: configparser.ConfigParser):
    """§1.2 — read and validate the server's WG private key at startup."""
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
    _load_server_wg_private_key(cfg)

    # §4.2 — start the lease sweeper. Poll interval defaults to 60 s; the
    # sweeper itself enforces whatever lease_ttl_seconds the auth handler
    # wrote into wg_peers.expires_at.
    interface     = cfg.get("server", "wg_interface", fallback="wg0")
    poll_interval = cfg.getint("server", "lease_sweeper_poll",
                                fallback=DEFAULT_SWEEPER_POLL)
    sweeper = LeaseSweeper(interface=interface, poll_interval=poll_interval)
    sweeper.start()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", port))
        sock.listen(64)
        log.info(f"SrvAuthn listening on port {port} (Noise-IK)")

        while True:
            try:
                conn, addr = sock.accept()
                t = threading.Thread(
                    target=handle_connection, args=(conn, addr, cfg),
                    daemon=True, name=f"conn-{addr[0]}:{addr[1]}",
                )
                t.start()
            except KeyboardInterrupt:
                log.info("Shutting down.")
                break
            except Exception as e:
                log.error(f"Accept error: {e}")


def main():
    parser = argparse.ArgumentParser(description="SrvAuthn — VPN Authentication Server")
    parser.add_argument("--interface", default="wg0", help="WireGuard interface")
    parser.add_argument("--config",    default="srvauthn.conf", help="Config file path")
    parser.add_argument("--port",      type=int, default=DEFAULT_PORT,
                        help="Noise-IK listen port (default 9999)")
    args = parser.parse_args()

    require_env("OAUTH_CLIENT_SECRET")

    cfg = load_config(args.config)
    if not cfg.has_section("server"):
        cfg.add_section("server")
    cfg.set("server", "wg_interface", args.interface)

    run_server(cfg, args.port)


if __name__ == "__main__":
    main()
