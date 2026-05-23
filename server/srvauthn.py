#!/usr/bin/env python3
"""
SrvAuthn — Server-side Authentication Application

Usage:
    srvauthn.py --interface wg0 --config srvauthn.conf [--port 9999]

Config file (srvauthn.conf):
    [server]
    wg_interface    = wg0
    wg_listen_port  = 51820
    wg_private_key  = <base64>
    wg_public_key   = <base64>
    internal_subnet = 10.10.10.0/24
    idp_url         = http://localhost:8080
    oauth_client_id = srvauthn
    oauth_client_secret = srvauthn-secret
    tls_cert        = /certs/srv.crt
    tls_key         = /certs/srv.key

SrvAuthn listens on a TLS port for UserAuthn connections.
For each connection it:
  1. Verifies the client wants to authenticate
  2. Starts the OAuth Device Grant flow with the IdP
  3. Returns device_code + verification_uri to UserAuthn
  4. Polls the IdP until the user completes MFA in browser
  5. On success: allocates WireGuard IP, generates PSK
  6. Sends (client_ip, server_pubkey, psk) to UserAuthn
  7. Registers the peer in the live WireGuard interface
"""

import argparse
import configparser
import ipaddress
import json
import logging
import os
import secrets
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
import db.database as database

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


def allocate_ip(interface: str, subnet: str) -> str:
    """Find the next free IP in subnet for a new peer."""
    net  = ipaddress.IPv4Network(subnet, strict=False)
    used = {row["client_ip"] for row in database.get_all_wg_peers(interface)}
    for host in net.hosts():
        ip = str(host)
        if ip == str(list(net.hosts())[0]):   # skip .1 (server)
            continue
        if ip not in used:
            return ip
    raise RuntimeError("No free IPs in subnet")


def register_wg_peer(interface: str, pubkey: str, client_ip: str, psk: str):
    """Add peer to live WireGuard interface."""
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
        log.info(f"Registered peer {client_ip} ({pubkey[:16]}…)")
    except subprocess.CalledProcessError as e:
        log.error(f"wg set failed: {e}")


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
        client_pub = hello.get("client_pubkey", "")
        interface  = hello.get("interface",
                               cfg.get("server", "wg_interface", fallback="wg0"))

        if not username or not client_pub:
            conn.sendall(json.dumps({"error": "missing username or client_pubkey"}).encode() + b"\n")
            return

        log.info(f"Auth request: user={username} interface={interface}")

        # ── 2. Start OAuth Device Grant flow ──────────────────────────────────
        idp_url   = cfg.get("server", "idp_url", fallback="http://localhost:8080")
        client_id = cfg.get("server", "oauth_client_id", fallback="srvauthn")
        client_sec= cfg.get("server", "oauth_client_secret", fallback="srvauthn-secret")

        try:
            dev_resp = _http_post(f"{idp_url}/oauth/device/code", {
                "client_id": client_id,
                "scope":     "vpn",
            })
        except Exception as e:
            log.error(f"IdP device/code failed: {e}")
            conn.sendall(json.dumps({"error": "IdP unreachable"}).encode() + b"\n")
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
                    conn.sendall(json.dumps({"error": "access_denied"}).encode() + b"\n")
                    return
                elif err == "expired_token":
                    conn.sendall(json.dumps({"error": "code_expired"}).encode() + b"\n")
                    return
                else:
                    log.error(f"Token poll error: {body}")
                    break
            except Exception as e:
                log.error(f"Token poll exception: {e}")
                break

        if not access_token:
            conn.sendall(json.dumps({"error": "auth_timeout"}).encode() + b"\n")
            return

        # ── 5. Get userinfo from IdP ──────────────────────────────────────────
        try:
            info = _http_get(
                f"{idp_url}/oauth/userinfo?interface={interface}",
                token=access_token,
            )
        except Exception as e:
            log.error(f"Userinfo failed: {e}")
            conn.sendall(json.dumps({"error": "userinfo_failed"}).encode() + b"\n")
            return

        # ── 6. Allocate WireGuard IP and PSK ─────────────────────────────────
        subnet  = cfg.get("server", "internal_subnet", fallback="10.10.10.0/24")
        srv_pub = cfg.get("server", "wg_public_key", fallback="")

        # Check if user already has a peer (reuse IP)
        user    = database.get_user(username)
        existing = database.get_wg_peer(user["id"], interface) if user else None

        if existing and existing["client_pubkey"] == client_pub:
            client_ip = existing["client_ip"]
            psk       = existing["psk"]
        else:
            client_ip = allocate_ip(interface, subnet)
            psk       = subprocess.check_output(["wg", "genpsk"]).decode().strip()
            if user:
                database.upsert_wg_peer(user["id"], interface,
                                         client_pub, client_ip, psk)

        # ── 7. Send WireGuard config to UserAuthn ─────────────────────────────
        conn.sendall(json.dumps({
            "status":      "success",
            "client_ip":   client_ip,
            "server_pubkey": srv_pub,
            "psk":         psk,
            "username":    info.get("username", username),
        }).encode() + b"\n")

        # ── 8. Register peer in live WireGuard ────────────────────────────────
        register_wg_peer(interface, client_pub, client_ip, psk)

    except Exception as e:
        log.exception(f"Error handling client {addr}: {e}")
    finally:
        conn.close()
        log.info(f"Connection from {peer_ip} closed")


def run_server(cfg: configparser.ConfigParser, port: int):
    database.init_db()
    database.ensure_default_client()

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

    cfg = load_config(args.config)
    if not cfg.has_section("server"):
        cfg.add_section("server")
    cfg.set("server", "wg_interface", args.interface)

    run_server(cfg, args.port)


if __name__ == "__main__":
    main()
