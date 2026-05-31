#!/usr/bin/env python3
"""
One-command teardown for the WireGuard-Authn stack — the mirror of setup.py.

Three levels, smallest to largest blast radius:

    python3 scripts/teardown.py
        Just stop the containers. Keeps the SQLite DB, the WG keypair,
        .env, srvauthn.conf and client/base.conf intact, so
        `scripts/setup.py` can bring everything back up in seconds.

    python3 scripts/teardown.py --session
        Keep the containers running and keep RBA history (rba_ip_history,
        rba_events), but remove the active WireGuard peer and clear session
        tables (wg_peers, oauth_tokens, device_codes, mfa_sessions).
        Use this between an L2 and L1 manual demo: the client IP stays
        known so the next login scores 0.00 and triggers password-only (L1).

    python3 scripts/teardown.py --reset
        Stop the containers AND delete every artifact setup.py regenerates
        from scratch: .env, srvauthn.conf, client/base.conf, the data
        directory, the WG server keypair, and the local Docker images.
        The next `setup.py` run is effectively a clean install.

Add --yes / -y to skip the "are you sure?" prompts.
"""

import argparse
import os
import re
import shutil
import subprocess
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVER_CTR   = "vpn-srvauthn"
CLIENT_CTR   = "vpn-client"
IDP_CTR      = "vpn-idp"


# ── Helpers ──────────────────────────────────────────────────────────────────

def step(n, msg):
    print(f"\n{'─'*60}\nStep {n}: {msg}\n{'─'*60}")

def ok(msg):   print(f"  ✓  {msg}")
def info(msg): print(f"  →  {msg}")
def warn(msg): print(f"  ⚠  {msg}")
def skip(msg): print(f"  ·  {msg}")


def shell(cmd, capture=True, check=False):
    return subprocess.run(
        cmd, shell=True, text=True, cwd=PROJECT_ROOT,
        capture_output=capture, check=check,
    )


def ctr_exec(container, *args, capture=True):
    return subprocess.run(
        ["docker", "exec", container] + list(args),
        capture_output=capture, text=True,
    )


def confirm(prompt: str, assume_yes: bool) -> bool:
    if assume_yes:
        return True
    try:
        ans = input(f"{prompt} [y/N] ").strip().lower()
    except EOFError:
        return False
    return ans in ("y", "yes")


def rm_path(path: str):
    """Delete a file or directory, using a Docker helper for root-owned content."""
    full = os.path.join(PROJECT_ROOT, path) if not os.path.isabs(path) else path
    if not os.path.exists(full):
        skip(f"{path} (not present)")
        return
    if os.path.isdir(full) and not os.path.islink(full):
        shutil.rmtree(full, ignore_errors=True)
        if os.path.exists(full):
            # Docker created root-owned files; use a throwaway container to remove them.
            r = subprocess.run(
                ["docker", "run", "--rm", "-v", f"{full}:/target",
                 "alpine", "sh", "-c", "rm -rf /target/*"],
                capture_output=True, text=True,
            )
            shutil.rmtree(full, ignore_errors=True)
            if os.path.exists(full):
                warn(f"could not fully remove {path} — run: sudo rm -rf {full}")
                return
    else:
        try:
            os.unlink(full)
        except OSError as e:
            warn(f"could not remove {path}: {e}")
            return
    ok(f"removed {path}")


# ── Steps ────────────────────────────────────────────────────────────────────

def stop_stack(remove_images: bool):
    step(1, "Stop the Docker stack")
    args = "--profile client down"
    if remove_images:
        args += " --rmi local --volumes"
    r = shell(f"docker compose {args}", capture=False)
    if r.returncode == 0:
        ok("docker compose --profile client down")
    else:
        warn("docker compose down exited non-zero — stack may already be stopped")


def bring_down_wg0():
    """Bring down the host-side wg0 so the next startup reloads wg0.conf cleanly."""
    r = shell("ip link show wg0", check=False)
    if r.returncode == 0:
        shell("wg-quick down wg0", check=False)
        ok("wg0 brought down")
    else:
        skip("wg0 not up")


def wipe_generated_files():
    step(2, "Delete generated configs and runtime state")

    # Files setup.py + init-wg.sh produce
    for p in (
        ".env",
        "server/srvauthn.conf",
        "client/base.conf",
        "wireguard/privatekey-server",
        "wireguard/publickey-server",
        "wireguard/wg0.conf",
    ):
        rm_path(p)

    # Runtime state (SQLite DB, WAL/SHM files, optional local GeoIP DBs).
    # setup.py recreates data/ before Docker bind-mounts it again.
    rm_path("data")


def session_reset():
    """Remove the active WG peer and clear session tables, keep RBA history."""
    step(1, "Remove active WireGuard peer")
    r = ctr_exec(SERVER_CTR, "wg", "show", "wg0")
    peers = re.findall(r"peer: (\S+)", r.stdout)
    for p in peers:
        ctr_exec(SERVER_CTR, "wg", "set", "wg0", "peer", p, "remove")
    if peers:
        ok(f"Removed {len(peers)} peer(s) from wg0")
    else:
        skip("No active peers")

    # Remove [Peer] sections from wg0.conf so restarts stay clean
    conf_path = os.path.join(PROJECT_ROOT, "wireguard/wg0.conf")
    if os.path.exists(conf_path):
        with open(conf_path) as f:
            lines = f.readlines()
        clean, in_peer = [], False
        for line in lines:
            if line.strip().startswith("[Peer]"):
                in_peer = True
            elif line.strip().startswith("[") and in_peer:
                in_peer = False
            if not in_peer:
                clean.append(line)
        with open(conf_path, "w") as f:
            f.writelines(clean)

    # Bring down wg0 inside the client container if it is running
    ctr_exec(CLIENT_CTR, "sh", "-c", "wg-quick down wg0 2>/dev/null; true")

    step(2, "Clear session tables (keeping rba_ip_history and rba_events)")
    r = subprocess.run(
        ["docker", "exec", IDP_CTR, "python3", "-c",
         "import sqlite3\n"
         "conn = sqlite3.connect('/data/vpnauth.db')\n"
         "for t in ('wg_peers','oauth_tokens','device_codes','mfa_sessions','auth_lockouts'):\n"
         "    conn.execute(f'DELETE FROM {t}')\n"
         "conn.execute('UPDATE users SET failed_attempts=0, locked_until=0, last_failure_at=0')\n"
         "conn.execute(\"DELETE FROM rba_events WHERE event_type IN ('password_fail','totp_fail','fido2_fail','auth_blocked_missing_factor','auth_failed')\")\n"
         "conn.commit()\n"
         "print('done')"
        ],
        capture_output=True, text=True,
    )
    if "done" in r.stdout:
        ok("Session tables cleared — rba_ip_history preserved")
    else:
        warn(f"DB reset may have failed: {r.stderr.strip()}")


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Teardown for the WireGuard-Authn stack",
    )
    parser.add_argument("--session", action="store_true",
                        help="Clear session state only (keeps RBA history). "
                             "Use between an L2 and L1 manual demo.")
    parser.add_argument("--reset", action="store_true",
                        help="Also delete generated configs, the SQLite DB, "
                             "the WG server keypair and local Docker images.")
    parser.add_argument("-y", "--yes", action="store_true",
                        help="Skip confirmation prompts.")
    args = parser.parse_args()

    if args.session and args.reset:
        print("Error: --session and --reset are mutually exclusive.")
        sys.exit(1)

    print("\n" + "═"*60)
    print("  WireGuard-Authn — Teardown")
    print("═"*60)

    if args.reset:
        warn("--reset will delete .env, srvauthn.conf, base.conf, the "
             "WireGuard server keypair, data/ and local Docker images.")
        if not confirm("Proceed with full reset?", args.yes):
            print("\nAborted.\n")
            sys.exit(0)

    if args.session:
        session_reset()
    else:
        stop_stack(remove_images=args.reset)
        if args.reset:
            bring_down_wg0()
            wipe_generated_files()

    print("\n" + "═"*60)
    print("  Done.")
    print("═"*60)
    if args.reset:
        print("\n  Re-bootstrap with:  python3 scripts/setup.py\n")
    elif args.session:
        print("\n  RBA history preserved — run userauthn.py for an L1 login.\n")
    else:
        print("\n  Bring back up with:  docker compose up -d\n")


if __name__ == "__main__":
    main()
