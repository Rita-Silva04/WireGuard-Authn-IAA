#!/usr/bin/env python3
"""
One-command teardown for the WireGuard-Authn stack — the mirror of setup.py.

Three levels, smallest to largest blast radius:

    python3 scripts/teardown.py
        Just stop the containers. Keeps the SQLite DB, the WG keypair,
        .env, srvauthn.conf, client/base.conf, and the Multipass VM
        intact, so `scripts/setup.py` can bring everything back up in
        seconds.

    python3 scripts/teardown.py --reset
        Stop the containers AND delete every artifact `setup.py` and
        `test_e2e.py` regenerate from scratch: .env, srvauthn.conf,
        client/base.conf, the data directory, the WG server keypair, and the
        local Docker images. The next `setup.py` run is effectively a
        clean install.

    python3 scripts/teardown.py --reset --vm
        Everything above, plus deletes the Multipass VM 'vpn-client'.

Add --yes / -y to skip the "are you sure?" prompts.
"""

import argparse
import os
import shutil
import subprocess
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VM_NAME      = "vpn-client"


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


def confirm(prompt: str, assume_yes: bool) -> bool:
    if assume_yes:
        return True
    try:
        ans = input(f"{prompt} [y/N] ").strip().lower()
    except EOFError:
        return False
    return ans in ("y", "yes")


def rm_path(path: str):
    """Best-effort delete a file or directory. Reports what happened."""
    full = os.path.join(PROJECT_ROOT, path) if not os.path.isabs(path) else path
    if not os.path.exists(full):
        skip(f"{path} (not present)")
        return
    if os.path.isdir(full) and not os.path.islink(full):
        shutil.rmtree(full, ignore_errors=True)
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


def wipe_generated_files():
    step(2, "Delete generated configs and runtime state")

    # Files setup.py + init-wg.sh + test_e2e.py produce
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


def remove_vm(assume_yes: bool):
    step(3, f"Remove Multipass VM '{VM_NAME}'")
    if not shutil.which("multipass"):
        skip("multipass not installed")
        return

    r = subprocess.run(["multipass", "info", VM_NAME],
                       capture_output=True, text=True)
    if r.returncode != 0:
        skip(f"VM '{VM_NAME}' does not exist")
        return

    if not confirm(f"Really delete and purge Multipass VM '{VM_NAME}'?",
                   assume_yes):
        skip("VM removal skipped")
        return

    subprocess.run(["multipass", "delete", VM_NAME, "--purge"],
                   capture_output=False)
    ok(f"VM '{VM_NAME}' deleted")


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Teardown for the WireGuard-Authn stack",
    )
    parser.add_argument("--reset", action="store_true",
                        help="Also delete generated configs, the SQLite DB, "
                             "the WG server keypair and local Docker images.")
    parser.add_argument("--vm", action="store_true",
                        help="Also delete the Multipass VM 'vpn-client'. "
                             "Implies --reset.")
    parser.add_argument("-y", "--yes", action="store_true",
                        help="Skip confirmation prompts.")
    args = parser.parse_args()

    if args.vm:
        args.reset = True

    print("\n" + "═"*60)
    print("  WireGuard-Authn — Teardown")
    print("═"*60)

    if args.reset:
        warn("--reset will delete .env, srvauthn.conf, base.conf, the "
             "WireGuard server keypair, data/ and local Docker images.")
        if not confirm("Proceed with full reset?", args.yes):
            print("\nAborted.\n")
            sys.exit(0)

    stop_stack(remove_images=args.reset)

    if args.reset:
        wipe_generated_files()

    if args.vm:
        remove_vm(args.yes)

    print("\n" + "═"*60)
    print("  Done.")
    print("═"*60)
    if args.reset:
        print("\n  Re-bootstrap with:  python3 scripts/setup.py\n")
    else:
        print("\n  Bring back up with:  docker compose up -d\n")


if __name__ == "__main__":
    main()
