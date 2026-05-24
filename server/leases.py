"""
WireGuard lease sweeper (STEPS.md §4.2).

A small daemon thread that wakes every ``poll_interval`` seconds, looks for
peers whose ``expires_at`` has passed, removes them from the live wg
interface (``wg set <iface> peer <pub> remove``), and marks the DB row
``active = 0``.

This is the only piece of code that *deletes* WireGuard peers. Provisioning
(``server/srvauthn.py:handle_auth``) only ever adds. The sweeper is started
by ``run_server`` after the DB is initialised.
"""

import logging
import os
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from common import db as database

log = logging.getLogger("srvauthn.leases")


def _remove_peer(interface: str, pubkey: str) -> bool:
    """Remove one peer from the live wg interface. Returns True on success."""
    try:
        subprocess.run(
            ["wg", "set", interface, "peer", pubkey, "remove"],
            check=True, capture_output=True, text=True,
        )
        return True
    except subprocess.CalledProcessError as e:
        log.warning(
            "wg set peer remove failed for %s on %s: %s",
            pubkey[:12] + "…", interface, (e.stderr or e.stdout or "").strip(),
        )
        return False


def sweep_once(interface: str) -> int:
    """Run one sweep pass. Returns the number of peers actually removed."""
    expired = database.get_expired_wg_peers(interface)
    removed = 0
    for row in expired:
        pub = row["client_pubkey"]
        if _remove_peer(interface, pub):
            database.deactivate_wg_peer(row["id"])
            removed += 1
            log.info(
                "Removed expired peer ip=%s pub=%s… (lease elapsed)",
                row["client_ip"], pub[:12],
            )
        else:
            # The DB and the kernel can desync if `wg set ... remove` failed
            # because the peer was never installed (e.g. after a restart with
            # a fresh wg0). Still mark inactive so we don't keep retrying it.
            database.deactivate_wg_peer(row["id"])
    return removed


class LeaseSweeper:
    """Thread that calls :func:`sweep_once` on a fixed cadence."""

    def __init__(self, interface: str, poll_interval: float = 60.0):
        self.interface     = interface
        self.poll_interval = float(poll_interval)
        self._stop         = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="lease-sweeper",
        )
        self._thread.start()
        log.info(
            "Lease sweeper started (interface=%s, poll=%.0fs)",
            self.interface, self.poll_interval,
        )

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2 * self.poll_interval)

    def _run(self) -> None:
        # Run one sweep right away so a stack restart with already-expired
        # leases cleans up immediately instead of waiting for the next tick.
        try:
            sweep_once(self.interface)
        except Exception:
            log.exception("initial sweep failed")

        while not self._stop.wait(self.poll_interval):
            try:
                sweep_once(self.interface)
            except Exception:
                log.exception("sweep failed")
