#!/bin/sh
# SrvAuthn container entrypoint.
#
# Brings up the wg0 WireGuard interface (if it's not already up) then launches
# SrvAuthn. wg0 lives on the host's network namespace because this container
# runs with network_mode=host.

set -e

if ! command -v wg >/dev/null 2>&1; then
    echo "[entrypoint] wireguard-tools not installed in this image — refusing to start"
    exit 1
fi

if ! [ -f /etc/wireguard/wg0.conf ]; then
    echo "[entrypoint] /etc/wireguard/wg0.conf is missing."
    echo "[entrypoint] Run 'bash scripts/init-wg.sh' on the host before starting compose."
    exit 1
fi

if ! [ -f /app/server/srvauthn.conf ]; then
    echo "[entrypoint] /app/server/srvauthn.conf is missing."
    echo "[entrypoint] cp server/srvauthn.conf.example server/srvauthn.conf and fill it in."
    exit 1
fi

# Bring up wg0 if not already running.
if ip link show wg0 >/dev/null 2>&1; then
    echo "[entrypoint] wg0 already up - leaving alone"
else
    echo "[entrypoint] bringing up wg0..."
    wg-quick up wg0
fi

echo "[entrypoint] launching SrvAuthn..."
exec python -m server.srvauthn --config /app/server/srvauthn.conf "$@"
