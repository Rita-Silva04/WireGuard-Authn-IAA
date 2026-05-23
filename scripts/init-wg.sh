#!/bin/bash
# Generate the server's WireGuard keypair and a starter wg0.conf.
#
# Run once on the gateway host. Subsequent runs refuse to overwrite existing keys.
# Output: ./wireguard/{privatekey-server, publickey-server, wg0.conf}
# The ./wireguard/ directory is gitignored.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WG_DIR="$ROOT/wireguard"
mkdir -p "$WG_DIR"

if [ -f "$WG_DIR/privatekey-server" ]; then
    echo "Error: $WG_DIR/privatekey-server already exists."
    echo "If you really want to regenerate, delete the existing files first:"
    echo "    rm -i $WG_DIR/privatekey-server $WG_DIR/publickey-server $WG_DIR/wg0.conf"
    exit 1
fi

if ! command -v wg >/dev/null 2>&1; then
    echo "Error: 'wg' command not found. Install wireguard-tools:"
    echo "    sudo apt install wireguard-tools     # Debian/Ubuntu"
    echo "    sudo dnf install wireguard-tools     # Fedora"
    exit 1
fi

umask 077

wg genkey | tee "$WG_DIR/privatekey-server" | wg pubkey > "$WG_DIR/publickey-server"

PRIVATE_KEY=$(cat "$WG_DIR/privatekey-server")

cat > "$WG_DIR/wg0.conf" <<EOF
[Interface]
PrivateKey = $PRIVATE_KEY
ListenPort = 51820
Address = 10.10.10.1/24

# Peers are added dynamically by SrvAuthn at provisioning time.
EOF

chmod 600 "$WG_DIR/wg0.conf" "$WG_DIR/privatekey-server"
chmod 644 "$WG_DIR/publickey-server"

PUBKEY=$(cat "$WG_DIR/publickey-server")

echo "Generated WireGuard server keys in $WG_DIR/"
echo ""
echo "  Public key: $PUBKEY"
echo ""
echo "Next steps:"
echo "  1. Paste the public key above into .env as SERVER_PUBKEY=..."
echo "  2. Paste the public key into server/srvauthn.conf as wg_public_key=..."
echo "  3. Paste the public key into each client's base.conf as public_key=..."
