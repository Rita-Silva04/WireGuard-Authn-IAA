#!/bin/bash
# Generate a self-signed TLS certificate for SrvAuthn (Phase 0 baseline only).
#
# This certificate is the trust anchor of the colleague's TLS-based design,
# which Phase 3 of STEPS.md replaces with a Noise-IK handshake keyed on the
# WireGuard public key. After Phase 3 lands these files become obsolete.
#
# Optional argument: the CN (Common Name) for the cert. Defaults to 'localhost'.
# For Multipass / remote clients, pass the gateway's IP (e.g. 192.168.64.1).

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CERT_DIR="$ROOT/certs"
mkdir -p "$CERT_DIR"

if [ -f "$CERT_DIR/srv.crt" ]; then
    echo "Error: $CERT_DIR/srv.crt already exists."
    echo "If you really want to regenerate:"
    echo "    rm -i $CERT_DIR/srv.{key,crt}"
    exit 1
fi

CN="${1:-localhost}"

# Build the SAN — Python ssl requires an iPAddress SAN for IP addresses;
# a bare CN is only accepted for hostnames (domain names), not IPs.
if echo "$CN" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
    SAN="IP:${CN},DNS:localhost"
else
    SAN="DNS:${CN},DNS:localhost"
fi

openssl req -x509 -newkey rsa:4096 \
    -keyout "$CERT_DIR/srv.key" -out "$CERT_DIR/srv.crt" \
    -days 30 -nodes -subj "/CN=$CN" \
    -addext "subjectAltName=${SAN}" 2>/dev/null

chmod 600 "$CERT_DIR/srv.key"
chmod 644 "$CERT_DIR/srv.crt"

echo "Generated TLS cert in $CERT_DIR/ (CN=$CN, expires in 30 days)."
echo ""
echo "Copy $CERT_DIR/srv.crt to each client machine and set its path as"
echo "tls_cert in the client's base.conf."
