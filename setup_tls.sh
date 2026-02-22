#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# setup_tls.sh  –  Generate a self-signed TLS certificate for the server
# Usage:  bash setup_tls.sh
# ─────────────────────────────────────────────────────────────────────────────

set -e

CERT="cert.pem"
KEY="key.pem"

echo "[TLS] Generating self-signed RSA-2048 certificate..."
openssl req -x509 \
    -newkey rsa:2048 \
    -keyout "$KEY" \
    -out "$CERT" \
    -days 365 \
    -nodes \
    -subj "/C=US/ST=Local/L=Dev/O=SecureMessaging/CN=127.0.0.1" \
    -addext "subjectAltName=IP:127.0.0.1,DNS:localhost"

echo ""
echo "[TLS] Done!"
echo "  Certificate: $CERT"
echo "  Private Key: $KEY"
echo ""
echo "[TLS] The client is configured to trust this cert (verify=CA_CERT in client.py)."
echo "[TLS] Copy both files to the same directory as client.py and server.py."
