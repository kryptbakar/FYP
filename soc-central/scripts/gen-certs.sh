#!/usr/bin/env bash
# Generate a dev PKI for mutual TLS between agents and ingest-edge.
#   certs/ca.crt           — dev CA (trust anchor)
#   certs/server.{crt,key} — ingest-edge server cert (SAN: ingest-edge, localhost)
#   certs/agent-001.{crt,key} — an agent client cert (CN = agent-001)
#
# DEV ONLY. Real deployments issue short-lived certs from Vault/an internal CA.
# certs/ is gitignored — never commit private keys.
set -euo pipefail

# On Windows/git-bash, MSYS rewrites args that look like paths (e.g. the openssl
# "-subj /O=.../CN=..." string). Disable that conversion so the DN is passed verbatim.
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL='*'

DIR="$(cd "$(dirname "$0")/.." && pwd)/certs"
mkdir -p "$DIR"
cd "$DIR"

DAYS=825

if [ -f ca.crt ] && [ "${1:-}" != "--force" ]; then
  echo "certs already exist in $DIR (use --force to regenerate)"; exit 0
fi

echo "[*] CA"
openssl genrsa -out ca.key 4096 2>/dev/null
openssl req -x509 -new -nodes -key ca.key -sha256 -days "$DAYS" \
  -subj "/O=SOC Central/CN=SOC Central Dev CA" -out ca.crt 2>/dev/null

echo "[*] server cert (ingest-edge)"
openssl genrsa -out server.key 2048 2>/dev/null
openssl req -new -key server.key -subj "/O=SOC Central/CN=ingest-edge" -out server.csr 2>/dev/null
cat > server.ext <<EOF
subjectAltName = DNS:ingest-edge, DNS:localhost, IP:127.0.0.1
extendedKeyUsage = serverAuth
EOF
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days "$DAYS" -sha256 -extfile server.ext -out server.crt 2>/dev/null

echo "[*] agent client cert (CN=agent-001)"
openssl genrsa -out agent-001.key 2048 2>/dev/null
openssl req -new -key agent-001.key -subj "/O=SOC Central/CN=agent-001" -out agent-001.csr 2>/dev/null
cat > agent.ext <<EOF
extendedKeyUsage = clientAuth
EOF
openssl x509 -req -in agent-001.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days "$DAYS" -sha256 -extfile agent.ext -out agent-001.crt 2>/dev/null

rm -f ./*.csr server.ext agent.ext ca.srl
chmod 600 ./*.key 2>/dev/null || true
chmod 644 ./*.crt 2>/dev/null || true

echo "[+] wrote:"
ls -1 "$DIR"
