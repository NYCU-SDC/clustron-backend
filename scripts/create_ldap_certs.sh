#!/usr/bin/env bash
#
# Generate a self-signed CA and an LDAP server certificate signed by it.
#
# Usage: scripts/create_ldap_certs.sh <output-dir> [san ...]
#
# Managed nodes verify the LDAP server against ca.crt, so every name or address
# they use to reach it has to appear as a SAN here. Arguments that look like an
# IPv4 address become IP SANs, everything else becomes a DNS SAN.
#
#   scripts/create_ldap_certs.sh .deploy/dev/certs ldap ldap.example.com 10.1.253.28
#
# Writes ca.crt, ca.key, ldap.crt and ldap.key into the output directory, which
# is mounted at /container/services/openldap/assets/certs in the osixia/openldap
# 2.6 image. That image has no self-signed fallback and only applies TLS during
# bootstrap, so these files must exist before the container first starts.

set -euo pipefail

if [ $# -lt 1 ]; then
    echo "usage: $0 <output-dir> [san ...]" >&2
    exit 1
fi

OUT_DIR=$1
shift

SANS=("$@")
if [ ${#SANS[@]} -eq 0 ]; then
    SANS=(ldap localhost)
fi

DAYS=${LDAP_CERT_DAYS:-3650}

mkdir -p "$OUT_DIR"

alt_names=""
dns_index=0
ip_index=0
for san in "${SANS[@]}"; do
    if [[ $san =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
        ip_index=$((ip_index + 1))
        alt_names+="IP.${ip_index} = ${san}"$'\n'
    else
        dns_index=$((dns_index + 1))
        alt_names+="DNS.${dns_index} = ${san}"$'\n'
    fi
done

ext_file=$(mktemp)
trap 'rm -f "$ext_file"' EXIT

cat > "$ext_file" <<EXT
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
${alt_names}
EXT

echo ":: Generating CA..."
openssl req -x509 -newkey rsa:4096 -sha256 -days "$DAYS" -nodes \
    -keyout "$OUT_DIR/ca.key" -out "$OUT_DIR/ca.crt" \
    -subj "/CN=Clustron LDAP CA"

echo ":: Generating server certificate for: ${SANS[*]}"
openssl req -newkey rsa:4096 -sha256 -nodes \
    -keyout "$OUT_DIR/ldap.key" -out "$OUT_DIR/ldap.csr" \
    -subj "/CN=${SANS[0]}"

openssl x509 -req -in "$OUT_DIR/ldap.csr" -sha256 -days "$DAYS" \
    -CA "$OUT_DIR/ca.crt" -CAkey "$OUT_DIR/ca.key" -CAcreateserial \
    -extfile "$ext_file" -out "$OUT_DIR/ldap.crt"

rm -f "$OUT_DIR/ldap.csr" "$OUT_DIR/ca.srl"

# slapd reads the server key directly as uid 911 inside the container, and that
# uid matches no host user under either docker or rootless podman, so the key
# has to be world-readable for TLS init to succeed. The CA key never enters the
# container and stays private -- it is the one that could sign new certificates.
chmod 600 "$OUT_DIR/ca.key"
chmod 644 "$OUT_DIR/ldap.key" "$OUT_DIR/ca.crt" "$OUT_DIR/ldap.crt"

echo ":: Done. Certificates written to $OUT_DIR"
openssl x509 -in "$OUT_DIR/ldap.crt" -noout -subject -ext subjectAltName
