#!/usr/bin/env bash
set -e

BASE_DIR="$(pwd)/pki"
ROOT_DIR="$BASE_DIR/root"
INT_DIR="$BASE_DIR/intermediate"
SERVER_DIR="$BASE_DIR/server"

mkdir -p "$ROOT_DIR" "$INT_DIR" "$SERVER_DIR"

echo "==> Generating Root CA"

openssl genrsa -out "$ROOT_DIR/root.key" 4096

openssl req -x509 -new -nodes \
  -key "$ROOT_DIR/root.key" \
  -sha256 -days 3650 \
  -out "$ROOT_DIR/root.crt" \
  -subj "/C=US/ST=Local/L=Local/O=Local Dev/CN=Local Root CA" \
  -extensions v3_ca \
  -config <(
    cat <<EOF
[req]
distinguished_name=req
x509_extensions=v3_ca
prompt=no

[v3_ca]
basicConstraints=critical,CA:TRUE,pathlen:1
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
EOF
)

echo "==> Generating Intermediate CA"

openssl genrsa -out "$INT_DIR/intermediate.key" 4096

openssl req -new \
  -key "$INT_DIR/intermediate.key" \
  -out "$INT_DIR/intermediate.csr" \
  -subj "/C=US/ST=Local/L=Local/O=Local Dev/CN=Local Intermediate CA"

openssl x509 -req \
  -in "$INT_DIR/intermediate.csr" \
  -CA "$ROOT_DIR/root.crt" \
  -CAkey "$ROOT_DIR/root.key" \
  -CAcreateserial \
  -out "$INT_DIR/intermediate.crt" \
  -days 1825 -sha256 \
  -extensions v3_intermediate_ca \
  -extfile <(
    cat <<EOF
[v3_intermediate_ca]
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
EOF
)

echo "==> Generating Server Certificate for localhost"

openssl genrsa -out "$SERVER_DIR/server.key" 2048

openssl req -new \
  -key "$SERVER_DIR/server.key" \
  -out "$SERVER_DIR/server.csr" \
  -subj "/C=US/ST=Local/L=Local/O=Local Dev/CN=localhost"

openssl x509 -req \
  -in "$SERVER_DIR/server.csr" \
  -CA "$INT_DIR/intermediate.crt" \
  -CAkey "$INT_DIR/intermediate.key" \
  -CAcreateserial \
  -out "$SERVER_DIR/server.crt" \
  -days 825 -sha256 \
  -extensions v3_server \
  -extfile <(
    cat <<EOF
[v3_server]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=@alt_names
authorityKeyIdentifier=keyid,issuer
subjectKeyIdentifier=hash

[alt_names]
DNS.1=localhost
IP.1=127.0.0.1
EOF
)

echo "==> Building certificate chains"

cat "$INT_DIR/intermediate.crt" "$ROOT_DIR/root.crt" > "$BASE_DIR/chain.pem"
cat "$SERVER_DIR/server.crt" "$INT_DIR/intermediate.crt" > "$BASE_DIR/fullchain.pem"
cat "$SERVER_DIR/server.crt" "$INT_DIR/intermediate.crt" "$ROOT_DIR/root.crt" > "$BASE_DIR/fullchain_with_root.pem"

echo "==> Done"
echo "PKI generated in $BASE_DIR"
