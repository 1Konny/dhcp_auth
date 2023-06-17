#! /bin/bash

KEY_SIZE=${1:-2048}
META_DIR="$PWD/server"
ASSET_DIR="$META_DIR/$KEY_SIZE"
ROOT_CA_META_DIR="$PWD/rootCA"

# Create the directory if it doesn't exist
mkdir -p "$ASSET_DIR"

# Create private key of the server
openssl genrsa \
    -out "$ASSET_DIR/server.key" "$KEY_SIZE" 

# Create the request for the certificate of the server
openssl req \
    -new \
    -key "$ASSET_DIR/server.key" \
    -out "$ASSET_DIR/server.csr" \
    -config "$META_DIR/server.config"

# Create the certificate of the server using root CA's key and certificate.
openssl x509 \
    -req -days 365 -CAcreateserial \
    -CA "$ROOT_CA_META_DIR/rootCA.crt" \
    -CAkey "$ROOT_CA_META_DIR/rootCA.key" \
    -in "$ASSET_DIR/server.csr" \
    -out "$ASSET_DIR/server.crt" \
    -extfile "$META_DIR/server.ext"
