#! /bin/bash

KEY_SIZE=${1:-2048}
META_DIR="$PWD/server"
ASSET_DIR="$META_DIR/$KEY_SIZE"
ROOT_CA_META_DIR="$PWD/rootCA"

# Create the directory if it doesn't exist
mkdir -p "$ASSET_DIR"

openssl genrsa -out "$ASSET_DIR/server.key" "$KEY_SIZE" >/dev/null 2>&1
openssl req -new -key "$ASSET_DIR/server.key" -out "$ASSET_DIR/server.csr" -config "$META_DIR/server.config" >/dev/null 2>&1
openssl x509 -req -CA "$ROOT_CA_META_DIR/rootCA.crt" -CAkey "$ROOT_CA_META_DIR/rootCA.key" -in "$ASSET_DIR/server.csr" -out "$ASSET_DIR/server.crt" -days 365 -CAcreateserial -extfile "$META_DIR/server.ext" >/dev/null 2>&1
