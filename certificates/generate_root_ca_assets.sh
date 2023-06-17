#! /bin/bash

KEY_SIZE=${1:-2048}
META_DIR="$PWD/rootCA"
ASSET_DIR="$META_DIR/$KEY_SIZE"

# Create the directory if it doesn't exist
mkdir -p "$ASSET_DIR"

# Generate Root CA Key (rootCA.key) and Self-Signed Certificate (rootCA.crt)
openssl req \
    -x509 -sha256 -days 1825 -nodes \
    -newkey rsa:$KEY_SIZE \
    -keyout "$ASSET_DIR/rootCA.key" \
    -out "$ASSET_DIR/rootCA.crt" \
    -config "$META_DIR/rootCA.config"

ln -s "$ASSET_DIR/rootCA.crt" "$META_DIR/rootCA.crt"
ln -s "$ASSET_DIR/rootCA.key" "$META_DIR/rootCA.key"
