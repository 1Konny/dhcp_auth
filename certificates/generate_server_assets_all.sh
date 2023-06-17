#! /bin/bash

for KEY_SIZE in {2048..4096}; do bash generate_server_assets.sh "$KEY_SIZE"; done

