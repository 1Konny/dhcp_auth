## Usage

1. Generate private keys and certificates for the root CA and DHCP server.
```
cd certificates
bash generate_root_ca_assets.sh
bash generate_server_assets.sh
cd ..
```

2. Run the DHCP server.
```
python dhcp_server.py
```

3. Run the DHCP client.
```
python dhcp_client.py
```
