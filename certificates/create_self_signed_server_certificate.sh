#! /bin/bash

# Generate DHCP Server Private Key
# openssl genrsa -aes256 -out dhcp.server.key 2048
# Enter pass phrase for rootca.key: 1234
# Verifying - Enter pass phrase for rootca.key: 1234

# Generate CSR.
openssl req -key dhcp.server.key -new -out dhcp.server.csr
# Country Name (2 letter code) [AU]:KR
# State or Province Name (full name) [Some-State]:.
# Locality Name (eg, city) []:.
# Organization Name (eg, company) [Internet Widgits Pty Ltd]:DHCP-Server
# Organizational Unit Name (eg, section) []:.
# Common Name (e.g. server FQDN or YOUR name) []:.
# Email Address []:wonkwang.lee@snu.ac.kr

# Please enter the following 'extra' attributes
# to be sent with your certificate request
# A challenge password []:1234
# An optional company name []:.

'''
# public keys that can be obtained from the certificate and private key should be identical
root at bffc6efbafc9 in ~/project/certificates
$ openssl x509 -in dhcp.server.crt -noout -pubkey
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxhoy6Oep9gbZME7VdY0z
AWoGlF+d+hNzy5qb02bJ+S8LMVcYENLgJFOYxzJ/gAEaEgv000ZdgENeTF/NKkav
KrjAL5JBmZA2SJ+h4mEw6FrWXtO8zcmLkeG9aZEjKnLyGsfT1nHw+SXrJeAo4zC1
a9lhMawppFapBQFAbXQs9+4foPr1LiBaovd1eoaJZIm5Ra1nDsRfvWy8feFZnn9E
uARt4GCvvb3LXHnmTl20rqmiJL5wU/uflwWYIF+PZtcG3Q76C752CAQTG2ukNRtc
fxMonRrPtau/kdjhixdvpq5UwMI8oFTibg49o2pRKXAF6qh5ug35vG+ZBop2U46J
PwIDAQAB
-----END PUBLIC KEY-----

root at bffc6efbafc9 in ~/project/certificates
$ openssl rsa -in dhcp.server.key -pubout
Enter pass phrase for dhcp.server.key: 1234
writing RSA key
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxhoy6Oep9gbZME7VdY0z
AWoGlF+d+hNzy5qb02bJ+S8LMVcYENLgJFOYxzJ/gAEaEgv000ZdgENeTF/NKkav
KrjAL5JBmZA2SJ+h4mEw6FrWXtO8zcmLkeG9aZEjKnLyGsfT1nHw+SXrJeAo4zC1
a9lhMawppFapBQFAbXQs9+4foPr1LiBaovd1eoaJZIm5Ra1nDsRfvWy8feFZnn9E
uARt4GCvvb3LXHnmTl20rqmiJL5wU/uflwWYIF+PZtcG3Q76C752CAQTG2ukNRtc
fxMonRrPtau/kdjhixdvpq5UwMI8oFTibg49o2pRKXAF6qh5ug35vG+ZBop2U46J
PwIDAQAB
-----END PUBLIC KEY-----
'''
