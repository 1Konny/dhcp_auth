#! /bin/bash

# Generate Root CA Key (rootCA.key) and Self-Signed Certificate (rootCA.crt)
openssl req -x509 -sha256 -days 1825 -newkey rsa:2048 -keyout rootCA.key -out rootCA.crt
# ..............................................................................................................................................................+++++
# ...+++++
# writing new private key to 'rootCA.key'
# Enter PEM pass phrase: 1234
# Verifying - Enter PEM pass phrase: 1234
# -----
# You are about to be asked to enter information that will be incorporated
# into your certificate request.
# What you are about to enter is what is called a Distinguished Name or a DN.
# There are quite a few fields but you can leave some blank
# For some fields there will be a default value,
# If you enter '.', the field will be left blank.
# -----
# Country Name (2 letter code) [AU]:KR
# State or Province Name (full name) [Some-State]:.
# Locality Name (eg, city) []:.
# Organization Name (eg, company) [Internet Widgits Pty Ltd]:Root_CA
# Organizational Unit Name (eg, section) []:.
# Common Name (e.g. server FQDN or YOUR name) []:.
# Email Address []:wonkwang.lee@vision.snu.ac.kr

openssl x509 -req -CA rootCA.crt -CAkey rootCA.key -in dhcp.server.csr -out dhcp.server.crt -days 365 -CAcreateserial -extfile dhcp.server.ext
# Signature ok
# subject=C = KR, O = DHCP-Server, emailAddress = wonkwang.lee@snu.ac.kr
# Getting CA Private Key
# Enter pass phrase for rootCA.key: 1234


