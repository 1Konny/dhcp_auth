from OpenSSL import crypto

# Load the certificate to be verified
with open('certificates/dhcp.server.crt', 'rb') as cert_file:
    cert_data = cert_file.read()
    certificate = crypto.load_certificate(crypto.FILETYPE_PEM, cert_data)

# Load the trusted CA certificates
store = crypto.X509Store()
with open('certificates/rootCA.crt', 'rb') as ca_file:
    ca_data = ca_file.read()
    ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, ca_data)
    store.add_cert(ca_cert)

context = crypto.X509StoreContext(store, certificate)

try:
    context.verify_certificate()
    print("Certificate is valid.")
except crypto.X509StoreContextError as e:
    print("Certificate verification failed:", e)
else:

    # Extract the distinguished name from the certificate
    subject = certificate.get_subject()
    common_name = subject.CN
    organization = subject.O
    print("Common Name (CN):", common_name)
    print("Organization (O):", organization)

    # Extract the public key from the certificate
    public_key = certificate.get_pubkey()
    public_key_type = public_key.type()
    public_key_bits = public_key.bits()
    print("Public Key Type:", public_key_type)
    print("Public Key Bits:", public_key_bits)
    print("Public Key:", public_key)
