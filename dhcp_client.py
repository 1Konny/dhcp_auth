import socket
import struct
from OpenSSL import crypto
from pathlib import Path

__SERVER_PORT__ = 67
__CLIENT_PORT__ = 68
__CERT_SIZE__ = 2048
__CERT_ROOT__ = 'certificates'
__CERT_CA_NAME__ = 'rootCA.crt'


class DHCPClient:
    def __init__(self, server_ip): 
        self.server_ip = server_ip
        self.server_port =__SERVER_PORT__ 
        self.client_port = __CLIENT_PORT__ 
        self.client_socket = None

        self.certroot = Path(__CERT_ROOT__)
        self.certificate_ca_path = self.certroot / __CERT_CA_NAME__ 

    def load_certificate(self, cert_data):
        return crypto.load_certificate(crypto.FILETYPE_PEM, cert_data)

    def verify_certificate(self, certificate):
        # Load trusted CA certificate
        with open(self.certificate_ca_path, 'rb') as ca_file:
            ca_data = ca_file.read()
            ca_cert = self.load_certificate(ca_data)

        # Create a certificate store and add the trusted CA certificate
        store = crypto.X509Store()
        store.add_cert(ca_cert)

        # Create a context with the certificate store
        context = crypto.X509StoreContext(store, certificate)

        try:
            context.verify_certificate()
            print("Server certificate is valid.")
            return True
        except crypto.X509StoreContextError as e:
            print("Server certificate verification failed:", e)
            return False

    def create_dhcp_discover_packet(self, transaction_id):
        # Create the DHCP discover packet
        packet = struct.pack('!4B', 1, 1, 6, 0)  # DHCP discover message type
        packet += struct.pack('!I', transaction_id)  # Transaction ID
        packet += b'\x00\x00\x00\x00'  # Seconds elapsed
        packet += b'\x00\x00'  # Flags
        packet += b'\x00\x00\x00\x00'  # Client IP address
        packet += b'\x00\x00\x00\x00'  # Your server IP address
        packet += b'\x00\x00\x00\x00'  # Next server IP address
        packet += b'\x00\x00\x00\x00'  # Relay agent IP address
        packet += b'\x00\x00\x00\x00' * 4  # Client hardware address padding
        packet += b'\x00' * 192  # Padding
        packet += b'\x63\x82\x53\x63'  # Magic cookie
        packet += b'\x35\x01\x01'  # Option 53 (DHCP message type) - DHCP Discover
        packet += b'\xff'  # End of options

        return packet

    def create_dhcp_request_packet(self, transaction_id, server_ip):
        # Create the DHCP request packet
        packet = struct.pack('!4B', 1, 1, 6, 0)  # DHCP request message type
        packet += struct.pack('!I', transaction_id)  # Transaction ID
        packet += b'\x00\x00\x00\x00'  # Seconds elapsed
        packet += b'\x00\x00'  # Flags
        packet += b'\x00\x00\x00\x00'  # Client IP address
        packet += server_ip  # Server IP address
        packet += b'\x00\x00\x00\x00'  # Next server IP address
        packet += b'\x00\x00\x00\x00'  # Relay agent IP address
        packet += b'\x00\x00\x00\x00' * 4  # Client hardware address padding
        packet += b'\x00' * 192  # Padding
        packet += b'\x63\x82\x53\x63'  # Magic cookie
        packet += b'\x35\x01\x03'  # Option 53 (DHCP message type) - DHCP Request
        packet += b'\x32\x04' + server_ip  # Option 50 (Requested IP address)
        packet += b'\xff'  # End of options

        return packet

    def start(self):
        # Create a socket
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        print("DHCP client started")

        # Generate a random transaction ID
        transaction_id = 123456

        # Send DHCP discover packet
        discover_packet = self.create_dhcp_discover_packet(transaction_id)
        self.client_socket.sendto(discover_packet, (self.server_ip, self.server_port))

        print("DHCP discover sent")

        try:
            # Receive server's certificate from server
            cert_data, server_address = self.client_socket.recvfrom(__CERT_SIZE__)

            # Load the received certificate
            certificate = self.load_certificate(cert_data)

            # Verify the server's certificate
            if not self.verify_certificate(certificate):
                print("Server certificate verification failed. Aborting.")
                return

            # Receive DHCP offer packet from server
            offer_packet, server_address = self.client_socket.recvfrom(1024)
            transaction_id = struct.unpack('!I', offer_packet[4:8])[0]

            print("Received DHCP offer from {} (transaction ID: {})".format(server_address[0], transaction_id))

            # Verify the authenticity of the offer packet using the server's public key
            public_key = certificate.get_pubkey()
            if not crypto.verify(certificate, offer_packet[24:], offer_packet[:24], 'sha256'):
                print("Offer packet verification failed. Aborting.")
                return

            import ipdb; ipdb.set_trace(context=25)
            # Send DHCP request packet
            request_packet = self.create_dhcp_request_packet(transaction_id, offer_packet[20:24])
            self.client_socket.sendto(request_packet, (self.server_ip, self.server_port))

            print("DHCP request sent")

            # Receive DHCP ACK packet from server
            ack_packet, server_address = self.client_socket.recvfrom(1024)
            transaction_id = struct.unpack('!I', ack_packet[4:8])[0]

            print("Received DHCP ACK from {} (transaction ID: {})".format(server_address[0], transaction_id))

            # Verify the authenticity of the ACK packet using the server's public key
            if not crypto.verify(certificate, ack_packet[24:], ack_packet[:24], 'sha256'):
                print("ACK packet verification failed. Aborting.")
                return

            # Extract assigned IP address from ACK packet
            assigned_ip = socket.inet_ntoa(ack_packet[16:20])

            print("Assigned IP address: {}".format(assigned_ip))

        except socket.timeout:
            print("No response received from DHCP server")

        self.client_socket.close()


if __name__ == '__main__':
    server_ip = '<broadcast>'
    client = DHCPClient(server_ip)
    client.start()

