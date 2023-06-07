import socket
import struct
from OpenSSL import crypto
from pathlib import Path
import getmac

from dhcp_base import DHCPBase


class DHCPClient(DHCPBase):
    def __init__(
            self, 
            server_ip,
            cert_root,
            ca_cert_name,
            ):
        super().__init__(
                server_ip=server_ip,
                cert_root=cert_root,
                )

        self.chaddr = getmac.get_mac_address().replace(':', '')
        self.ca_cert_path = self.cert_root / ca_cert_name 

    def load_certificate(self, cert_data):
        return crypto.load_certificate(crypto.FILETYPE_PEM, cert_data)

    def verify_certificate(self, certificate):
        # Load trusted CA certificate
        with open(self.ca_cert_path, 'rb') as ca_file:
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
        # Create the DHCP discover msg 
        dhcp_msg = self.create_dhcp_msg_packet(
                op=1,
                transaction_id=transaction_id,
                chaddr=self.chaddr,
                )

        # Create the DHCP discover option 
        dhcp_opt = self.create_dhcp_option_packet(
                [53, 1, [1]], # Option 53 (DHCP message type). 1 for DHCP Discover.
                )

        packet = dhcp_msg + dhcp_opt

        return packet

    def create_dhcp_request_packet(self, transaction_id, server_ip):
        # Create the DHCP request msg 
        dhcp_msg = self.create_dhcp_msg_packet(
                op=1,
                transaction_id=transaction_id,
                siaddr=server_ip,
                chaddr=self.chaddr,
                )

        # Create the DHCP request option 
        dhcp_opt = self.create_dhcp_option_packet(
                # Option 53 (DHCP message type). 3 for DHCP Request.
                [53, 1, [3]], 
                # Option 50 (Requested IP address) 
                [50, 4, [int(val) for val in server_ip.split('.')]], 
                )

        packet = dhcp_msg + dhcp_opt

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
            cert_length_data, server_address = self.client_socket.recvfrom(self.cert_max_size)
            cert_length = cert_length_data[:4]
            cert_data = cert_length_data[4:4+int.from_bytes(cert_length, 'big')]

            # Load the received certificate
            certificate = self.load_certificate(cert_data)

            # Verify the server's certificate
            if not self.verify_certificate(certificate):
                print("Server certificate verification failed. Aborting.")
                return
            else:
                print("Server is authenticated")

            # Receive DHCP offer packet from server
            offer_packet, server_address = self.client_socket.recvfrom(1024)
            offer_msg, offer_option, offer_signature = self.split_received_packet(offer_packet)
            transaction_id = struct.unpack('!I', offer_msg[4:8])[0]

            print("Received DHCP offer from {} (transaction ID: {})".format(server_address[0], transaction_id))

            # Verify the authenticity of the offer packet using the server's public key
            # public_key = certificate.get_pubkey()
            if not crypto.verify(certificate, offer_signature, offer_msg+offer_option, 'sha256'):
                print("Offer packet verification succeeded.")
            else:
                print("Offer packet verification failed. Aborting.")
                return

            # Send DHCP request packet
            request_packet = self.create_dhcp_request_packet(
                    transaction_id, 
                    # offer_packet[20:24],
                    socket.inet_ntoa(offer_packet[20:24]),
                    )
            self.client_socket.sendto(request_packet, (self.server_ip, self.server_port))

            print("DHCP request sent")

            # Receive DHCP ACK packet from server
            ack_packet, server_address = self.client_socket.recvfrom(1024)
            ack_msg, ack_option, ack_signature = self.split_received_packet(ack_packet)
            transaction_id = struct.unpack('!I', ack_packet[4:8])[0]

            print("Received DHCP ACK from {} (transaction ID: {})".format(server_address[0], transaction_id))

            # Verify the authenticity of the ACK packet using the server's public key
            if not crypto.verify(certificate, ack_signature, ack_msg+ack_option, 'sha256'):
                print("ACK packet verification succeeded.")
            else:
                print("ACK packet verification failed. Aborting.")
                return

            # Extract assigned IP address from ACK packet
            assigned_ip = socket.inet_ntoa(ack_packet[16:20])

            print("Assigned IP address: {}".format(assigned_ip))

        except socket.timeout:
            print("No response received from DHCP server")

        self.client_socket.close()

    def split_received_packet(self, packet):
        msg, others = packet[:self.msg_cutoff], packet[self.msg_cutoff:]
        option_cutoff = others.find(b'\xff')
        options, signature = others[:option_cutoff+1], others[option_cutoff+1:]
        return msg, options, signature


if __name__ == '__main__':
    server_ip = '<broadcast>'
    cert_root = 'certificates'
    ca_cert_name = 'rootCA.crt'
    client = DHCPClient(
            server_ip=server_ip,
            cert_root=cert_root,
            ca_cert_name=ca_cert_name,
            )
    client.start()
