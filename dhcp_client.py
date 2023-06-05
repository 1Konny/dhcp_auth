import socket
import struct
from OpenSSL import crypto
from pathlib import Path
import getmac

__SERVER_PORT__ = 67
__CLIENT_PORT__ = 68
__CERT_SIZE__ = 2048
__CERT_ROOT__ = 'certificates'
__CERT_CA_NAME__ = 'rootCA.crt'
__DHCP_MSG_LEN__ = 240
__MAGIC_COOKIE__ = b'\x63\x82\x53\x63'


class DHCPClient:
    def __init__(self, server_ip):
        self.server_ip = server_ip
        self.server_port =__SERVER_PORT__
        self.client_port = __CLIENT_PORT__
        self.client_socket = None

        self.msg_cutoff = __DHCP_MSG_LEN__

        self.chaddr = getmac.get_mac_address().replace(':', '')

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

    def create_dhcp_msg_packet(
            self,
            op,
            transaction_id,
            ciaddr=None,
            yiaddr=None,
            siaddr=None,
            giaddr=None,
            chaddr=None,
            ):

        ciaddr = '0.0.0.0' if ciaddr is None else ciaddr
        yiaddr = '0.0.0.0' if yiaddr is None else yiaddr
        siaddr = '0.0.0.0' if siaddr is None else siaddr
        giaddr = '0.0.0.0' if giaddr is None else giaddr
        chaddr = '000000000000' if chaddr is None else chaddr

        packet = b''
        packet += struct.pack('!1B', op)            # OP: Operation Code. 1 for REQUEST, 2 for REPLY.
        packet += struct.pack('!1B', 1)             # HTYPE: Hardware Address Type. 1 to specify ETHERNET.
        packet += struct.pack('!1B', 6)             # HLEN: Hardware Address Length. 6 for MAC address.
        packet += struct.pack('!1B', 0)             # HOPS: Number of relay agents a request message traveled.
        packet += struct.pack('!I', transaction_id) # XID: Transaction ID. 4 bytes.
        packet += struct.pack('!2B', 0, 0)          # SECS: Set to 0 by default. 
        packet += struct.pack('!2B', 0, 0)          # FLAGS. 
        packet += socket.inet_aton(ciaddr)          # CIADDR: Client IP address. 
        packet += socket.inet_aton(yiaddr)          # YIADDR. Your IP address. 
        packet += socket.inet_aton(siaddr)          # SIADDR. Server IP address.
        packet += socket.inet_aton(giaddr)          # GIADDR. Relay agent IP address.
        packet += bytearray.fromhex(chaddr+'00'*10) # CHADDR: Client hardware address. 16 bytes.
        packet += b'\x00' * 192                     # Padding: 192 bytes.
        packet += b'\x63\x82\x53\x63'               # Magic cookie.

        return packet

    def create_dhcp_option_packet(
            self,
            *triplets,
            ):

        packet = b''

        for tag, length, values in triplets:
            packet += struct.pack('!1B', tag)
            packet += struct.pack('!1B', length)
            packet += struct.pack(f'!{length}B', *values)

        packet += struct.pack('!1B', 255)

        return packet

    def create_dhcp_discover_packet(self, transaction_id):
        # References
        # 1. https://techhub.hpe.com/eginfolib/networking/docs/switches/5120si/cg/5998-8491_l3-ip-svcs_cg/content/436042653.htm
        # 2. http://www.tcpipguide.com/free/t_DHCPMessageFormat.htm
        # 3. https://en.wikipedia.org/wiki/Dynamic_Host_Configuration_Protocol
        # 4. http://www.ktword.co.kr/test/view/view.php?m_temp1=1925

        # Create the DHCP discover packet

        dhcp_msg = self.create_dhcp_msg_packet(
                op=1,
                transaction_id=transaction_id,
                chaddr=self.chaddr,
                )

        dhcp_opt = self.create_dhcp_option_packet(
                [53, 1, [1]], # Option 53 (DHCP message type). 1 for DHCP Discover.
                )

        packet = dhcp_msg + dhcp_opt

        return packet

    def create_dhcp_request_packet(self, transaction_id, server_ip):
        # Create the DHCP request packet

        dhcp_msg = self.create_dhcp_msg_packet(
                op=1,
                transaction_id=transaction_id,
                siaddr=server_ip,
                chaddr=self.chaddr,
                )

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
            cert_length_data, server_address = self.client_socket.recvfrom(__CERT_SIZE__)
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
    client = DHCPClient(server_ip)
    client.start()

