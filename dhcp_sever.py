import socket
import struct
import getmac
from OpenSSL import crypto
from pathlib import Path
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

from dhcp_base import DHCPBase


class DHCPServer(DHCPBase):
    def __init__(
            self, 
            server_ip,
            cert_root,
            server_cert_name,
            server_key_name,
            ): 
        super().__init__(
                server_ip=server_ip,
                cert_root=cert_root,
                )

        self.shaddr = getmac.get_mac_address().replace(':', '')
        self.server_key_path = self.cert_root / server_key_name 
        self.server_cert_path = self.cert_root / server_cert_name 
        self.my_cert_packet = self.create_certificate_packet()

    def create_certificate_packet(self):
        with open(self.server_cert_path, 'rb') as cert_file:
            cert_data = cert_file.read()

            packet = b''
            packet += struct.pack('!1B', 90)
            packet += struct.pack('!I', len(cert_data))
            packet += cert_data 

            return packet

    def sign_message(self, message, private_key_file):
        with open(private_key_file, 'rb') as key:
            key_data = key.read()
            private_key = serialization.load_pem_private_key(key_data, password=None)
            signature = private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())
            return signature

    def create_dhcp_offer_packet(self, transaction_id, client_mac):
        # Create the DHCP offer msg 
        dhcp_msg = self.create_dhcp_msg_packet(
                op=2,
                transaction_id=transaction_id,
                yiaddr='192.168.1.1',
                #siaddr=self.server_ip,
                siaddr='192.168.1.100',
                #chaddr=client_mac,
                chaddr='000000000000',
                )

        # Create the DHCP offer option 
        dhcp_opt = self.create_dhcp_option_packet(
                [53, 1, [2]],                   # Option 53 (DHCP message type). 2 for DHCP Offer.
                [54, 4, [192, 168, 1, 100]],    # Option 54 (DHCP server identifier)
                add_certificate=True,           # Option 90 (DHCP authentication option)
                )

        packet = dhcp_msg + dhcp_opt

        # Sign the packet with server's private key
        signature = self.sign_message(packet, self.server_key_path)
        packet += signature

        return packet

    def create_dhcp_ack_packet(self, transaction_id, client_mac):
        # Create the DHCP ACK msg 
        dhcp_msg = self.create_dhcp_msg_packet(
                op=2,
                transaction_id=transaction_id,
                yiaddr='192.168.1.1',
                #siaddr=self.server_ip,
                siaddr='192.168.1.100',
                #chaddr=client_mac,
                chaddr='000000000000',
                )

        # Create the DHCP ACK option 
        dhcp_opt = self.create_dhcp_option_packet(
                [53, 1, [5]],                   # Option 53 (DHCP message type). 5 for DHCP Ack.
                [54, 4, [192, 168, 1, 100]],    # Option 54 (DHCP server identifier)
                add_certificate=True,           # Option 90 (DHCP authentication option)
                )

        packet = dhcp_msg + dhcp_opt

        # Sign the packet with server's private key
        signature = self.sign_message(packet, self.server_key_path)
        packet += signature

        return packet

    def start(self):
        # Create a socket and bind it to the DHCP server port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((self.server_ip, self.server_port))

        print("DHCP server started on {}:{}".format(self.server_ip, self.server_port))

        while True:
            # Receive DHCP discover packet from client
            rx_data, rx_address = self.socket.recvfrom(1024)
            transaction_id = struct.unpack('!I', rx_data[4:8])[0]
            client_mac = ':'.join('{:02x}'.format(byte) for byte in rx_data[28:34]).replace(':', '')
            print("Received DHCP discover from {} (transaction ID: {})".format(client_mac, transaction_id))

            # Create and send DHCP offer packet to client
            offer_packet = self.create_dhcp_offer_packet(transaction_id, client_mac)
            self.socket.sendto(offer_packet, rx_address)
            print("DHCP offer sent to {} (transaction ID: {})".format(rx_address[0], transaction_id))

            # Receive DHCP request packet from client
            data, address = self.socket.recvfrom(1024)
            transaction_id = struct.unpack('!I', data[4:8])[0]
            client_mac = ':'.join('{:02x}'.format(byte) for byte in data[28:34]).replace(':', '')
            print("Received DHCP request from {} (transaction ID: {})".format(address[0], transaction_id))

            # Create and send DHCP ACK packet to client
            ack_packet = self.create_dhcp_ack_packet(transaction_id, client_mac)
            self.socket.sendto(ack_packet, address)
            print("DHCP ACK sent to {} (transaction ID: {})".format(address[0], transaction_id))

    def stop(self):
        if self.socket:
            self.socket.close()

    def split_offer_packet(self, offer_packet_all):
        offer_msg, others = offer_packet_all[:self.msg_cutoff], offer_packet_all[self.msg_cutoff:]

        magic_cookie, others = others[:4], others[4:] 
        assert magic_cookie == self.magic_cookie 

        option_cutoff = others.find(b'\xff')
        offer_options, offer_signature = others[:option_cutoff], others[option_cutoff+1:]
        # assert len(offer_options) % 3 == 0
        # offer_options = [struct.unpack('!3B', offer_options[i:i+3]) for i in range(0, len(offer_options), 3)]
        return offer_msg, offer_options, offer_signature


if __name__ == '__main__':
    server_ip = ''
    cert_root = 'certificates'
    # server_cert_name = 'dhcp.server.crt'
    # server_key_name = 'dhcp.server.key'
    server_cert_name = 'dhcp.server.crt.nopass'
    server_key_name = 'dhcp.server.key.nopass'
    server = DHCPServer(
            server_ip=server_ip,
            cert_root=cert_root,
            server_cert_name=server_cert_name,
            server_key_name=server_key_name,
            )
    server.start()
