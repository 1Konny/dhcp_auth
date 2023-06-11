import socket
import struct

from dhcp_base import DHCPBase


class DHCPServer(DHCPBase):
    def __init__(
            self, 
            server_ip,
            cert_root,
            server_cert_name,
            server_key_name,
            ca_cert_name,
            ): 
        super().__init__(
                server_ip=server_ip,
                cert_root=cert_root,
                my_cert_name=server_cert_name,
                my_key_name=server_key_name,
                trusted_cert_name=ca_cert_name,
                )

    def create_dhcp_offer_packet(self, transaction_id, client_mac):
        # Reference: https://en.wikipedia.org/wiki/Dynamic_Host_Configuration_Protocol#Offer

        # Create the DHCP offer msg 
        dhcp_msg = self.create_dhcp_msg_packet(
                op=2,
                transaction_id=transaction_id,
                ciaddr='0.0.0.0',
                yiaddr='172.17.0.3',
                siaddr=self.server_ip,
                chaddr=client_mac,
                )

        # Create the DHCP offer option 
        dhcp_opt = self.create_dhcp_option_packet(
                [53, 1, [2]],                   # Option 53 (DHCP message type). 2 for DHCP Offer.
                [1, 4, [255, 255, 255, 0]],     # Option 01 (Subnet Mask).
                [3, 4, [172, 17, 0, 100]],       # Option 03 (Router IP).
                [51, 4, [0, 1, 81, 128]],       # Option 51 (IP address lease time). For 1 day.
                # # Option 54 (DHCP server identifier).
                [54, 4, [int(val) for val in self.server_ip.split('.')]],
                [6, 4, [172, 17, 0, 101]],         # Option 06 (DNS Server).
                add_certificate=True,           # Option 90 (DHCP authentication option)
                )

        packet = dhcp_msg + dhcp_opt

        # Sign the packet with server's private key
        signature = self.sign_message(packet, self.my_private_key)
        packet += signature

        return packet

    def create_dhcp_ack_packet(self, transaction_id, client_mac):
        # Reference: https://en.wikipedia.org/wiki/Dynamic_Host_Configuration_Protocol#Acknowledgement

        # Create the DHCP ACK msg 
        dhcp_msg = self.create_dhcp_msg_packet(
                op=2,
                transaction_id=transaction_id,
                ciaddr='0.0.0.0',
                yiaddr='172.17.0.3',
                siaddr=self.server_ip,
                chaddr=client_mac,
                )

        # Create the DHCP ACK option 
        dhcp_opt = self.create_dhcp_option_packet(
                [53, 1, [5]],                   # Option 53 (DHCP message type). 5 for DHCP Ack.
                [1, 4, [255, 255, 255, 0]],     # Option 01 (Subnet Mask).
                [3, 4, [172, 17, 0, 100]],       # Option 03 (Router IP).
                [51, 4, [0, 1, 81, 128]],       # Option 51 (IP address lease time). For 1 day.
                # # Option 54 (DHCP server identifier).
                [54, 4, [int(val) for val in self.server_ip.split('.')]],
                [6, 4, [172, 17, 0, 101]],         # Option 06 (DNS Server).
                add_certificate=True,           # Option 90 (DHCP authentication option)
                )

        packet = dhcp_msg + dhcp_opt

        # Sign the packet with server's private key
        signature = self.sign_message(packet, self.my_private_key)
        packet += signature

        return packet

    def start(self):
        # Create a socket and bind it to the DHCP server port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(('', self.server_port))

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

        self.stop()

    def stop(self):
        if self.socket:
            self.socket.close()


if __name__ == '__main__':
    server_ip = '172.17.0.2'
    cert_root = 'certificates'
    server_cert_name = 'dhcp.server.crt.nopass'
    server_key_name = 'dhcp.server.key.nopass'
    ca_cert_name = 'rootCA.crt'
    server = DHCPServer(
            server_ip=server_ip,
            cert_root=cert_root,
            server_cert_name=server_cert_name,
            server_key_name=server_key_name,
            ca_cert_name=ca_cert_name,
            )
    server.start()
