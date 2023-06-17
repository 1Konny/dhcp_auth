import time
import socket
import struct

from dhcp_base import DHCPBase


class DHCPServer(DHCPBase):
    def __init__(
            self,
            server_ip,
            ca_asset_dir,
            ca_asset_name,
            my_asset_dir,
            my_asset_name,
            ):
        super().__init__(
                server_ip=server_ip,
                ca_asset_dir=ca_asset_dir,
                ca_asset_name=ca_asset_name,
                my_asset_dir=my_asset_dir,
                my_asset_name=my_asset_name,
                )

        self.time_dict = {}

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
                # Option 53 (DHCP message type). 2 for DHCP Offer.
                [53, 1, [2]],
                # Option 01 (Subnet Mask).
                [1, 4, [255, 255, 255, 0]],
                # Option 03 (Router IP).
                [3, 4, [172, 17, 0, 100]],
                # Option 51 (IP address lease time). For 1 day.
                [51, 4, [0, 1, 81, 128]],
                # # Option 54 (DHCP server identifier).
                [54, 4, [int(val) for val in self.server_ip.split('.')]],
                # Option 06 (DNS Server).
                [6, 4, [172, 17, 0, 101]],
                # Option 90 (DHCP authentication option)
                add_certificate=True,
                )

        packet = dhcp_msg + dhcp_opt

        # Sign the packet with server's private key
        signature = self.sign_message(packet, self.my_key)
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
                # Option 53 (DHCP message type). 5 for DHCP ACK.
                [53, 1, [5]],
                # Option 01 (Subnet Mask).
                [1, 4, [255, 255, 255, 0]],
                # Option 03 (Router IP).
                [3, 4, [172, 17, 0, 100]],
                # Option 51 (IP address lease time). For 1 day.
                [51, 4, [0, 1, 81, 128]],
                # # Option 54 (DHCP server identifier).
                [54, 4, [int(val) for val in self.server_ip.split('.')]],
                # Option 06 (DNS Server).
                [6, 4, [172, 17, 0, 101]],
                # Option 90 (DHCP authentication option)
                add_certificate=True,
                )

        packet = dhcp_msg + dhcp_opt

        # Sign the packet with server's private key
        signature = self.sign_message(packet, self.my_key)
        packet += signature

        return packet

    def start(self):
        # Create a socket and bind it to the DHCP server port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(('', self.server_port))

        print("DHCP server started on {}:{}".format(self.server_ip, self.server_port))

        while True:
            # Receive DHCP discover packet from client
            discover_packet, rx_address = self.socket.recvfrom(self.msg_buffer_size)
            self.length_dict['discover_packet'] = len(discover_packet)
            transaction_id = struct.unpack('!I', discover_packet[4:8])[0]
            client_mac = ':'.join('{:02x}'.format(byte) for byte in discover_packet[28:34]).replace(':', '')
            print("Received DHCP discover from {} (transaction ID: {})".format(client_mac, transaction_id))

            # Create and send DHCP offer packet to client
            self.time_dict['offer_packet_generate_stime'] = time.time()
            offer_packet = self.create_dhcp_offer_packet(transaction_id, client_mac)
            self.time_dict['offer_packet_generate_etime'] = time.time()
            self.time_dict['offer_packet_generate_time'] = self.time_dict['offer_packet_generate_etime'] - self.time_dict['offer_packet_generate_stime']
            self.length_dict['offer_packet'] = len(offer_packet)
            self.socket.sendto(offer_packet, rx_address)
            print("DHCP offer sent to {} (transaction ID: {})".format(rx_address[0], transaction_id))

            # Receive DHCP request packet from client
            request_packet, address = self.socket.recvfrom(self.msg_buffer_size)
            self.length_dict['request_packet'] = len(request_packet)
            transaction_id = struct.unpack('!I', request_packet[4:8])[0]
            client_mac = ':'.join('{:02x}'.format(byte) for byte in request_packet[28:34]).replace(':', '')
            print("Received DHCP request from {} (transaction ID: {})".format(address[0], transaction_id))

            # Create and send DHCP ACK packet to client
            self.time_dict['ack_packet_generate_stime'] = time.time()
            ack_packet = self.create_dhcp_ack_packet(transaction_id, client_mac)
            self.time_dict['ack_packet_generate_etime'] = time.time()
            self.time_dict['ack_packet_generate_time'] = self.time_dict['ack_packet_generate_etime'] - self.time_dict['ack_packet_generate_stime']
            self.length_dict['ack_packet'] = len(ack_packet)
            self.socket.sendto(ack_packet, address)
            print("DHCP ACK sent to {} (transaction ID: {})".format(address[0], transaction_id))
            print('='*50)

            print('Discover packet length: {}'.format(self.length_dict['discover_packet']))
            print('Offer packet length: {}'.format(self.length_dict['offer_packet']))
            print('Offer packet generate time: {}'.format(self.time_dict['offer_packet_generate_time']))
            print('Request packet length: {}'.format(self.length_dict['request_packet']))
            print('ACK packet length: {}'.format(self.length_dict['ack_packet']))
            print('ACK packet generate time: {}'.format(self.time_dict['ack_packet_generate_time']))
            print('='*50)

            break

        self.stop()

        self.time_dict = {k:v for k,v in self.time_dict.items() if 'stime' not in k and 'etime' not in k}
        return self.length_dict, self.time_dict

    def stop(self):
        if self.socket:
            self.socket.close()


if __name__ == '__main__':
    server_ip = '172.17.0.2'
    ca_asset_dir = 'certificates/rootCA/2048'
    ca_asset_name = 'rootCA'
    my_asset_dir = 'certificates/server/4096'
    my_asset_name = 'server'
    server = DHCPServer(
            server_ip=server_ip,
            ca_asset_dir=ca_asset_dir,
            ca_asset_name=ca_asset_name,
            my_asset_dir=my_asset_dir,
            my_asset_name=my_asset_name,
            )
    length_dict, time_dict = server.start()
