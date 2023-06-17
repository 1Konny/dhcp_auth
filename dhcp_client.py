import time
import socket
import struct

from dhcp_base import DHCPBase


class DHCPClient(DHCPBase):
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

    def create_dhcp_discover_packet(self, transaction_id):
        # Reference: https://en.wikipedia.org/wiki/Dynamic_Host_Configuration_Protocol#Discovery

        # Create the DHCP discover msg 
        dhcp_msg = self.create_dhcp_msg_packet(
                op=1,
                transaction_id=transaction_id,
                ciaddr='0.0.0.0',
                yiaddr='0.0.0.0',
                siaddr='0.0.0.0',
                giaddr='0.0.0.0',
                chaddr=self.my_haddr,
                )

        # Create the DHCP discover option 
        dhcp_opt = self.create_dhcp_option_packet(
                # Option 53 (DHCP message type). 1 for DHCP Discover.
                [53, 1, [1]],               

                # Option 55 (Parameter request list).
                # 1 (Request Subnet Mask),
                # 3 (Router),
                # 15 (Domain Name),
                # 6 (Domain Name Server)
                [55, 4, [1, 3, 15, 6]],     
                )

        packet = dhcp_msg + dhcp_opt

        return packet

    def create_dhcp_request_packet(self, transaction_id, obtained_ip, server_ip):
        # Create the DHCP request msg 
        dhcp_msg = self.create_dhcp_msg_packet(
                op=1,
                transaction_id=transaction_id,
                ciaddr='0.0.0.0',
                yiaddr='0.0.0.0',
                siaddr=server_ip,
                giaddr='0.0.0.0',
                chaddr=self.my_haddr,
                )

        # Create the DHCP request option 
        dhcp_opt = self.create_dhcp_option_packet(
                # Option 53 (DHCP message type). 3 for DHCP Request.
                [53, 1, [3]], 
                # Option 50 (Requested IP address) 
                [50, 4, [int(val) for val in obtained_ip.split('.')]], 
                # Option 54 (DHCP server IP).
                [54, 4, [int(val) for val in server_ip.split('.')]], 
                )

        packet = dhcp_msg + dhcp_opt

        return packet

    def start(self):
        # Create a socket
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        print("DHCP client started")

        # Generate a random transaction ID
        transaction_id = 123456

        # Send DHCP discover packet
        self.time_dict['discover_packet_generate_stime'] = time.time()
        discover_packet = self.create_dhcp_discover_packet(transaction_id)
        self.time_dict['discover_packet_generate_etime'] = time.time()
        self.time_dict['discover_packet_generate_time'] = self.time_dict['discover_packet_generate_etime'] - self.time_dict['discover_packet_generate_stime'] 
        self.length_dict['discover_packet'] = len(discover_packet)
        self.socket.sendto(discover_packet, (self.server_ip, self.server_port))
        print("DHCP discover sent")

        try:
            # 2. DHCP Client <- DHCP Offer <- DHCP Server

            ## 2-1. Receive DHCP offer packet from server
            offer_packet, server_address = self.socket.recvfrom(self.msg_buffer_size)
            self.length_dict['offer_packet'] = len(offer_packet)

            self.time_dict['offer_packet_split_stime'] = time.time()
            offer_msg, offer_options, offer_options_dict, offer_signature = self.split_received_packet(offer_packet)
            offer_certificate = offer_options_dict.get(90, None)
            self.time_dict['offer_packet_split_etime'] = time.time()
            self.time_dict['offer_packet_split_time'] = self.time_dict['offer_packet_split_etime'] - self.time_dict['offer_packet_split_stime']

            ## 2-2. Verify the validity of the offer certificate using the CA's certificate (public key). 
            self.time_dict['offer_cert_verify_stime'] = time.time()
            offer_certificate = self.verify_certificate(offer_certificate)
            self.time_dict['offer_cert_verify_etime'] = time.time()
            self.time_dict['offer_cert_verify_time'] = self.time_dict['offer_cert_verify_etime'] - self.time_dict['offer_cert_verify_stime']

            if offer_certificate is None:
                self.socket.close()
                return

            ## 2-3. Verify the authenticity of the offer packet using the server's certificate (public key)..
            self.time_dict['offer_sign_verify_stime'] = time.time()
            offer_key = self.verify_packet(offer_certificate, offer_signature, offer_msg+offer_options)
            self.time_dict['offer_sign_verify_etime'] = time.time()
            self.time_dict['offer_sign_verify_time'] = self.time_dict['offer_sign_verify_etime'] - self.time_dict['offer_sign_verify_stime']

            if offer_key is None:
                self.socket.close()
                return

            offer_transaction_id = struct.unpack('!I', offer_msg[4:8])[0]
            print("Received DHCP offer from {} (transaction ID: {})".format(server_address[0], offer_transaction_id))

            self.client_ip = socket.inet_ntoa(offer_packet[16:20])
            self.server_ip = socket.inet_ntoa(offer_packet[20:24])

            # 3. DHCP Client -> DHCP Request -> DHCP Server
            ## 3-1. Send DHCP request packet to server
            self.time_dict['request_packet_generate_stime'] = time.time()
            request_packet = self.create_dhcp_request_packet(
                    transaction_id, 
                    obtained_ip=self.client_ip,
                    server_ip=self.server_ip,
                    )
            self.time_dict['request_packet_generate_etime'] = time.time()
            self.time_dict['request_packet_generate_time'] = self.time_dict['request_packet_generate_etime'] - self.time_dict['request_packet_generate_stime'] 
            self.length_dict['request_packet'] = len(request_packet)
            self.socket.sendto(request_packet, (self.server_ip, self.server_port))
            print("DHCP request sent")

            # 4. DHCP Client <= DHCP Ack <- DHCP Server

            ## 4-1. Receive DHCP ACK packet from server

            ack_packet, server_address = self.socket.recvfrom(self.msg_buffer_size)

            self.time_dict['ack_packet_split_stime'] = time.time()
            ack_msg, ack_options, ack_options_dict, ack_signature = self.split_received_packet(ack_packet)
            ack_certificate = ack_options_dict.get(90, None)
            self.time_dict['ack_packet_split_etime'] = time.time()
            self.time_dict['ack_packet_split_time'] = self.time_dict['ack_packet_split_etime'] - self.time_dict['ack_packet_split_stime']
            self.length_dict['ack_packet'] = len(ack_packet)

            ## 4-2. Verify the validity of the ack certificate using the CA's certificate (public key). 
            self.time_dict['ack_cert_verify_stime'] = time.time()
            ack_certificate = self.verify_certificate(ack_certificate)
            self.time_dict['ack_cert_verify_etime'] = time.time()
            self.time_dict['ack_cert_verify_time'] = self.time_dict['ack_cert_verify_etime'] - self.time_dict['ack_cert_verify_stime']

            if ack_certificate is None:
                self.socket.close()
                return

            ## 4-3. Verify the authenticity of the ack packet using the server's certificate (public key)..
            self.time_dict['ack_sign_verify_stime'] = time.time()
            ack_key = self.verify_packet(ack_certificate, ack_signature, ack_msg+ack_options)
            self.time_dict['ack_sign_verify_etime'] = time.time()
            self.time_dict['ack_sign_verify_time'] = self.time_dict['ack_sign_verify_etime'] - self.time_dict['ack_sign_verify_stime']

            if ack_key is None:
                self.socket.close()
                return

            ack_transaction_id = struct.unpack('!I', ack_packet[4:8])[0]
            print("Received DHCP ACK from {} (transaction ID: {})".format(server_address[0], ack_transaction_id))
            print('='*50)

            # Extract assigned IP address from ACK packet
            self.client_ip = socket.inet_ntoa(ack_packet[16:20])
            self.server_ip = socket.inet_ntoa(ack_packet[20:24])
            self.subnet_mask = '.'.join([str(val) for val in ack_options_dict[1]])
            self.router_ip = '.'.join([str(val) for val in ack_options_dict[3]])
            self.dns_server_ip = '.'.join([str(val) for val in ack_options_dict[6]])
            print("Assigned IP address: {}".format(self.client_ip))
            print("Server IP address: {}".format(self.server_ip))
            print("Subnet mask: {}".format(self.subnet_mask))
            print("Router IP address: {}".format(self.router_ip))
            print("DNS server IP address: {}".format(self.dns_server_ip))
            print('='*50)

            print('Discover packet length: {}'.format(self.length_dict['discover_packet']))
            print('Discover packet generate time: {}'.format(self.time_dict['discover_packet_generate_time']))
            print('Offer packet length: {}'.format(self.length_dict['offer_packet']))
            print('Offer packet split time: {}'.format(self.time_dict['offer_packet_split_time']))
            print('Offer cert verify time: {}'.format(self.time_dict['offer_cert_verify_time']))
            print('Offer sign verify time: {}'.format(self.time_dict['offer_sign_verify_time']))
            print('Request packet length: {}'.format(self.length_dict['request_packet']))
            print('Request packet generate time: {}'.format(self.time_dict['request_packet_generate_time']))
            print('ACK packet length: {}'.format(self.length_dict['ack_packet']))
            print('ACK packet split time: {}'.format(self.time_dict['ack_packet_split_time']))
            print('ACK cert verify time: {}'.format(self.time_dict['ack_cert_verify_time']))
            print('ACK sign verify time: {}'.format(self.time_dict['ack_sign_verify_time']))
            print('='*50)

        except socket.timeout:
            print("No response received from DHCP server")

        self.stop()

        self.time_dict = {k:v for k,v in self.time_dict.items() if 'stime' not in k and 'etime' not in k}
        return self.length_dict, self.time_dict

    def stop(self):
        if self.socket:
            self.socket.close()



if __name__ == '__main__':
    server_ip = '<broadcast>'
    ca_asset_dir = 'certificates/rootCA/2048'
    ca_asset_name = 'rootCA'
    my_asset_dir = None 
    my_asset_name = None 
    client = DHCPClient(
            server_ip=server_ip,
            ca_asset_dir=ca_asset_dir,
            ca_asset_name=ca_asset_name,
            my_asset_dir=my_asset_dir,
            my_asset_name=my_asset_name,
            )
    length_dict, time_dict = client.start()
