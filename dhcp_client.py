import socket
import struct

from dhcp_base import DHCPBase


class DHCPClient(DHCPBase):
    def __init__(
            self, 
            server_ip,
            cert_root,
            client_key_name,
            ca_cert_name,
            ):
        super().__init__(
                server_ip=server_ip,
                cert_root=cert_root,
                my_key_name=client_key_name,
                trusted_cert_name=ca_cert_name,
                )

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
        discover_packet = self.create_dhcp_discover_packet(transaction_id)
        self.socket.sendto(discover_packet, (self.server_ip, self.server_port))

        print("DHCP discover sent")

        try:
            # 2. DHCP Client <- DHCP Offer <- DHCP Server

            ## 2-1. Receive DHCP offer packet from server
            offer_packet, server_address = self.socket.recvfrom(2048)
            offer_msg, offer_options, offer_options_dict, offer_signature = self.split_received_packet(offer_packet)

            ## 2-2. Verify the validity of the offer certificate using the CA's certificate (public key). 
            offer_certificate = offer_options_dict.get(90, None)
            offer_certificate = self.verify_certificate(offer_certificate)

            if offer_certificate is None:
                self.socket.close()
                return

            ## 2-3. Verify the authenticity of the offer packet using the server's certificate (public key)..
            offer_key = self.verify_packet(offer_certificate, offer_signature, offer_msg+offer_options)

            if offer_key is None:
                self.socket.close()
                return

            offer_transaction_id = struct.unpack('!I', offer_msg[4:8])[0]
            print("Received DHCP offer from {} (transaction ID: {})".format(server_address[0], offer_transaction_id))

            self.client_ip = socket.inet_ntoa(offer_packet[16:20])
            self.server_ip = socket.inet_ntoa(offer_packet[20:24])

            # 3. DHCP Client -> DHCP Request -> DHCP Server
            ## 3-1. Send DHCP request packet to server
            request_packet = self.create_dhcp_request_packet(
                    transaction_id, 
                    obtained_ip=self.client_ip,
                    server_ip=self.server_ip,
                    )
            self.socket.sendto(request_packet, (self.server_ip, self.server_port))
            print("DHCP request sent")

            # 4. DHCP Client <= DHCP Ack <- DHCP Server

            ## 4-1. Receive DHCP ACK packet from server
            ack_packet, server_address = self.socket.recvfrom(2048)
            ack_msg, ack_options, ack_options_dict, ack_signature = self.split_received_packet(ack_packet)

            ## 4-2. Verify the validity of the ack certificate using the CA's certificate (public key). 
            ack_certificate = ack_options_dict.get(90, None)
            ack_certificate = self.verify_certificate(ack_certificate)

            if ack_certificate is None:
                self.socket.close()
                return

            ## 4-3. Verify the authenticity of the ack packet using the server's certificate (public key)..
            ack_key = self.verify_packet(ack_certificate, ack_signature, ack_msg+ack_options)

            if ack_key is None:
                self.socket.close()
                return

            ack_transaction_id = struct.unpack('!I', ack_packet[4:8])[0]
            print("Received DHCP ACK from {} (transaction ID: {})".format(server_address[0], ack_transaction_id))

            # Extract assigned IP address from ACK packet
            print('='*50)
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

        except socket.timeout:
            print("No response received from DHCP server")

        self.socket.close()


if __name__ == '__main__':
    server_ip = '<broadcast>'
    cert_root = 'certificates'
    ca_cert_name = 'rootCA.crt'
    client_key_name = None
    client = DHCPClient(
            server_ip=server_ip,
            cert_root=cert_root,
            ca_cert_name=ca_cert_name,
            client_key_name=client_key_name,
            )
    client.start()

