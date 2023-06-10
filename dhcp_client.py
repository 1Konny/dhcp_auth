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
        # Create the DHCP discover msg 
        dhcp_msg = self.create_dhcp_msg_packet(
                op=1,
                transaction_id=transaction_id,
                chaddr=self.my_haddr,
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
                chaddr=self.my_haddr,
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
            offer_msg, offer_options, offer_signature = self.split_received_packet(offer_packet)
            offer_options_dict = self.parse_all_options(offer_options)

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

            #transaction_id = struct.unpack('!I', offer_msg[4:8])[0]
            offer_transaction_id = struct.unpack('!I', offer_msg[4:8])[0]
            print("Received DHCP offer from {} (transaction ID: {})".format(server_address[0], offer_transaction_id))

            # 3. DHCP Client -> DHCP Request -> DHCP Server
            ## 3-1. Send DHCP request packet to server
            request_packet = self.create_dhcp_request_packet(
                    transaction_id, 
                    # offer_packet[20:24],
                    socket.inet_ntoa(offer_packet[20:24]),
                    )
            self.socket.sendto(request_packet, (self.server_ip, self.server_port))
            print("DHCP request sent")

            # 4. DHCP Client <= DHCP Ack <- DHCP Server

            ## 4-1. Receive DHCP ACK packet from server
            ack_packet, server_address = self.socket.recvfrom(2048)
            ack_msg, ack_options, ack_signature = self.split_received_packet(ack_packet)
            ack_options_dict = self.parse_all_options(ack_options)

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
            assigned_ip = socket.inet_ntoa(ack_packet[16:20])
            print("Assigned IP address: {}".format(assigned_ip))

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
