import socket
import struct


class DHCPClient:
    def __init__(self, server_ip, server_port=67, client_port=68):
        self.server_ip = server_ip
        self.server_port = server_port
        self.client_port = client_port 
        self.client_socket = None

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

        # DHCP options
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

        # DHCP options
        packet += b'\x35\x01\x03'  # Option 53 (DHCP message type) - DHCP Request
        packet += b'\x32\x04' + server_ip  # Option 50 (Requested IP address)
        packet += b'\xff'  # End of options

        return packet

    def start(self):
        # Create a socket
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        # self.client_socket.bind(('0.0.0.0', self.client_port))
        # self.client_socket.settimeout(5)

        print("DHCP client started")

        # Generate a random transaction ID
        transaction_id = 123456

        # Send DHCP discover packet
        discover_packet = self.create_dhcp_discover_packet(transaction_id)
        self.client_socket.sendto(discover_packet, (self.server_ip, self.server_port))

        print("DHCP discover sent")

        try:
            # Receive DHCP offer packet from server
            offer_packet, server_address = self.client_socket.recvfrom(1024)
            transaction_id = struct.unpack('!I', offer_packet[4:8])[0]

            print("Received DHCP offer from {} (transaction ID: {})".format(server_address[0], transaction_id))

            # Extract server IP address from offer packet
            server_ip = offer_packet[20:24]
            import ipdb; ipdb.set_trace(context=25)

            # Send DHCP request packet
            request_packet = self.create_dhcp_request_packet(transaction_id, server_ip)
            self.client_socket.sendto(request_packet, (self.server_ip, self.server_port))

            print("DHCP request sent")

            # Receive DHCP ACK packet from server
            ack_packet, server_address = self.client_socket.recvfrom(1024)
            transaction_id = struct.unpack('!I', ack_packet[4:8])[0]

            print("Received DHCP ACK from {} (transaction ID: {})".format(server_address[0], transaction_id))

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
