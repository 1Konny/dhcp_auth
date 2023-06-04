import socket
import struct


class DHCPServer:
    def __init__(self, server_ip, server_port=67, client_port=68):
        self.server_ip = server_ip
        self.server_port = server_port
        self.client_port = client_port 
        self.server_socket = None

    def create_dhcp_offer_packet(self, transaction_id, client_mac):
        # Create the DHCP offer packet
        packet = struct.pack('!4B', 2, 1, 6, 0)  # DHCP offer message type
        packet += struct.pack('!I', transaction_id)  # Transaction ID
        packet += b'\x80\x00\x00\x00'  # Flags
        packet += b'\x00\x00\x00\x00'  # Client IP address
        packet += socket.inet_aton('192.168.1.1')  # Your server IP address
        packet += b'\x00\x00\x00\x00'  # Next server IP address
        packet += socket.inet_aton('255.255.255.0')  # Subnet mask
        packet += socket.inet_aton('192.168.1.1')  # Router IP address
        packet += socket.inet_aton('192.168.1.1')  # DNS server IP address
        packet += b'\x00' * 192  # Padding
        packet += b'\x63\x82\x53\x63'  # Magic cookie

        # DHCP options
        packet += b'\x35\x01\x02'  # Option 53 (DHCP message type) - DHCP Offer
        packet += b'\x36\x04\xc0\xa8\x01\x01'  # Option 54 (DHCP server identifier)
        packet += b'\xff'  # End of options

        return packet

    def create_dhcp_ack_packet(self, transaction_id, client_mac):
        # Create the DHCP ACK packet
        packet = struct.pack('!4B', 2, 1, 6, 0)  # DHCP ACK message type
        packet += struct.pack('!I', transaction_id)  # Transaction ID
        packet += b'\x80\x00\x00\x00'  # Flags
        packet += socket.inet_aton('192.168.1.100')  # Assigned IP address
        packet += socket.inet_aton('192.168.1.1')  # Your server IP address
        packet += b'\x00\x00\x00\x00'  # Next server IP address
        packet += socket.inet_aton('255.255.255.0')  # Subnet mask
        packet += socket.inet_aton('192.168.1.1')  # Router IP address
        packet += socket.inet_aton('192.168.1.1')  # DNS server IP address
        packet += b'\x00' * 192  # Padding
        packet += b'\x63\x82\x53\x63'  # Magic cookie

        # DHCP options
        packet += b'\x35\x01\x05'  # Option 53 (DHCP message type) - DHCP ACK
        packet += b'\x36\x04\xc0\xa8\x01\x01'  # Option 54 (DHCP server identifier)
        packet += b'\xff'  # End of options

        return packet

    def start(self):
        # Create a socket and bind it to the DHCP server port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
        # self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST,1)
        self.server_socket.bind((self.server_ip, self.server_port))

        print("DHCP server started on {}:{}".format(self.server_ip, self.server_port))

        while True:
            # Receive DHCP discover packet from client
            data, address = self.server_socket.recvfrom(1024)
            transaction_id = struct.unpack('!I', data[4:8])[0]
            client_mac = ':'.join('{:02x}'.format(byte) for byte in data[28:34])

            print("Received DHCP discover from {} (transaction ID: {})".format(address[0], transaction_id))

            # Create and send DHCP offer packet to client
            offer_packet = self.create_dhcp_offer_packet(transaction_id, client_mac)
            self.server_socket.sendto(offer_packet, address)

            print("DHCP offer sent to {} (transaction ID: {})".format(address[0], transaction_id))

            # Receive DHCP request packet from client
            data, address = self.server_socket.recvfrom(1024)
            transaction_id = struct.unpack('!I', data[4:8])[0]
            client_mac = ':'.join('{:02x}'.format(byte) for byte in data[28:34])

            print("Received DHCP request from {} (transaction ID: {})".format(address[0], transaction_id))

            # Create and send DHCP ACK packet to client
            ack_packet = self.create_dhcp_ack_packet(transaction_id, client_mac)
            self.server_socket.sendto(ack_packet, address)

            print("DHCP ACK sent to {} (transaction ID: {})".format(address[0], transaction_id))

    def stop(self):
        if self.server_socket:
            self.server_socket.close()


if __name__ == '__main__':
    server_ip = ''
    server = DHCPServer(server_ip)
    server.start()

