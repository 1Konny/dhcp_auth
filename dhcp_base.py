import socket
import struct
from pathlib import Path
import getmac


class DHCPBase:
    def __init__(
            self, 
            server_ip=None,
            server_port=67,
            client_port=68,
            cert_max_size=2048,
            msg_cutoff=240,
            cert_root='certificates',
            magic_cookie=b'\x63\x82\x53\x63',
            ):

        self.server_ip = server_ip
        self.server_port = server_port
        self.client_port = client_port 
        self.cert_max_size = cert_max_size
        self.msg_cutoff = msg_cutoff
        self.cert_root = Path(cert_root)
        self.magic_cookie = magic_cookie

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

        # References
        # 1. https://techhub.hpe.com/eginfolib/networking/docs/switches/5120si/cg/5998-8491_l3-ip-svcs_cg/content/436042653.htm
        # 2. http://www.tcpipguide.com/free/t_DHCPMessageFormat.htm
        # 3. https://en.wikipedia.org/wiki/Dynamic_Host_Configuration_Protocol
        # 4. http://www.ktword.co.kr/test/view/view.php?m_temp1=1925

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

    def split_received_packet(self, packet):
        msg, others = packet[:self.msg_cutoff], packet[self.msg_cutoff:]
        option_cutoff = others.find(b'\xff')
        options, signature = others[:option_cutoff+1], others[option_cutoff+1:]
        return msg, options, signature
