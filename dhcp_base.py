import socket
import struct
import getmac
import pathlib
from OpenSSL import crypto


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
        self.cert_root = pathlib.Path(cert_root)
        self.magic_cookie = magic_cookie

        self.my_cert_packet = None
        self.cert_store = None

    def load_certificate(self, cert_data):
        if isinstance(cert_data, (pathlib.PosixPath)):
            with open(cert_data, 'rb') as ca_file:
                cert_data = ca_file.read()

        if isinstance(cert_data, (bytes,)):
            cert_data = crypto.load_certificate(crypto.FILETYPE_PEM, cert_data)

        if isinstance(cert_data, crypto.X509):
            pass

        return cert_data

    def verify_certificate(self, certificate):
        if certificate is None:
            print("No certificate is received")
            return None

        certificate = self.load_certificate(certificate)

        # Create a context with the certificate store
        context = crypto.X509StoreContext(self.cert_store, certificate)

        try:
            context.verify_certificate()
            print("Server certificate is valid.")
            return certificate 
        except crypto.X509StoreContextError as e:
            print("Server certificate verification failed:", e)
            return None 

    def verify_packet(self, certificate, signature, packet):
        if not crypto.verify(certificate, signature, packet, 'sha256'):
            print("Packet verification succeeded.")
            return certificate.get_pubkey()
        else:
            print("Packet verification failed.")
            return None

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
            add_certificate=False,
            ):

        packet = b''

        for tag, length, values in triplets:
            packet += struct.pack('!1B', tag)
            packet += struct.pack('!1B', length)
            packet += struct.pack(f'!{length}B', *values)

        if add_certificate:
            assert self.my_cert_packet is not None
            packet += self.my_cert_packet

        packet += struct.pack('!1B', 255)

        return packet

    def split_received_packet(self, packet):
        msg, others = packet[:self.msg_cutoff], packet[self.msg_cutoff:]
        option_cutoff = others.find(b'\xff')
        options = others[:option_cutoff+1]
        signature = others[option_cutoff+1:]
        return msg, options, signature

    def parse_one_options(self, options):
        if options == b'\xff':
            tag = length = values = others = None
        else:
            idx = 0
            tag = struct.unpack('!1B', options[idx:idx+1])[0]
            idx += 1

            if tag == 90:
                length = struct.unpack('!I', options[idx:idx+4])[0]
                idx += 4

                values = options[idx:idx+length]
            else:
                length = struct.unpack('!1B', options[idx:idx+1])[0]
                idx += 1

                values = struct.unpack(f'!{length}B', options[idx:idx+length])

            others = options[idx+length:]
        return tag, length, values, others

    def parse_all_options(self, options):
        options_dict = {}

        while True:
            tag, length, values, options = self.parse_one_options(options)
            if tag:
                options_dict[tag] = values
            else:
                break

        return options_dict

