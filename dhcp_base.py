import socket
import struct
import getmac
import pathlib

from OpenSSL import crypto
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

class DHCPBase:
    def __init__(
            self, 
            server_ip=None,
            server_port=67,
            client_port=68,
            msg_cutoff=240,
            cert_max_size=2048,
            cert_root=None,
            my_cert_name=None,
            my_key_name=None,
            trusted_cert_name=None,
            magic_cookie=b'\x63\x82\x53\x63',
            ):

        self.server_ip = server_ip
        self.server_port = server_port
        self.client_port = client_port 
        self.cert_max_size = cert_max_size
        self.msg_cutoff = msg_cutoff
        self.magic_cookie = magic_cookie

        self.my_haddr = getmac.get_mac_address().replace(':', '')

        if cert_root is not None:
            self.cert_root = pathlib.Path(cert_root)

            if my_key_name is not None:
                self.my_private_key = self.load_private_key(self.cert_root / my_key_name)
            else:
                self.my_private_key = None

            if my_cert_name is not None:
                self.my_cert = self.load_certificate(self.cert_root / my_cert_name)
                self.my_dhcp_auth_packet = self.create_dhcp_auth_packet(self.my_cert)
            else:
                self.my_cert = None
                self.my_dhcp_auth_packet = None 

            if trusted_cert_name is not None:
                self.trusted_cert = self.load_certificate(self.cert_root / trusted_cert_name)
            else:
                self.trusted_cert = None

        self.cert_store = crypto.X509Store()
        if self.trusted_cert is not None:
            self.cert_store.add_cert(self.trusted_cert)

    def load_private_key(self, path, password=None):
        if password is not None:
            password = password.encode('utf-8') 

        try:
            with open(path, 'rb') as key:
                key_data = key.read()
                private_key = serialization.load_pem_private_key(key_data, password=password)
        except Exception as e:
            print(e)
            private_key = None

        return private_key

    def sign_message(self, message, private_key):
        assert private_key is not None
        signature = private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())
        return signature

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

    def create_dhcp_auth_packet(self, certificate):
        assert isinstance(certificate, crypto.X509)
        cert_data = crypto.dump_certificate(crypto.FILETYPE_PEM, certificate)

        packet = b''
        packet += struct.pack('!1B', 90)
        packet += struct.pack('!I', len(cert_data))
        packet += cert_data 

        return packet

    def create_dhcp_option_packet(
            self,
            *triplets,
            add_certificate=False,
            ):

        packet = b''

        for tag, length, values in triplets:
            packet += struct.pack('!1B', tag)
            packet += struct.pack('!1I', length)
            packet += struct.pack(f'!{length}B', *values)

        if add_certificate:
            assert self.my_dhcp_auth_packet is not None
            packet += self.my_dhcp_auth_packet

        packet += struct.pack('!1B', 255)

        return packet

    def split_received_packet(self, packet):
        msg, others = packet[:self.msg_cutoff], packet[self.msg_cutoff:]
        options, options_dict, signature = self.parse_all_options(others)
        return msg, options, options_dict, signature

    def parse_one_options(self, options):
        if options[:1] == b'\xff':
            tag = length = values = None
            others = options[1:]
            return tag, length, values, others

        else:
            idx = 0

            tag = struct.unpack('!1B', options[idx:idx+1])[0]
            idx += 1

            length = struct.unpack('!I', options[idx:idx+4])[0]
            idx += 4

            values = options[idx:idx+length]
            if tag != 90:
                values = struct.unpack(f'!{length}B', values)

            others = options[idx+length:]
        return tag, length, values, others

    def parse_all_options(self, options):
        options_dict = {}

        others = options
        while True:
            tag, length, values, others = self.parse_one_options(others)
            if tag:
                options_dict[tag] = values
            else:
                break

        cutoff = options.index(others)
        return options[:cutoff], options_dict, options[cutoff:]
