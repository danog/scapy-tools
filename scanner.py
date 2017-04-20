import socket
import sys
import struct
from random import randint

class IPConstants:
    # IP version
    VERSION_IPv4 = 4
    VERSION_ST_DATAGRAM = 5
    VERSION_IPv6 = 6

    # TOS Precedence
    TOS_PRECEDENCE_ROUTINE = 0
    TOS_PRECEDENCE_PRIORITY = 1
    TOS_PRECEDENCE_IMMEDIATE = 2
    TOS_PRECEDENCE_FLASH = 3
    TOS_PRECEDENCE_FLASH_OVERRIDE = 4
    TOS_PRECEDENCE_CRITIC = 5
    TOS_PRECEDENCE_INTERNETWORK_CONTROL = 6
    TOS_PRECEDENCE_NETWORK_CONTROL = 7
    
    # TOS delay
    TOS_DELAY_NORMAL = 0
    TOS_DELAY_LOW = 1
    
    # TOS throughput
    TOS_TROUGHPUT_NORMAL = 0
    TOS_TROUGHPUT_HIGH = 1

    # TOS relibility
    TOS_RELIBILITY_NORMAL = 0
    TOS_RELIBILITY_HIGH = 1


    # reserved flag
    FLAGS_RESERVED = 0

    # DF flag
    FLAGS_DF_MAY_FRAGMENT = 0
    FLAGS_DF_DO_NOT_FRAGMENT = 1

    # LF flag
    FLAGS_LF_LAST_FRAGMENT = 0
    FLAGS_LF_MORE_FRAGMENTS = 1

    # Protocol number
    PROTOCOL_HOPOPT = 0
    PROTOCOL_ICMP = 1
    PROTOCOL_IGMP = 2
    PROTOCOL_GGP = 3
    PROTOCOL_IP_in_IP = 4
    PROTOCOL_ST = 5
    PROTOCOL_TCP = 6
    PROTOCOL_CBT = 7
    PROTOCOL_EGP = 8
    PROTOCOL_IGP = 9
    PROTOCOL_BBN_RCC_MON = 10
    PROTOCOL_NVP_II = 11
    PROTOCOL_PUP = 12
    PROTOCOL_ARGUS = 13
    PROTOCOL_EMCON = 14
    PROTOCOL_XNET = 15
    PROTOCOL_CHAOS = 16
    PROTOCOL_UDP = 17
    PROTOCOL_MUX = 18
    PROTOCOL_DCN_MEAS = 19
    PROTOCOL_HMP = 20
    PROTOCOL_PRM = 21
    PROTOCOL_XNS_IDP = 22
    PROTOCOL_TRUNK_1 = 23
    PROTOCOL_TRUNK_2 = 24
    PROTOCOL_LEAF_1 = 25
    PROTOCOL_LEAF_2 = 26
    PROTOCOL_RDP = 27
    PROTOCOL_IRTP = 28
    PROTOCOL_ISO_TP4 = 29
    PROTOCOL_NETBLT = 30
    PROTOCOL_MFE_NSP = 31
    PROTOCOL_MERIT_INP = 32
    PROTOCOL_DCCP = 33
    PROTOCOL_3PC = 34
    PROTOCOL_IDPR = 35
    PROTOCOL_XTP = 36
    PROTOCOL_DDP = 37
    PROTOCOL_IDPR_CMTP = 38
    PROTOCOL_TP_PLUS_PLUS = 39
    PROTOCOL_IL = 40
    PROTOCOL_IPv6 = 41
    PROTOCOL_SDRP = 42
    PROTOCOL_IPv6_Route = 43
    PROTOCOL_IPv6_Frag = 44
    PROTOCOL_IDRP = 45
    PROTOCOL_RSVP = 46
    PROTOCOL_GRE = 47
    PROTOCOL_DSR = 48
    PROTOCOL_BNA = 49
    PROTOCOL_ESP = 50
    PROTOCOL_AH = 51
    PROTOCOL_I_NLSP = 52
    PROTOCOL_SWIPE = 53
    PROTOCOL_NARP = 54
    PROTOCOL_MOBILE = 55
    PROTOCOL_TLSP = 56
    PROTOCOL_SKIP = 57
    PROTOCOL_IPv6_ICMP = 58
    PROTOCOL_IPv6_NoNxt = 59
    PROTOCOL_IPv6_Opts = 60
    PROTOCOL_Any = 61
    PROTOCOL_CFTP = 62
    PROTOCOL_Any = 63
    PROTOCOL_SAT_EXPAK = 64
    PROTOCOL_KRYPTOLAN = 65
    PROTOCOL_RVD = 66
    PROTOCOL_IPPC = 67
    PROTOCOL_Any = 68
    PROTOCOL_SAT_MON = 69
    PROTOCOL_VISA = 70
    PROTOCOL_IPCU = 71
    PROTOCOL_CPNX = 72
    PROTOCOL_CPHB = 73
    PROTOCOL_WSN = 74
    PROTOCOL_PVP = 75
    PROTOCOL_BR_SAT_MON = 76
    PROTOCOL_SUN_ND = 77
    PROTOCOL_WB_MON = 78
    PROTOCOL_WB_EXPAK = 79
    PROTOCOL_ISO_IP = 80
    PROTOCOL_VMTP = 81
    PROTOCOL_SECURE_VMTP = 82
    PROTOCOL_VINES = 83
    PROTOCOL_TTP = 84
    PROTOCOL_IPTM = 84
    PROTOCOL_NSFNET_IGP = 85
    PROTOCOL_DGP = 86
    PROTOCOL_TCF = 87
    PROTOCOL_EIGRP = 88
    PROTOCOL_OSPF = 89
    PROTOCOL_Sprite_RPC = 90
    PROTOCOL_LARP = 91
    PROTOCOL_MTP = 92
    PROTOCOL_AX_25 = 93
    PROTOCOL_OS = 94
    PROTOCOL_MICP = 95
    PROTOCOL_SCC_SP = 96
    PROTOCOL_ETHERIP = 97
    PROTOCOL_ENCAP = 98
    PROTOCOL_Any = 99
    PROTOCOL_GMTP = 100
    PROTOCOL_IFMP = 101
    PROTOCOL_PNNI = 102
    PROTOCOL_PIM = 103
    PROTOCOL_ARIS = 104
    PROTOCOL_SCPS = 105
    PROTOCOL_QNX = 106
    PROTOCOL_A_N = 107
    PROTOCOL_IPComp = 108
    PROTOCOL_SNP = 109
    PROTOCOL_Compaq_Peer = 110
    PROTOCOL_IPX_in_IP = 111
    PROTOCOL_VRRP = 112
    PROTOCOL_PGM = 113
    PROTOCOL_Any = 114
    PROTOCOL_L2TP = 115
    PROTOCOL_DDX = 116
    PROTOCOL_IATP = 117
    PROTOCOL_STP = 118
    PROTOCOL_SRP = 119
    PROTOCOL_UTI = 120
    PROTOCOL_SMP = 121
    PROTOCOL_SM = 122
    PROTOCOL_PTP = 123
    PROTOCOL_IS_IS = 124
    PROTOCOL_FIRE = 125
    PROTOCOL_CRTP = 126
    PROTOCOL_CRUDP = 127
    PROTOCOL_SSCOPMCE = 128
    PROTOCOL_IPLT = 129
    PROTOCOL_SPS = 130
    PROTOCOL_PIPE = 131
    PROTOCOL_SCTP = 132
    PROTOCOL_FC = 133
    PROTOCOL_RSVP_E2E_IGNORE = 134
    PROTOCOL_Mobility = 135
    PROTOCOL_UDPLite = 136
    PROTOCOL_MPLS_in_IP = 137
    PROTOCOL_manet = 138
    PROTOCOL_HIP = 139
    PROTOCOL_Shim6 = 140
    PROTOCOL_WESP = 141
    PROTOCOL_ROHC = 142


    # Keys
    TOS_PRECEDENCE = 0
    TOS_DELAY = 1
    TOS_THROUGHPUT = 2
    TOS_RELIBILITY = 3

    FLAGS_DF = 1
    FLAGS_LF = 2

    # Defaults
    DEFAULT_VERSION = VERSION_IPv4
    DEFAULT_TOS = {TOS_PRECEDENCE: TOS_PRECEDENCE_ROUTINE, TOS_DELAY: TOS_DELAY_NORMAL, TOS_THROUGHPUT: TOS_TROUGHPUT_NORMAL, TOS_RELIBILITY: TOS_RELIBILITY_NORMAL}
    DEFAULT_FLAGS = {FLAGS_RESERVED: FLAGS_RESERVED, FLAGS_DF: FLAGS_DF_MAY_FRAGMENT, FLAGS_LF: FLAGS_LF_LAST_FRAGMENT}
    DEFAULT_TTL = 255
    DEFAULT_PROTOCOL = PROTOCOL_ICMP

class IPPacket:
    version = IPConstants.DEFAULT_VERSION
    # TOS IS OUTDATED; MUST UPDATE TO RFC 2474
    tos = IPConstants.DEFAULT_TOS
    identification = randint(0, 65535)
    flags = IPConstants.DEFAULT_FLAGS
    fragment_offset = 0
    ttl = IPConstants.DEFAULT_TTL
    protocol = IPConstants.DEFAULT_PROTOCOL
    checksum = -1
    source_address = 0
    destination_address = 0
    options = {}
    options_length = 0
    data = b''

    def check_int(self, number, bitnumber):
        if (number < 0 or number > 2**bitnumber-1):
            raise ValueError('Invalid value provided!')

    # Setters

    def set_version(self, version):
        self.check_int(version, 4)
        self.version = version
        return version
        
    def set_tos(self, tos):
        default_tos = IPConstants.DEFAULT_TOS
        default_tos.update(tos)
        for key, item in default_tos:
            if key == IPConstants.TOS_PRECEDENCE:
                if item < 0 or item > 7:
                    raise ValueError('Invalid precedence!')
            elif key == IPConstants.TOS_DELAY:
                if item < 0 or item > 1:
                    raise ValueError('Invalid delay!')
            elif key == IPConstants.TOS_THROUGHPUT:
                if item < 0 or item > 1:
                    raise ValueError('Invalid throughput!')
            elif key == IPConstants.TOS_RELIBILITY:
                if item < 0 or item > 1:
                    raise ValueError('Invalid relibility!')
            else:
                raise ValueError('Invalid key '+key+' in TOS dictionary!')

        self.tos = default_tos
        return self.tos

    def set_identification(self, identification=-1):
        if identification == -1: identification = randint(0, 65535)
        self.check_int(identification, 16)
        self.identification = identification
        return identification

    def set_flags(self, flags):
        default_flags = IPConstants.DEFAULT_FLAGS
        default_flags.update(flags)
        for key, item in default_flags:
            if key == IPConstants.FLAGS_RESERVED:
                if item != IPConstants.FLAGS_RESERVED:
                    raise ValueError('Invalid reserved flag!')
            elif key == IPConstants.FLAGS_DF:
                if item < 0 or item > 1:
                    raise ValueError('Invalid DF!')
            elif key == IPConstants.FLAGS_LF:
                if item < 0 or item > 1:
                    raise ValueError('Invalid LF!')
            else:
                raise ValueError('Invalid key '+key+' in TOS dictionary!')

        self.flags = default_flags
        return self.flags
    
    def set_fragment_offset(self, fragment_offset):
        self.check_int(fragment_offset, 13)
        self.fragment_offset = fragment_offset
        return self.fragment_offset

    def set_ttl(self, ttl):
        self.check_int(ttl, 8)
        self.ttl = ttl
        return self.ttl

    def set_protocol(self, protocol):
        self.check_int(protocol, 8)
        self.protocol = protocol
        return self.protocol

    def set_source_address(self, source_address):
        if isinstance(source_address, basestring):
            source_address = self.ip2long(source_address)
        self.check_int(source_address, 32)
        self.source_address = source_address
        return self.source_address

    def set_destination_address(self, destination_address):
        if isinstance(destination_address, basestring):
            destination_address = self.ip2long(destination_address)

        self.check_int(destination_address, 32)
        self.destination_address = destination_address
        return self.destination_address

    def set_data(self, data):
        self.data = data
    # Userspace getters

    def get_version(self):
        return self.version

    def get_ihl(self):
        length = self.get_bit_length()
        if length % 32:
            raise ValueError('IHL is not divisible by 32!')
        length /= 32
        if length < 5:
            raise ValueError('IHL smaller than 5!')
        if length > 15:
            raise ValueError('IHL bigger than 15!')
        
        return length

    def get_tos(self):
        return self.tos

    def get_total_length(self):
        total_length = self.get_bit_length() + len(data)*8
        if total_length % 8:
            raise ValueError('Length is not divisible by 8!')

        total_length /= 8
        if total_length > 65535:
            raise ValueError('Length is too big, will have to fragmentate!')

        return total_length

    def get_identification(self):
        return self.identification

    def get_flags(self):
        return self.flags

    def get_fragment_offset(self):
        return self.fragment_offset

    def get_ttl(self):
        return self.fragment_offset

    def get_protocol(self):
        return self.protocol

    def get_checksum(self, msg=''):
        if (len(msg)):
            s = 0
            for i in range(0, len(msg), 2):
                w = (ord(msg[i]) << 8) + (ord(msg[i + 1]))
                s = s + w

            s = (s >> 16) + (s & 0xffff)
            s = ~s & 0xffff

            return s

        return self.checksum

    def get_source_address(self):
        return self.source_address
        
    def get_destination_address(self):
        return self.destination_address
    def get_data(self):
        return self.data

    # Internal getters
    def ip2long(self, ip):
        """
        Convert an IP string to long
        """
        packedIP = socket.inet_aton(ip)
        return struct.unpack("!L", packedIP)[0]

    def get_bit_length(self): # without the data 
        return (
            4  + # version
            4  + # ihl
            8  + # tos
            16 + # total length
            16 + # identification
            3  + # flags
            13 + # fragment offset
            8  + # ttl
            8  + # protocol
            16 + # checksum
            32 + # source address
            32 + # destination address
            self.options_length
        )

    def get_version_and_ihl(self):
        return (self.get_version() << 4) | self.get_ihl()

    def get_byte_tos(self):
        return (self.tos[IPConstants.TOS_PRECEDENCE] << 5) | (self.tos[IPConstants.TOS_DELAY] << 4) | (self.tos[IPConstants.TOS_THROUGHPUT] << 3) | (self.tos[IPConstants.TOS_RELIBILITY] << 2)
    
    def get_byte_flags(self):
        return (self.flags[IPConstants.FLAGS_RESERVED] << 7) | (self.flags[IPConstants.FLAGS_DF] << 6) | (self.flags[IPConstants.FLAGS_LF] << 5)
    
    def get_flags_and_fragment_offset(self):
        return (self.get_byte_flags() << 13) | self.get_fragment_offset()


    def create_socket(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, self.get_protocol())
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

packet = IPPacket()
packet.set_identification()
packet.set_ttl(255)
packet.set_protocol(IPConstants.PROTOCOL_ICMP)
packet.set_source_address([l for l in ([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")][:1], [[(s.connect(('8.8.8.8', 53)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]]) if l][0][0])
packet.set_destination_address(socket.gethostbyname(sys.argv[1]))

# scapy

# Header is type (8), code (8), checksum (16), id (16), sequence (16)
checksum = 0

# Make a dummy header with a 0 checksum.
header = struct.pack(
	"!BBHHH", 8, 0, checksum, 1, 1
)
padBytes = []
startVal = 0x42
for i in range(startVal, startVal + (self.packet_size)):
	padBytes += [(i & 0xff)]  # Keep chars in the 0-255 range
data = bytes(padBytes)

# Calculate the checksum on the data and the dummy header.
checksum = packet.get_checksum(header + data) # Checksum is in network order
# Now that we have the right checksum, we put that in. It's just easier
# to make up a new header than to stuff it into the dummy.
header = struct.pack(
	   "!BBHHH", ICMP_ECHO, 0, checksum, 1, 1
)
packet.set_data(header + data)

# now start constructing the packet
packet = ''


version = 4 # IPv4
ihl = 5 # Length of header in 32 bit words, alias divide this by 4 to get the length in bytes
tos = 0 # Type of service
tot_len = ihl*4 
id = 54321
frag_off = 0
ttl = 255
protocol = socket.IPPROTO_TCP
check = 10  # python seems to correctly fill the checksum
# Spoof the source ip address if you want to
saddr = socket.inet_aton(source_ip)
daddr = socket.inet_aton(dest_ip)

ihl_version = (version << 4) + ihl

# the ! in the pack format string means network order
ip_header = pack('!BBHHHBBH4s4s', ihl_version, tos, tot_len,
                 id, frag_off, ttl, protocol, check, saddr, daddr)

# tcp header fields
source = 1234   # source port
dest = 80   # destination port
seq = 0
ack_seq = 0
doff = 5  # 4 bit field, size of tcp header, 5 * 4 = 20 bytes
# tcp flags
fin = 0
syn = 1
rst = 0
psh = 0
ack = 0
urg = 0
window = socket.htons(5840)  # maximum allowed window size
check = 0
urg_ptr = 0

offset_res = (doff << 4) + 0
tcp_flags = fin + (syn << 1) + (rst << 2) + \
    (psh << 3) + (ack << 4) + (urg << 5)

# the ! in the pack format string means network order
tcp_header = pack('!HHLLBBHHH', source, dest, seq, ack_seq,
                  offset_res, tcp_flags,  window, check, urg_ptr)

# pseudo header fields
source_address = socket.inet_aton(source_ip)
dest_address = socket.inet_aton(dest_ip)
placeholder = 0
protocol = socket.IPPROTO_TCP
tcp_length = len(tcp_header)

psh = pack('!4s4sBBH', source_address, dest_address,
           placeholder, protocol, tcp_length)
psh = psh + tcp_header

tcp_checksum = checksum(psh)

# make the tcp header again and fill the correct checksum
tcp_header = pack('!HHLLBBHHH', source, dest, seq, ack_seq,
                  offset_res, tcp_flags,  window, tcp_checksum, urg_ptr)

# final full packet - syn packets dont have any data
packet = ip_header + tcp_header

# Send the packet finally - the port specified has no effect
# put this in a loop if you want to flood the target
s.sendto(packet, (dest_ip, 0))
