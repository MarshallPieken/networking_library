"""
Purpose: Learning about ICMP packets, and learning how to carft payloads into them.
How: Manually crafting IP, ICMP and other packets. Detection of this could come from the length of it as a network traffic anomaly.

NOTE: Any Layer 2 or lower packet crafting does not work for Windows, thanks to its netowrking stack restrictions. 
I'll eventually build out a Scapy or C module to bypass those restrictions as well. In the meantime, Linux will process anything here.

Sources: 
- https://docs.python.org/3/library/socket.html
- https://inc0x0.com/tcp-ip-packets-introduction/tcp-ip-packets-3-manually-create-and-send-raw-tcp-ip-packets/
- https://inc0x0.com/icmp-ip-packets-ping-manually-create-and-send-icmp-ip-packets/
- https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml
- https://www.w3schools.com/python/python_class_methods.asp  
- https://www.geeksforgeeks.org/python/extend-class-method-in-python/
- https://www.scribd.com/doc/13628928/802-11-Protocol-Stack-and-Physical-Layer
- TCP: https://www.rfc-editor.org/info/rfc9293/ 
================================================================================================================================
Basic conversion from decimal -> hex -> binary                                                | 
----------------------------------------------------------------------------------------------|
Decimal:     0    1    2    3    4    5    6    7    8    9    10   11   12   13   14   15    |
Hexadecimal: 0    1    2    3    4    5    6    7    8    9    A    B    C    D    E    F     |
Binary:      0000 0001 0010 0011 0100 0101 0110 0111 1000 1001 1010 1011 1100 1101 1110 1111  |
================================================================================================================================
Worth noting for when I inevitably confuse myself again:                                            |
----------------------------------------------------------------------------------------------------|
hex:       E    8 <- each of these is a nibble (i.e., each hex character), & represents 4 bits.     |
binary:    1100 1000                                                                                |
----------------------------------------------------------------------------------------------------|

TODO:
- Eventually make a layer 4 TCP/IP header to append to the IP packet header 
    - (including self, sourcePort, destPort, tcpipSeqNum, ackNum, flags, windowSize, checksum, urgentPointer)
    - Also a checksum calculationmethod for this one
- Test/debug/fix this program
- Eventually add in other packet construction methods: 
    Layer 2 (Needs socket's AF_PACKET in a separate L2 packet carfting method)
    |- ethernet II (IEEE 802.1Q LAN): https://www.geeksforgeeks.org/computer-networks/ethernet-frame-format/, https://ieeexplore.ieee.org/browse/standards/get-program/page/series?id=68 
    |- VLAN (IEEE 802.1Q): https://en.wikipedia.org/wiki/IEEE_802.1Q, https://learningnetwork.cisco.com/s/question/0D56e0000EBtaQ9CQJ/ieee-8021q-vlan-tagging-and-trunking-in-networking, 
    layer 3
    |- ARP: https://en.wikipedia.org/wiki/Address_Resolution_Protocol, https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml 
    Layer 4 
    |- TCP (RFC 9293): https://www.ietf.org/rfc/rfc9293.html#name-header-format
    |- SCTP (9260): https://www.ietf.org/rfc/rfc9260.pdf

After all this is made in the next little while, we can move on to bluetooth, phone, etc.
Everything here could also be in an array adn you can index those array fields (owie, my brain!)
"""
import struct
from typing import override
import utils
from AbstractPacket import AbstractPacket

"""
Class IPheader: Constructs a user-defined IP packet header. 

-------------------------------------------------------------------------------------------------------------------
IP Header Construction
Bit
0   4   8    12   16   20   24   28   32
0100 0101 0000 0000 0000 0000 0001 1101  | Version (4), IHL (5), Type of Service (00), Total Length (00 1C)
1010 1011 1100 1101 0000 0000 0000 0000  | ID (AB CD), Flags (bits: 000), Fragment Offset (bits: 0 0000 0000 0000)
0100 0000 0000 0001 0000 0000 0000 0000  | TTL (40), Protocol (01), Header Checksum (?? ??)
1101 0000 0110 1000 1001 0010 1000 0011  | Source IP: C0 A8 92 83 (192.168.164.131)
0000 1000 0000 1000 0000 1000 0000 1000  | Destination IP: 08 08 08 08 (8.8.8.8)
-------------------------------------------------------------------------------------------------------------------
Sources:
- https://www.rfc-editor.org/info/rfc791/#section-3.1 
- https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
"""
class IPheader(AbstractPacket):
    def  __init__(self,
                    version: int, 
                    ihl: int, 
                    serviceType: int, 
                    id: int, 
                    flags: int, 
                    fragmentOffset: int, 
                    ttl: int, 
                    protocol: int, 
                    checksum: int, 
                    sourceAddr: str, 
                    destAddr: str,
                    payload = None):

        # Constructor
        self.version = version
        self.ihl = ihl
        self.serviceType = serviceType  
        self.id = id
        self.flags = flags
        self.fragmentOffset = fragmentOffset
        self.ttl = ttl
        self.protocol = protocol
        self.checksum = checksum
        self.sourceAddr = sourceAddr
        self.destAddr = destAddr
        self.payload = payload

    @override
    def build(self):

        if self.payload:
            raw_payload = self.payload.build()
        else:
            raw_payload = b''

        # Crafting the packet's ip header
        ip_header  = utils.int_to_byte((self.version << 4) + self.ihl, 1) # Since it's only 4 bits, bitwase operations to move it left 4 bits & add the 4-bit ihl as well to the same byte
        ip_header += utils.int_to_byte(self.serviceType, 1)
        ip_header += utils.int_to_byte(len(raw_payload) + 24, 2) # 24 bytes is IP header length
        ip_header += utils.int_to_byte(self.id, 2)
        ip_header += utils.int_to_byte(self.flags << 13 | self.fragmentOffset, 2)
        ip_header += utils.int_to_byte(self.ttl, 1)
        ip_header += utils.int_to_byte(self.protocol, 1)
        ip_header += utils.int_to_byte(self.checksum, 2)
        ip_header += utils.ipv4_to_byte_hex(self.sourceAddr)
        ip_header += utils.ipv4_to_byte_hex(self.destAddr)

        return ip_header

    def calc_ip_checksum(self, version, ihl, serviceType, length, id, flags, 
                        fragmentOffset, ttl, protocol, sourceAddr, destAddr):
        """
            out = calc_ip_checksum(4, 5, 0, 0x0028, 0xabcd, 0, 0, 0x0040, 0x0006, 0x0a0a, 0x0a01)
        Calculates the checksum for the IP packet header. It's meant to be inserted as the checksum of the packet.
        _________________________________________________________________________
        | Example IP header checksum calculation                                  |
        |-------------------------------------------------------------------------|
        | version & ihl & serviceType, + length   |  0x4500 + 0x0028 +            |
        | id & flags + fragmentOffset             |  0xabcd + 0x0000 +            |
        | ttl & protocol + checksum (0000 temp)   |  0x4006 + 0x0000 +            |
        | sourceAddr (IP)                         |  0x0a0a + 0x0a02 +            |
        | destAddr (IP)                           |  0x0a0a + 0x0a01 =            |
        | Subtotal                                |  0x5912                       |
        |-------------------------------------------------------------------------|
        | Removing the carryover                  |  0x5912 + 0x0001 = 0x5913     |
        | Negation with 0xffff                    |  0xffff - 0x5913 =            |
        | Header Checksum                         |  0xa6ec                       |
        |_________________________________________________________________________|

        args:
        - version, ihl, serviceType, length, id, flags, fragmentOffset, ttl, protocol, sourceAddr, destAddr

        returns:
        - ipChecksum: The checksum to be loaded into the header
        """
        
        subtotal  = (((version << 4) | ihl) << 8) | serviceType # nested bitshift for 3-variable hex byte concatenation
        subtotal += length # id: 0000 0000 0000 0000 flags: 000 fragOffset: 0 0000 0000 0000
        subtotal += id # id is 4 bits (1 nibble)
        subtotal += flags << 13 | fragmentOffset # flags is 3 bits(?); fragmentOffest is 13 bits (wtf)
        subtotal += (ttl << 8 | protocol) # empty temporary checksum value is implied
        subtotal += sourceAddr
        subtotal += destAddr

        if subtotal > 0xffff:
            subtotal  = (subtotal & 0xffff) + 0x0001 # remove carryover
        
        ipChecksum = 0xffff - subtotal # Perform negation with 0xffff

        return ipChecksum  


"""
Class ICMPheader: Constructs a user-defined ICMP packet header.
=================================================================================================================================
Here's the ICMP header breakdown: (Shown as in https://inc0x0.com/icmp-ip-packets-ping-manually-create-and-send-icmp-ip-packets/)
ICMP Packet Header Params
bit
1  4    8    12   16   20   24   28   32 
0000 1000 0000 0000 0000 0000 0000 0000 | Type of Message (08), Code (00), Checksum (?? ??)
0001 0010 0011 0100 0000 0000 0000 0001 | Identifier (12 34), Sequence Number (00 01)
0000 0000 0000 0000 000...              | Payload Data (OPTIONAL; 00 00 00 00 0...)
=================================================================================================================================

Sources: 
- https://www.rfc-editor.org/info/rfc792/ 
"""
class ICMPheader(AbstractPacket):
    def __init__(self, icmpMessageType, icmpCode, icmpChecksum, icmpIdentifier, icmpSeqNum, icmpPayload):
        
        # ICMP class Constructor
        self.icmpMessageType = icmpMessageType
        self.icmpCode = icmpCode
        self.icmpChecksum = icmpChecksum
        self.icmpIdentifier = icmpIdentifier
        self.icmpSeqNum = icmpSeqNum
        self.icmpPayload = icmpPayload

        # Assemble the ICMP packet 
        self.icmp_header = utils.int_to_byte(self.icmpMessageType, 1)
        self.icmp_header = utils.int_to_byte(self.icmpCode, 1)
        self.icmp_header = utils.int_to_byte(self.icmpChecksum, 2)
        self.icmp_header = utils.int_to_byte(self.icmpIdentifier, 2)
        self.icmp_header = utils.int_to_byte(self.icmpSeqNum, 2)

        payload = "example"
        self.icmp_header = utils.int_to_byte(self.icmpPayload, 0) # make a function to feed a payload into and calculate its length in hex for this. then make this a variable which does that.

    #--------------------------------------------------------------------------------------------------------------#
    def calc_icmp_checksum(self, icmpMessageType, icmpCode, icmpIdentifier, icmpSeqNum):
        """
        Calculates the checksum for the ICMP packet header. It's meant to be inserted as the checksum of the packet.
         ___________________________________________________________________
        | Example ICMP header checksum calculation                          |
        |-------------------------------------------------------------------|
        | icmpMessageType & icmpCode + tmp checksum |  0x0800 + 0x0000 +    |
        | icmpIdentifier + icmpSeqNum               |  0x1234 + 0x0001 =    |
        | Subtotal                                  |  0x1A35               |
        |-------------------------------------------------------------------|
        | Negation with 0xffff                      |  0xFFFF - 0x1A35 =    |
        | ICMP Checksum                             |  0xE5CA               |
        |___________________________________________________________________|

        args:
        - icmpMessageType, icmpCode, icmpChecksum, icmpIdentifier, icmpSeqNum

        returns:
        - ipChecksum: The checksum to be loaded into the header of the packet to send.
        """

        subtotal  = (icmpMessageType << 8 ) | icmpCode # tmp checksum is implied since it has no value before calculation
        subtotal += icmpIdentifier + icmpSeqNum

        icmpHeader = 0xffff - subtotal # Perform negation with the subtotal

        return icmpHeader


"""
Class TCPheader: Constructs a user-defined TCP packet header.
=================================================================================================================================
Here's the ICMP header breakdown: (Shown as in https://inc0x0.com/icmp-ip-packets-ping-manually-create-and-send-icmp-ip-packets/)
ICMP Packet Header Params
bit
1  4    8    12   16   20   24   28   32 
0000 1000 0000 0000 0000 0000 0000 0000 | Source Port (00 00), Destination Port (00 00)
0001 0010 0011 0100 0000 0000 0000 0001 | Sequence Number (00 00 00 00)
0000 0000 0000 0000 0000 0000 0000 0000 | Acknowledgement Number (00 00 00 00)
          CEUA PRSF
          WCRC SSYI  TCP Flags (CWR, ERE, URG, ACK, PSH, RST, SYN, FIN): Active if that bit is 1.
          REGK HTNN
0000 0000 0000 0000 0000 0000 0000 0000 | Data Offset (0), Reserved (000, bits), flags (00000000, bits), Window (00 00)
0000 0000 0000 0000 0000 0000 0000 0000 | Checksum (00 00), Urgent Pointer (00 00)
0000 0000 0000 0000 0000 0000 0000 0000 | Options (00 00 00 00)
0000 0000 0000 0000 0000 0000 0000...   | Data (00 00 00 0...)
=================================================================================================================================

Sources: 
- https://www.ietf.org/rfc/rfc9293.html 
"""
class TCPheader(AbstractPacket): # TODO: after ARP

    def __init__(self, sourcePort, destPort, tcpSeqNum, ackNum, dataOffset, 
                                nullPad, ns, cwr, ece, urg, ack, psh, rst, syn, fin, 
                                winSize, tcpChecksum, urgentPointer, tcpPayload):
        
        # TCP class Constructor
        self.sourcePort = sourcePort
        self.destPort = destPort
        self.tcpSeqNum = tcpSeqNum
        self.ackNum = ackNum
        self.dataOffset = dataOffset
        self.nullPad = nullPad
        self.ns = ns
        self.cwr = cwr
        self.ece = ece
        self.urg = urg
        self.ack = ack
        self.psh = psh
        self.rst = rst
        self.syn = syn
        self.fin = fin
        self.winSize = winSize
        self.tcpChecksum = tcpChecksum
        self.urgentPointer = urgentPointer
        self.tcpPayload = tcpPayload

    def calc_tcp_checksum(self):
        pass


"""
Class UDPheader : Constructs a user-defined UDP packet header.
=================================================================================================
Documentation for reference and more learning: https://www.rfc-editor.org/info/rfc768/ 

Here's the packet header breakdown in the way that made the most sense to me:
UDP packet header
bit
0  4    8    12   16   20   24   28   32 
0000 0000 0000 0000 0000 0000 0000 0000 | Source Port (00 00), Destination Port (00 00) 
0000 0000 0000 0000 0000 0000 0000 0000 | Length (00 00), Checksum (00 00)
0000 0000 0000 0000 0000 0000...        | Payload (00 00 00...)
=================================================================================================
"""
class UDPheader():
    def __init__(self, sourcePort, destPort, payload) -> None:
        
        # UDP Header Constructor
        self.sourcePort = sourcePort
        self.destPort = destPort
        self.udpLength = self.calc_udp_packet_length(payload) # calcumalate it here
        self.checksum = 0       # placeholder
        self.payload = payload

    def calc_udp_packet_length(self, payload):
        """
        Calculates the laength of the UDP packet before it's sent.

        From RFC 768 (https://www.rfc-editor.org/info/rfc768):
        "Length  is the length  in octets  of this user datagram  including  this
        header  and the data.   (This  means  the minimum value of the length is
        eight.)"

        args:
        - payload: The payload which the user wishes to send to their target.

        returns:
        - udpLength: The length of the udp packet for header checksum caulculation & receiving interface accuracy.
        """    
        udpHeaderBytes = 8
        return udpHeaderBytes + len(payload)

    def calc_udp_checksum(self, IPheader, payload):
        """ 
        Calculates the UDP checksum
        Sources: 
        - https://stackoverflow.com/questions/1480580/udp-checksum-calculation
        - https://nithishkgnani.github.io/blog/checksum/

        args:
        Pseudoheader
            - sourceAddr: source IP derived from the IP header object itself
            - destAddr: destination IP derviced from the IP header object itself
            - zero: extra padding
            - protocol: 
            - calc_udp_packet_length(payload)
            - sourcePort: port on machine sending packet
            - destPort: port of the machine on which the packet isbeing received
            - payload: the non-header data in the oacket itself.

        returns:
        - pseudoHeader: The fully constructed pseudoHeader
        """
       
        # Padding payload to even byte length (if necessary)
        # if payload is not en even amt of bytes, append one byte to it to make it even.
        if len(payload) % 2 != 0: # if the payload length in bytes isn't even, pad it to be even
            payload += b'\x00'

        # Let's learn how to use struct.pack here, it seems much better for building packets
        #Build the pseudoheader from the IPheader object
        pseudoHeader = struct.pack(
                        f'!4s4sBBHHH{len(payload)}s', # Notation: https://www.geeksforgeeks.org/python/struct-pack-in-python/ 
                        IPheader.sourceAddr,    # 4 bytes (00 00 00 00)
                        IPheader.destAddr,      # 4 bytes (00 00 00 00)
                        0,                      # padding byte
                        IPheader.protocol,      # protocol number (17 for UDP)
                        self.calc_udp_packet_length(payload), # UDP length calc' length of header & payload 
                        self.sourcePort,        # 2 bytes (00 00)
                        self.destPort,          # 2 bytes (00 00)
                        payload                 # dynamically allocate the payload in struct.pack
        )

        print(f"[dbg] UDP pseudo header: {pseudoHeader}")

        # for loop to turn pseudoHeader into 16-bit (2-byte) words
        udpChecksum= 0
        carryOver = 0x0

        for i in range(0, len(pseudoHeader), 2): 
            udpChecksum += pseudoHeader[i] << 8 | pseudoHeader[i+1]
        
        # fold the carries
        while udpChecksum > 0xFFFF:
            carryOver = udpChecksum >> 16 # get the carrover (everything left of 16 bits)
            udpChecksum = udpChecksum & 0xFFFF # exclude the subtotal from its carryover 
            udpChecksum += carryOver # add on the carryover to the subtotal 

        udpChecksum = ~udpChecksum & 0xFFFF #

        return udpChecksum

"""
Class ARPheader: Constructs a user-defined ARP packet header.
=================================================================================================================================
Here's the ICMP header breakdown: (Shown as in https://inc0x0.com/icmp-ip-packets-ping-manually-create-and-send-icmp-ip-packets/)
ICMP Packet Header Params
bit
1  4    8    12   16   20   24   28   32 
0000 1000 0000 0000 0000 0000 0000 0000 | Hardware Type (08 00), Protocol Type (00 00, 16 bits)
0001 0010 0011 0100 0000 0000 0000 0001 | Hardware Addresss Length (00, 8 bits), Protocol Addr Length (00, 8 bits), Opcode (00 00, 16 bits)
0000 0000 0000 0000 0000 0000 0000 0000 | Sender Hardware Address (00 00 00 00 00 00 or 1.5 lines or 48 bits)
0000 0000 0000 0000 0000 0000 0000 0000 | Sender Protocol Address (00 00 00 00, 32 bits)
0000 0000 0000 0000 0000 0000 0000 0000 | Target Hardware Addeess (00 00 00 00 00 00 or 1.5 lines or 48 bits)
0000 0000 0000 0000 0000 0000 0000 0000 | 
0000 0000 0000 0000 0000 0000 0000 0000 | Target Protocol Address (00 00 00 00, 32 bits)
=================================================================================================================================

Sources: 
- https://www.rfc-editor.org/info/rfc792/ 
"""
class ARPheader():
    def __init__(self, hardwareType, protoType, hwAddrLen, protoAddrLen, 
                    opcode, senderHwAddr, senderProtoAddr, targetHwAddr, targetProtoAddr):

        # ARPheader Constructor
        self.hardwareType = hardwareType
        self.protoType = protoType
        self.hwAddrLen = hwAddrLen
        self.protoAddrLen = protoAddrLen
        self.opcode = opcode
        self.senderHeAddr = senderHwAddr
        self.senderProtoAddr = senderProtoAddr
        self.targetHeAddr = targetHwAddr
        self.targetProtoAddr = targetProtoAddr

    #TODO: Make a series of methods for CLI scripting implementation with -flags & args for options.
    # - layer this over the packet construction class params, allowing for easier implementation.
    # - if there are header fields the user doesn't specify, use defaults. 
    # - Definitely use (probably nested) switch statements with if/else statements for input checks    