"""
Purpose: Learning about ICMP packets, and learning how to carft payloads into them.
How: Manually crafting IP, ICMP and other packets. Detection of this could come from the length of it as a network traffic anomaly.

NOTE: Any Layer 2 or lower packet crafting does not work for Windows, thanks to its netowrking stack restrictions. 
I'll eventually build out a Scapy module to bypass those restrictions as well. In the meantime, Linux will process anything here.

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
- Make the if statement for converting & loading an ICMP payload
- Eventually make a layer 4 TCP/IP header to append to the IP packet header 
    - (including self, sourcePort, destPort, tcpipSeqNum, ackNum, flags, windowSize, checksum, urgentPointer)
    - Also a checksum calculationmethod for this one
- Test/debug/fix this program
- Eventually add in other packet construction methods: 
    Layer 2 (Needs socket's AF_PACKET in a separate L2 packet carfting method)
    |- ethernet II (IEEE 802.1Q LAN): https://www.geeksforgeeks.org/computer-networks/ethernet-frame-format/, https://ieeexplore.ieee.org/browse/standards/get-program/page/series?id=68 
    |    |- arp: https://en.wikipedia.org/wiki/Address_Resolution_Protocol, https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml
    |- VLAN (IEEE 802.1Q): https://en.wikipedia.org/wiki/IEEE_802.1Q, https://learningnetwork.cisco.com/s/question/0D56e0000EBtaQ9CQJ/ieee-8021q-vlan-tagging-and-trunking-in-networking, 
    layer 3
    |- 
    Layer 4
    |- UDP (RFC 768): https://www.rfc-editor.org/info/rfc768/  
    |- TCP (RFC 9293): https://www.ietf.org/rfc/rfc9293.html#name-header-format
    |- SCTP (9260): https://www.ietf.org/rfc/rfc9260.pdf

After all this is made in the next little while, we can move on to bluetooth, phone, etc.
Everything here could also be in an array adn you can index those array fields (owie, my brain!)
"""

import socket
import binascii
import re
import ipaddress

"""
Class IPpacket: Constructs a user-defined IP packet header. 

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
class IPpacket():
    def  __init__(self,
                    version: int, 
                    ihl: int, 
                    serviceType: int, 
                    length: int, 
                    id: int, 
                    flags: int, 
                    fragmentOffset: int, 
                    ttl: int, 
                    protocol: int, 
                    checksum: int, 
                    sourceAddr: str, 
                    destAddr: str):

        # Constructor
        self.version = version
        self.ihl = ihl
        self.serviceType = serviceType  
        self.length = length
        self.id = id
        self.flags = flags
        self.fragmentOffset = fragmentOffset
        self.ttl = ttl
        self.protocol = protocol
        self.checksum = checksum
        self.sourceAddr = sourceAddr
        self.destAddr = destAddr
        
        # Crafting the packet's ip header
        self.ip_header  = self.int_to_byte((self.version << 4) + self.ihl, 1) # Since it's only 4 bits, bitwase operations to move it left 4 bits & add the 4-bit ihl as well to the same byte
        self.ip_header += self.int_to_byte(self.serviceType, 1)
        self.ip_header += self.int_to_byte(self.length, 2)
        self.ip_header += self.int_to_byte(self.id, 2)
        self.ip_header += self.int_to_byte(self.flags << 13 | self.fragmentOffset, 2)
        self.ip_header += self.int_to_byte(self.ttl, 1)
        self.ip_header += self.int_to_byte(self.protocol, 1)
        self.ip_header += self.int_to_byte(self.checksum, 2)
        self.ip_header += self.ipv4_to_byte_hex(self.sourceAddr)
        self.ip_header += self.ipv4_to_byte_hex(self.destAddr)

        # Debugging
        print(f'Here\'s the raw IP packet header: {self.ip_header}')

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

    #-------------------------------------------------------------------------------------------------#
    def payload_to_hex_byte(self, input, z):
        """
        User inserts a payload and this calculates the payload's length in hex bytes. 
        If the payload is larger than 1472 bytes, the packet is too large.

        args:
        - input: user-input palyoad

        returns:
        - payload_hex: hex byte - converted payload. 

        """
        return binascii.a2b_hex(input).zfill(z * 2)

    #-------------------------------------------------------------------------------------------------#
    def int_to_byte(self, n, z):
        """ 
        Convert integers to hex byte representation

        args:
        - n: integer that's passed in
        - z: zfill amt of hex digits to pad to the ICMP packet header field 

        returns:
        - binary hex of n
        """
        return binascii.a2b_hex(hex(int(n)).replace("0x","").zfill(z * 2))

    #-------------------------------------------------------------------------------------------------#
    def ipv4_to_byte_hex(self, ipstr: str):
        """
        Converts IP Addresses to byte representation.

        args:
        - ipstr: The IP which is being fed into this method to be translated for an IP packet.

        returns:
        - out: binary hex representation of the IP address.
        """

        #use regex to translate ip address into hex
        split_ip: list[str] = ipstr.split(".")

        if len(split_ip) != 4:
            print("Not a real IPv4 - check your input")
            exit(code=5)
        
        out = b""
        for n in split_ip:
            if not n.isdigit():
                print("Make sure the IP address only has digits around the periods. ")
                exit(code=5)
            out += binascii.a2b_hex(hex(int(n)).replace("0x","").zfill(2))
        return out

    #--------------------------------------------------------------------------#
    def send_layer3_packet(self):
        """
        Actually crafts and sends the packet based on out preferences. 
        socket() flags:
        - AF_INET lets us jump in at layer 3 (network) of packet construction
        - SOCK_RAW includes the layer 2 (data link) packet 
        - IPPROTO_RAW signals sending of rse IP datagrams (also implies IP_HDRINCL on Linux, but good to have nonetheless)  
        - IPPROTO_IP specifies we're carfting headers at IP level.
        - IP_HDRINCL being set to 1 tells the kernel to *not* generate an IP header, since we're crafting it.

        For ethernet & other layer 2 protocols, we'll need to use AF_PACKET to craft packets on Linux. 
        Windows is too restrictive so we'll need to use scapy (or C) for that.

        """
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s.sendto(self.ip_header, (self.destAddr, 0))


"""
Class ICMPHeader: Constructs a user-defined ICMP packet header.
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
class ICMPheader(IPpacket):
    def __init__(self, icmpMessageType, icmpCode, icmpChecksum, icmpIdentifier, icmpSeqNum, icmpPayload):
        super().__init__(4, 5, 0, 28, 0xabcd, 0, 0, 64, 1, 0, "1.1.1.1", "8.8.8.8"):
        
        # ICMP subclass Constructor
        self.icmpMessageType = icmpMessageType
        self.icmpCode = icmpCode
        self.icmpChecksum = icmpChecksum
        self.icmpIdentifier = icmpIdentifier
        self.icmpSeqNum = icmpSeqNum
        self.icmpPayload = icmpPayload

        # Assemble the ICMP packet 
        self.icmp_header = self.int_to_byte(self.icmpMessageType, 1)
        self.icmp_header = self.int_to_byte(self.icmpCode, 1)
        self.icmp_header = self.int_to_byte(self.icmpChecksum, 2)
        self.icmp_header = self.int_to_byte(self.icmpIdentifier, 2)
        self.icmp_header = self.int_to_byte(self.icmpSeqNum, 2)
        # TODO Make an if statement for whether the user wants to add in a payload.
            # if so, call payload_to_hex_byte() to convert it and append it to the ICMP paket.
            # if not, send just the headers.
        self.icmp_header = self.int_to_byte(self.icmpPayload, self.payload_to_hex_byte()) # make a function to feed a payload into and calculate its length in hex for this. then make this a variable which does that.

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

if __name__ == "__main__":
    packet1 = IPpacket(4, 5, 0, 28, 0xabcd, 0, 0, 64, 1, 0, "1.1.1.1", "8.8.8.8")
    packet1.send_layer3_packet()

    #TODO: Make a deries of methods for CLI scripting implementation with -flags & args for options.
    # - layer this over the packet construction class params, allowing for easier implementation.
    # - if there are header fields the user doesn't specify, use defaults. 
    # - Definitely use (probably nested) switch statements with if/else statements for input checks    