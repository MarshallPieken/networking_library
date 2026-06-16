"""
================================================================================================================================
Purpose: Learning about ICMP packets, and learning how to carft payloads into them.
How: Manually crafting an ICMP echo request. Detection of this could come from the length of it as a network traffic anomaly.
Here's each part of the packet: 
- Version, IHL, Type of Service, Total Length
- Identification, Flags, Fragment Offset 
- TTL, Protocol, header checksum
- Source Address
- Destination Address
- Payload (This is where the packet gains an unusual length)
These are all crafted in hex representation of ASCII chars.

Sources: 
- https://docs.python.org/3/library/socket.html 
- https://inc0x0.com/tcp-ip-packets-introduction/tcp-ip-packets-3-manually-create-and-send-raw-tcp-ip-packets/#improve-packet
- https://inc0x0.com/icmp-ip-packets-ping-manually-create-and-send-icmp-ip-packets/
- https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml
- https://www.w3schools.com/python/python_class_methods.asp  
- https://www.geeksforgeeks.org/python/extend-class-method-in-python/
================================================================================================================================

Here's the ICMP header breakdown: (Shown as in https://inc0x0.com/icmp-ip-packets-ping-manually-create-and-send-icmp-ip-packets/)
---------------------------------------------------------------------------------------------
Decimal:     0    1    2    3    4    5    6    7    8    9    10   11   12   13   14   15 
Hexadecimal: 0    1    2    3    4    5    6    7    8    9    A    B    C    D    E    F 
Binary:      0000 0001 0010 0011 0100 0101 0110 0111 1000 1001 1010 1011 1100 1101 1110 1111 
---------------------------------------------------------------------------------------------
IP Header
Bit
0    4    8    12   16   20   24   28   32
0100 0101 0000 0000 0000 0000 0001 1101   | Version (4), IHL (5), Type of Service (00), Total Length (00 1C)
1010 1011 1100 1101 0000 0000 0000 0000   | ID (AB CD), Flags (000), Fragment Offset (000000000000)
0100 0000 0000 0001 0000 0000 0000 0000   | TTL (40), Protocol (01), Header Checksum (?? ??)
1101 0000 0110 1000 1001 0010 1000 0011   | Source IP: C0 A8 92 83 (192.168.164.131)
0000 1000 0000 1000 0000 1000 0000 1000   | Destination IP: 08 08 08 08 (8.8.8.8)
--------------------------------------------------------------------------------------------
ICMP Header
bit
0    4    8    12   16   20   24   28   32
0000 1000 0000 0000 0000 0000 0000 0000  | Type of Message (08), Code (00), Checksum (?? ??)
0001 0010 0011 0100 0000 0000 0000 0001  | Identifier (12 34) Sequence Number (00 01)
0000 0000 0000 0000 ...                  | Payload data (optional)
--------------------------------------------------------------------------------------------

TODO:
- Make another  
- use enums for class ICMPServiceType(Enum), maybe

Everything here could also be in an array adn you can index those array fields (ouch, my brain!)
"""

import socket
import binascii
import re
import ipaddress

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

        # Example variable assignments
        # version = 4 # Since it's only 4 bits, bitwase operations to move it left 4 bits & add the 4-bit ihl as well to the same byte
        # ihl = 5
        # serviceType = 0
        # length = 28
        # id = 0xabcd
        # flags = 0
        # fragmentOffset = 0
        # ttl = 64
        # protocol = 1
        # checksum = 0
        # sourceAddr = ""
        # destaddr = ""
        
        # packet1 = IPpacket(4, 5, 0, 28, 0xabcd, 0, 0, 64, 1, 0, "1.1.1.1", "8.8.8.8")

        # Constructing the packet's ip header
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

        print(f'Here\'s the raw IP packet header: {self.ip_header}')

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
    def send_packet(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s.sendto(self.ip_header, (self.destAddr, 0))

if __name__ == "__main__":
    packet1 = IPpacket(4, 5, 0, 28, 0xabcd, 0, 0, 64, 1, 0, "1.1.1.1", "8.8.8.8")
    packet1.send_packet()
    print(f"Packet sent!")