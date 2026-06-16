"""
================================================================================================================================
Purpose: Learning about ICMP echo requests, and learning how to carft payloads into them.
How: Manually crafting an ICMP echo request. Detection of this could come from the length of it as a network traffic anomaly.
Here's each part of the packet: 
- Version, IHL, Type of Service, Total Length
- Identification, Flags, Fragment Offset 
- TTL, Protocol, header checksum
- Source Address
- Destination Address
- Payload (This is where the packet gains an unusual length)

ICMP header requires:
- type of msg, code, checksum
- identifier, sequence number

These are all crafted in hex representation of ASCII chars.

Sources: 
- https://docs.python.org/3/library/socket.html 
- https://inc0x0.com/tcp-ip-packets-introduction/tcp-ip-packets-3-manually-create-and-send-raw-tcp-ip-packets/#improve-packet
- https://inc0x0.com/icmp-ip-packets-ping-manually-create-and-send-icmp-ip-packets/
- https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml 
================================================================================================================================

Here's the ICMP header breakdown: (Shown as in https://inc0x0.com/icmp-ip-packets-ping-manually-create-and-send-icmp-ip-packets/)
---------------------------------------------------------------------------------------------
Decimal:     0    1    2    3    4    5    6    7    8    9    10   11   12   13   14   15 
Hexadecimal: 0    1    2    3    4    5    6    7    8    9    A    B    C    D    E    F 
Binary:      0000 0001 0010 0011 0100 0101 0110 0111 1000 1001 1010 1011 1100 1101 1110 1111 
---------------------------------------------------------------------------------------------
ICMP Header
Bit
0    4    8    12   16   20   24   28   32
0100 0101 0000 0000 0000 0000 0001 1101   | Version (4), IHL (5), Type of Service (00), Total Length (00 1C)
1010 1011 1100 1101 0000 0000 0000 0000   | ID (AB CD), Flags (000), Fragment Offset (000000000000)
0100 0000 0000 0001 0000 0000 0000 0000   | TTL (40), Protocol (01), Header Checksum (To be calculated)
1101 0000 0110 1000 1001 0010 1000 0011   | Source IP: C0 A8 92 83 (192.168.164.131)
0000 1000 0000 1000 0000 1000 0000 1000   | Destination IP: 8.8.8.8
---------------------------------------------------------------------------------------------
"""


import socket
import binascii
import re
import ipaddress
from scapy.all import IP, ICMP, srl

def default_http_packet():
    """ This is a default construction of an HTTP packet for network transmission.
    
    args: 
    - s: socket created for the transmission of thepacket from machine interface to machine interface.
    - ip_header: haeder it represented in byte hex for Layer 3 
    - http_header: header bit represented in byte hex.

    This is how http packet headers are syntactically transmitted over the wire:
        GET / HTTP/1.1\r\n
        Host: example.com\r\n
        User-Agent: MyClient/1.0\r\n
        \r\n
     """
    # initialize socket var w/ internet (IPv4 or domain) addressing, raw socket, TCP protocol.
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
      
    # socket options for including IP headers
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    ip_header = b'\x45\x00\x00\x1c' # version, IHL, type of service | total length
    ip_header += b'\xab\xcd\x00\x00' # identification | flags, fragment offset
    ip_header += b'\x40\x01\x6b\xd8' # TTL, protocol | header checksum
    ip_header += b'\xc0\xa8\x92\x83' # source address - this can be used for spoofing and its automation
    ip_header += b'\x08\x08\x08\x08' # destination address (8.8.8.8)

    # time to dig through some diagrams to understand & define an example for this 
    http_header = b'' # working on this, e.g., make a user-agent field.


def default_icmp_packet():
    """ the basic hex byte construction of an ICMP packet."""
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    #same as above honestly
    ip_header = b'\x45\x00\x00\x1c' # version, IHL, type of service | total length
    ip_header += b'\xab\xcd\x00\x00' # identification | flags, fragment offset
    ip_header += b'\x40\x01\x6b\xd8' # TTL, protocol | header checksum
    ip_header += b'\xc0\xa8\x92\x83' # source address - this can be used fro spoofing BTW
    ip_header += b'\x08\x08\x08\x08' # destination address (8.8.8.8)

    icmp_header = b'\x08\x00\xe5\xca' # type of msg, code | checksum
    icmp_header += b'\x12\x34\x00\x01' # identifier | sequence number
    
    # data would go here:
    # data = b'\xff\xff\xff\xff\xff\xff\xff\xff', etc. 

    packet = ip_header + icmp_header # + data
    s.sendto(packet, ('8.8.8.8', 0))

def hex_bytes_to_ascii(byte_hex_string: str):
    """ 
    payload you have into hex for packet payload delivery. Calls sanitize_hex() for conversion into raw hex. 
    Make sure payloads don't increase the entire length of hte ISMP packet above 65,500 bytes. 
    Make sure they're much closer to typical packet sizes, though to help avoid modren EDR detection.

    For example, in hex bytes, GET is \x47\x45\x54. This is using the ASCII table's numbers for each character, represented in hex form.
    e.g,:
    - G is 71 on the ASCII table, or 47 (4*16 + 7) in hex.
    - E is 69 on the ASCII Table, or 45 (4*16 + 5) in hex.
    - T is 84 on the ASCII table, or 54 (5*15 + 4) in hex.
    
    args: 
    - byte_hex_string: packet bytes in hex form fed into this method for conversion (e.g., \x47\x45\x54).

    other variables:
    - hex_string: The sanitized hex string (e.g.,474554)

    returns:
        ascii_string: The ASCII text (e.g., GET)
    """
    #passed in string
    byte_hex_string = r"\\x47\\x45\\x54"
    
    # filter out the \x 
    hex_string = sanitize_hex(byte_hex_string)
    
    # make ascii string
    ascii_string = binascii.unhexlify(hex_string).decode("ASCII")

    return ascii_string


def sanitize_hex(byte_hex: str):
    """ 
    Santizes hex to be purely represented in a string without slashed characters. 
    
    args: 
    - byte_hex: 

    returns:
    - sanitized_hex: 
    """
    #replace the slash x with blank str 
    sanitized_hex = re.sub(r'\\x', '', byte_hex)

    return sanitized_hex
    
    
def ascii_to_hex_bytes(ascii_input: str):
    """
    This is just the opposite of the previous method, hex_bytes_to_ascii().

    args:
    - ascii_input: the ASCII to be converted into byte hex for packet transmission.

    returns:
    - packet_hex: converted into hex format for the packet to transmit across networks
    """
    
    ascii_input = """
    GET / HTTP/1.1\r\n
    Host: example.com\r\n
    User-Agent: MyClient/1.0\r\n
    \r\n
    """

    #convert to hex
    raw_hex = binascii.hexlify(ascii_input.encode('ascii')).decode('asciii')

    # use regex to add the '\x'
    packet_hex = re.sub(r'([0-9A-Fa-f]{2})', r'\\x\1', raw_hex)
    print(f"[*] Packet byte hex: \n{packet_hex}\n\n")
    
    return packet_hex


def convert_http_headers():
    """
    This will eventually receive HTTP header fields, parse them, attend \r\n to them, and convert them to hex bytes for packet payloads.
    We can make a CLI program to ask the user to type them and/or feed in a file with them.

    vars:
    hex_string: The orignal backet bytecode in hex.


    Syntax example:
        GET / HTTP/1.1\r\n
        Host: example.com\r\n
        User-Agent: Mozilla/1.0\r\n
        \r\n
    I can make a basic converter which sues the binascii library to convert whatever into ASCII after parsing out the slash x, \r and \n.
    
    """
    pass 

