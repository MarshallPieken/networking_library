"""
This contains the helper functions for the crafting, de/encoding, and sending of user-defined packets. 

Methods:
- payload_to_hex_bytes(): lets the program change the 
- int_to_byte(): 
- ipv4_to_byte_hex():
- send_layer3_packet():  


"""
import socket
import binascii

#-------------------------------------------------------------------------------------------------#
def payload_to_hex_byte(input, z):
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
def int_to_byte(n, z):
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
def ipv4_to_byte_hex(ipstr: str):
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
def send_layer3_packet(packet, port):
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
    s.sendto(packet.destAddr, port)

def starting_sequence():
    print("""
    ██████   █████   ██████ ██   ██ ███████ ████████  ██████ ██████   █████  ███████ ████████ 
    ██   ██ ██   ██ ██      ██  ██  ██         ██    ██      ██   ██ ██   ██ ██         ██    
    ██████  ███████ ██      █████   █████      ██    ██      ██████  ███████ █████      ██    
    ██      ██   ██ ██      ██  ██  ██         ██    ██      ██   ██ ██   ██ ██         ██    
    ██      ██   ██  ██████ ██   ██ ███████    ██     ██████ ██   ██ ██   ██ ██         ██    
    version 0.1

    use -h or --help to see the help menu.
    """)
