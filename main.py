"""
This is the main of the PacketCraft program. 
Author: Alex Pieken
"""

import PacketCraft
from utils import starting_sequence
import argparse

"""
TODO: Make a series of methods for CLI scripting implementation with -flags & args for options.
- Connect the actual arguments to the socket
- if there are header fields the user doesn't specify, use defaults. 
- Definitely use (probably nested) switch statements with if/else statements for input checks  
"""

"""
The methods below are the CLI layer of PacketCraft. 
I decided to place these arguemnts into Python's version of case statements, which a series of methods with a dictionary for each case, as shown below.

Source: https://stackoverflow.com/questions/21962763/using-a-dictionary-as-a-switch-statement-in-python 

"""


# create the argparse object for the CLI program to run with
parser = argparse.ArgumentParser(prog='PacketCraft')

# TODO: 
# - nest packet header args in _if_ statements, with _else_ being defaults pulled from the machine which the program is running on
def parse_args():


    # make a mutually exclusive group to prevent protocol conflicts
    protocol_group = parser.add_mutually_exclusive_group()
    protocol_group.add_argument('--tcp', help='TCP packet construction. See RFC 9293 for help understanding header options: https://www.ietf.org/rfc/rfc9293.html')
    protocol_group.add_argument('--icmp', help='ICMP packet construction. See RFC 792 for help understanding header options: https://www.rfc-editor.org/info/rfc792/')
    protocol_group.add_argument('--arp', help='ARP packet construction. See RFC 826 for help understanding header options: https://www.rfc-editor.org/info/rfc826/')
    protocol_group.add_argument('--ip', help='IP packet construction See RFC 791 for help understanding header options: https://www.rfc-editor.org/info/rfc791/')
    protocol_group.add_argument('--udp', help='UDP packet construction. See RFC 768 for help understanding header options: https://www.rfc-editor.org/info/rfc768/')


    #Construct a TCP packet per user specificaton.
    parser.add_argument('--tcp-src-port', help='The source port for your TCP packet')
    parser.add_argument('--tcp-dest-port', help='The destination port for your TCP packet')
    parser.add_argument('--cwr', help='set the TCP CWR (Congestion Window Reduced) flag')
    parser.add_argument('--ece', help='set the TCP ECE (ECN-echo) flag (see https://www.rfc-editor.org/info/rfc3168/)')
    parser.add_argument('--urg', help='set the TCP URG (Urgent) flag')
    parser.add_argument('--ack', help='set the TCP ACK (Acknowledgement) flag')
    parser.add_argument('--psh', help='set the TCP PSH (Push) flag')
    parser.add_argument('--rst', help='set the TCP RST (Reset) flag')
    parser.add_argument('--syn', help='set the TCP SYN (Synchronization) flag')
    parser.add_argument('--fin', help='set the TCP FIN (No more data from sender) flag')


    # Construct an ICMP packet per user specificaton.
    parser.add_argument('--icmp-message-type', help='Specify ICMP message type (e.g., 3 for destination unreachable). ICMP message types are available here: https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml')
    parser.add_argument('--icmp-code', help='Specify the ICMP packet\'s code (e.g., 3 again for tpye 3\'s port unreachable). See https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml#icmp-parameters-codes-3.')
    parser.add_argument('--icmp-id', help='ICMP Identifier, only applicable to Echo & Echo Reply (types 8 & 0) requests.')


    # Construct an ARP packet per user specificaton. 
    parser.add_argument('--arp-hardware-type', help='hardware type of the network on which ARP is running (e.g., 1 for Ethernet). See https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml')
    parser.add_argument('--arp-protocol-type', help='This option doesn\'t have options per IANA. It\'s just here if you want to tamper with it.')
    parser.add_argument('--arp-opcode', help='Operation Code (e.g., 1 for REQUEST). See https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml')
    parser.add_argument('--arp-sender-mac', help='Specify the sender\'s MAC address.')
    parser.add_argument('--arp-sender-ip', help='Specify the sender\'s IP(v4) address.')
    parser.add_argument('--arp-target-mac', help='Specify the target\'s MAC address.')
    parser.add_argument('--arp-target-ip', help='Specify the target\'s IPv4 address.')


    # IP packet header user specificatons 
    parser.add_argument('--ip-ihl', help='IHL is Internet Haeder Length.')
    parser.add_argument('--ip-service-type', help='Service Type is defined more in-detail at https://www.rfc-editor.org/info/rfc791')
    parser.add_argument('--ip-id', help='The ID the receiver uses to construct a datagram from multiple packets.')
    parser.add_argument('--ip-flags', help='Flags to define transmission structure: see https://www.rfc-editor.org/info/rfc791')
    parser.add_argument('--ip-ttl', help='Time to Live is the time a packet may remain on the internet.')
    parser.add_argument('--ip-protocol', help='')
    parser.add_argument('--ip-source-address', help='')
    parser.add_argument('--ip-target-address', help='')

    # UDP packet per user specificatons
    parser.add_argument('--udp-source-port', help='Specify the UDP packet\'s source port')
    parser.add_argument('--udp-dest-port', help='Specify the UDP packet\'s detination port')

if __name__ == "__main__":
    starting_sequence()
    parse_args()
    args = parser.parse_args()
