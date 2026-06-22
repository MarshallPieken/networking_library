"""
This is the main of the PacketCraft program. 
Author: Alex Pieken
"""

from utils import starting_sequence
import argparse

"""
TODO: Make a series of methods for CLI scripting implementation with -flags & args for options.
- if there are header fields the user doesn't specify, use defaults. 
- Definitely use (probably nested) switch statements with if/else statements for input checks  
"""

"""
The methods below are the CLI layer of PacketCraft. 
I decided to place these arguemnts into Python's version of case statements, which a series of methods with a dictionary for each case, as shown below.

Source: https://stackoverflow.com/questions/21962763/using-a-dictionary-as-a-switch-statement-in-python 

"""
# create the argparse object for the CLI program to run with
def parse_args():
    parser = argparse.ArgumentParser(prog='PacketCraft')

    #Construct a TCP packet per user specificaton.
    parser.add_argument('--tcp', help='TCP packet construction. See RFC 9293 for help understanding header options: https://www.ietf.org/rfc/rfc9293.html')

    """ Construct an ICMP packet per user specificaton. """
    parser.add_argument('--icmp', help='ICMP packet construction. See RFC 792 for help understanding header options: https://www.rfc-editor.org/info/rfc792/')

    """ Construct an ARP packet per user specificaton. """
    parser.add_argument('--arp', help='ARP packet construction. See RFC 826 for help understanding header options: https://www.rfc-editor.org/info/rfc826/')

    """ Construct an IP packet header per user specificaton. """
    parser.add_argument('--ip', help='IP packet construction See RFC 791 for help understanding header options: https://www.rfc-editor.org/info/rfc791/')

    """ Construct a UDP packet per user specificaton. """
    parser.add_argument('--udp', help='UDP packet construction. See RFC 768 for help understanding header options: https://www.rfc-editor.org/info/rfc768/')

if __name__ == "__main__":
    starting_sequence()
    parse_args()
