# networking_library
Low-level manual packet crafting &amp; basic translation programming in python via socket &amp; other libraries.

# Programs
**ascii_to_byte_hex.py**
Translates ASCII characters to byte hex for python's socket library, via the binascii & re lirbaries.

**icmp_packet_craft.py**
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

**  **

---
# Sources
- https://docs.python.org/3/library/socket.html 
- https://inc0x0.com/tcp-ip-packets-introduction/tcp-ip-packets-3-manually-create-and-send-raw-tcp-ip-packets/#improve-packet
- https://inc0x0.com/icmp-ip-packets-ping-manually-create-and-send-icmp-ip-packets/
- https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml 
