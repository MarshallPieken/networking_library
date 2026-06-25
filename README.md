# networking_library
Low-level manual packet crafting &amp; basic translation programming in python via socket &amp; other libraries. Still a work in progress.

This started as just an ICMP packet crafting script and turned into something larger with IP & ICMP headers, as well as payload encoding for transmission & checksum calculation. Here's the to-do from it: 
TODO:
- Eventually add in other packet construction methods to understand 'em:

    Layer 2 (Needs socket's AF_PACKET in a separate L2 packet carfting method)
  
    |- ethernet II (IEEE 802.1Q LAN): https://www.geeksforgeeks.org/computer-networks/ethernet-frame-format/, https://ieeexplore.ieee.org/browse/standards/get-program/page/series?id=68
  
    |- VLAN (IEEE 802.1Q): https://en.wikipedia.org/wiki/IEEE_802.1Q, https://learningnetwork.cisco.com/s/question/0D56e0000EBtaQ9CQJ/ieee-8021q-vlan-tagging-and-trunking-in-networking,
  
    Layer 4
  
    |- SCTP (9260): https://www.ietf.org/rfc/rfc9260.pdf

---
# More Learning Sources
- https://docs.python.org/3/library/socket.html 
- https://inc0x0.com/tcp-ip-packets-introduction/tcp-ip-packets-3-manually-create-and-send-raw-tcp-ip-packets/#improve-packet
- https://inc0x0.com/icmp-ip-packets-ping-manually-create-and-send-icmp-ip-packets/
- https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml 
