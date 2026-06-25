# packet_builer.py
import socket
from PacketCraft import IPheader, ICMPheader, UDPheader, ARPheader, TCPheader

def _int(val, base=0):
    """ Safely convert any string arguments and parameters into integers. 
    Return 0 if none."""

    return int(val, base) if isinstance(val, str) else (val or 0)

def build_ip(args):
    return IPheader (
        version = 4, 
        ip_ihl = _int(args.ip_ihl) if args.ip_ihl else 5,
        ip_service_type=_int(args.ip_service_type, 0) if args.ip_service_type else 0,
        ip_id=_int(args.ip_id, 0) if args.ip_id else 0,
        ip_flags=_int(args.ip_flags, 0) if args.ip_flags else 0,
        fragmentOffset=0,
        ip_ttl=_int(args.ip_ttl) if args.ip_ttl else 64,
        ip_protocol=_int(args.ip_protocol, 0) if args.ip_protocol else 0,
        checksum = 0, # alwyas build this so it's not dropped by the receiving interface's network stack
        ip_source_address=args.ip_source_address or socket.gethostbyname(socket.gethostname()),
        ip_target_address=args.ip_target_address or '0.0.0.0'
    )


def build_icmp(args):
    return ICMPheader(
        icmp_message_type=_int(args.icmp_message_type) if args.icmp_message_type else 8,
        icmp_code=_int(args.icmp_code) if args.icmp_code else 0,
        icmp_checksum= 0,
        icmp_identifier=_int(args.icmp_id) if args.icmp_id else 0,
        icmp_seq_num= 0, 
        icmp_payload= b'',
    )

def build_tcp(args):
    def flag(val):
        """1' / '0' / None -> int bit """
        return 1 if val == '1' else 0

    return TCPheader(
        tcp_src_port=_int(args.tcp_src_port) if args.tcp_src_port else 0,
        tcp_dest_port=_int(args.tcp_dest_port) if args.tcp_dest_port else 0,
        tcpSeqNum=0,
        ackNum=0,
        nullPad=0,
        ns=0,
        cwr=flag(args.cwr),
        ece=flag(args.ece),
        urg=flag(args.urg),
        ack=flag(args.ack),
        psh=flag(args.psh),
        rst=flag(args.rst),
        syn=flag(args.syn),
        fin=flag(args.fin),
        winSize=0,
        urgentPointer=0,
        tcpPayload=b''
    )

def build_udp(args):
    return UDPheader(
        udp_source_port=_int(args.udp_source_port) if args.udp_source_port else 0,
        udp_dest_port=_int(args.udp_dest_port) if args.udp_dest_port else 0,
        payload = b'',
    )

def build_arp(args):
    return ARPheader(
        arp_hardware_type=_int(args.arp_hardware_type) if args.arp_hardware_type else 1,
        arp_protocol_type=_int(args.arp_protocol_type, 0) if args.arp_protocol_type else 0x0800,
        hwAddrLen=6,
        protoAddrLen=4,
        arp_opcode=_int(args.arp_opcode) if args.arp_opcode else 1,
        arp_sender_mac=args.arp_sender_mac or '00:00:00:00:00:00',
        arp_sender_ip=args.arp_sender_ip or '0.0.0.0',
        arp_target_mac=args.arp_target_mac or '00:00:00:00:00:00',
        arp_target_ip=args.arp_target_ip or '0.0.0.0'
    )

BUILDERS = {
    'tcp': build_tcp,
    'icmp': build_icmp,
    'arp': build_arp,
    'ip': build_ip,
    'udp': build_udp
}

def build_packet(args):
    for proto, builder in BUILDERS.items():
        if getattr(args, proto) is not None:
            return builder(args)
    raise ValueError("Not protocol specified. Use --tcp, --icmp, --arp, --ip, or --udp.")