from PacketCraft import IPheader
from utils import send_layer3_packet

if __name__ == "__main__":
    packet1 = IPheader(4, 5, 0, 28, 0xabcd, 0, 0, 64, 1, "1.1.1.1", "8.8.8.8")
    send_layer3_packet(packet1, 80)