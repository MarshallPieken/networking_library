"""
Basic program for turning ASCII characters into byte hex for ease of packet payload dumping.

Purpose: These can be pre/appended into a variable with other binary hex, and get sent to a target address or domain via socket's sendto() method as a form of autmocation.

Pentesting application: delivering payloads via HTTP (and other) packets. This is the beginning of bing able to use socket() in python to delvier payloads.

"""
import re
import binascii

#-------------------------------------------------------------------------------------------------#
def ascii_to_hex_bytes(ascii_input: str):

    #convert to hex
    raw_hex = binascii.hexlify(ascii_input.encode('ascii')).decode('ascii')
    print(f"[*] Processing... Here's the raw hex:\n {raw_hex}\n")

    # add in \x per each hex byte
    packet_hex = re.sub(r'([0-9A-Fa-f]{2})', r'\\x\1', raw_hex)

    return packet_hex
    
#-------------------------------------------------------------------------------------------------#
if __name__ == "__main__":
    
    ascii_input = """
GET / HTTP/1.1\r\n
Host: example.com\r\n
User-Agent: MyClient/1.0\r\n
\r\n
    """
    print(f"[*] Starting HTTP request headers: {ascii_input}")
    
    #convert to hex with \x prepends
    result = ascii_to_hex_bytes(ascii_input)
    print(f"[*] Finshed! Result: \n{result}\n\n")
    
    print("==================================================================================================\n")
    
    ascii_input_2 = """
POST / HTTP/1.1\r\n
Accept: */*\r\n
Accept-Encoding: gzip, deflate, br, zstd\r\n
Accept-Language: en-US,en;q=0.9\r\n
Connection:	keep-alive\r\n
Host: www.marshall.edu\r\n
Referer: https://www.marshall.edu/\r\n
Sec-Fetch-Dest:	script\r\n
Sec-Fetch-Mode:	no-cors\r\n
Sec-Fetch-Site:	same-origin\r\n
User-Agent:	Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:151.0) Gecko/20100101 Firefox/151.0\r\n
    \r\n
    """
    print(f"[*] Starting HTTP request headers: {ascii_input_2}")
    
    #convert to hex with \x prepends
    result = ascii_to_hex_bytes(ascii_input_2)
    print()
    print(f"[*] Finshed! Result: \n{result}\n\n")
    