"""
Basic program for turning ASCII characters into byte hex for ease of packet payload dumping.

Purpose: These can be pre/appended into a variable with other binary hex, and get sent to a target address or domain via socket's sendto() method as a form of autmocation. 

Methods:
- ascii_to_hex_bytes: converts ascii to hexbytes.
- ipv4_to_byte_hex: takes an ipv4 string and outputs it in 

TODO: 
- Make another method which translates IPv6 into byte hex?

"""
import re
import binascii

#-------------------------------------------------------------------------------------------------#
def ascii_to_hex_bytes(ascii_input: str):
    """
    encodes(decodes?) ASCII to hex bytes.

    args:
    - ascii_input: The header infromation to be converted

    returns:
    - raw_hex: hexbyte-converted ASCII. 
    """

    #convert to hex
    raw_hex = binascii.a2b_hex(binascii.hexlify(ascii_input.encode()))

    return raw_hex
    
#-------------------------------------------------------------------------------------------------#
def ipv4_to_byte_hex(ipstr: str):
    """
    Converts IPv4 to hex bytes for loading into the rest of the program. This will be a useful helper fcuntion in designing a program to custom-load & send packets.

    args:
    - ipstr: the user-identified IP which they wish to convert.

    returns: 
    - out: the hex-converted IPv4 address.
    """

    #use regex to translate ip address into hex
    split_ip: list[str] = ipstr.split(".")

    if len(split_ip) != 4:
        print("Not a real IPv4 - check the input")
        exit(code=5)
    
    out = b""
    for n in split_ip:
        if not n.isdigit():
            print("It's gotta be a digit")
            exit(code=5)
        out += binascii.a2b_hex(hex(int(n)).replace("0x","").zfill(2))
    return out



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
Referer: https://www.marshall.edu/\r\n\xff
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

print(ipv4_to_byte_hex("7.7.7.7")) 