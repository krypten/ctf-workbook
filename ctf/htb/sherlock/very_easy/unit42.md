# Unit42 (Very Easy)

<img src="https://labs.hackthebox.com/storage/challenges/abd815286ba1007abfbb8415b83ae2cf.png" alt="logo" width="75"/>

## Scenario

In this Sherlock, you will familiarize yourself with Sysmon logs and various useful EventIDs for identifying and analyzing malicious activities on a Windows system. Palo Alto's Unit42 recently conducted research on an UltraVNC campaign, wherein attackers utilized a backdoored version of UltraVNC to maintain access to systems. This lab is inspired by that campaign and guides participants through the initial access stage of the campaign.

## Analysis

Checking the file types:
```
$ file Microsoft-Windows-Sysmon-Operational.evtx
Microsoft-Windows-Sysmon-Operational.evtx: MS Windows Vista Event Log, 3 chunks (no. 2 in use), next record no. 170
```

For analysis on `evtx` file, we will use [chainsaw](https://github.com/WithSecureLabs/chainsaw) tool.
```
$ ./chainsaw search -t 'Event.System.EventID: =11' ~/Microsoft-Windows-Sysmon-Operational.evtx

[+] Loading forensic artefacts from: ~/Microsoft-Windows-Sysmon-Operational.evtx
[+] Loaded 1 forensic files (1.1 MB)
[+] Searching forensic artefacts...
[+] Found 56 hits
```

System EventID 11 is for driver access and sysmon EventId 11 is mentioned to be `FileCreate` at https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon with description as:
> File create operations are logged when a file is created or overwritten. This event is useful for monitoring autostart locations, like the Startup folder, as well as temporary and download directories, which are common places malware drops during initial infection.

Just getting list of programs which were autorun:
```
$ ./chainsaw search -t 'Event.System.EventID: =11' ~/Microsoft-Windows-Sysmon-Operational.evtx | grep 'Image' | sort | uniq

Image: C:\Program Files\Mozilla Firefox\firefox.exe
Image: C:\Users\CyberJunkie\Downloads\Preventivo24.02.14.exe.exe
Image: C:\Windows\system32\mmc.exe
Image: C:\Windows\system32\msiexec.exe
Image: C:\Windows\system32\svchost.exe
```

Now we will check for process creation at event id 1 which is described as:
> The process creation event provides extended information about a newly created process. The full command line provides context on the process execution. The ProcessGUID field is a unique value for this process across a domain to make event correlation easier. The hash is a full hash of the file with the algorithms in the HashType field.

Let's get all the commands which exected to create a process.
```
$ ./chainsaw search -t 'Event.System.EventID: =1' ~/Microsoft-Windows-Sysmon-Operational.evtx

[+] Searching forensic artefacts...
    CommandLine: '"C:\Program Files\Mozilla Firefox\pingsender.exe" https://incoming.telemetry.mozilla.org/submit/telemetry/cb88145b-129d-471c-b605-4fdf09fec680/event/Firefox/122.0.1/release/20240205133611?v=4 C:\Users\CyberJunkie\AppData\Roaming\Mozilla\Firefox\Profiles\avsa4d81.default-release\saved-telemetry-pings\cb88145b-129d-471c-b605-4fdf09fec680 https://incoming.telemetry.mozilla.org/submit/telemetry/6fcd92a2-cc60-4df6-b6fb-66356dd011c1/main/Firefox/122.0.1/release/20240205133611?v=4 C:\Users\CyberJunkie\AppData\Roaming\Mozilla\Firefox\Profiles\avsa4d81.default-release\saved-telemetry-pings\6fcd92a2-cc60-4df6-b6fb-66356dd011c1'
    CommandLine: '"C:\Users\CyberJunkie\Downloads\Preventivo24.02.14.exe.exe" '
    CommandLine: C:\Windows\system32\msiexec.exe /V
    CommandLine: C:\Windows\syswow64\MsiExec.exe -Embedding 5364C761FA9A55D636271A1CE8A6742D C
    CommandLine: '"C:\Windows\system32\msiexec.exe" /i "C:\Users\CyberJunkie\AppData\Roaming\Photo and Fax Vn\Photo and vn 1.1.2\install\F97891C\main1.msi" AI_SETUPEXEPATH=C:\Users\CyberJunkie\Downloads\Preventivo24.02.14.exe.exe SETUPEXEDIR=C:\Users\CyberJunkie\Downloads\ EXE_CMD_LINE="/exenoupdates  /forcecleanup  /wintime 1707880560  " AI_EUIMSI=""'
    CommandLine: C:\Windows\syswow64\MsiExec.exe -Embedding 5250A3DB12224F77D2A18B4EB99AC5EB
[+] Found 6 hits
```

Now let's take a look at DNS queries at event id 22 to identify which websites were reached to download this.
>  This event is generated when a process executes a DNS query, whether the result is successful or fails, cached or not. The telemetry for this event was added for Windows 8.1 so it is not available on Windows 7 and earlier.


Getting the list of queries:
```
$ ./chainsaw search -t 'Event.System.EventID: =22' ~/Microsoft-Windows-Sysmon-Operational.evtx

QueryName: uc2f030016253ec53f4953980a4e.dl.dropboxusercontent.com
QueryName: d.dropbox.com
QueryName: www.example.com
```

Looks like dropbox was used to get the malware.


Checking the change to file creation time which is recorded by event id 2.
```
$ ./chainsaw search -t 'Event.System.EventID: =2' ~/Microsoft-Windows-Sysmon-Operational.evtx
...
Event:
  EventData:
    CreationUtcTime: 2024-01-14 08:10:06.029
    Image: C:\Users\CyberJunkie\Downloads\Preventivo24.02.14.exe.exe
    PreviousCreationUtcTime: 2024-02-14 03:41:58.404
    ProcessId: 10672
    RuleName: technique_id=T1070.006,technique_name=Timestomp
    TargetFilename: C:\Users\CyberJunkie\AppData\Roaming\Photo and Fax Vn\Photo and vn 1.1.2\install\F97891C\TempFolder\~.pdf
    User: DESKTOP-887GK2L\CyberJunkie
    UtcTime: 2024-02-14 03:41:58.404
  System:
    Computer: DESKTOP-887GK2L
    EventID: 2
    Security_attributes:
      UserID: S-1-5-18
...
```

This looks like the malware modified the timestamp of some pdf file to `2024-01-14 08:10:06` from `2024-02-14 03:41:58`.

---

**Task 1: How many Event logs are there with Event ID 11?**
> 56

**Task 2: Whenever a process is created in memory, an event with Event ID 1 is recorded with details such as command line, hashes, process path, parent process path, etc. This information is very useful for an analyst because it allows us to see all programs executed on a system, which means we can spot any malicious processes being executed. What is the malicious process that infected the victim's system?**
> C:\Users\CyberJunkie\Downloads\Preventivo24.02.14.exe.exe

**Task 3: Which Cloud drive was used to distribute the malware?**
> dropbox

**Task 4: The initial malicious file time-stamped (a defense evasion technique, where the file creation date is changed to make it appear old) many files it created on disk. What was the timestamp changed to for a PDF file?**
> 2024-01-14 08:10:06

---


We are now half way through, let's try to identify other files created by the malware:
```
$ ./chainsaw search -t 'Event.EventData.Image: C:\Users\CyberJunkie\Downloads\Preventivo24.02.14.exe.exe' -t 'Event.System.EventID: =11' ~/Microsoft-Windows-Sysmon-Operational.evtx

TargetFilename: C:\Users\CyberJunkie\AppData\Roaming\Photo and Fax Vn\Photo and vn 1.1.2\install\F97891C\WindowsVolume\Games\c.cmd
TargetFilename: C:\Users\CyberJunkie\AppData\Roaming\Photo and Fax Vn\Photo and vn 1.1.2\install\F97891C\WindowsVolume\Games\cmmc.cmd
TargetFilename: C:\Users\CyberJunkie\AppData\Roaming\Photo and Fax Vn\Photo and vn 1.1.2\install\F97891C\WindowsVolume\Games\on.cmd
TargetFilename: C:\Users\CyberJunkie\AppData\Roaming\Photo and Fax Vn\Photo and vn 1.1.2\install\F97891C\WindowsVolume\Games\once.cmd
TargetFilename: C:\Users\CyberJunkie\AppData\Roaming\Photo and Fax Vn\Photo and vn 1.1.2\install\F97891C\WindowsVolume\Games\taskhost.exe
TargetFilename: C:\Users\CyberJunkie\AppData\Roaming\Photo and Fax Vn\Photo and vn 1.1.2\install\F97891C\WindowsVolume\Games\viewer.exe
```

Looks like multiple were created in `C:\Users\CyberJunkie\AppData\Roaming\Photo and Fax Vn\Photo and vn 1.1.2\install\F97891C\WindowsVolume\Games` folder.

Checking the network connects the malware tried to make using event id 3.
```
$ ./chainsaw search -t 'Event.System.EventID: =3' ~/Microsoft-Windows-Sysmon-Operational.evtx

---
Event:
  EventData:
    DestinationIp: 93.184.216.34
    DestinationIsIpv6: false
    DestinationPort: 80
    Image: C:\Users\CyberJunkie\Downloads\Preventivo24.02.14.exe.exe
    RuleName: technique_id=T1036,technique_name=Masquerading
    SourceIp: 172.17.79.132
    SourceIsIpv6: false
    SourcePort: 61177
    User: DESKTOP-887GK2L\CyberJunkie
    UtcTime: 2024-02-14 03:41:57.159
  System:
    Computer: DESKTOP-887GK2L
    EventID: 3
    Task: 3
    TimeCreated_attributes:
      SystemTime: 2024-02-14T03:41:58.905483Z
    Version: 5

[+] Found 1 hits
```

Looke like they tried to reach out to `93.184.216.34` from earlier logs we also know that this is `www.example.com`.

Checking for when did this malware process end (Event Id: 5 - ProcessTerminate):

```
$ ./chainsaw search -t 'Event.System.EventID: =5' ~/Microsoft-Windows-Sysmon-Operational.evtx

Event:
  EventData:
    Image: C:\Users\CyberJunkie\Downloads\Preventivo24.02.14.exe.exe
    ProcessId: 10672
    User: DESKTOP-887GK2L\CyberJunkie
    UtcTime: 2024-02-14 03:41:58.795
  System:
    EventID: 5
    Execution_attributes:
      ProcessID: 3028
      ThreadID: 4412
    TimeCreated_attributes:
      SystemTime: 2024-02-14T03:41:58.799651Z

[+] Found 1 hits
```

So the malware process ended at `2024-02-14 03:41:58`.

---

**Task 5: The malicious file dropped a few files on disk. Where was "once.cmd" created on disk? Please answer with the full path along with the filename.**
> C:\Users\CyberJunkie\AppData\Roaming\Photo and Fax Vn\Photo and vn 1.1.2\install\F97891C\WindowsVolume\Games\once.cmd

**Task 6: The malicious file attempted to reach a dummy domain, most likely to check the internet connection status. What domain name did it try to connect to?**
> www.example.com

**Task 7: Which IP address did the malicious process try to reach out to?**
> 93.184.216.34

**Task 8: The malicious process terminated itself after infecting the PC with a backdoored variant of UltraVNC. When did the process terminate itself?**
> 2024-02-14 03:41:58

---
