# Information gathering
`10.10.10.6`
## Nmap Scan Result

``` bash
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-06 09:37 CST
Nmap scan report for 10.10.10.6
Host is up (0.15s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 5.1p1 Debian 6ubuntu2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 3e:c8:1b:15:21:15:50:ec:6e:63:bc:c5:6b:80:7b:38 (DSA)
|_  2048 aa:1f:79:21:b8:42:f4:8a:38:bd:b8:05:ef:1a:07:4d (RSA)
80/tcp open  http    Apache httpd 2.2.12 ((Ubuntu))
|_http-server-header: Apache/2.2.12 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 29.82 seconds
```

## Service Enumerate


### Web Enumerate

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-small-words-lowercase.txt  -u http://10.10.10.6/FUZZ
```



### Service 2


## Password Crack
### john

### hydra


# Exploit
shell upload
## Initial Foothold
Upload a webshell php file as the background picture.
![[Pasted image 20230106104613.png]]
### Exploit method
set up listener and then acess the url to trigger the reverse shell.
```bash
http://10.10.10.6/torrent/upload/6c57fce73fdc10da4abdcb5a2fdd65096fc653e9.php?cmd=whoami
```

### Vulnerability Explanation

### Exp code or link

### Proof screen shot

![[Pasted image 20230106104747.png]]

## Lateral Movement

### Exploit method

1. grep database password in config.php file
![[Pasted image 20230106104858.png]]
2. 
### Exp code or link

### Proof screen shot


## Privilege Escalation

https://www.exploit-db.com/exploits/14339

### Exploit method
在home cache目录发现这个文件`motd.legal-displayed`
考虑PAM提权。
https://www.exploit-db.com/exploits/14339
PAM 1.1.0 suffer privilege escalation vuln.
### Exp code or link

### Proof screen shot