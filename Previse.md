# Information gathering
10.10.11.104
## Port Scan

``` bash
# masscan
sudo masscan -p 1-65535 10.10.11.104 --rate=10000 -e tun0
[sudo] password for kali: 
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2023-01-11 06:12:25 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [65535 ports/host]
Discovered open port 80/tcp on 10.10.11.104                                    
Discovered open port 22/tcp on 10.10.11.104 

# nmap
nmap -sC -sTV -Pn -p22,80 10.10.11.104 -oA previse       
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-11 14:14 CST
Nmap scan report for 10.10.11.104
Host is up (0.31s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 53:ed:44:40:11:6e:8b:da:69:85:79:c0:81:f2:3a:12 (RSA)
|   256 bc:54:20:ac:17:23:bb:50:20:f4:e1:6e:62:0f:01:b5 (ECDSA)
|_  256 33:c1:89:ea:59:73:b1:78:84:38:a4:21:10:0c:91:d8 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-title: Previse Login
|_Requested resource was login.php
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.44 seconds
```

## Service Enumerate

### Web Enumerate



### Service 2


## Password Crack
### john

### hydra


# Exploit

## Initial Foothold

1. create new user
![[Pasted image 20230111151108.png]]

2. command injection
![[Pasted image 20230111153039.png]]

3. get reverse shell
![[Pasted image 20230111153008.png]]

4. get password hash in mysql databases
```bash
$1$🧂llol$DQpmdvnb7EeuO6UaqRItf.
```

5. crack m4lwhere password with john
![[Pasted image 20230111160631.png]]
### Exploit method

### Vulnerability Explanation

### Exp code or link

### Proof screen shot



## Lateral Movement

### Exploit method
1. ssh login with the credential cracked at last stage.

### Exp code or link

### Proof screen shot


## Privilege Escalation

### Exploit method
1. `sudo -l` to find out that m4lwhere use can run access_backup.sh with root privilege.
2. edit PATH env variable, insert /tmp directory at the first position of PATH. create gzip and add execute permission. The content is reverse shell. 
![[Pasted image 20230111163428.png]]

### Exp code or link

### Proof screen shot