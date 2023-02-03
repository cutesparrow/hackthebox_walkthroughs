# Information gathering

## system network

`10.10.10.117`

## Nmap Scan Result

``` bash
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-03 09:30 CST
Nmap scan report for 10.10.10.117
Host is up (0.15s latency).
Not shown: 65528 closed tcp ports (conn-refused)
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 6.7p1 Debian 5+deb8u4 (protocol 2.0)
| ssh-hostkey: 
|   1024 6a:5d:f5:bd:cf:83:78:b6:75:31:9b:dc:79:c5:fd:ad (DSA)
|   2048 75:2e:66:bf:b9:3c:cc:f7:7e:84:8a:8b:f0:81:02:33 (RSA)
|   256 c8:a3:a2:5e:34:9a:c4:9b:90:53:f7:50:bf:ea:25:3b (ECDSA)
|_  256 8d:1b:43:c7:d0:1a:4c:05:cf:82:ed:c1:01:63:a2:0c (ED25519)
80/tcp    open  http    Apache httpd 2.4.10 ((Debian))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.10 (Debian)
111/tcp   open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100024  1          32889/tcp   status
|   100024  1          37874/udp6  status
|   100024  1          55869/tcp6  status
|_  100024  1          56101/udp   status
6697/tcp  open  irc     UnrealIRCd
8067/tcp  open  irc     UnrealIRCd
32889/tcp open  status  1 (RPC #100024)
65534/tcp open  irc     UnrealIRCd
Service Info: Host: irked.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1141.77 seconds
```

## Directory enumeration


## Password Crack


# Exploit

## Initial Foothold

```bash
nc -vn 10.10.10.117 6697

find version of the irc => Unreal3.2.8.1
```

### Exp

[UnrealIRCE-3.2.8.1 RCE](https://github.com/XorgX304/UnrealIRCd-3.2.8.1-RCE)

### Proof

![[Pasted image 20230103110240.png]]

## Lateral Movement

### Method

find .backup file in home directory of djmardov user.
try to use  Stegextract to extract info from the jpeg picture.

[[steghide]]: It is used to hide or extract infomation into or from a file(usually a picture or documents)

```bash
steghide extract -p UPupDOWNdownLRlrBAbaSSss -sf irked.jpg
```

I got pass.txt file within a password. Use that password to login through ssh


### Proof

![[Pasted image 20230103111410.png]]

## Privilege Escalation

### Method

find a interesting suid binary file called viewuser.
![[Pasted image 20230103113234.png]]

```bash
find / -type f -perm -4000 2>/dev/null
```

from the error message, I indicated that /tmp/listusers may be run by the binary with root permisson. So I created a listusers file in /tmp directory. And the content should be `sh`. Execute `viewuser` directly and we'll get the shell.

### proof

![[Pasted image 20230103113601.png]]