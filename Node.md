# Information gathering

## system network

`10.10.10.58`

## Nmap Scan Result

``` bash
nmap -sC -sTV -Pn  10.10.10.58 -p- -oA node

Not shown: 65533 filtered tcp ports (no-response)
PORT     STATE SERVICE            VERSION
22/tcp   open  ssh                OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 dc:5e:34:a6:25:db:43:ec:eb:40:f4:96:7b:8e:d1:da (RSA)
|   256 6c:8e:5e:5f:4f:d5:41:7d:18:95:d1:dc:2e:3f:e5:9c (ECDSA)
|_  256 d8:78:b8:5d:85:ff:ad:7b:e6:e2:b5:da:1e:52:62:36 (ED25519)
3000/tcp open  hadoop-tasktracker Apache Hadoop
|_http-title: MyPlace
| hadoop-datanode-info: 
|_  Logs: /login
| hadoop-tasktracker-info: 
|_  Logs: /login
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Directory enumeration

1. find /api/user/
2. grep admin username and password hash
![[Pasted image 20221229112553.png]]
3. crack password with hashcat or online
4. get password of admin user: `manchester`
5. login with admin user and download backup file
## Password Crack

```bash
tom - spongebob
mark - snowflake
rastating - 5065db2df0d4ee53562c650c29bacf55b97e231e3fe88570abc9edd8b78ac2f0
myP14ceAdm1nAcc0uNT - manchester
```

# Exploit

## Initial Foothold

_find password in backup file_

![[Pasted image 20221229140733.png]]

### Exp

```bash
ssh mark@10.10.10.58
password: 5AYRft73VtFpc84k
```

### Proof

![[Pasted image 20221229140716.png]]

## Lateral Movement

### Method

_Monitor the process with pspy64, Find process run as tom

![[Pasted image 20221229154509.png]]

_Analyze app.js file_

get a doc object from mongodb. and then use exec to execute it.
![[Pasted image 20221229154623.png]]

_Insert reverse shell code into database and wait for reverse shell_

![[Pasted image 20221229154711.png]]

_get the Reverse shell as `tom` user_

### Proof

![[Pasted image 20221229154350.png]]

## Privilege Escalation

[CVE-2021-4034](https://raw.githubusercontent.com/arthepsy/CVE-2021-4034/main/cve-2021-4034-poc.c)

### Method

use the poc of CVE-2021-4034

### proof

![[Pasted image 20221229155800.png]]


Root Returning to the backup script at /var/www/myplace/app.js, it appears that the SUID binary at /user/local/bin/backup is called with the arguments /usr/local/bin/backup -q 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 /var/www/myplace. Upon closer examination, the binary appears to hit a segmentation fault if enough data is passed (508 bytes) for the third argument (path), and the -q (quiet mode) flag is not set. ASLR and NX are enabled, so the binary must be exploited by going the `ret2libc` route. 

_use checksec tool to identify ASLR and NX flag_
```bash
checksec --file=backup
```

● Find libc address: ldd /usr/local/bin/backup 
`0xf75c3000`
● Find libc system function: readelf -s /lib32/libc.so.6 | grep system
`0x0003a940`
● Find libc exit function: readelf -s /lib32/libc.so.6 | grep exit 
`0x0002e7b0`
● Find libc /bin/sh reference: strings -a -t x /lib32/libc.so.6 | grep /bin/sh 
`0x0015900b`
After the above information has been gathered, it is fairly straightforward to create a script to handle exploitation. Refer to node_bof.py (Appendix A) for a functional example. 

![[Pasted image 20221229162857.png]]