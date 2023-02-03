# Information gathering

## system network

10.10.10.7

## Nmap Scan Result

``` bash
Starting Nmap 7.92 ( https://nmap.org ) at 2022-12-22 06:09 EST
Nmap scan report for 10.10.10.7
Host is up (0.23s latency).
Not shown: 987 closed tcp ports (conn-refused)
PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 4.3 (protocol 2.0)
25/tcp    open  smtp       Postfix smtpd
80/tcp    open  http       Apache httpd 2.2.3
110/tcp   open  pop3?
111/tcp   open  rpcbind    2 (RPC #100000)
143/tcp   open  imap?
443/tcp   open  ssl/http   Apache httpd 2.2.3 ((CentOS))
880/tcp   open  status     1 (RPC #100024)
993/tcp   open  imaps?
995/tcp   open  pop3s?
3306/tcp  open  mysql?
4445/tcp  open  upnotifyp?
10000/tcp open  http       MiniServ 1.570 (Webmin httpd)
Service Info: Hosts:  beep.localdomain, 127.0.0.1

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 226.14 seconds
```

Exploit

当暴露面这么大的时候，如何下手？

当cve很多的时候，怎么选择？

当爆破目录的时候怎么选择字典？

searchsploit中指定的版本号不一定准