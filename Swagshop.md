# Information gathering

`10.10.10.140`

## Nmap Scan Result

``` bash
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-04 11:43 CST                                                                                      
Nmap scan report for 10.10.10.140                                                                                                                    
Host is up (0.15s latency).                                                                                                                          
Not shown: 998 closed tcp ports (conn-refused)                                                                                                       
PORT   STATE SERVICE VERSION                                                                                                                         
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)                                                                    
| ssh-hostkey:                                                                                                                                       
|   2048 b6:55:2b:d2:4e:8f:a3:81:72:61:37:9a:12:f6:24:ec (RSA)                                                                                       
|   256 2e:30:00:7a:92:f0:89:30:59:c1:77:56:ad:51:c0:ba (ECDSA)                                                                                      
|_  256 4c:50:d5:f2:70:c5:fd:c4:b2:f0:bc:42:20:32:64:34 (ED25519)                                                                                    
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))                                                                                                  
|_http-title: Did not follow redirect to http://swagshop.htb/                                                                                        
|_http-server-header: Apache/2.4.18 (Ubuntu)                                                                                                         
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel                                                                                              
                                                                                                                                                     
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .                                                       
Nmap done: 1 IP address (1 host up) scanned in 23.56 seconds
```

## Service Enumerate

22/tcp ssh
80/tcp http

### Web Enumerate

Magento CE version is at 2014, should be about 1.9.x
the admin panel is at http://swagshop.htb/index.php/admin

## Password Crack
### john

### hydra


# Exploit

## Initial Foothold

[insert admin user](https://www.exploit-db.com/exploits/37977)
[rce](https://www.exploit-db.com/exploits/37811)

### Exploit method



### Vulnerability Explanation

### Exp code or link

### Proof screen shot



## Lateral Movement

### Exploit method

### Exp code or link

### Proof screen shot


## Privilege Escalation

### Exploit method

`sudo -l`

### Exp code or link

https://gtfobins.github.io/gtfobins/vi/

### Proof screen shot