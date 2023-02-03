# Information gathering
10.10.10.37
## Port Scan

``` bash
# masscan

# nmap

Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-09 19:13 CST                                                                                                                                                                      
Nmap scan report for 10.10.10.37                                                                                  
Host is up (0.15s latency).                                                                                       
                                                         
PORT      STATE SERVICE   VERSION                                                                                 
21/tcp    open  ftp       ProFTPD 1.3.5a                                                                          
22/tcp    open  ssh       OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)                                                                                                                                               
| ssh-hostkey:                                                                                                    
|   2048 d6:2b:99:b4:d5:e7:53:ce:2b:fc:b5:d7:9d:79:fb:a2 (RSA)                                                                                                                                                                       
|   256 5d:7f:38:95:70:c9:be:ac:67:a0:1e:86:e7:97:84:03 (ECDSA)                                                                                                                                                                      
|_  256 09:d5:c2:04:95:1a:90:ef:87:56:25:97:df:83:70:67 (ED25519)                                                                                                                                                                    
80/tcp    open  http      Apache httpd 2.4.18                                                                     
|_http-title: Did not follow redirect to http://blocky.htb                                                        
|_http-server-header: Apache/2.4.18 (Ubuntu)                                                                      
25565/tcp open  minecraft Minecraft 1.11.2 (Protocol: 127, Message: A Minecraft Server, Users: 0/20)                                                                                                                                 
Service Info: Host: 127.0.1.1; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel                                                                                                                                                      

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .                                                                                                                                       
Nmap done: 1 IP address (1 host up) scanned in 13.01 seconds
```

## Service Enumerate

### Web Enumerate

find plugins directory, and two jar packages which include a credential. 
![[Pasted image 20230109195003.png]]




## Password Crack
### john

### hydra


# Exploit

## Initial Foothold
Login phpmyadmin with the credential.

update the password hash in wp_user table.

Login wordpress admin panel.

rce

![[Pasted image 20230109200920.png]]

### Exploit method

### Vulnerability Explanation

### Exp code or link

### Proof screen shot



## Lateral Movement
ssh into notch with same credential
### Exploit method

### Exp code or link

### Proof screen shot


## Privilege Escalation
sudo -i to raise root shell
### Exploit method

### Exp code or link

### Proof screen shot

![[Pasted image 20230109202643.png]]