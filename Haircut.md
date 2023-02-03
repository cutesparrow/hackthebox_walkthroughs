# Information gathering

`10.10.10.24`

## Port Scan 

``` bash
masscan:
sudo masscan -p1-65535 10.10.10.24 -e tun0 --rate=2000
nmap
nmap -sC -sTV -Pn -p80,22 10.10.10.24
```

## Service Enumerate

### Web Enumerate
http://10.10.10.24/exposed.php
### Service 2


## Password Crack
### john

### hydra


# Exploit

## Initial Foothold
1. start evil web server on attack machine.
2. send request
3. access the reverse shell php script
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

### Exp code or link

### Proof screen shot