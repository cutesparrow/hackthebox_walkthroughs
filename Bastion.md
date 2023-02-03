# Information gathering

## Port Scan

``` bash
10.10.10.134
```

## Service Enumerate

### Web Enumerate

### SMBClient
backups share, get SAM and SYSTEM files.
C:\\Windows\\System32\\config\

## Password Crack
### john

### hydra

### dump credential from SAM and SYSTEM
```
impacket-secretsdump 

hashcat -m 1000 password.hash rockyou.txt
#L4mpje:bureaulampje
```

# Exploit

## Initial Foothold

### Exploit method

### Vulnerability Explanation

### Exp code or link

### Proof screen shot

![[Pasted image 20230131093447.png]]

## Lateral Movement

### Exploit method
![[Pasted image 20230131100414.png]]
### Exp code or link

### Proof screen shot


## Privilege Escalation

### Exploit method

### Exp code or link

### Proof screen shot