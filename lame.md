# Information gathering

### system IP:

#### service Enumeration
```bash
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 2.3.4
22/tcp  open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

Vulnerability: CVE-2007-2447
Exploit Code: https://github.com/amriunix/CVE-2007-2447/blob/master/usermap_script.py
*screenshot*
![image-20221220144831943](D:\OSCP\hackthebox\attachments\image-20221220144831943.png)

