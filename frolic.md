# Information gathering

## Port Scan

``` bash
10.10.10.111
```

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



## Lateral Movement

### Exploit method

### Exp code or link

### Proof screen shot


## Privilege Escalation

### Exploit method

### Exp code or link

### Proof screen shot

奇怪编程语言 解码 ：https://www.splitbrain.org/_static/ook/


因为 gdb gef 中checksec发现 NX启用了， 所以只能 return to libc
return to libc 教程：
1. https://snowscan.io/htb-writeup-frolic/#
2. https://blog.nihilism.network/HTB/Easy/23.html
3. https://hipotermia.pw/htb/frolic

利用one gadget 工具

https://blog.nihilism.network/HTB/Easy/23.html

![[Pasted image 20230203161220.png]]


[[generate return 2 libc payload]]![[Pasted image 20230203163732.png]]


exploit

```
./rop `python3 payload2.py`
```