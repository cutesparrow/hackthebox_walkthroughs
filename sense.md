# Information gathering

## system network

10.10.10.60

## Nmap Scan Result

``` bash
PORT    STATE SERVICE  VERSION
80/tcp  open  http     lighttpd 1.4.35
|_http-title: Did not follow redirect to https://10.10.10.60/
|_http-server-header: lighttpd/1.4.35
443/tcp open  ssl/http lighttpd 1.4.35
|_http-title: Login
| ssl-cert: Subject: commonName=Common Name (eg, YOUR name)/organizationName=CompanyName/stateOrProvinceName=Somewhere/countryName=US
| Not valid before: 2017-10-14T19:21:35
|_Not valid after:  2023-04-06T19:21:35
|_ssl-date: TLS randomness does not represent time
|_http-server-header: lighttpd/1.4.35
```

Enum

```bash
/usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-medium.txt:system-users
/usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt:system-users
```

Exploit

[poc]: https://www.exploit-db.com/exploits/43560	"CVE-2014-4688"

#### Proof

![image-20221223171700514](D:\OSCP\hackthebox\attachments\image-20221223171700514.png)

