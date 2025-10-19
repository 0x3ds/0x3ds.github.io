---
title: "HTB - Noxious"
author: [0x3ds]
date: 2025-10-19 16:00:00 +1000 #update date
description: "In this sherlock, players will go through network traffic and uncover credential-stealing technique by abusing the LLMNR protocol feature in Windows. Players will learn how a victim made a typo navigating to a network share and how the attacker was using the Responder tool to steal hashes and pose as a legitimate device in the internal network. Players will also learn to crack NTLMV2 hashes by gathering information from SMB traffic."
categories: [Hack The Box, Sherlocks - SOC]
tags: [htb-noxious, noxious, hackthebox, sherlock, IDS, very-easy, IPS, network, analysis, logs, event-logs, SOC, security, response, LLMNR, NTLMV2, smb, responder]
image:
  path: /assets/img/posts/htb/sherlocks/SOC/very-easy/noxious/noxious_infocard.png
cover: /assets/img/posts/htb/sherlocks/SOC/very-easy/noxious/noxious_infocard.png
---

## Sherlock Scenario

The IDS device alerted us to a possible rogue device in the internal Active Directory network. The Intrusion Detection System also indicated signs of LLMNR traffic, which is unusual. It is suspected that an LLMNR poisoning attack occurred. The LLMNR traffic was directed towards `Forela-WKstn002`, which has the IP address `172.17.79.136`. A limited packet capture from the surrounding time is provided to you, our Network Forensics expert. Since this occurred in the Active Directory VLAN, it is suggested that we perform network threat hunting with the Active Directory attack vector in mind, specifically focusing on LLMNR poisoning.



### Task 1

> Its suspected by the security team that there was a rogue device in Forela's internal network running responder tool to perform an LLMNR Poisoning attack. Please find the malicious IP Address of the machine.
{: .prompt-info }

After unzipping the files provided to us for the Sherlock, we can go ahead and list out what evidence files we have to work with.

```zsh
0x3ds@kali $ la

total 261M
-rw-rw-r-- 1 0x3ds 0x3ds   131M Jun 24  2024 capture.pcap
-rw-r--r-- 1 0x3ds dialout 130M Oct 19 19:11 noxious.zip
```

We can see that we have a `capture.pcap` file, which is a file containing captured network packet data.

We can go ahead and utilise `wireshark` to analyse the evidence file and view the contents of the captured network packet data.

```zsh
0x3ds@kali $ wireshark capture.pcap

```

This opens up the GUI version of the `wireshark` tool as we can see below.

![light mode only](/assets/img/posts/htb/sherlocks/SOC/very-easy/noxious/wireshark_1.png){: .light .w-100 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/sherlocks/SOC/very-easy/noxious/wireshark_1.png){: .dark .w-100 .shadow .rounded-10 w='1212' h='668' }


From the scenario briefing, we understand that there has been a suspected LLMNR poisoning attack that occurred, where the LLMNR traffic was directed towards `Forela-WKstn002`, which has the IP address `172.17.79.136`. 

As such, we can apply a filter for the IP Address `172.17.79.136` to analyse the events that occurred involving this host by entering `ip.addr == 172.17.79.136` into the filter bar.

![light mode only](/assets/img/posts/htb/sherlocks/SOC/very-easy/noxious/wireshark_2.png){: .light .w-75 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/sherlocks/SOC/very-easy/noxious/wireshark_2.png){: .dark .w-75 .shadow .rounded-10 w='1212' h='668' }



We can also apply a display filter using the shortcut `CTRL + F` for the protocol `llmnr` to find the first instance of LLMNR network packets.

![light mode only](/assets/img/posts/htb/sherlocks/SOC/very-easy/noxious/wireshark_3.png){: .light .w-100 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/sherlocks/SOC/very-easy/noxious/wireshark_3.png){: .dark .w-100 .shadow .rounded-10 w='1212' h='668' }


We can now see that the potential victim host `Forela-WKstn002` (IP Address: `172.17.79.136`) has performed a query for `DCC01` which may be a typo for the actual legitimate `DC01`.

Reviewing the packets that occurred prior to this, we can see that a query at **packet 9241** was made for `DCC01.forela.local` to the legitimate domain controller `172.17.79.4`. However, no host was found with that name as per the query response at **packet 9242**. Further, then we can see at **packet 9269** that there was a query response from the malicious IP `172.17.79.135` claiming to be `DCC01`.

![light mode only](/assets/img/posts/htb/sherlocks/SOC/very-easy/noxious/wireshark_4.png){: .light .w-100 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/sherlocks/SOC/very-easy/noxious/wireshark_4.png){: .dark .w-100 .shadow .rounded-10 w='1212' h='668' }

Based upon the analysis thus far, it appears that a typo of `DCC01` occurred when attempting to navigate to a legitimate network share `DC01`. Since the network share does not actually exist, it turned to the Link-Local Multicast Name Resolution (LLMNR) protocol to attempt to resolve it. However, the malicious actor at IP Address `172.17.79.135` was there to perform a LLMNR Poison attack.


> **Answer: `172.17.79.135`**
{: .prompt-tip }



---
### Task 2

> What is the hostname of the rogue machine?
{: .prompt-info }


Now that we know the IP Address of the malicious actor, we can attempt to uncover the hostname of their machine. A quick way to achieve this is to analyse the DHCP packets that involve `172.17.79.135` as the source address as this typically would include the hostname.

To do this, we can apply a filter for malicious IP Address and the DHCP protocol. Our filter will be:\
`ip.addr == 172.17.79.135 && dhcp`

![light mode only](/assets/img/posts/htb/sherlocks/SOC/very-easy/noxious/wireshark_5.png){: .light .w-100 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/sherlocks/SOC/very-easy/noxious/wireshark_5.png){: .dark .w-100 .shadow .rounded-10 w='1212' h='668' }


We can see at **packet 12714** the DHCP Request. We can select this packet and analyse the details inside of it.

![light mode only](/assets/img/posts/htb/sherlocks/SOC/very-easy/noxious/wireshark_6.png){: .light .w-75 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/sherlocks/SOC/very-easy/noxious/wireshark_6.png){: .dark .w-75 .shadow .rounded-10 w='1212' h='668' }

As we can see, the malicious actor's hostname is `kali`. 


> **Answer: `kali`**
{: .prompt-tip }



---
### Task 3

> Now we need to confirm whether the attacker captured the user's hash and it is crackable!! What is the username whose hash was captured?
{: .prompt-info }

To discover the username whose hash was captured, we will need to identify packets where there is authentication negotiations. Responder can capture the NTLM hashes, thus we can apply a filter to try and identify these packets around the LLMNR poisoning attacks. To do this, we will apply the filter to find both packets for the LLMNR and SMB2 protocols. Our filter will be: `llmnr or smb2`.

![light mode only](/assets/img/posts/htb/sherlocks/SOC/very-easy/noxious/wireshark_7.png){: .light .w-100 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/sherlocks/SOC/very-easy/noxious/wireshark_7.png){: .dark .w-100 .shadow .rounded-10 w='1212' h='668' }

From the packets that we have filtered for, we can clearly see NTLM authentication negotiation packets immediately after the LLMNR packets. Additionally, we can see that there is a username in **packet 9292** which is `john.deacon`.


> **Answer: `john.deacon`**
{: .prompt-tip }



---
### Task 4

> In NTLM traffic we can see that the victim credentials were relayed multiple times to the attacker's machine. When were the hashes captured the First time?
{: .prompt-info }


Since we have already identified the first set of NTLM authentication negotiation packets in **Task 3**, we can simply either amend our view settings in wireshark to have the time column display in UTC time, or we could also select the packet and view the details of it. 

![light mode only](/assets/img/posts/htb/sherlocks/SOC/very-easy/noxious/wireshark_8.png){: .light .w-75 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/sherlocks/SOC/very-easy/noxious/wireshark_8.png){: .dark .w-75 .shadow .rounded-10 w='1212' h='668' }

From the details of **packet 9292**, we can see that the UTC Arrival Time is June 24, 2024 at 11:18:30 UTC.


> **Answer: `2024-06-24 11:18:30`**
{: .prompt-tip }



---
### Task 5

> What was the typo made by the victim when navigating to the file share that caused his credentials to be leaked?
{: .prompt-info }

As we had discovered in **Task 1**, we can see that a query at **packet 9241** was made for `DCC01.forela.local` to the legitimate domain controller `172.17.79.4`. However, no host was found with that name as per the query response at **packet 9242**. Further, then we can see at **packet 9269** that there was a query response from the malicious IP `172.17.79.135` claiming to be `DCC01`.

![light mode only](/assets/img/posts/htb/sherlocks/SOC/very-easy/noxious/wireshark_4.png){: .light .w-100 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/sherlocks/SOC/very-easy/noxious/wireshark_4.png){: .dark .w-100 .shadow .rounded-10 w='1212' h='668' }

It appears that a typo of `DCC01` occurred when attempting to navigate to a legitimate network share `DC01`. Since the network share does not actually exist, it turned to the Link-Local Multicast Name Resolution (LLMNR) protocol to attempt to resolve it. However, the malicious actor at IP Address `172.17.79.135` was there to perform a LLMNR Poison attack.


> **Answer: `DCC01`**
{: .prompt-tip }



---
### Task 6

> To get the actual credentials of the victim user we need to stitch together multiple values from the ntlm negotiation packets. What is the NTLM server challenge value?
{: .prompt-info }

To obtain the user's NTLM hash we need to stitch together various values from the NTLM authentication negotiation packets. 

First, we need to obtain the *NTLM Server Challenge* value. We can find this by locating the `NTLMSSP_Challenge` packet which can be found at **packet 9291**. We can select this packet and view the details of it.

![light mode only](/assets/img/posts/htb/sherlocks/SOC/very-easy/noxious/wireshark_9.png){: .light .w-100 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/sherlocks/SOC/very-easy/noxious/wireshark_9.png){: .dark .w-100 .shadow .rounded-10 w='1212' h='668' }

Upon reviewing the details of the packet, we can see the NTLM Server Challenge value is `601019d191f054f1`.


> **Answer: `601019d191f054f1`**
{: .prompt-tip }



---
### Task 7

> Now doing something similar find the NTProofStr value.
{: .prompt-info }

To obtain the `NTProofStr` value, we need to locate the `NTLMSSP_AUTH` packet. We can see this at **packet 9292**. We can select this packet and view the details of it.

![light mode only](/assets/img/posts/htb/sherlocks/SOC/very-easy/noxious/wireshark_10.png){: .light .w-100 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/sherlocks/SOC/very-easy/noxious/wireshark_10.png){: .dark .w-100 .shadow .rounded-10 w='1212' h='668' }

After analysing the details of the packet, we are able to see that the NTProofStr value is `c0cc803a6d9fb5a9082253a04dbd4cd4`.


> **Answer: `c0cc803a6d9fb5a9082253a04dbd4cd4`**
{: .prompt-tip }


---
### Task 8

> To test the password complexity, try recovering the password from the information found from packet capture. This is a crucial step as this way we can find whether the attacker was able to crack this and how quickly.
{: .prompt-info }


To test the password complexity by way of attempting to recover the password from the information found from the packet capture, we are essentially trying to crack the password hash and see if we are successful along with how easily it was. This is to to see if the malicious actor would be able to crack the hash and obtain the clear text password easily.

First, we need to understand the structure of the values we are attempting to stitch together:\
`User::Domain:ServerChallenge:NTProofStr:NTLMv2Response` \
Where we remove the first 16 bytes from the `NTLMv2Response` (since this is equivalent to the `NTProofStr` value).

Reviewing what we know so far:
- [x] User = `john.deacon`
- [x] Domain = `FORELA`
- [x] ServerChallenge = `601019d191f054f1`
- [x] NTProofStr = `c0cc803a6d9fb5a9082253a04dbd4cd4`
- [ ] NTLMv2Response

To obtain the `NTLMv2Response` value, we can refer to the same `NTLMSSP_AUTH` packet from **Task 7** being **packet 9292**, where just above the `NTProofStr` value is the `NTLMv2Response` value.

![light mode only](/assets/img/posts/htb/sherlocks/SOC/very-easy/noxious/wireshark_11.png){: .light .w-100 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/sherlocks/SOC/very-easy/noxious/wireshark_11.png){: .dark .w-100 .shadow .rounded-10 w='1212' h='668' }

We can copy this value to obtain the full `NTLMv2Response` value and then remove the first 16 bytes to be left with only the relevant part we need:\
`010100000000000080e4d59406c6da01cc3dcfc0de9b5f2600000000020008004e0042004600590001001e00570049004e002d00360036004100530035004c003100470052005700540004003400570049004e002d00360036004100530035004c00310047005200570054002e004e004200460059002e004c004f00430041004c00030014004e004200460059002e004c004f00430041004c00050014004e004200460059002e004c004f00430041004c000700080080e4d59406c6da0106000400020000000800300030000000000000000000000000200000eb2ecbc5200a40b89ad5831abf821f4f20a2c7f352283a35600377e1f294f1c90a001000000000000000000000000000000000000900140063006900660073002f00440043004300300031000000000000000000`

We can now go ahead and put all of these values together in the correct format. After stitching together all the values, this makes:\
`john.deacon::FORELA:601019d191f054f1:c0cc803a6d9fb5a9082253a04dbd4cd4:010100000000000080e4d59406c6da01cc3dcfc0de9b5f2600000000020008004e0042004600590001001e00570049004e002d00360036004100530035004c003100470052005700540004003400570049004e002d00360036004100530035004c00310047005200570054002e004e004200460059002e004c004f00430041004c00030014004e004200460059002e004c004f00430041004c00050014004e004200460059002e004c004f00430041004c000700080080e4d59406c6da0106000400020000000800300030000000000000000000000000200000eb2ecbc5200a40b89ad5831abf821f4f20a2c7f352283a35600377e1f294f1c90a001000000000000000000000000000000000000900140063006900660073002f00440043004300300031000000000000000000`


We can go ahead and copy it and put it into a file that we will pass to `hashcat` to try and crack.

```zsh
0x3ds@kali $ echo 'john.deacon::FORELA:601019d191f054f1:c0cc803a6d9fb5a9082253a04dbd4cd4:010100000000000080e4d59406c6da01cc3dcfc0de9b5f2600000000020008004e0042004600590001001e00570049004e002d00360036004100530035004c003100470052005700540004003400570049004e002d00360036004100530035004c00310047005200570054002e004e004200460059002e004c004f00430041004c00030014004e004200460059002e004c004f00430041004c00050014004e004200460059002e004c004f00430041004c000700080080e4d59406c6da0106000400020000000800300030000000000000000000000000200000eb2ecbc5200a40b89ad5831abf821f4f20a2c7f352283a35600377e1f294f1c90a001000000000000000000000000000000000000900140063006900660073002f00440043004300300031000000000000000000' > john.deacon-ntlmv2

```

Now that we have our file ready to pass to `hashcat`, we can go ahead and do so by specifying the wordlist we want to use, along with the `-m 5600` to specify the correct hash mode (NetNTLMv2).

```zsh
0x3ds@kali $ hashcat -m 5600 john.deacon-ntlmv2 /usr/share/wordlists/rockyou.txt

hashcat (v7.1.2) starting

<SNIP>

Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 1 sec

JOHN.DEACON::FORELA:601019d191f054f1:c0cc803a6d9fb5a9082253a04dbd4cd4:010100000000000080e4d59406c6da01cc3dcfc0de9b5f2600000000020008004e0042004600590001001e00570049004e002d00360036004100530035004c003100470052005700540004003400570049004e002d00360036004100530035004c00310047005200570054002e004e004200460059002e004c004f00430041004c00030014004e004200460059002e004c004f00430041004c00050014004e004200460059002e004c004f00430041004c000700080080e4d59406c6da0106000400020000000800300030000000000000000000000000200000eb2ecbc5200a40b89ad5831abf821f4f20a2c7f352283a35600377e1f294f1c90a001000000000000000000000000000000000000900140063006900660073002f00440043004300300031000000000000000000:NotMyPassword0k?

<SNIP>

```
We can see that we have successfully cracked the NTLMv2 hash to reveal the plaintext password `NotMyPassword0k?` for the user `john.deacon`


> **Answer: `NotMyPassword0k?`**
{: .prompt-tip }



---
### Task 9

> Just to get more context surrounding the incident, what is the actual file share that the victim was trying to navigate to?
{: .prompt-info }

To identify the actual file share that the victim was trying to navigate to, we can amend our filter to see all `smb2` packets for the IP Address `172.17.79.136`.

Our filter will be: `ip.addr == 172.17.79.136 && smb2`.

![light mode only](/assets/img/posts/htb/sherlocks/SOC/very-easy/noxious/wireshark_12.png){: .light .w-100 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/assets/img/posts/htb/sherlocks/SOC/very-easy/noxious/wireshark_12.png){: .dark .w-100 .shadow .rounded-10 w='1212' h='668' }

We can see **packet 10214** which contains a Tree Connect Request for the file share path `\\DC01\DC-Confidential`



> **Answer: `\\DC01\DC-Confidential`**
{: .prompt-tip }

---