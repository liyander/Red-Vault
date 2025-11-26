# Red Teaming Checklist for Active Directory Environments

A comprehensive, modern guide for red team operations in Active Directory environments. This checklist covers reconnaissance through post-exploitation with detailed techniques, modern tooling, and evasion strategies relevant to 2025 security landscapes.

---

## Table of Contents

1. [Pre-Engagement](#pre-engagement)
2. [Initial Access](#initial-access)
3. [Execution & Defense Evasion](#execution--defense-evasion)
4. [Credential Access](#credential-access)
5. [Discovery & Enumeration](#discovery--enumeration)
6. [Lateral Movement](#lateral-movement)
7. [Privilege Escalation](#privilege-escalation)
8. [Persistence](#persistence)
9. [Command & Control](#command--control)
10. [Exfiltration](#exfiltration)
11. [Impact & Objectives](#impact--objectives)
12. [Operational Security (OPSEC)](#operational-security-opsec)
13. [Modern Attack Scenarios](#modern-attack-scenarios)
14. [Detection & Remediation](#detection--remediation)

---

## Pre-Engagement

### Objectives & Scope Definition

-  **Define engagement objectives** (crown jewels, data exfiltration, AD compromise, ransomware simulation, etc.)
-  **Establish rules of engagement (ROE)**
  - Authorized target IP ranges and domains
  - Prohibited actions (DoS, data destruction, production outages)
  - Communication protocols and escalation procedures
  - Authorized attack techniques and tools
-  **Define success criteria and objectives**
  - Primary goals (e.g., Domain Admin access, specific data access)
  - Secondary goals (persistence, stealth duration, detection testing)
  - Reporting requirements and deliverables
-  **Establish communication channels**
  - Emergency contact procedures
  - Daily/weekly status updates
  - Out-of-band communication methods
-  **Review legal agreements**
  - Signed authorization letters
  - NDA and confidentiality agreements
  - Insurance and liability coverage

### OSINT & External Reconnaissance

-  **Domain and subdomain enumeration**
  - Tools: `Amass`, `Subfinder`, `Sublist3r`, `DNSdumpster`, `SecurityTrails`
  - Certificate Transparency logs (`crt.sh`, `Censys`)
  - Google dorking and search engine reconnaissance
-  **Email address harvesting**
  - Tools: `theHarvester`, `Hunter.io`, `Clearbit`, `RocketReach`
  - LinkedIn enumeration with `linkedin2username`
  - GitHub/GitLab user enumeration
-  **Breach data analysis**
  - Check `Have I Been Pwned`, `Dehashed`, `WeLeakInfo`
  - Analyze leaked credentials for password patterns
  - Identify reused passwords across services
-  **Technology stack identification**
  - Tools: `Wappalyzer`, `BuiltWith`, `Shodan`, `Censys`
  - Identify VPN solutions, email gateways, web applications
  - Cloud service enumeration (Azure AD, AWS, GCP)
-  **Social media reconnaissance**
  - LinkedIn for org structure, employee roles, technologies
  - Twitter/X for employee posts about tech stack
  - GitHub for code repositories and leaked credentials
-  **Network infrastructure mapping**
  - IP range identification via ARIN/RIPE/APNIC
  - ASN enumeration and BGP route analysis
  - Cloud vs. on-premise infrastructure identification

### Documentation Setup

-  **Establish logging infrastructure**
  - Command logging and screenshot automation
  - Traffic capture setup (tcpdump, Wireshark)
  - Timestamp all activities for timeline reconstruction
-  **Create engagement documentation**
  - Target inventory spreadsheet
  - Finding tracker (vulnerabilities, misconfigurations, credentials)
  - Attack path diagrams and decision trees
-  **Set up secure data handling**
  - Encrypted storage for sensitive data
  - Secure transfer mechanisms for evidence
  - Data retention and destruction policies

---

## Initial Access

### External Attack Surface

-  **Web application exploitation**
  - SQL injection (SQLMap, manual testing)
  - XSS for credential harvesting or session hijacking
  - File upload vulnerabilities for webshells
  - Deserialization attacks (Java, .NET)
  - SSRF to access internal services
  - Authentication bypass and broken access control
-  **VPN exploitation**
  - Pulse Secure, Fortinet, Citrix vulnerabilities (CVE hunting)
  - Credential stuffing against VPN portals
  - MFA bypass techniques (MFA fatigue, push bombing)
  - Exploit: CVE-2024-21887 (Ivanti Connect Secure), CVE-2023-46805
-  **Email gateway exploitation**
  - Identify email filtering solutions (Proofpoint, Mimecast, Barracuda)
  - Exchange vulnerabilities (ProxyShell, ProxyLogon, ProxyNotShell)
  - Exploit: CVE-2022-41040, CVE-2022-41082, CVE-2021-34473
-  **Remote service exploitation**
  - RDP brute force or credential stuffing (Hydra, Crowbar, Medusa)
  - SMB exploitation (EternalBlue, SMBGhost) - CVE-2020-0796
  - SSH credential attacks and key-based authentication abuse

### Phishing & Social Engineering

-  **Email phishing campaigns**
  - Tools: `Gophish`, `King Phisher`, `Social-Engineer Toolkit (SET)`
  - Craft convincing pretext (IT support, HR, vendor)
  - Weaponized Office documents (macros, DDE, template injection)
  - HTML smuggling for payload delivery
  - Modern techniques: QR code phishing (quishing), AiTM phishing
-  **Credential harvesting**
  - Fake login pages (Evilginx2, Modlishka for MFA bypass)
  - OAuth consent phishing (illicit consent grant)
  - Browser-in-the-middle attacks
-  **Malicious attachments**
  - Macro-enabled documents (`.docm`, `.xlsm`) with obfuscation
  - ISO/IMG file attachments (bypass Mark-of-the-Web)
  - LNK files with embedded payloads
  - OneNote files with embedded scripts (modern alternative)
  - PDF with embedded JavaScript or exploits
-  **Link-based attacks**
  - URL shorteners to hide malicious domains
  - Typosquatting domains
  - Homograph attacks (IDN homograph)
  - Teams/Slack external messaging abuse

### Advanced Initial Access

-  **Supply chain attacks**
  - Compromise third-party vendors with access
  - Poisoned software updates
  - Dependency confusion attacks
-  **Physical access**
  - Rogue device deployment (Raspberry Pi, Bash Bunny, LAN Turtle)
  - USB drop attacks (Rubber Ducky, Digispark)
  - Badge cloning and tailgating
-  **Cloud service abuse**
  - Azure AD password spraying
  - AWS/Azure metadata service exploitation
  - Stolen API keys and access tokens
-  **Zero-day exploitation**
  - Monitor threat intelligence for 0-days
  - N-day exploitation (recent patches not yet deployed)

---

## Execution & Defense Evasion

### Initial Execution

-  **Payload execution techniques**
  - PowerShell cradles (IEX, DownloadString, DownloadFile)
  - Rundll32, Regsvr32 for DLL execution
  - Mshta for HTA file execution
  - Certutil for file download and decode
  - Bitsadmin for background downloads
  - Modern: msedge.exe, msedgewebview2.exe for LOLBin execution
-  **Living-off-the-land binaries (LOLBins)**
  - Reference: [LOLBAS Project](https://lolbas-project.github.io/)
  - Common: `wmic`, `regsvr32`, `mshta`, `msiexec`, `installutil`, `regasm`
  - Modern additions: `teams.exe`, `OneDrive.exe`, `msdt.exe` (Follina)
-  **Fileless execution**
  - In-memory PowerShell execution
  - Reflective DLL injection
  - Process hollowing and process doppelgänging
  - Heaven's Gate (WoW64 transition for x64 on x86)

### Defense Evasion Techniques

-  **Antivirus evasion**
  - Payload obfuscation (packers, crypters, encoding)
  - AMSI bypass techniques (memory patching, reflection)
  - Signature evasion (code refactoring, polymorphism)
  - Tools: `Veil`, `Shellter`, `Invoke-Obfuscation`, `Chameleon`
-  **EDR evasion**
  - Unhook EDR hooks (DLL unhooking)
  - Direct syscalls (SysWhispers, SysWhispers2, SysWhispers3)
  - Sleep obfuscation (Ekko, Foliage, Zilean)
  - ETW patching to blind logging
  - PPL bypass for protected processes
  - Modern: BRC4 (Blue Frost Security), TartarusGate, HellsGate variations
-  **AppLocker/WDAC bypass**
  - Whitelisted path exploitation (`C:\Windows\Tasks`, `C:\Windows\Temp`)
  - Trusted binary hijacking
  - Script-based execution (mshta, wmic, cscript)
  - Alternate Data Streams (ADS)
-  **Logging evasion**
  - Disable Windows Event Logging (wevtutil)
  - Clear event logs selectively
  - PowerShell logging bypass (AMSI + Script Block Logging)
  - Sysmon evasion (process name masquerading, log tampering)

### Modern Execution Techniques (2024-2025)

-  **WebView2 exploitation**
  - Abuse Microsoft Edge WebView2 for code execution
  - Leverage trusted Microsoft binaries
-  **MSI exploitation**
  - Custom MSI packages for code execution
  - Abuse Windows Installer for privilege escalation
-  **WSL (Windows Subsystem for Linux) abuse**
  - Execute Linux binaries on Windows
  - Evade Windows-based EDR solutions
-  **Container escape**
  - Docker/Kubernetes breakout techniques
  - Exploit container misconfigurations

---

## Credential Access

### Credential Dumping

-  **LSASS dumping**
  - Tools: `Mimikatz`, `SafetyKatz`, `SharpKatz`, `pypykatz`, `lsassy`
  - Techniques: `procdump`, `comsvcs.dll`, `SqlDumper.exe`, `PPLBlade`
  - Modern: Nanodump, MirrorDump, HandleKatz (handle duplication)
  - EDR evasion: Process forking, LSASS Shtinkering
-  **SAM/SYSTEM/SECURITY dumping**
  - Registry hive extraction (reg save, Volume Shadow Copy)
  - Tools: `secretsdump.py` (Impacket), `pwdump`, `fgdump`
-  **NTDS.dit extraction**
  - DCSync attack (Mimikatz, secretsdump.py, SharpKatz)
  - VSS copy: `ntdsutil`, `vssadmin`, `diskshadow`
  - Offline extraction from domain controller backups
-  **Browser credential extraction**
  - Chrome/Edge: Local State + Login Data SQLite DB decryption
  - Firefox: key4.db + logins.json
  - Tools: `SharpChrome`, `SharpEdge`, `LaZagne`, `HackBrowserData`
-  **Credential Manager dumping**
  - Windows Credential Manager (vaultcmd, VaultPasswordView)
  - RDP saved credentials (Credential Manager + DPAPI)

### Credential Attacks

-  **Kerberoasting**
  - Tools: `Rubeus`, `Invoke-Kerberoast`, `GetUserSPNs.py` (Impacket)
  - Crack TGS tickets offline (Hashcat mode 13100, John the Ripper)
  - Target high-value SPNs (MSSQLSvc, HTTP, etc.)
  - Modern: AES Kerberoasting detection evasion
-  **AS-REP Roasting**
  - Identify accounts without Kerberos pre-authentication
  - Tools: `Rubeus`, `GetNPUsers.py` (Impacket)
  - Crack AS-REP hashes offline (Hashcat mode 18200)
-  **Password spraying**
  - Tools: `Spray`, `DomainPasswordSpray`, `TREVORspray`, `o365spray`
  - Target: AD, OWA, O365, VPN, Citrix
  - Use common passwords: `Season+Year` (Winter2024!, Spring2025!)
  - Account lockout awareness and timing
-  **NTLM relay attacks**
  - Tools: `ntlmrelayx.py`, `Responder`, `Inveigh`, `PetitPotam`, `PrinterBug`
  - Relay to: SMB, LDAP, HTTP, MSSQL
  - WebDAV coercion (WebClient service)
  - Modern: ADCS relay (ESC8), Shadow Credentials relay
-  **Forced authentication & coercion**
  - Tools: `PetitPotam`, `PrinterBug`, `DFSCoerce`, `ShadowCoerce`
  - Coerce authentication to attacker-controlled systems
  - Capture NTLM hashes or relay to sensitive services

### Advanced Credential Techniques

-  **DPAPI decryption**
  - Extract master keys (user and system DPAPI)
  - Decrypt: browser passwords, RDP credentials, WiFi passwords
  - Tools: `Mimikatz`, `SharpDPAPI`, `DonPAPI`
-  **Kerberos attacks**
  - **Golden Ticket**: krbtgt hash for persistent domain access
  - **Silver Ticket**: Service account hash for service impersonation
  - **Diamond Ticket**: Modified TGT with legitimate encryption
  - **Sapphire Ticket**: Service ticket modification
  - Tools: `Rubeus`, `Mimikatz`, `ticketer.py`
-  **Pass-the-Hash (PtH)**
  - Use NTLM hash without plaintext password
  - Tools: `Mimikatz`, `pth-winexe`, `crackmapexec`, `evil-winrm`
-  **Pass-the-Ticket (PtT)**
  - Inject stolen Kerberos tickets
  - Tools: `Rubeus`, `Mimikatz` (kerberos::ptt)
-  **Overpass-the-Hash**
  - Convert NTLM hash to Kerberos ticket
  - Tools: `Rubeus` (asktgt), `Mimikatz`

---

## Discovery & Enumeration

### Domain Enumeration

-  **Domain information gathering**
  - Tools: `PowerView`, `SharpView`, `ADModule`, `BloodHound`, `ADExplorer`
  - Enumerate: domains, forests, trusts, OUs, GPOs
  - Modern: `ADCollector`, `Roadtools` (Azure AD), `AADInternals`
-  **User enumeration**
  - All domain users, privileged users (Domain Admins, Enterprise Admins)
  - Service accounts (SPNs), disabled accounts, never-expire passwords
  - User attributes: description, info fields (password leaks)
  - Modern: Entra ID (Azure AD) user enumeration via Graph API
-  **Computer enumeration**
  - All domain computers, operating systems, live hosts
  - Domain controllers, servers vs. workstations
  - Unconstrained delegation computers
-  **Group enumeration**
  - All groups, nested groups, privileged groups
  - AdminSDHolder-protected accounts
  - Foreign security principals (cross-domain memberships)
-  **GPO enumeration**
  - All GPOs, GPO application (to OUs/computers/users)
  - GPP passwords (MS14-025, older environments)
  - Restricted Groups, login scripts, scheduled tasks in GPOs
-  **ACL enumeration**
  - Weak ACLs (GenericAll, WriteDACL, WriteOwner)
  - Paths to privilege escalation via ACL abuse
  - Tools: `PowerView` (Find-InterestingDomainAcl), `BloodHound`
-  **Trust enumeration**
  - Domain trusts (parent/child, external, forest)
  - Trust direction and type (transitive vs. non-transitive)
  - SID filtering status

### Network Mapping

-  **Network scanning**
  - Tools: `nmap`, `masscan`, `RustScan`, `Nessus`, `OpenVAS`
  - Identify: live hosts, open ports, services, OS fingerprinting
  - Modern: Cloud-aware scanning (Azure, AWS VPC enumeration)
-  **Service enumeration**
  - SMB, LDAP, RPC, WinRM, RDP, MSSQL, DNS
  - Version detection and vulnerability identification
-  **BloodHound data collection**
  - Tools: `SharpHound`, `BloodHound.py`, `AzureHound`, `Roadtools`
  - Collect: sessions, ACLs, group memberships, local admins
  - Analyze attack paths to Domain Admin, Tier 0 assets
  - Custom Cypher queries for specific scenarios

### High-Value Target Identification

-  **Privileged account discovery**
  - Domain/Enterprise Admins, local admins on servers
  - Accounts with DCSync rights
  - Schema Admins, Account Operators, Backup Operators
-  **Sensitive system identification**
  - Domain controllers, file servers, database servers
  - Certificate authorities (ADCS), SCCM servers, backup servers
  - Exchange servers, SharePoint, cloud sync servers (AD Connect)
-  **Crown jewel identification**
  - Critical business systems and data repositories
  - Financial systems, HR databases, IP/source code repos
  - Admin workstations (PAWs), jump servers

---

## Lateral Movement

### Remote Execution

-  **WinRM / PowerShell Remoting**
  - Tools: `evil-winrm`, `Invoke-Command`, `Enter-PSSession`
  - Port 5985 (HTTP), 5986 (HTTPS)
  - Modern: PowerShell Core remoting over SSH
-  **PsExec variants**
  - Tools: `PsExec` (SysInternals), `Impacket psexec.py`, `CrackMapExec`
  - Service-based execution (creates service, runs command, deletes)
-  **WMI execution**
  - Tools: `wmic`, `Invoke-WmiMethod`, `Impacket wmiexec.py`
  - Fileless, stealthy, no service creation
  - Modern: CIM cmdlets (Get-CimInstance, Invoke-CimMethod)
-  **DCOM exploitation**
  - Tools: `Impacket dcomexec.py`, `Invoke-DCOM`
  - Abuse DCOM objects: MMC20.Application, ShellWindows, etc.
-  **RDP**
  - Restricted Admin mode (pass-the-hash support)
  - Tools: `xfreerdp`, `rdesktop`, `mstsc.exe`
  - Session hijacking (tscon)
-  **SMB/RPC**
  - Remote scheduled tasks (schtasks, at)
  - Remote service creation (sc)
  - Tools: `CrackMapExec`, `Impacket smbexec.py`

### Modern Lateral Movement

-  **SCCM exploitation**
  - Admin Service abuse for remote execution
  - Application deployment for code execution
  - Tools: `SharpSCCM`, `MalSCCM`
-  **Exchange exploitation**
  - PrivExchange for privilege escalation
  - ProxyShell/ProxyLogon for initial access → lateral movement
-  **MSSQL lateral movement**
  - xp_cmdshell execution
  - Linked server abuse for pivoting
  - Tools: `PowerUpSQL`, `SQLRecon`, `Impacket mssqlclient.py`
-  **SSH lateral movement**
  - SSH keys harvesting and reuse
  - SSH agent hijacking
  - Port forwarding for pivoting
-  **RPC/DCOM variations**
  - Impacket's atexec, wmiexec, dcomexec
  - ShellExecute for process creation

---

## Privilege Escalation

### Local Privilege Escalation

-  **Windows privilege escalation**
  - Tools: `WinPEAS`, `PrivescCheck`, `PowerUp`, `Seatbelt`, `Watson`, `Sherlock`
  - Techniques:
    - Unquoted service paths
    - Weak service permissions (modify service binary/config)
    - AlwaysInstallElevated (MSI as SYSTEM)
    - Kernel exploits (CVE-based: MS16-032, MS16-135, etc.)
    - DLL hijacking and search order exploitation
    - Token impersonation (Potato variants)
-  **Potato exploits**
  - Variants: `JuicyPotato`, `RoguePotato`, `PrintSpoofer`, `GodPotato`
  - Modern (2024-2025): `EfsPotato`, `DCOMPotato`, `SweetPotato`
  - Requirements: SeImpersonate or SeAssignPrimaryToken privileges
-  **UAC bypass**
  - Techniques: fodhelper, eventvwr, sdclt, ComputerDefaults
  - Tools: `UACME`, `UACBypass scripts`
  - Modern: msdt.exe (Follina), msedge elevated COM

### Domain Privilege Escalation

-  **Kerberos delegation abuse**
  - **Unconstrained Delegation**: Capture TGTs, printer bug coercion
  - **Constrained Delegation**: S4U2Self + S4U2Proxy abuse
  - **Resource-Based Constrained Delegation (RBCD)**: Machine account quota abuse
  - Tools: `Rubeus`, `Impacket getST.py`, `Powermad`
-  **ACL abuse**
  - GenericAll → Password reset, SPN addition, RBCD
  - WriteDACL → Modify ACL to grant GenericAll
  - WriteOwner → Take ownership, modify ACL
  - Tools: `PowerView`, `BloodHound`, `RACE`
-  **GPO abuse**
  - Write permission on GPO → add scheduled task, logon script
  - Tools: `SharpGPOAbuse`, `PowerView`
  - Immediate GPO refresh: `gpupdate /force` or wait for refresh interval
-  **ADCS (Active Directory Certificate Services) attacks**
  - **ESC1**: Misconfigured certificate templates (SAN specification)
  - **ESC2**: Any purpose EKU certificates
  - **ESC3**: Enrollment agent abuse
  - **ESC4**: Vulnerable ACLs on certificate templates
  - **ESC6**: EDITF_ATTRIBUTESUBJECTALTNAME2 flag
  - **ESC7**: Vulnerable CA ACLs
  - **ESC8**: NTLM relay to AD CS HTTP endpoints
  - **ESC9-ESC13**: Modern variations (2023-2024)
  - Tools: `Certify`, `Certipy`, `ForgeCert`, `PassTheCert`
-  **LAPS exploitation**
  - Read LAPS passwords if granted (ACL misconfiguration)
  - Relay attacks to read LAPS passwords
  - Tools: `LAPSToolkit`, `SharpLAPS`, `CrackMapExec`
-  **Group membership escalation**
  - Nested group exploitation
  - AdminSDHolder timing attacks
  - Foreign security principal abuse

### Modern Privilege Escalation (2024-2025)

-  **Azure AD Connect exploitation**
  - Extract AD sync account credentials (highly privileged)
  - Tools: `AADInternals`, custom scripts
-  **PrintNightmare (CVE-2021-34527)**
  - Point-and-Print abuse for SYSTEM execution
  - Tools: `CVE-2021-1675.ps1`, `cube0x0's exploit`
-  **NoPac (CVE-2021-42278 + CVE-2021-42287)**
  - sAMAccountName spoofing for privilege escalation
  - Tools: `noPac.py`, `sam_the_admin`
-  **Shadow Credentials (ADCS alternative)**
  - Add msDS-KeyCredentialLink attribute
  - Authenticate with certificate for TGT
  - Tools: `Whisker`, `Certipy`, `PyWhisker`
-  **ZeroLogon (CVE-2020-1472)**
  - Reset domain controller machine account password
  - Tools: `zerologon-exploit`, `secretsdump.py`

---

## Persistence

### Domain Persistence

-  **Golden Ticket**
  - Forge TGT with krbtgt hash
  - Lifetime: 10 years (configurable)
  - Tools: `Mimikatz`, `Rubeus`, `ticketer.py`
-  **Silver Ticket**
  - Forge TGS for specific services (CIFS, HTTP, MSSQL, etc.)
  - More stealthy than Golden Ticket
  - Tools: `Mimikatz`, `ticketer.py`
-  **Diamond Ticket**
  - Request legitimate TGT, modify PAC, re-encrypt
  - Harder to detect than Golden Ticket
  - Tools: `Rubeus` (diamond), `ticketer.py`
-  **Skeleton Key**
  - Patch LSASS on DC to accept master password
  - Tools: `Mimikatz` (misc::skeleton)
  - Modern detection: difficult to persist across reboots
-  **DSRM password abuse**
  - Use Directory Services Restore Mode local admin
  - Change DsrmAdminLogonBehavior registry key
  - Tools: `Mimikatz`
-  **AdminSDHolder manipulation**
  - Add user to protected groups indirectly
  - SDProp propagates permissions every 60 minutes
-  **DCSync rights**
  - Grant DCSync rights to controlled user
  - Persistent ability to dump credentials
  - Modify ACL: `DS-Replication-Get-Changes`, `DS-Replication-Get-Changes-All`
-  **SID History injection**
  - Add privileged SID to SID history
  - Tools: `Mimikatz` (sid::add)

### Local Persistence

-  **Scheduled tasks**
  - Create scheduled tasks as SYSTEM
  - Tools: `schtasks`, `Invoke-AtomicRedTeam`
-  **Services**
  - Create malicious services
  - Modify existing service binaries
-  **Registry Run keys**
  - HKLM/HKCU Run, RunOnce keys
  - Startup folder
-  **WMI event subscriptions**
  - Permanent WMI event consumers
  - Tools: `PowerLurk`, `Invoke-WMIMethod`
-  **DLL hijacking**
  - Replace or add DLLs in search path
  - COM hijacking
-  **Account manipulation**
  - Create hidden local admin accounts
  - Modify ACLs for persistence

### Modern Persistence (Cloud-Integrated)

-  **Azure AD persistence**
  - Service Principal secrets/certificates
  - Consent grant attacks (OAuth apps)
  - Azure AD roles assignment
  - Tools: `AADInternals`, `ROADtools`
-  **Federation trust manipulation**
  - Golden SAML attacks
  - Modify ADFS signing certificates
  - Tools: `AADInternals`
-  **Conditional Access bypass**
  - Trusted IP ranges exploitation
  - Device compliance bypass
-  **MFA bypass persistence**
  - Register attacker-controlled MFA device
  - Add trusted device
  - Phone number/email modification

---

## Command & Control

### C2 Frameworks

-  **Cobalt Strike**
  - Malleable C2 profiles for evasion
  - SMB/DNS/HTTP(S) listeners
  - Modern alternatives: `Havoc`, `Brute Ratel C4`, `Sliver`
-  **Metasploit Framework**
  - Multi-handler for reverse shells
  - Meterpreter for advanced post-exploitation
-  **Empire / Starkiller**
  - PowerShell-based C2 (original Empire deprecated)
  - Python 3 rewrite: `BC-SECURITY/Empire`
-  **Covenant**
  - .NET-based C2 framework
  - gRPC-based communication
-  **Modern C2 (2024-2025)**
  - `Mythic` - multi-agent framework
  - `Havoc` - modern C2 with advanced evasion
  - `Sliver` - Go-based C2 from BishopFox
  - `Nighthawk` - commercial MDR evasion C2

### C2 Communication Channels

-  **HTTPS C2**
  - Domain fronting (CloudFlare, Azure CDN)
  - Valid SSL certificates (Let's Encrypt)
  - Malleable C2 profiles (Cobalt Strike)
-  **DNS C2**
  - DNS tunneling for data exfiltration
  - Tools: `dnscat2`, `iodine`, Cobalt Strike DNS listener
-  **SMB C2**
  - Named pipes for internal lateral movement
  - No external network communication
-  **Cloud-based C2**
  - AWS/Azure/GCP infrastructure
  - Serverless C2 (Lambda, Azure Functions)
  - Tools: `C3` (Custom Command and Control)
-  **Encrypted channels**
  - Signal, Telegram, Discord bots for C2
  - GitHub/Pastebin as dead-drop resolvers

### C2 Evasion

-  **Traffic obfuscation**
  - Encrypted C2 communication
  - Traffic shaping to blend with normal HTTPS
  - Jitter and sleep time randomization
-  **Domain rotation**
  - Fast flux DNS
  - DGA (Domain Generation Algorithms)
  - Backup C2 infrastructure
-  **Beacon evasion**
  - Sleep obfuscation (stack encryption)
  - Memory evasion (heap encryption, module stomping)
  - Process injection alternatives (APC injection, thread hijacking)

---

## Exfiltration

### Data Identification & Collection

-  **Sensitive data discovery**
  - Tools: `Snaffler`, `PowerShell scripts`, `WinDirStat`
  - Search for: passwords, keys, PII, financial data, IP
  - File types: .doc, .xls, .pdf, .txt, .sql, .kdbx, .config
-  **SharePoint/OneDrive enumeration**
  - Tools: `SharePoint-Hunter`, `OneDrive enumeration scripts`
  - Search libraries for sensitive documents
-  **Database dumping**
  - MSSQL, MySQL, PostgreSQL, Oracle
  - Tools: `sqlcmd`, `Invoke-Sqlcmd`, `PowerUpSQL`
-  **Email extraction**
  - Exchange mailbox access
  - Tools: `MailSniper`, `Ruler`, `EWS exploitation`
-  **Source code repositories**
  - Git, SVN, TFS repositories
  - Search for hardcoded credentials

### Exfiltration Methods

-  **HTTP/HTTPS exfiltration**
  - Upload to attacker-controlled web servers
  - Cloud storage (Mega, Dropbox, Google Drive)
  - Pastebin, GitHub Gists
-  **DNS exfiltration**
  - Tools: `dnscat2`, `iodine`, `DNSExfiltrator`
  - Encode data in DNS queries
-  **Email exfiltration**
  - Send to external email addresses
  - Encrypted attachments
-  **Cloud storage exfiltration**
  - Azure Blob Storage, AWS S3
  - Legitimate SaaS services to blend in
-  **Physical exfiltration**
  - USB drives, external hard drives
  - Bluetooth/NFC data transfer

### Evasion & OpSec

-  **Data encryption**
  - Encrypt before exfiltration (AES, GPG)
  - Password-protected archives
-  **Compression & chunking**
  - Split large files into chunks
  - Compress to reduce size
-  **Steganography**
  - Hide data in images, audio files
  - Tools: `Steghide`, `OpenStego`
-  **Bandwidth throttling**
  - Slow exfiltration to avoid DLP/network monitoring
  - Exfiltrate during business hours (blend with normal traffic)

---

## Impact & Objectives

### Objective Achievement

-  **Crown jewel access**
  - Access to defined critical systems/data
  - Document access paths and methods
-  **Domain Admin compromise**
  - Full domain control via DA/EA/krbtgt
  - Document privilege escalation chain
-  **Data exfiltration**
  - Extract defined sensitive data
  - Prove exfiltration capability (without actually stealing in real ops)
-  **Business impact demonstration**
  - Ransomware simulation (DO NOT EXECUTE - document capability)
  - Service disruption scenarios (theoretical)
  - Financial impact assessment

### Impact Scenarios (Demonstration Only)

-  **Ransomware simulation**
  - Map encryption capability (do NOT execute)
  - Document affected systems and data
  - Tools reference: `Conti`, `LockBit`, `BlackCat` (for research only)
-  **Data destruction capability**
  - Identify critical data stores
  - Document deletion/corruption methods (do NOT execute)
-  **Service disruption**
  - Identify single points of failure
  - Document DoS vectors (do NOT execute without approval)
-  **Supply chain compromise**
  - Demonstrate ability to affect downstream customers
  - Software update mechanisms

---

## Operational Security (OPSEC)

### Stealth & Detection Avoidance

-  **Activity monitoring**
  - Check for active monitoring (Splunk, SIEM alerts)
  - Review logs for your activities
  - Monitor SOC communication channels (if accessible)
-  **Tool OPSEC**
  - Use native tools when possible (AD Module vs. PowerView)
  - Obfuscate PowerShell scripts
  - Remove tool artifacts after use
  - Modify tool signatures (recompile with different strings)
-  **Network OPSEC**
  - Use corporate proxies when available
  - Mimic normal user behavior patterns
  - Avoid mass scanning (rate limiting)
  - Blend C2 traffic with legitimate HTTPS
-  **Account OPSEC**
  - Use compromised legitimate accounts (avoid creating new ones when possible)
  - Maintain normal activity patterns (login times, source IPs)
  - Use accounts appropriate to action (don't use DA for recon)
-  **Time-based OPSEC**
  - Operate during business hours when activity is expected
  - Avoid late-night/weekend activity unless target normally has 24/7 ops
  - Respect timezone of target organization

### Artifact Cleanup

-  **File cleanup**
  - Remove uploaded tools and payloads
  - Clear temp directories
  - Remove staged files
-  **Registry cleanup**
  - Remove added registry keys
  - Restore modified values
-  **Log cleanup** (if authorized)
  - Clear relevant event logs (risky, often detected)
  - Selective log entry deletion
  - Timestamp manipulation
-  **Persistence removal**
  - Remove scheduled tasks, services
  - Delete added accounts
  - Remove registry Run keys, WMI subscriptions
-  **Network artifact cleanup**
  - Remove firewall rules
  - Close open sessions
  - Remove shared files

### Documentation & Evidence

-  **Screenshot everything**
  - Privileged access (whoami, net user)
  - Sensitive data access
  - Critical system access
-  **Maintain activity logs**
  - Command history with timestamps
  - Systems accessed
  - Credentials obtained
  - Files accessed/exfiltrated
-  **Video recordings**
  - Record critical exploitation steps
  - Screen recordings of privilege escalation
-  **Preserve evidence**
  - Encrypted storage of credentials and data samples
  - Chain of custody for any exfiltrated data
  - Hash values of accessed files

---

## Modern Attack Scenarios

### Hybrid Cloud AD Attacks

-  **Azure AD Connect exploitation**
  - Extract sync account credentials
  - Password hash synchronization abuse
  - Tools: `AADInternals` (Get-AADIntSyncCredentials)
-  **Pass-through Authentication abuse**
  - Intercept PTA traffic
  - Credential harvesting from PTA agents
-  **Seamless SSO exploitation**
  - Extract AZUREADSSOACC account hash
  - Silver Ticket for cloud resources
  - Tools: `AADInternals`
-  **Device registration abuse**
  - Register attacker device in Azure AD
  - Obtain Primary Refresh Token (PRT)
  - Tools: `ROADtools`, `AADInternals`
-  **Conditional Access bypass**
  - Compliant device spoofing
  - Trusted location exploitation
  - Legacy authentication abuse

### ADCS Attack Chains

-  **ESC1-ESC13 exploitation**
  - Certificate template abuse for privilege escalation
  - NTLM relay to certificate enrollment
  - Tools: `Certify`, `Certipy`, `Cert-Recon`
-  **Shadow Credentials**
  - Add Key Credentials to user/computer objects
  - Authenticate with certificate
  - Tools: `Whisker`, `PyWhisker`, `Certipy shadow`
-  **Pass-the-Certificate**
  - Use obtained certificates for authentication
  - Request TGT with certificate (PKINIT)
  - Tools: `Rubeus`, `gettgtpkinit.py`

### SCCM Exploitation

-  **SCCM site takeover**
  - Abuse site servers for code execution
  - Network Access Account credential retrieval
  - Tools: `SharpSCCM`, `PowerSCCM`, `MalSCCM`
-  **Client push exploitation**
  - Automatic client push for code execution
  - Capture client push credentials
-  **Application deployment abuse**
  - Deploy malicious applications to collections
  - Modify existing deployments

### Cross-Forest Attacks

-  **SID filtering bypass**
  - Identify trusts without SID filtering
  - Exploit SID history for cross-forest access
-  **Foreign security principal abuse**
  - Enumerate cross-forest group memberships
  - Exploit trust relationships
-  **MSSQL server trust abuse**
  - Enumerate SQL Server linked servers
  - Pivot across trust boundaries via SQL
  - Tools: `PowerUpSQL`, `SQLRecon`

---

## Detection & Remediation

### Blue Team Perspective

#### Common Detection Signatures

-  **PowerShell activity**
  - Event ID 4103 (Script Block Logging)
  - Event ID 4104 (Enhanced Script Block Logging)
  - Suspicious cmdlets: Get-Domain*, Invoke-*, Find-*
-  **LSASS access**
  - Event ID 10 (Sysmon - ProcessAccess)
  - LSASS dump detection (MiniDump, procdump)
-  **Kerberos attacks**
  - Event ID 4769 (TGS request) - RC4 encryption for Kerberoasting
  - Event ID 4768 (TGT request) - AS-REP Roasting
  - Event ID 4770 (TGS renewal) - Golden Ticket detection
-  **Lateral movement**
  - Event ID 4624 (Logon Type 3 - network, Type 10 - RDP)
  - Event ID 4648 (Explicit credential use)
  - Event ID 4672 (Special privileges assigned)
-  **Privilege escalation**
  - Event ID 4673 (Sensitive privilege use)
  - Event ID 4688 (Process creation) with Sysmon
-  **DCSync**
  - Event ID 4662 (Directory Service Access)
  - Replication operations from non-DC

#### Defensive Recommendations

-  **Preventive controls**
  - LAPS for local admin password management
  - Tiered Admin Model (separate admin accounts per tier)
  - Disable NTLM (where possible)
  - Enable SMB signing
  - Enable LDAP signing and channel binding
  - Remove admin rights from standard users
  - Application whitelisting (AppLocker, WDAC)
-  **Detective controls**
  - Enable enhanced PowerShell logging
  - Deploy Sysmon with comprehensive configuration
  - SIEM with AD-specific detections
  - Honeypot accounts and honey credentials
  - File integrity monitoring on DCs
  - Network traffic analysis (Zeek, Suricata)
-  **Hardening**
  - Remove deprecated protocols (SMBv1, LM/NTLMv1)
  - Patch management (prioritize credential theft vulns)
  - ADCS template hardening
  - GPO hardening (remove cached credentials, limit delegations)
  - Credential Guard and Remote Credential Guard
  - Protected Users group for high-value accounts
-  **Monitoring**
  - Anomalous authentication patterns
  - Unusual LDAP queries
  - Kerberos anomalies (RC4 usage, ticket anomalies)
  - Privileged account usage from unexpected locations
  - Mass file access or exfiltration

### Post-Engagement Remediation

-  **Immediate actions**
  - Reset compromised account passwords
  - Disable compromised accounts (if appropriate)
  - Reset krbtgt password (twice, 24hr apart) if Golden Ticket suspected
  - Revoke issued certificates if ADCS was abused
  - Remove persistence mechanisms
-  **Investigation**
  - Identify root cause (initial access vector)
  - Map attacker activity timeline
  - Identify all compromised accounts and systems
  - Assess data accessed/exfiltrated
-  **Long-term remediation**
  - Implement recommendations from assessment report
  - Architectural changes (tiered admin, PAWs)
  - Policy changes (privileged account management)
  - Enhanced monitoring and detection capabilities

---

## Essential Toolset

### Reconnaissance & Enumeration
- **PowerView** / **SharpView** - AD enumeration
- **BloodHound** / **SharpHound** - Attack path mapping
- **ADRecon** - Comprehensive AD reporting
- **PingCastle** - AD security assessment
- **ldapdomaindump** - LDAP dumping
- **Snaffler** - Credential/sensitive file hunting

### Credential Access
- **Mimikatz** / **SafetyKatz** / **pypykatz** - Credential dumping
- **Rubeus** - Kerberos abuse toolkit
- **Impacket** - Python tools for SMB/MSRPC
- **LaZagne** - Local credential harvesting
- **SharpDPAPI** - DPAPI decryption
- **Certify** / **Certipy** - ADCS enumeration and exploitation

### Exploitation & Privilege Escalation
- **CrackMapExec** - Swiss army knife for AD pentesting
- **Evil-WinRM** - WinRM exploitation
- **PowerUpSQL** - MSSQL exploitation
- **SharpGPOAbuse** - GPO abuse automation
- **Whisker** - Shadow Credentials exploitation
- **Potatoes** (Juicy, Rogue, God, etc.) - Token impersonation

### Lateral Movement & C2
- **Cobalt Strike** / **Havoc** / **Sliver** - C2 frameworks
- **Empire** / **Starkiller** - PowerShell C2
- **Metasploit** - Exploitation framework
- **Covenant** - .NET C2

### Defense Evasion
- **Invoke-Obfuscation** - PowerShell obfuscation
- **Invoke-DOSfuscation** - Command obfuscation
- **AMSI.fail** - AMSI bypass repository
- **SysWhispers3** - Direct syscall generation

### Cloud/Hybrid
- **AADInternals** - Azure AD exploitation toolkit
- **ROADtools** - Azure AD/O365 recon
- **MicroBurst** - Azure security toolkit
- **PowerZure** - Azure exploitation

---

## References & Resources

### Learning Resources
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Ired.team](https://www.ired.team/)
- [HackTricks](https://book.hacktricks.xyz/welcome/readme)
- [WADComs](https://wadcoms.github.io/)
- [Active Directory Security Blog](https://adsecurity.org/)
- [SpecterOps Blog](https://posts.specterops.io/)
- [Harmj0y's Blog](http://blog.harmj0y.net/)

### Practice Labs
- [HackTheBox - Active Directory Labs](https://www.hackthebox.com/)
- [TryHackMe - AD Rooms](https://tryhackme.com/)
- [VulnHub - AD VMs](https://www.vulnhub.com/)
- [GOAD (Game of Active Directory)](https://github.com/Orange-Cyberdefense/GOAD)
- [Detection Lab](https://github.com/clong/DetectionLab)

### Modern Attack Research (2024-2025)
- [Certified Pre-Owned (ADCS Attacks)](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
- [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- [Azure AD Attack & Defense Playbook](https://github.com/Cloud-Architekt/AzureAD-Attack-Defense)
- [SCCM Exploitation (0xsp)](https://0xsp.com/offensive/red-team-operations/sccm-exploitation)
- [UnPAC the hash](https://www.thehacker.recipes/ad/movement/kerberos/unpac-the-hash)

---

*Remember: Red teaming is about improving security posture, not causing harm. Always act professionally, ethically, and within legal boundaries.*

