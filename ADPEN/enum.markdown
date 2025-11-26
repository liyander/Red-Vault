## Domain Enumeration

This document lists common Active Directory enumeration commands with plain-language explanations of what each command does and when to use it. Use these examples as a starting point and adapt parameters to your environment.

---

## Core Concepts to Master

### 1. Active Directory Architecture
**Foundation**: Understanding AD's hierarchical structure is critical for effective enumeration. AD organizes objects (users, computers, groups) into Organizational Units (OUs), which are grouped into domains, which form forests.

**Key Components**:
- **Domain Controllers (DCs)**: Authoritative servers that store the AD database and handle authentication
- **Global Catalog**: Searchable database containing partial replicas of all objects in the forest
- **LDAP Protocol**: The primary protocol for querying AD (port 389/636)
- **Schema**: Defines all object types and attributes that can exist in AD

**Why It Matters**: Knowing the structure helps you target the right objects and understand trust relationships that enable lateral movement across domains.

### 2. LDAP Querying & Filters
**Foundation**: LDAP (Lightweight Directory Access Protocol) is the query language for Active Directory. Most enumeration tools use LDAP queries under the hood.

**Key Concepts**:
- **Distinguished Names (DN)**: Unique paths to AD objects (e.g., `CN=John,OU=Users,DC=domain,DC=com`)
- **Search Filters**: Boolean logic to find objects (e.g., `(&(objectClass=user)(adminCount=1))`)
- **Attributes**: Properties of objects (samAccountName, memberOf, servicePrincipalName, etc.)
- **Search Base & Scope**: Where to start searching and how deep to go

**Why It Matters**: Understanding LDAP helps you craft custom queries, troubleshoot tool failures, and bypass basic security filters.

### 3. Authentication Protocols
**Foundation**: AD supports multiple authentication mechanisms, each with different security implications.

**Protocols**:
- **NTLM**: Challenge-response protocol vulnerable to relay and cracking attacks
- **Kerberos**: Ticket-based protocol (preferred in AD) with exploitable components (TGT, TGS, PAC)
- **LDAPS**: LDAP over SSL/TLS (port 636) for encrypted queries
- **Negotiate**: Automatic negotiation between Kerberos and NTLM

**Why It Matters**: Each protocol has different attack surfaces. Enumeration helps identify which protocols are in use and where they can be exploited.

### 4. Access Control Lists (ACLs) & Permissions
**Foundation**: ACLs define who can do what to each AD object. Misconfigurations are a primary attack vector.

**Key Concepts**:
- **Access Control Entries (ACEs)**: Individual permission assignments
- **Security Descriptors**: Container for ACLs (DACL for access, SACL for auditing)
- **Active Directory Rights**: GenericAll, WriteDACL, WriteOwner, ForceChangePassword, etc.
- **Inheritance**: How permissions flow from parent to child objects

**Why It Matters**: Finding weak ACLs (e.g., users who can reset admin passwords) is often the fastest path to privilege escalation.

### 5. Group Policy Objects (GPOs)
**Foundation**: GPOs are the primary mechanism for deploying configuration across AD environments. They can contain credentials, scripts, and privilege assignments.

**Key Components**:
- **Group Policy Container (GPC)**: AD object storing GPO properties
- **Group Policy Template (GPT)**: File system folder with policy settings
- **Application**: How GPOs are linked to OUs and their filtering/enforcement
- **Restricted Groups**: GPO-based local admin assignments

**Why It Matters**: GPOs can leak credentials (cpassword in older systems), reveal administrative patterns, and be modified for persistence or privilege escalation.

### 6. Trust Relationships
**Foundation**: Trusts allow users in one domain to access resources in another. They create attack paths across domain and forest boundaries.

**Trust Types**:
- **Parent-Child**: Automatic two-way transitive trusts in the same forest
- **Tree-Root**: Trusts between domain trees in the same forest
- **External**: One-way or two-way trusts between different forests
- **Forest**: Trusts between entire forests
- **Shortcut/Cross-link**: Manual trusts to optimize authentication paths

**Why It Matters**: Trusts are highways for lateral movement. Mapping trusts reveals the full scope of a potential compromise.

### 7. Session & Logon Tracking
**Foundation**: Knowing where users are logged in is critical for targeted attacks. Session enumeration identifies where to steal credentials.

**Techniques**:
- **NetSessionEnum**: Lists active SMB sessions on a target
- **NetWkstaUserEnum**: Shows users logged onto a workstation
- **Registry Queries**: Last logged-on user information
- **Event Logs**: Logon events (4624, 4648) reveal authentication patterns

**Why It Matters**: Finding where Domain Admins are logged in is the key to privilege escalation. Session hunting is the bridge between enumeration and exploitation.

### 8. Service Principal Names (SPNs)
**Foundation**: SPNs are unique identifiers for service instances in AD. They're used by Kerberos for service ticket requests and are the foundation of Kerberoasting attacks.

**Key Concepts**:
- **SPN Format**: `service/host:port` (e.g., `MSSQLSvc/sql.domain.com:1433`)
- **Service Accounts**: Accounts running services with SPNs set
- **Ticket Granting Service (TGS)**: Kerberos tickets encrypted with service account password hashes
- **SPN Discovery**: LDAP queries to find all registered SPNs

**Why It Matters**: Any domain user can request TGS tickets for services, allowing offline password cracking of service accounts (Kerberoasting).

---

### Using PowerView

[Powerview v.3.0](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)<br>
[Powerview Wiki](https://powersploit.readthedocs.io/en/latest/)

- **Get Current Domain:** `Get-Domain`
  - **What:** Returns the name and basic info for the domain the current user is authenticated to.
- **Enumerate Other Domains:** `Get-Domain -Domain <DomainName>`
  - **What:** Queries information about a different domain (requires visibility/credentials to that domain).
- **Get Domain SID:** `Get-DomainSID`
  - **What:** Shows the domain SID (security identifier) used for rights/ACLs and SID history checks.
- **Get Domain Policy:**

  ```powershell
  Get-DomainPolicy

  #Will show us the policy configurations of the Domain about system access or kerberos
  Get-DomainPolicy | Select-Object -ExpandProperty SystemAccess
  Get-DomainPolicy | Select-Object -ExpandProperty KerberosPolicy
  ```
  - **What:** Dumps domain-wide Group Policy and security settings (password policies, lockout, Kerberos settings).

- **Get Domain Controllers:**
  ```powershell
  Get-DomainController
  Get-DomainController -Domain <DomainName>
  ```
  - **What:** Lists domain controllers (DCs). Useful to identify authoritative servers and targets for LDAP/NTLM interactions.
- **Enumerate Domain Users:**

  ```powershell
  #Save all Domain Users to a file
  Get-DomainUser | Out-File -FilePath .\DomainUsers.txt

  #Will return specific properties of a specific user
  Get-DomainUser -Identity [username] -Properties DisplayName, MemberOf | Format-List

  #Enumerate user logged on a machine
  Get-NetLoggedon -ComputerName <ComputerName>

  #Enumerate Session Information for a machine
  Get-NetSession -ComputerName <ComputerName>

  #Enumerate domain machines of the current/specified domain where specific users are logged into
  Find-DomainUserLocation -Domain <DomainName> | Select-Object UserName, SessionFromName
  ```
  - **What:** User enumeration and session discovery. Use to find accounts, their group membership, and where users are currently logged in (helps with lateral movement and targeting).

- **Enum Domain Computers:**

  ```powershell
  Get-DomainComputer -Properties OperatingSystem, Name, DnsHostName | Sort-Object -Property DnsHostName

  #Enumerate Live machines
  Get-DomainComputer -Ping -Properties OperatingSystem, Name, DnsHostName | Sort-Object -Property DnsHostName
  ```
  - **What:** Lists computer objects in the domain and optionally filters to live hosts — useful to build an asset list.

- **Enum Groups and Group Members:**

  ```powershell
  #Save all Domain Groups to a file:
  Get-DomainGroup | Out-File -FilePath .\DomainGroup.txt

  #Return members of Specific Group (eg. Domain Admins & Enterprise Admins)
  Get-DomainGroup -Identity '<GroupName>' | Select-Object -ExpandProperty Member
  Get-DomainGroupMember -Identity '<GroupName>' | Select-Object MemberDistinguishedName

  #Enumerate the local groups on the local (or remote) machine. Requires local admin rights on the remote machine
  Get-NetLocalGroup | Select-Object GroupName

  #Enumerates members of a specific local group on the local (or remote) machine. Also requires local admin rights on the remote machine
  Get-NetLocalGroupMember -GroupName Administrators | Select-Object MemberName, IsGroup, IsDomain

  #Return all GPOs in a domain that modify local group memberships through Restricted Groups or Group Policy Preferences
  Get-DomainGPOLocalGroup | Select-Object GPODisplayName, GroupName
  ```
  - **What:** Use these to find privileged groups and their members. Knowing group membership is crucial to identify high-privilege accounts.

- **Enumerate Shares:**

  ```powershell
  #Enumerate Domain Shares
  Find-DomainShare

  #Enumerate Domain Shares the current user has access
  Find-DomainShare -CheckShareAccess

  #Enumerate "Interesting" Files on accessible shares
  Find-InterestingDomainShareFile -Include *passwords*
  ```
  - **What:** Discovers SMB shares and exposed files that may contain credentials or configuration data.

- **Enum Group Policies:**

  ```powershell
  Get-DomainGPO -Properties DisplayName | Sort-Object -Property DisplayName

  #Enumerate all GPOs to a specific computer
  Get-DomainGPO -ComputerIdentity <ComputerName> -Properties DisplayName | Sort-Object -Property DisplayName

  #Get users that are part of a Machine's local Admin group
  Get-DomainGPOComputerLocalGroupMapping -ComputerName <ComputerName>
  ```
  - **What:** GPOs often reveal automated privilege assignments, logon scripts, and other configuration that can be abused.

- **Enum OUs:**
  ```powershell
  Get-DomainOU -Properties Name | Sort-Object -Property Name
  ```
  - **What:** Lists OUs (Organizational Units) to understand domain structure and where user/computer objects are organized.
- **Enum ACLs:**

  ```powershell
  # Returns the ACLs associated with the specified account
  Get-DomaiObjectAcl -Identity <AccountName> -ResolveGUIDs

  #Search for interesting ACEs
  Find-InterestingDomainAcl -ResolveGUIDs

  #Check the ACLs associated with a specified path (e.g smb share)
  Get-PathAcl -Path "\\Path\Of\A\Share"
  ```
  - **What:** ACL (Access Control List) and privilege enumeration helps find misconfigurations (e.g., write access to critical objects) that can be escalated.

- **Enum Domain Trust:**

  ```powershell
  Get-DomainTrust
  Get-DomainTrust -Domain <DomainName>

  #Enumerate all trusts for the current domain and then enumerates all trusts for each domain it finds
  Get-DomainTrustMapping
  ```
  - **What:** Trusts show relationships between domains/forests. Trusts can be attack paths for cross-domain escalation.

- **Enum Forest Trust:**

  ```powershell
  Get-ForestDomain
  Get-ForestDomain -Forest <ForestName>

  #Map the Trust of the Forest
  Get-ForestTrust
  Get-ForestTrust -Forest <ForestName>
  ```
  - **What:** Similar to domain trusts but at the forest level; useful for large AD deployments.

- **User Hunting:**

  ```powershell
  #Finds all machines on the current domain where the current user has local admin access
  Find-LocalAdminAccess -Verbose

  #Find local admins on all machines of the domain
  Find-DomainLocalGroupMember -Verbose

  #Find computers were a Domain Admin OR a specified user has a session
  Find-DomainUserLocation | Select-Object UserName, SessionFromName

  #Confirming admin access
  Test-AdminAccess
  ```
  - **What:** Use these to identify where privileged accounts are actively logged in or where you already have elevated access.

  :heavy_exclamation_mark: **Priv Esc to Domain Admin with User Hunting:** \
  I have local admin access on a machine -> A Domain Admin has a session on that machine -> I steal his token and impersonate him -> Profit!

### Using AD Module

- **Get Current Domain:** `Get-ADDomain`
  - **What:** Equivalent AD module call to `Get-Domain` from PowerView. Returns domain information.
- **Enum Other Domains:** `Get-ADDomain -Identity <Domain>`
  - **What:** Query AD domain details for a specified domain.
- **Get Domain SID:** `Get-DomainSID`
  - **What:** Returns the domain SID.
- **Get Domain Controlers:**

  ```powershell
  Get-ADDomainController
  Get-ADDomainController -Identity <DomainName>
  ```
  - **What:** Lists domain controllers using the AD module.

- **Enumerate Domain Users:**

  ```powershell
  Get-ADUser -Filter * -Identity <user> -Properties *

  #Get a specific "string" on a user's attribute
  Get-ADUser -Filter 'Description -like "*wtver*"' -Properties Description | select Name, Description
  ```
  - **What:** AD module commands to list users and search attributes (e.g., finding passwords in user descriptions).

- **Enum Domain Computers:**
  ```powershell
  Get-ADComputer -Filter * -Properties *
  Get-ADGroup -Filter *
  ```
  - **What:** Lists computer and group objects using the AD module.
- **Enum Domain Trust:**
  ```powershell
  Get-ADTrust -Filter *
  Get-ADTrust -Identity <DomainName>
  ```
  - **What:** AD module trust enumeration.
- **Enum Forest Trust:**

  ```powershell
  Get-ADForest
  Get-ADForest -Identity <ForestName>

  #Domains of Forest Enumeration
  (Get-ADForest).Domains
  ```
  - **What:** Forest-level enumeration and domain list.

- **Enum Local AppLocker Effective Policy:**

  ```powershell
  Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
  ```
  - **What:** Shows effective AppLocker rules on a host (can indicate application restrictions that affect payload choices).

### Using BloodHound

**What is BloodHound:** A tool that visualizes AD attack paths and relationships using graph theory. It collects data (users, groups, sessions, ACLs) and maps privilege escalation routes.

#### Remote BloodHound

[Python BloodHound Repository](https://github.com/fox-it/BloodHound.py) or install it with `pip3 install bloodhound`

```powershell
bloodhound-python -u <UserName> -p <Password> -ns <Domain Controller's Ip> -d <Domain> -c All
```
- **What:** Remote collector that queries LDAP/SMB to collect data into BloodHound format (use from a non-domain-joined machine).

#### On Site BloodHound

```powershell
#Using exe ingestor
.\SharpHound.exe --CollectionMethod All --LdapUsername <UserName> --LdapPassword <Password> --domain <Domain> --domaincontroller <Domain Controller's Ip> --OutputDirectory <PathToFile>

#Using PowerShell module ingestor
. .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All --LdapUsername <UserName> --LdapPassword <Password> --OutputDirectory <PathToFile>
```
- **What:** Run locally in the environment to collect a wider set of high-fidelity data (sessions, ACLs, local admin mappings).

### Using Adalanche

**What is Adalanche:** An AD security assessment tool that automates data collection and provides a local web UI for analysis.

#### Remote Adalanche

```bash
# kali linux:
./adalanche collect activedirectory --domain <Domain> \
--username <Username@Domain> --password <Password> \
--server <DC>

# Example:
./adalanche collect activedirectory --domain windcorp.local \
--username spoNge369@windcorp.local --password 'password123!' \
--server dc.windcorp.htb
## -> Terminating successfully

## Any error?:

# LDAP Result Code 200 "Network Error": x509: certificate signed by unknown authority ?

./adalanche collect activedirectory --domain windcorp.local \
--username spoNge369@windcorp.local --password 'password123!' \
--server dc.windcorp.htb --tlsmode NoTLS --port 389

# Invalid Credentials ?
./adalanche collect activedirectory --domain windcorp.local \
--username spoNge369@windcorp.local --password 'password123!' \
--server dc.windcorp.htb --tlsmode NoTLS --port 389 \
--authmode basic

# Analyze data 
# go to web browser -> 127.0.0.1:8080
./adalanche analyze
```
- **What:** Collects AD data remotely and starts a local web server for interactive analysis.

#### Export Enumerated Objects

You can export enumerated objects from any module/cmdlet into an XML file for later analysis.

The `Export-Clixml` cmdlet creates a Common Language Infrastructure (CLI) XML-based representation of an object or objects and stores it in a file. You can then use the `Import-Clixml` cmdlet to recreate the saved object based on the contents of that file.

```powershell
# Export Domain users to xml file.
Get-DomainUser | Export-CliXml .\DomainUsers.xml

# Later, when you want to utilise them for analysis even on any other machine.
$DomainUsers = Import-CliXml .\DomainUsers.xml

# You can now apply any condition, filters, etc.

$DomainUsers | select name

$DomainUsers | ? {$_.name -match "User's Name"}
```
- **What:** Export/import is useful to decouple collection from analysis or to work offline without re-running queries.

### Useful Enumeration Tools

- [ldapdomaindump](https://github.com/dirkjanm/ldapdomaindump) — LDAP information dumper (creates HTML reports)
- [adidnsdump](https://github.com/dirkjanm/adidnsdump) — Dumps DNS records from AD-integrated DNS zones
- [ACLight](https://github.com/cyberark/ACLight) — Advanced discovery of privileged accounts and shadow admins
- [ADRecon](https://github.com/sense-of-security/ADRecon) — Detailed Active Directory reconnaissance tool (Excel/CSV output)

## Skills to Develop

### Technical Skills

#### 1. PowerShell Proficiency
- **Cmdlet Syntax**: Understanding PowerShell pipeline, parameters, and object manipulation
- **Filtering & Formatting**: `Where-Object`, `Select-Object`, `Format-List/Table`, output redirection
- **Script Execution**: Bypass execution policies, dot-sourcing modules, remote execution
- **AMSI Bypass**: Techniques to evade Anti-Malware Scan Interface for tool execution
- **Practice**: Write PowerShell one-liners to replicate common PowerView queries using pure AD module

#### 2. LDAP Query Construction
- **Filter Syntax**: Boolean operators (`&`, `|`, `!`), comparison operators, wildcards
- **Attribute Knowledge**: Memorize critical AD attributes (adminCount, userAccountControl, memberOf, servicePrincipalName)
- **Search Optimization**: Using indexed attributes, limiting scope, pagination for large results
- **Custom Tools**: Build your own LDAP enumeration scripts in Python or PowerShell
- **Practice**: Use `ldapsearch` (Linux) or `Get-ADObject` (Windows) to replicate PowerView functionality

#### 3. BloodHound Analysis
- **Graph Queries**: Cypher query language for custom path finding
- **Attack Path Identification**: Reading shortest path displays, understanding edge types
- **Data Interpretation**: ACL edges, group membership chains, session data reliability
- **Custom Queries**: Building reusable queries for specific scenarios (unconstrained delegation, LAPS readers, etc.)
- **Practice**: Import sample BloodHound data and manually trace 5 different privilege escalation paths

#### 4. Network Protocol Analysis
- **Packet Capture**: Using Wireshark/tcpdump to capture LDAP, SMB, Kerberos traffic
- **Traffic Patterns**: Recognizing enumeration signatures in network traffic
- **Protocol Security**: Understanding LDAP signing, SMB signing, Kerberos encryption
- **Proxy Awareness**: Detecting and adapting to LDAP/SMB proxies or gateways
- **Practice**: Capture and analyze traffic from PowerView enumeration and identify IOCs

#### 5. SMB/RPC Enumeration
- **SMB Protocol**: Understanding SMB versions, signing requirements, null sessions
- **RPC Calls**: NetAPI functions (NetUserEnum, NetGroupEnum, NetShareEnum)
- **Share Permissions**: Differentiating between share-level and NTFS permissions
- **Named Pipes**: Enumerating and interacting with IPC$ and admin shares
- **Practice**: Use `smbclient`, `rpcclient`, `crackmapexec` to enumerate without PowerView

#### 6. Credential Extraction from Enumeration
- **Sensitive Attributes**: Finding passwords in AD attributes (description, info, comment fields)
- **GPP Passwords**: Identifying and decrypting Group Policy Preferences passwords (cpassword)
- **Script Analysis**: Extracting credentials from logon scripts, GPO scripts
- **Certificate Stores**: Locating certificates and private keys in AD
- **Practice**: Build a script to automatically search all user/computer attributes for password-like strings

#### 7. DNS Reconnaissance
- **AD-Integrated DNS**: Understanding how AD uses DNS for service location
- **DNS Records**: SRV records for DC discovery, A records for host enumeration
- **Zone Transfers**: Attempting DNS zone transfers (AXFR) from DCs
- **Dynamic DNS**: Enumerating machines via DNS dynamic updates
- **Practice**: Use `adidnsdump` or `dnscmd` to extract and analyze all DNS records

#### 8. Privilege Mapping
- **Nested Groups**: Tracing effective permissions through group membership chains
- **AdminSDHolder**: Identifying protected accounts via adminCount attribute
- **Delegation**: Finding users with delegated admin rights (OU permissions)
- **Local Admin**: Mapping local administrator access across the domain
- **Practice**: Create a script that outputs all effective Domain Admins (including nested groups)

### Analytical Skills

#### 1. Pattern Recognition
- **Naming Conventions**: Identifying admin accounts, service accounts, test accounts from naming patterns
- **Organizational Structure**: Inferring business units and departments from OU/group structure
- **Security Posture**: Assessing maturity from GPO configuration, group structure, ACL hygiene
- **Anomaly Detection**: Spotting unusual configurations that might indicate misconfigurations or backdoors

#### 2. Attack Path Planning
- **Privilege Mapping**: Building a map from current access level to target (usually Domain Admin)
- **Risk Assessment**: Evaluating detectability and impact of different paths
- **Dependency Analysis**: Understanding prerequisites for each attack step
- **Alternative Routes**: Identifying backup paths if primary route is blocked

#### 3. Data Correlation
- **Cross-Tool Validation**: Verifying findings across PowerView, AD Module, BloodHound
- **Time-Based Analysis**: Correlating session data with user logon patterns
- **Permission Inheritance**: Tracing effective permissions through multiple ACL sources
- **Trust Path Mapping**: Building multi-domain attack chains

#### 4. Intelligence Prioritization
- **High-Value Targets**: Identifying crown jewels (domain admins, sensitive systems, data repositories)
- **Low-Hanging Fruit**: Finding quick wins (weak ACLs, cached credentials, overprivileged accounts)
- **Operational Impact**: Assessing which enumeration actions might trigger alerts
- **Resource Efficiency**: Focusing on data that directly supports attack objectives

### Operational Skills

#### 1. Stealth & OPSEC
- **Query Rate Limiting**: Avoiding noisy mass enumeration that triggers SOC alerts
- **Blend In**: Using legitimate tools (AD Module) vs. suspicious tools (PowerView)
- **Account Selection**: Choosing appropriate accounts for enumeration (avoid service accounts)
- **Log Awareness**: Understanding what gets logged (LDAP queries, SMB connections, etc.)

#### 2. Tool Selection & Adaptation
- **Environment Assessment**: Choosing appropriate tools based on host restrictions
- **Fallback Planning**: Having alternative enumeration methods when primary tools are blocked
- **Custom Development**: Modifying existing tools or writing custom scripts for unique scenarios
- **Living Off the Land**: Using native Windows tools when attacker tools are restricted

#### 3. Data Management
- **Output Organization**: Structured file naming, organized directories for different enumeration types
- **Data Parsing**: Converting raw tool output into actionable intelligence
- **Version Control**: Tracking changes in AD over time (new accounts, permission changes)
- **Secure Storage**: Protecting enumerated data (contains sensitive organizational information)

#### 4. Collaboration & Reporting
- **Finding Documentation**: Recording enumeration results for team members
- **Attack Narrative**: Building a timeline of enumeration → exploitation → escalation
- **Evidence Collection**: Preserving proof of vulnerabilities for client reporting
- **Remediation Guidance**: Translating enumeration findings into defensive recommendations

---

## Learning Path

### Level 1: Foundation (Beginner)
**Goal**: Understand AD basics and run standard enumeration tools

- Learn Active Directory fundamentals (users, groups, computers, OUs, GPOs, DCs)
- Set up a local AD lab (Windows Server + client VMs)
- Run PowerView/AD Module commands and understand their output
- Install and use BloodHound to visualize AD relationships
- Practice basic LDAP queries with `Get-ADObject`
- Enumerate trusts, GPOs, and shares in lab environment

**Milestone**: Successfully enumerate entire lab domain and identify all privileged accounts

### Level 2: Intermediate (Practitioner)
**Goal**: Understand how enumeration leads to exploitation

- Study attack paths: Kerberoasting, ASREPRoasting, ACL abuse, delegation attacks
- Practice session hunting and identifying where admins are logged in
- Learn to read BloodHound graphs and identify shortest privilege escalation paths
- Use enumeration findings to execute privilege escalation attacks
- Understand the blue team perspective: what gets logged during enumeration
- Practice enumeration in environments with basic defenses (AMSI, AppLocker)

**Milestone**: Complete an end-to-end attack chain: enumeration → Kerberoasting → privilege escalation → Domain Admin

### Level 3: Advanced (Expert)
**Goal**: Operate in hardened environments and find subtle attack paths

- Master custom LDAP query construction for targeted enumeration
- Write custom Cypher queries in BloodHound for complex scenarios
- Enumerate across forest trusts and identify cross-domain attack paths
- Bypass common detection (AppLocker, AMSI, EDR) during enumeration
- Understand Certificate Services enumeration and exploitation (ADCS attacks)
- Enumerate and exploit unconstrained/constrained/resource-based delegation

**Milestone**: Compromise a hardened lab environment using only enumeration data and delegation/ACL abuse

### Level 4: Master (Specialist)
**Goal**: Develop custom tools and advanced tradecraft

- Build custom enumeration tools tailored to specific environments
- Automate attack path discovery and exploitation
- Enumerate at scale (large multi-domain forests)
- Understand graph theory and implement custom pathfinding algorithms
- Contribute to open-source AD security tools
- Research and discover new AD enumeration techniques

**Milestone**: Publish a custom enumeration tool or technique; teach others through blog posts or talks

---

## Practice & Labs

### Scenario 1: Basic Domain Enumeration
**Setup**: Single-domain AD lab with 50+ users, 5+ computers, 10+ groups

**Objectives**:
- Enumerate all domain users and export to CSV
- Identify all members of Domain Admins and Enterprise Admins
- Find all computers and identify live hosts
- List all shares and identify accessible ones
- Enumerate all GPOs and identify which apply to specific OUs

**Tools**: PowerView, AD Module

**Success Criteria**: Complete inventory of domain objects with no missed privileged accounts

---

### Scenario 2: BloodHound Attack Path Discovery
**Setup**: Multi-tier AD environment with complex ACLs and nested groups

**Objectives**:
- Collect BloodHound data using SharpHound
- Import into BloodHound and identify all paths to Domain Admins
- Find the shortest path from a low-privilege user to DA
- Identify all users with DCSync rights
- Find all computers with unconstrained delegation

**Tools**: SharpHound, BloodHound, Cypher queries

**Success Criteria**: Document 5 different privilege escalation paths with step-by-step exploitation plan

---

### Scenario 3: Session Hunting & Lateral Movement Planning
**Setup**: Domain with 100+ users, 20+ workstations, users actively logging in/out

**Objectives**:
- Identify all machines where current user has local admin access
- Find all Domain Admin sessions across the domain
- Map the shortest lateral movement path to a machine with DA session
- Enumerate local administrators on all domain computers
- Identify stale sessions or cached credentials

**Tools**: PowerView `Find-*` cmdlets, BloodHound

**Success Criteria**: Lateral movement plan that reaches a DA session in ≤3 hops

---

### Scenario 4: GPO & ACL Exploitation Discovery
**Setup**: Environment with misconfigured GPOs and weak ACLs

**Objectives**:
- Enumerate all GPOs and identify ones containing credentials
- Find GPOs that grant local admin rights via Restricted Groups
- Identify all objects where you have Write permissions
- Find users you can perform Kerberoasting attacks against
- Locate ACLs that allow password resets on privileged accounts

**Tools**: PowerView, BloodHound, Get-GPO cmdlets

**Success Criteria**: Identify at least 3 different paths to privilege escalation through GPO/ACL abuse

---

### Scenario 5: Multi-Domain Trust Enumeration
**Setup**: Forest with parent domain, 2 child domains, and external trust to separate forest

**Objectives**:
- Map all trust relationships (parent-child, external, forest)
- Enumerate users and groups across all trusted domains
- Identify cross-domain group memberships (foreign security principals)
- Find SID history entries that might indicate previous compromises
- Enumerate resources accessible via trust relationships

**Tools**: PowerView, AD Module, BloodHound

**Success Criteria**: Complete trust map with documented attack paths across domain boundaries

---

### Scenario 6: Kerberoasting Target Discovery
**Setup**: Domain with 20+ service accounts with varying password strengths

**Objectives**:
- Enumerate all accounts with SPNs set
- Identify high-value service accounts (SQL servers, IIS, etc.)
- Find service accounts that are members of privileged groups
- Request TGS tickets for all Kerberoastable accounts
- Prioritize targets based on group membership and last password change

**Tools**: PowerView, Rubeus, Impacket's GetUserSPNs.py

**Success Criteria**: Prioritized list of Kerberoasting targets with exploitation likelihood assessment

---

### Scenario 7: Stealth Enumeration Under Monitoring
**Setup**: Monitored environment with SIEM, EDR, and active SOC

**Objectives**:
- Enumerate domain using only native Windows tools (no PowerView/BloodHound)
- Limit query rate to avoid detection thresholds
- Use only LDAPS (encrypted) for queries
- Enumerate without triggering honeypot accounts or objects
- Achieve same intelligence as noisy enumeration with minimal logs

**Tools**: AD Module, native Windows utilities, LDAP queries

**Success Criteria**: Complete enumeration without triggering any alerts (verified by reviewing logs)

---

## Detection & Blue Team Awareness

### Indicators of Compromise (IOCs)

**LDAP Enumeration Signatures**:
- High volume of LDAP queries from single source (Event ID 2889)
- Queries for all users, all groups, all computers in short time window
- LDAP queries from unexpected sources (non-admin workstations)
- Queries for sensitive attributes: `adminCount=1`, `servicePrincipalName`

**SMB Enumeration**:
- NetSessionEnum calls to multiple hosts (RPC enumeration)
- Rapid connection attempts to IPC$ shares across many hosts
- Share enumeration (NetShareEnum) from non-administrative accounts

**PowerShell/Tool Execution**:
- PowerView module loaded (Event ID 4103, Script Block Logging)
- Suspicious cmdlets: `Get-Domain*`, `Find-*`, `Invoke-*` from PowerView
- BloodHound/SharpHound execution (process creation events)
- Base64 encoded PowerShell commands (common obfuscation)

**Account Behaviors**:
- Service account performing interactive LDAP queries
- Failed authentication attempts during enumeration (password spraying)
- Kerberos pre-authentication requests for all accounts (ASREPRoast enumeration)
- TGS requests for many SPNs in short period (Kerberoasting)

### Defensive Recommendations

1. **Enable Advanced Logging**: Script Block Logging, Module Logging, Transcription
2. **LDAP Signing & Channel Binding**: Prevent relay attacks and enforce encryption
3. **Minimal Permissions**: Restrict LDAP query permissions where possible
4. **Honeypot Accounts**: Create attractive fake admin accounts to detect reconnaissance
5. **Baseline Normal Activity**: Understand typical LDAP/SMB query patterns to detect anomalies
6. **Segment Privileged Access**: Use tiered admin model to limit lateral movement paths
7. **Monitor BloodHound IOCs**: Alert on SharpHound.exe, specific LDAP query patterns
8. **Regular ACL Audits**: Identify and remediate overly permissive ACLs before attackers find them

---

**Remember**: Enumeration is legal and authorized during penetration tests with proper scope/authorization. Unauthorized enumeration of AD environments is illegal. Always have written permission before performing security assessments.