# SMB Enumeration with NXC

## Overview

SMB (Server Message Block) enumeration is the most commonly used NXC capability. The SMB protocol module allows you to discover hosts, enumerate users, groups, shares, sessions, password policies, and gather detailed OS information — all of which feed directly into attack planning during an Active Directory penetration test.

---

## Host Discovery and OS Fingerprinting

Running NXC against a target without credentials performs unauthenticated SMB enumeration. This reveals the operating system, hostname, domain, SMB signing status, and SMBv1 support:

```bash
nxc smb 192.168.1.0/24
```

**Example output:**
```
SMB         192.168.1.10    445    DC01             [*] Windows Server 2019 Build 17763 x64 (name:DC01) (domain:CORP.LOCAL) (signing:True) (SMBv1:False)
SMB         192.168.1.20    445    WS01             [*] Windows 10 Build 19041 x64 (name:WS01) (domain:CORP.LOCAL) (signing:False) (SMBv1:False)
SMB         192.168.1.30    445    FILE01           [*] Windows Server 2016 Build 14393 x64 (name:FILE01) (domain:CORP.LOCAL) (signing:False) (SMBv1:True)
```

### Key Fields in the Output

- **Protocol (SMB)** — the protocol module used
- **IP address (192.168.1.10)** — target IP
- **Port (445)** — the port connected to
- **Hostname (DC01)** — the NetBIOS name of the host
- **OS version** — Windows Server 2019 Build 17763 x64
- **domain** — the AD domain the host belongs to
- **signing:True/False** — whether SMB signing is required (critical for relay attacks)
- **SMBv1:True/False** — whether SMBv1 is enabled (security risk, potential EternalBlue)

### SMB Signing Analysis

SMB signing is one of the most important fields:

- **signing:True** — SMB signing is required. NTLM relay attacks **will not work** against this host. Domain controllers typically have signing enabled by default.
- **signing:False** — SMB signing is not required. This host is **vulnerable to NTLM relay attacks** (e.g., via Responder + ntlmrelayx).

```bash
# Find all hosts with SMB signing disabled (relay targets)
nxc smb 192.168.1.0/24 --gen-relay-list relay_targets.txt
```

This generates a file `relay_targets.txt` containing only the IPs of hosts where SMB signing is disabled — ready to feed into ntlmrelayx.

---

## Null Sessions and Anonymous Access

A null session uses empty credentials to connect. Some misconfigured systems allow enumeration via null sessions:

```bash
# Null session attempt
nxc smb 192.168.1.10 -u '' -p ''
```

**Successful null session output:**
```
SMB         192.168.1.10    445    DC01             [+] CORP.LOCAL\:
```

The `[+]` with empty credentials indicates null session access is permitted.

```bash
# Guest access attempt
nxc smb 192.168.1.10 -u 'guest' -p ''
```

If guest access works, you may be able to enumerate shares, users, and other information without valid domain credentials.

---

## Share Enumeration (--shares)

Enumerating network shares reveals file servers, sensitive data locations, and potential attack paths:

```bash
# Enumerate shares with valid credentials
nxc smb 192.168.1.10 -u jsmith -p 'Password123' --shares
```

**Example output:**
```
SMB         192.168.1.10    445    FILE01           [*] Windows Server 2016 Build 14393 x64 (name:FILE01) (domain:CORP.LOCAL) (signing:False) (SMBv1:False)
SMB         192.168.1.10    445    FILE01           [+] CORP.LOCAL\jsmith:Password123
SMB         192.168.1.10    445    FILE01           [*] Enumerated shares
SMB         192.168.1.10    445    FILE01           Share           Permissions     Remark
SMB         192.168.1.10    445    FILE01           -----           -----------     ------
SMB         192.168.1.10    445    FILE01           ADMIN$                          Remote Admin
SMB         192.168.1.10    445    FILE01           C$                              Default share
SMB         192.168.1.10    445    FILE01           IPC$            READ            Remote IPC
SMB         192.168.1.10    445    FILE01           IT_Share        READ,WRITE      IT Department Files
SMB         192.168.1.10    445    FILE01           HR_Data         READ            HR Documents
SMB         192.168.1.10    445    FILE01           Public          READ            Public Share
SMB         192.168.1.10    445    FILE01           Backups         READ            Backup Files
```

### Understanding Share Permissions

- **No permissions listed** for ADMIN$ and C$ — the user cannot access admin shares (not local admin)
- **READ** — the user can read/list files
- **WRITE** — the user can write/upload files
- **READ,WRITE** — full read and write access
- If `ADMIN$` shows `READ,WRITE`, the user has local admin access

### Enumerating Shares Across a Subnet

```bash
# Enumerate shares on all hosts in the subnet
nxc smb 192.168.1.0/24 -u jsmith -p 'Password123' --shares
```

### Null Session Share Enumeration

```bash
nxc smb 192.168.1.10 -u '' -p '' --shares
```

---

## Share Spidering (--spider, --spider-folder, --pattern)

Share spidering recursively browses share contents to find interesting files:

```bash
# Spider all readable shares for interesting files
nxc smb 192.168.1.10 -u jsmith -p 'Password123' --spider C$ --pattern txt,xml,config,ini,bat,ps1,vbs
```

### Spider Options

```bash
# Spider a specific folder within a share
nxc smb 192.168.1.10 -u jsmith -p 'Password123' --spider IT_Share --spider-folder 'Scripts'

# Spider with a custom regex pattern
nxc smb 192.168.1.10 -u jsmith -p 'Password123' --spider IT_Share --pattern 'pass|cred|secret|key'

# Spider with depth limit
nxc smb 192.168.1.10 -u jsmith -p 'Password123' --spider IT_Share --depth 3
```

### What to Look For When Spidering

Files commonly containing credentials or sensitive data:
- `web.config`, `app.config` — .NET configuration files with connection strings
- `*.ps1`, `*.bat`, `*.vbs` — scripts that may contain hardcoded passwords
- `unattend.xml`, `sysprep.xml` — Windows deployment files with credentials
- `*.kdbx` — KeePass database files
- `*.rdp` — RDP connection files with saved credentials
- `Groups.xml` — Group Policy Preferences with encrypted (crackable) passwords
- `*.pfx`, `*.p12`, `*.pem` — certificate files

---

## User Enumeration (--users)

Enumerates domain users via SAM-R or LDAP:

```bash
nxc smb 192.168.1.10 -u jsmith -p 'Password123' --users
```

**Example output:**
```
SMB         192.168.1.10    445    DC01             [*] Windows Server 2019 Build 17763 x64 (name:DC01) (domain:CORP.LOCAL) (signing:True) (SMBv1:False)
SMB         192.168.1.10    445    DC01             [+] CORP.LOCAL\jsmith:Password123
SMB         192.168.1.10    445    DC01             [*] Enumerated domain user(s)
SMB         192.168.1.10    445    DC01             CORP.LOCAL\Administrator                  Built-in account for administering the computer/domain
SMB         192.168.1.10    445    DC01             CORP.LOCAL\Guest                          Built-in account for guest access
SMB         192.168.1.10    445    DC01             CORP.LOCAL\krbtgt                         Key Distribution Center Service Account
SMB         192.168.1.10    445    DC01             CORP.LOCAL\jsmith                         John Smith - IT Support
SMB         192.168.1.10    445    DC01             CORP.LOCAL\svc_sql                        SQL Service Account
SMB         192.168.1.10    445    DC01             CORP.LOCAL\svc_backup                     Backup Service Account
SMB         192.168.1.10    445    DC01             CORP.LOCAL\admin.jones                    Admin - Sarah Jones
SMB         192.168.1.10    445    DC01             CORP.LOCAL\t.williams                     Tom Williams
```

The user list is valuable for:
- Building a username wordlist for password spraying
- Identifying service accounts (svc_*) which often have SPNs (Kerberoastable)
- Identifying admin accounts for targeted attacks

---

## Group Enumeration (--groups)

Enumerates domain groups:

```bash
nxc smb 192.168.1.10 -u jsmith -p 'Password123' --groups
```

**Example output:**
```
SMB         192.168.1.10    445    DC01             [+] CORP.LOCAL\jsmith:Password123
SMB         192.168.1.10    445    DC01             [*] Enumerated domain group(s)
SMB         192.168.1.10    445    DC01             Domain Admins                             membercount: 3
SMB         192.168.1.10    445    DC01             Domain Users                              membercount: 45
SMB         192.168.1.10    445    DC01             Enterprise Admins                         membercount: 1
SMB         192.168.1.10    445    DC01             Schema Admins                             membercount: 1
SMB         192.168.1.10    445    DC01             IT_Admins                                 membercount: 5
SMB         192.168.1.10    445    DC01             SQL_Admins                                membercount: 2
SMB         192.168.1.10    445    DC01             Backup Operators                          membercount: 3
```

### Local Group Enumeration (--local-groups)

Enumerates local groups on a specific host (useful for finding local admins):

```bash
nxc smb 192.168.1.20 -u jsmith -p 'Password123' --local-groups
```

**Example output:**
```
SMB         192.168.1.20    445    WS01             [+] CORP.LOCAL\jsmith:Password123
SMB         192.168.1.20    445    WS01             [*] Enumerated local groups
SMB         192.168.1.20    445    WS01             Administrators                            membercount: 3
SMB         192.168.1.20    445    WS01             Remote Desktop Users                      membercount: 2
SMB         192.168.1.20    445    WS01             Remote Management Users                   membercount: 1
```

---

## Session Enumeration (--sessions)

Enumerates active SMB sessions on a host — shows who is currently connected:

```bash
nxc smb 192.168.1.10 -u jsmith -p 'Password123' --sessions
```

**Example output:**
```
SMB         192.168.1.10    445    DC01             [+] CORP.LOCAL\jsmith:Password123
SMB         192.168.1.10    445    DC01             [*] Enumerated sessions
SMB         192.168.1.10    445    DC01             \\192.168.1.50                            CORP\admin.jones
SMB         192.168.1.10    445    DC01             \\192.168.1.55                            CORP\svc_backup
```

This reveals:
- Which users are actively connected (potential targets for credential theft)
- Source IPs of connections (identifying admin workstations)

---

## Logged-On Users (--loggedon-users)

Shows users who are logged into the target host:

```bash
nxc smb 192.168.1.20 -u jsmith -p 'Password123' --loggedon-users
```

**Example output:**
```
SMB         192.168.1.20    445    WS01             [+] CORP.LOCAL\jsmith:Password123
SMB         192.168.1.20    445    WS01             [*] Enumerated logged_on users
SMB         192.168.1.20    445    WS01             CORP.LOCAL\admin.jones                    logon_server: DC01
SMB         192.168.1.20    445    WS01             CORP.LOCAL\t.williams                     logon_server: DC01
```

This is valuable for:
- Finding where high-value users (domain admins) are logged in
- Planning credential theft (dump LSASS on hosts where admins are active)
- Lateral movement targeting

---

## Password Policy Enumeration (--pass-pol)

Retrieves the domain password policy — essential before password spraying:

```bash
nxc smb 192.168.1.10 -u jsmith -p 'Password123' --pass-pol
```

**Example output:**
```
SMB         192.168.1.10    445    DC01             [+] CORP.LOCAL\jsmith:Password123
SMB         192.168.1.10    445    DC01             [+] Dumping password info for domain: CORP
SMB         192.168.1.10    445    DC01             Minimum password length: 8
SMB         192.168.1.10    445    DC01             Password history length: 12
SMB         192.168.1.10    445    DC01             Maximum password age: 90 days
SMB         192.168.1.10    445    DC01             Password Complexity Flags: 000001
SMB         192.168.1.10    445    DC01                 Domain Refuse Password Change: 0
SMB         192.168.1.10    445    DC01                 Domain Password Store Cleartext: 0
SMB         192.168.1.10    445    DC01                 Domain Password Lockout Admins: 0
SMB         192.168.1.10    445    DC01             Minimum password age: 1 day
SMB         192.168.1.10    445    DC01             Reset Account Lockout Counter: 30 minutes
SMB         192.168.1.10    445    DC01             Locked Account Duration: 30 minutes
SMB         192.168.1.10    445    DC01             Account Lockout Threshold: 5
SMB         192.168.1.10    445    DC01             Forced Logoff Time: Not Set
```

### Critical Fields for Password Spraying

- **Account Lockout Threshold: 5** — after 5 failed attempts, the account locks out
- **Reset Account Lockout Counter: 30 minutes** — the counter resets after 30 minutes
- **Locked Account Duration: 30 minutes** — locked accounts unlock after 30 minutes

**Safe spraying rule:** Try at most (threshold - 2) passwords per lockout reset period. With a threshold of 5, try at most 3 passwords, then wait 30+ minutes.

---

## RID Brute Forcing (--rid-brute)

RID (Relative Identifier) brute forcing enumerates users and groups by cycling through RID values. This works even when SAM-R enumeration is restricted:

```bash
# Default RID range (500-4000)
nxc smb 192.168.1.10 -u jsmith -p 'Password123' --rid-brute
```

**Example output:**
```
SMB         192.168.1.10    445    DC01             [+] CORP.LOCAL\jsmith:Password123
SMB         192.168.1.10    445    DC01             500: CORP\Administrator (SidTypeUser)
SMB         192.168.1.10    445    DC01             501: CORP\Guest (SidTypeUser)
SMB         192.168.1.10    445    DC01             502: CORP\krbtgt (SidTypeUser)
SMB         192.168.1.10    445    DC01             512: CORP\Domain Admins (SidTypeGroup)
SMB         192.168.1.10    445    DC01             513: CORP\Domain Users (SidTypeGroup)
SMB         192.168.1.10    445    DC01             514: CORP\Domain Guests (SidTypeGroup)
SMB         192.168.1.10    445    DC01             515: CORP\Domain Computers (SidTypeGroup)
SMB         192.168.1.10    445    DC01             516: CORP\Domain Controllers (SidTypeGroup)
SMB         192.168.1.10    445    DC01             1103: CORP\jsmith (SidTypeUser)
SMB         192.168.1.10    445    DC01             1104: CORP\svc_sql (SidTypeUser)
SMB         192.168.1.10    445    DC01             1105: CORP\svc_backup (SidTypeUser)
SMB         192.168.1.10    445    DC01             1106: CORP\admin.jones (SidTypeUser)
```

```bash
# Extended RID range for larger domains
nxc smb 192.168.1.10 -u jsmith -p 'Password123' --rid-brute 10000
```

RID brute forcing is especially valuable when:
- SAM-R enumeration is blocked by GPO
- You only have a null session or guest access
- You need to enumerate users that --users misses

---

## Disk Enumeration (--disks)

Enumerates physical/logical disks on a target (requires admin access):

```bash
nxc smb 192.168.1.20 -u admin -p 'Password123' --disks
```

**Example output:**
```
SMB         192.168.1.20    445    WS01             [+] CORP.LOCAL\admin:Password123 (Pwn3d!)
SMB         192.168.1.20    445    WS01             [*] Enumerated disks
SMB         192.168.1.20    445    WS01             C:
SMB         192.168.1.20    445    WS01             D:
```

---

## Domain vs Local Authentication

Understanding the difference between domain and local authentication is critical:

### Domain Authentication (default)

```bash
# Domain auth — credentials checked against Active Directory
nxc smb 192.168.1.10 -u jsmith -p 'Password123' -d CORP.LOCAL
```

If you omit `-d`, NXC uses the domain reported by the target. For domain-joined machines this is correct automatically.

### Local Authentication

```bash
# Local auth — credentials checked against the local SAM database
nxc smb 192.168.1.10 -u administrator -p 'LocalAdmin!' --local-auth
```

Use `--local-auth` when:
- Targeting non-domain-joined machines (workgroup)
- Using credentials from a SAM dump (`--sam` output)
- The local admin password was found separately from domain creds
- Testing built-in Administrator account with a known password

### Combining with Subnet Scanning

```bash
# Check if a local admin password is reused across hosts
nxc smb 192.168.1.0/24 -u administrator -p 'LocalAdmin!' --local-auth
```

**Output showing password reuse:**
```
SMB         192.168.1.20    445    WS01             [+] WS01\administrator:LocalAdmin! (Pwn3d!)
SMB         192.168.1.21    445    WS02             [+] WS02\administrator:LocalAdmin! (Pwn3d!)
SMB         192.168.1.22    445    WS03             [-] WS03\administrator:LocalAdmin! STATUS_LOGON_FAILURE
SMB         192.168.1.30    445    FILE01           [+] FILE01\administrator:LocalAdmin! (Pwn3d!)
```

This reveals that the same local admin password is used on WS01, WS02, and FILE01 — a critical finding for any penetration test.

---

## Combining Multiple Enumeration Actions

You can combine multiple enumeration flags in a single command:

```bash
# Enumerate users, shares, and password policy in one pass
nxc smb 192.168.1.10 -u jsmith -p 'Password123' --users --shares --pass-pol

# Enumerate sessions and logged-on users across the subnet
nxc smb 192.168.1.0/24 -u jsmith -p 'Password123' --sessions --loggedon-users
```

---

## Practical SMB Enumeration Workflow

A typical SMB enumeration sequence during a penetration test:

```bash
# Step 1: Discover hosts and check SMB signing
nxc smb 192.168.1.0/24

# Step 2: Generate relay target list
nxc smb 192.168.1.0/24 --gen-relay-list relay_targets.txt

# Step 3: Try null sessions
nxc smb 192.168.1.0/24 -u '' -p '' --shares

# Step 4: With first valid credentials, enumerate everything
nxc smb 192.168.1.10 -u jsmith -p 'Password123' --users --groups --shares --pass-pol --sessions

# Step 5: Spider shares for sensitive files
nxc smb 192.168.1.10 -u jsmith -p 'Password123' --spider IT_Share --pattern 'pass|cred|secret|key'

# Step 6: Check where credentials have admin access
nxc smb 192.168.1.0/24 -u jsmith -p 'Password123'
```
