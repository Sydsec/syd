# NXC/NetExec Basics

## What is NXC/NetExec?

NetExec (NXC) is the modern, actively maintained successor to CrackMapExec (CME). It is a network service exploitation tool used by penetration testers and red teamers to automate the assessment of large Active Directory (AD) environments. NXC can authenticate to multiple network services, enumerate information, spray credentials, execute commands, and dump secrets — all from a single command-line interface.

### History: CrackMapExec to NetExec

CrackMapExec (CME) was originally created by byt3bl33d3r (Marcello Salvati) and became the de facto standard for AD network pentesting. In late 2023, the project was forked and renamed to **NetExec (nxc)** by the community under the Pennyw0rth organization on GitHub. The rename happened because:

- The original CME repository was archived by the author
- The community needed an actively maintained fork with bug fixes and new features
- The new project adopted the command name `nxc` instead of `crackmapexec` or `cme`

**Key difference:** All modern usage should use the `nxc` command. The `crackmapexec` and `cme` commands are deprecated and may not be available in newer installations. Every command in this knowledge base uses `nxc`.

### Installation

**On Kali Linux (recommended):**
```bash
# Kali 2024+ includes NetExec by default
sudo apt update && sudo apt install netexec

# Verify installation
nxc --version
```

**Via pipx (recommended for non-Kali):**
```bash
pipx install netexec
```

**Via pip:**
```bash
pip install netexec
```

**From source (latest development version):**
```bash
git clone https://github.com/Pennyw0rth/NetExec.git
cd NetExec
pipx install .
```

---

## Basic Syntax Structure

The fundamental syntax of every NXC command follows this pattern:

```
nxc <protocol> <target(s)> [options]
```

Where:
- `<protocol>` — the service/protocol to target (smb, ldap, winrm, rdp, ssh, ftp, mssql, vnc, wmi)
- `<target(s)>` — one or more IP addresses, hostnames, CIDR ranges, or a file containing targets
- `[options]` — authentication credentials, actions to perform, output options

### Minimal Examples

```bash
# Enumerate SMB on a single host (no authentication)
nxc smb 192.168.1.10

# Authenticate to SMB with username and password
nxc smb 192.168.1.10 -u admin -p Password123

# Authenticate to LDAP on a domain controller
nxc ldap 10.10.10.5 -u jsmith -p 'Summer2024!' -d CORP.LOCAL

# Check WinRM access
nxc winrm 192.168.1.10 -u admin -p Password123
```

---

## Protocol Modules Overview

NXC supports multiple protocol modules. Each module targets a specific network service:

| Protocol | Default Port | Use Case |
|----------|-------------|----------|
| **smb** | 445 | File shares, user/group enum, credential attacks, command execution, secret dumping |
| **ldap** | 389/636 | Active Directory queries, user/group/trust enumeration |
| **winrm** | 5985/5986 | Remote PowerShell execution, command execution |
| **rdp** | 3389 | RDP authentication checking, NLA validation |
| **ssh** | 22 | SSH authentication and command execution on Linux/network devices |
| **ftp** | 21 | FTP authentication checking, anonymous access |
| **mssql** | 1433 | SQL Server authentication, xp_cmdshell, query execution |
| **vnc** | 5900 | VNC authentication checking |
| **wmi** | 135 | WMI-based command execution and enumeration |

To see available protocols:
```bash
nxc --help
```

To see options for a specific protocol:
```bash
nxc smb --help
nxc ldap --help
nxc winrm --help
```

---

## Understanding NXC Output Symbols

NXC uses specific symbols in its output to indicate the result of each operation. Understanding these is critical for interpreting results:

### [+] — Success (Green)

Indicates successful authentication or operation.

```
SMB         192.168.1.10    445    DC01             [+] CORP.LOCAL\administrator:Password123
```

This means the credentials `administrator:Password123` successfully authenticated to SMB on DC01.

### [+] with (Pwn3d!) — Admin Access Confirmed

When `(Pwn3d!)` appears after a successful authentication, it means the authenticated user has **local administrator privileges** on the target host. This is the most important indicator in NXC output.

```
SMB         192.168.1.10    445    DC01             [+] CORP.LOCAL\administrator:Password123 (Pwn3d!)
```

The `(Pwn3d!)` flag means:
- For SMB: The user can access the `ADMIN$` or `C$` administrative shares
- For WinRM: The user can execute commands via PowerShell Remoting
- For MSSQL: The user has sysadmin privileges
- **This user can execute commands, dump secrets, and fully compromise the host**

### [-] — Failure (Red)

Indicates failed authentication or a failed operation.

```
SMB         192.168.1.10    445    DC01             [-] CORP.LOCAL\administrator:WrongPassword STATUS_LOGON_FAILURE
```

Common failure status codes:
- `STATUS_LOGON_FAILURE` — wrong username or password
- `STATUS_ACCOUNT_DISABLED` — the account is disabled
- `STATUS_ACCOUNT_LOCKED_OUT` — the account is locked out (too many failed attempts)
- `STATUS_PASSWORD_EXPIRED` — the password has expired
- `STATUS_PASSWORD_MUST_CHANGE` — user must change password at next logon
- `STATUS_LOGON_TYPE_NOT_GRANTED` — user doesn't have the logon type rights

### [*] — Informational (Blue)

Provides informational output such as host details discovered during enumeration.

```
SMB         192.168.1.10    445    DC01             [*] Windows Server 2019 Build 17763 x64 (name:DC01) (domain:CORP.LOCAL) (signing:True) (SMBv1:False)
```

This informational line reveals:
- Operating system: Windows Server 2019 Build 17763
- Architecture: x64
- Hostname: DC01
- Domain: CORP.LOCAL
- SMB signing: True (enabled — relay attacks won't work against this host)
- SMBv1: False (disabled)

---

## Target Specification

NXC supports multiple ways to specify targets:

### Single IP Address
```bash
nxc smb 192.168.1.10
```

### Multiple IPs (space-separated)
```bash
nxc smb 192.168.1.10 192.168.1.11 192.168.1.12
```

### CIDR Range
```bash
nxc smb 192.168.1.0/24
nxc smb 10.10.10.0/24
```

### IP Range
```bash
nxc smb 192.168.1.1-50
```

### From a File (one target per line)
```bash
nxc smb targets.txt
```

Where `targets.txt` contains:
```
192.168.1.10
192.168.1.11
10.10.10.5
```

### Hostname
```bash
nxc smb dc01.corp.local
```

---

## Authentication Options

### Domain Authentication (default)
```bash
# Authenticate as a domain user
nxc smb 192.168.1.10 -u jsmith -p 'Password123' -d CORP.LOCAL
```

If `-d` is not specified, NXC uses the domain reported by the target host (from the SMB negotiation).

### Local Authentication
```bash
# Authenticate against the local SAM database instead of Active Directory
nxc smb 192.168.1.10 -u administrator -p 'LocalPass!' --local-auth
```

The `--local-auth` flag is critical when:
- Targeting workgroup machines (not domain-joined)
- Using local administrator credentials (e.g., from SAM dump)
- The local admin password differs from domain credentials

### Multiple Credentials
```bash
# Try multiple usernames
nxc smb 192.168.1.10 -u user1 -u user2 -u user3 -p Password123

# Try multiple passwords
nxc smb 192.168.1.10 -u admin -p pass1 -p pass2 -p pass3

# From files
nxc smb 192.168.1.10 -u users.txt -p passwords.txt
```

### Null Session (no credentials)
```bash
# Attempt null session (empty username and password)
nxc smb 192.168.1.10 -u '' -p ''
```

### Guest Authentication
```bash
# Attempt guest access
nxc smb 192.168.1.10 -u 'guest' -p ''
```

---

## Port Specification

By default NXC uses the standard port for each protocol. To specify a custom port:

```bash
nxc smb 192.168.1.10 --port 4455
nxc mssql 192.168.1.10 --port 14330
nxc ssh 192.168.1.10 --port 2222
```

---

## Timeout and Threading

```bash
# Set connection timeout (seconds)
nxc smb 192.168.1.0/24 --timeout 10

# Set number of threads (default: 100 for most protocols)
nxc smb 192.168.1.0/24 -t 50
```

Reducing threads is important for:
- Avoiding network congestion
- Reducing detection surface
- Preventing account lockouts during spraying

---

## Kerberos Authentication

NXC supports Kerberos authentication instead of NTLM:

```bash
# Use Kerberos authentication
nxc smb dc01.corp.local -u admin -p Password123 -k

# Use a .ccache ticket file
export KRB5CCNAME=/tmp/admin.ccache
nxc smb dc01.corp.local -k --use-kcache
```

Requirements for Kerberos:
- Target must be specified by hostname (not IP)
- `/etc/krb5.conf` must be configured or DNS must resolve the domain
- A valid TGT or credentials to obtain one

---

## CME to NXC Migration Reference

For analysts migrating from CrackMapExec:

| CrackMapExec | NetExec |
|-------------|---------|
| `crackmapexec smb ...` | `nxc smb ...` |
| `cme smb ...` | `nxc smb ...` |
| `~/.cme/` config directory | `~/.nxc/` config directory |
| `cmedb` | `nxcdb` |
| `--exec-method` values identical | Same: wmiexec, smbexec, atexec, mmcexec |

Most command-line flags are identical. The primary change is the binary name from `cme`/`crackmapexec` to `nxc` and the config/database directory from `.cme` to `.nxc`.
