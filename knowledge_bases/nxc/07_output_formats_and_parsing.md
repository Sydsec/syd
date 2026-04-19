# NXC Output Formats and Parsing

## Understanding NXC Output Structure

Every line of NXC output follows a consistent format that is critical for parsing tool output pasted by analysts. Understanding this format allows accurate extraction of hosts, credentials, access levels, and findings.

### Standard Output Line Format

```
PROTOCOL    IP_ADDRESS      PORT   HOSTNAME         [SYMBOL] MESSAGE
```

Each field is padded with spaces for alignment:
- **PROTOCOL** — left-aligned, padded to ~12 characters (SMB, LDAP, WINRM, RDP, MSSQL, SSH, FTP, WMI, VNC)
- **IP_ADDRESS** — the target IP, padded to ~16 characters
- **PORT** — the port number, padded to ~7 characters
- **HOSTNAME** — the NetBIOS name or IP of the target, padded to ~17 characters
- **[SYMBOL]** — one of [*], [+], [-]
- **MESSAGE** — the result content

---

## Exact Output Patterns by Protocol

### SMB Output Patterns

**Host Discovery (unauthenticated):**
```
SMB         192.168.1.10    445    DC01             [*] Windows Server 2019 Build 17763 x64 (name:DC01) (domain:CORP.LOCAL) (signing:True) (SMBv1:False)
```

**Successful Authentication:**
```
SMB         192.168.1.10    445    DC01             [+] CORP.LOCAL\administrator:Password123
```

**Successful Authentication with Admin:**
```
SMB         192.168.1.10    445    DC01             [+] CORP.LOCAL\administrator:Password123 (Pwn3d!)
```

**Successful PTH Authentication:**
```
SMB         192.168.1.10    445    DC01             [+] CORP.LOCAL\administrator:5f4dcc3b5aa765d61d8327deb882cf99 (Pwn3d!)
```

**Failed Authentication:**
```
SMB         192.168.1.10    445    DC01             [-] CORP.LOCAL\jsmith:WrongPass STATUS_LOGON_FAILURE
```

**Account Locked Out:**
```
SMB         192.168.1.10    445    DC01             [-] CORP.LOCAL\jsmith:Password123 STATUS_ACCOUNT_LOCKED_OUT
```

**Account Disabled:**
```
SMB         192.168.1.10    445    DC01             [-] CORP.LOCAL\olduser:Password123 STATUS_ACCOUNT_DISABLED
```

**Password Expired:**
```
SMB         192.168.1.10    445    DC01             [-] CORP.LOCAL\jsmith:OldPass STATUS_PASSWORD_EXPIRED
```

**Password Must Change:**
```
SMB         192.168.1.10    445    DC01             [-] CORP.LOCAL\newuser:TempPass STATUS_PASSWORD_MUST_CHANGE
```

**Share Enumeration:**
```
SMB         192.168.1.10    445    FILE01           [*] Enumerated shares
SMB         192.168.1.10    445    FILE01           Share           Permissions     Remark
SMB         192.168.1.10    445    FILE01           -----           -----------     ------
SMB         192.168.1.10    445    FILE01           ADMIN$                          Remote Admin
SMB         192.168.1.10    445    FILE01           C$                              Default share
SMB         192.168.1.10    445    FILE01           IPC$            READ            Remote IPC
SMB         192.168.1.10    445    FILE01           IT_Share        READ,WRITE      IT Department Files
```

**SAM Dump:**
```
SMB         192.168.1.20    445    WS01             [*] Dumping SAM hashes
SMB         192.168.1.20    445    WS01             Administrator:500:aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99:::
SMB         192.168.1.20    445    WS01             Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```

**LSA Dump:**
```
SMB         192.168.1.20    445    WS01             [*] Dumping LSA secrets
SMB         192.168.1.20    445    WS01             CORP.LOCAL/svc_sql:$DCC2$10240#svc_sql#a1b2c3d4e5f6...
```

**NTDS Dump:**
```
SMB         192.168.1.10    445    DC01             [*] Dumping the NTDS, this could take a while so go grab a redbull...
SMB         192.168.1.10    445    DC01             Administrator:500:aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99:::
SMB         192.168.1.10    445    DC01             krbtgt:502:aad3b435b51404eeaad3b435b51404ee:b7a9c5b2c0d5e8f6a1b2c3d4e5f6a7b8:::
```

**User Enumeration:**
```
SMB         192.168.1.10    445    DC01             [*] Enumerated domain user(s)
SMB         192.168.1.10    445    DC01             CORP.LOCAL\Administrator                  Built-in account for administering the computer/domain
SMB         192.168.1.10    445    DC01             CORP.LOCAL\jsmith                         John Smith - IT Support
```

**Group Enumeration:**
```
SMB         192.168.1.10    445    DC01             [*] Enumerated domain group(s)
SMB         192.168.1.10    445    DC01             Domain Admins                             membercount: 3
SMB         192.168.1.10    445    DC01             Domain Users                              membercount: 45
```

**Password Policy:**
```
SMB         192.168.1.10    445    DC01             [+] Dumping password info for domain: CORP
SMB         192.168.1.10    445    DC01             Minimum password length: 8
SMB         192.168.1.10    445    DC01             Account Lockout Threshold: 5
SMB         192.168.1.10    445    DC01             Reset Account Lockout Counter: 30 minutes
```

**RID Brute Force:**
```
SMB         192.168.1.10    445    DC01             500: CORP\Administrator (SidTypeUser)
SMB         192.168.1.10    445    DC01             512: CORP\Domain Admins (SidTypeGroup)
SMB         192.168.1.10    445    DC01             1103: CORP\jsmith (SidTypeUser)
```

**Command Execution:**
```
SMB         192.168.1.20    445    WS01             [*] Executing command via wmiexec
SMB         192.168.1.20    445    WS01             corp\administrator
```

**Session Enumeration:**
```
SMB         192.168.1.10    445    DC01             [*] Enumerated sessions
SMB         192.168.1.10    445    DC01             \\192.168.1.50                            CORP\admin.jones
```

**Logged-On Users:**
```
SMB         192.168.1.20    445    WS01             [*] Enumerated logged_on users
SMB         192.168.1.20    445    WS01             CORP.LOCAL\admin.jones                    logon_server: DC01
```

### LDAP Output Patterns

**Authentication:**
```
LDAP        192.168.1.10    389    DC01             [+] CORP.LOCAL\jsmith:Password123
```

**Kerberoasting:**
```
LDAP        192.168.1.10    389    DC01             [*] Total of records returned: 3
LDAP        192.168.1.10    389    DC01             svc_sql - MSSQLSvc/sql01.corp.local:1433
LDAP        192.168.1.10    389    DC01             svc_http - HTTP/web01.corp.local
```

**AS-REP Roasting:**
```
LDAP        192.168.1.10    389    DC01             [*] Total of records returned: 1
LDAP        192.168.1.10    389    DC01             svc_legacy - UF_DONT_REQUIRE_PREAUTH
```

### WinRM Output Patterns

**Authentication:**
```
WINRM       192.168.1.20    5985   WS01             [*] Windows 10 Build 19041 (name:WS01) (domain:CORP.LOCAL)
WINRM       192.168.1.20    5985   WS01             [+] CORP.LOCAL\administrator:Password123 (Pwn3d!)
```

**Command Execution:**
```
WINRM       192.168.1.20    5985   WS01             [+] CORP.LOCAL\administrator:Password123 (Pwn3d!)
WINRM       192.168.1.20    5985   WS01             corp\administrator
```

### RDP Output Patterns

**Authentication:**
```
RDP         192.168.1.20    3389   WS01             [+] CORP.LOCAL\administrator:Password123 (Pwn3d!)
```

**Failed Authentication:**
```
RDP         192.168.1.20    3389   WS01             [-] CORP.LOCAL\jsmith:WrongPass
```

### MSSQL Output Patterns

**Authentication:**
```
MSSQL       192.168.1.25    1433   SQL01            [+] CORP.LOCAL\sa:SQLPassword123! (Pwn3d!)
```

**Query Results:**
```
MSSQL       192.168.1.25    1433   SQL01            [*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
MSSQL       192.168.1.25    1433   SQL01            [*] INFO(SQL01): Line 1: Changed database context to 'master'.
MSSQL       192.168.1.25    1433   SQL01            master
MSSQL       192.168.1.25    1433   SQL01            tempdb
MSSQL       192.168.1.25    1433   SQL01            model
MSSQL       192.168.1.25    1433   SQL01            msdb
```

**xp_cmdshell:**
```
MSSQL       192.168.1.25    1433   SQL01            [*] Executing command via xp_cmdshell
MSSQL       192.168.1.25    1433   SQL01            nt service\mssqlserver
```

### SSH Output Patterns

**Authentication:**
```
SSH         192.168.1.100   22     192.168.1.100    [+] root:toor
```

**Command Execution:**
```
SSH         192.168.1.100   22     192.168.1.100    uid=0(root) gid=0(root) groups=0(root)
```

### FTP Output Patterns

**Authentication:**
```
FTP         192.168.1.40    21     192.168.1.40     [+] anonymous:
FTP         192.168.1.40    21     192.168.1.40     [-] ftpuser:wrongpass
```

---

## Output Flags and Logging

### Verbose Output

```bash
# Show more detail about what NXC is doing
nxc smb 192.168.1.10 -u jsmith -p 'Password123' --shares --verbose
```

### Debug Output

```bash
# Full debug output (very detailed, useful for troubleshooting)
nxc smb 192.168.1.10 -u jsmith -p 'Password123' --debug
```

### Logging to File

```bash
# Log all output to a file
nxc smb 192.168.1.0/24 -u jsmith -p 'Password123' --log /tmp/nxc_output.log

# Log with specific output directory
nxc smb 192.168.1.0/24 -u jsmith -p 'Password123' -o /tmp/nxc_results/
```

### NXC Log Directory

By default, NXC stores logs in:
```
~/.nxc/logs/
```

Log files are created per-run with timestamps.

---

## Parsing NXC Output

### Key Parsing Patterns

**Extracting successful authentications:**
Look for lines containing `[+]` — these indicate successful operations.

**Identifying admin access:**
Look for `(Pwn3d!)` at the end of authentication lines.

**Extracting hostnames and IPs:**
The second and fourth columns of every output line contain the IP and hostname respectively.

**Identifying the domain:**
Look for the `(domain:DOMAIN.NAME)` field in the `[*]` informational lines.

**Identifying SMB signing status:**
Look for `(signing:True)` or `(signing:False)` in the `[*]` host info lines.

**Extracting hash dumps:**
SAM/NTDS hashes follow the format: `username:RID:LM_hash:NT_hash:::`

**Extracting credential dump results (lsassy/mimikatz):**
Look for `DOMAIN\username` followed by an NT hash (32 hex characters).

### Parsing Examples with grep

```bash
# Find all hosts with admin access
cat nxc_output.log | grep "(Pwn3d!)"

# Find all failed logins
cat nxc_output.log | grep "\[-\]"

# Find all hosts with SMB signing disabled
cat nxc_output.log | grep "signing:False"

# Extract all SAM/NTDS hashes
cat nxc_output.log | grep ":::"

# Find locked accounts
cat nxc_output.log | grep "STATUS_ACCOUNT_LOCKED_OUT"
```

---

## Hash Dump Output Format

### SAM Hash Format
```
username:RID:LM_hash:NT_hash:::
```

Example:
```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99:::
```

Fields:
- `Administrator` — username
- `500` — RID (Relative Identifier)
- `aad3b435b51404eeaad3b435b51404ee` — LM hash (usually empty/disabled)
- `5f4dcc3b5aa765d61d8327deb882cf99` — NT hash (the important one)
- `:::` — trailing delimiter

### NTDS Hash Format
Same as SAM but prefixed with the domain:
```
CORP.LOCAL\jsmith:1103:aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42:::
```

### DCC2 Hash Format (from LSA)
```
CORP.LOCAL/svc_sql:$DCC2$10240#svc_sql#a1b2c3d4e5f6...
```

DCC2 (Domain Cached Credentials v2) hashes are much slower to crack than NTLM.
Hashcat mode: `-m 2100`

### Kerberoast Hash Format
```
$krb5tgs$23$*svc_sql$CORP.LOCAL$MSSQLSvc/sql01.corp.local:1433*$a1b2c3d4...
```
Hashcat mode: `-m 13100`

### AS-REP Hash Format
```
$krb5asrep$23$svc_legacy@CORP.LOCAL:a1b2c3d4...
```
Hashcat mode: `-m 18200`

---

## Status Code Reference

| Status Code | Meaning | Action |
|-------------|---------|--------|
| STATUS_LOGON_FAILURE | Wrong username or password | Try different credentials |
| STATUS_ACCOUNT_LOCKED_OUT | Too many failed attempts | Stop spraying, wait for lockout timer |
| STATUS_ACCOUNT_DISABLED | Account is disabled | Skip this account |
| STATUS_PASSWORD_EXPIRED | Password has expired | Note for report, may still work for some services |
| STATUS_PASSWORD_MUST_CHANGE | Must change at next logon | Note for report |
| STATUS_LOGON_TYPE_NOT_GRANTED | Logon type not allowed | Try different protocol (e.g., RDP instead of SMB) |
| STATUS_ACCESS_DENIED | Access denied after auth | Valid creds but insufficient permissions |
| STATUS_NOT_SUPPORTED | Operation not supported | Try different execution method |
