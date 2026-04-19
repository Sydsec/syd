#!/usr/bin/env python3
"""
NXC/NetExec Fact Extractor
Parses raw NXC terminal output into structured facts for Syd analysis.
"""

import re
from dataclasses import dataclass, field
from typing import List, Optional, Dict


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class NXCHost:
    ip:          str
    hostname:    str  = ""
    port:        str  = "445"
    protocol:    str  = "SMB"
    os:          str  = ""
    domain:      str  = ""
    signing:     bool = True
    smb_v1:      bool = False
    admin_access: bool = False   # (Pwn3d!)

@dataclass
class NXCCredential:
    domain:   str
    username: str
    secret:   str            # password or hash
    host_ip:  str  = ""
    hostname: str  = ""
    is_hash:  bool = False
    pwned:    bool = False
    status:   str  = "SUCCESS"  # SUCCESS / FAIL / LOCKED / DISABLED

@dataclass
class NXCShare:
    host_ip:     str
    hostname:    str
    share_name:  str
    permissions: str
    remark:      str = ""

@dataclass
class NXCUser:
    username:   str
    host_ip:    str = ""
    hostname:   str = ""
    rid:        str = ""
    enabled:    bool = True

@dataclass
class NXCFacts:
    # Raw input
    raw_output:    str = ""

    # Parsed findings
    hosts:         List[NXCHost]       = field(default_factory=list)
    credentials:   List[NXCCredential] = field(default_factory=list)
    shares:        List[NXCShare]      = field(default_factory=list)
    users:         List[NXCUser]       = field(default_factory=list)

    # Quick-access summaries
    pwned_hosts:   List[str]           = field(default_factory=list)  # IPs with Pwn3d!
    domains:       List[str]           = field(default_factory=list)
    protocols_seen: List[str]          = field(default_factory=list)
    hash_dump:     List[str]           = field(default_factory=list)  # secretsdump/NTDS lines
    exec_output:   List[str]           = field(default_factory=list)  # command exec results
    confirmed_vulns: List[str]         = field(default_factory=list)  # confirmed vuln check results
    gpp_passwords:  List[str]          = field(default_factory=list)  # GPP passwords found


# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

# Standard NXC line: PROTO  IP  PORT  HOSTNAME  [SYMBOL] MESSAGE
_LINE_RE = re.compile(
    r'^(SMB|LDAP|WINRM|RDP|MSSQL|SSH|FTP|VNC|WMI)\s+'
    r'([\d.]+)\s+'
    r'(\d+)\s+'
    r'(\S+)\s+'
    r'(\[\*\]|\[\+\]|\[-\])\s+'
    r'(.+)$'
)

# NXC prefixed line WITHOUT a symbol — used for share/user table rows that
# still carry the PROTO IP PORT HOSTNAME prefix in real NXC output.
# e.g.  SMB  192.168.1.20  445  FILE01  Finance  READ,WRITE  Dept Files
_PLAIN_LINE_RE = re.compile(
    r'^(SMB|LDAP|WINRM|RDP|MSSQL|SSH|FTP|VNC|WMI)\s+'
    r'[\d.]+\s+\d+\s+\S+\s+'
    r'(.+)$'
)

# Host discovery: [*] Windows Server 2019... (name:X) (domain:Y) (signing:True) (SMBv1:False)
_HOST_INFO_RE = re.compile(
    r'Windows[^(]*\(name:([^)]+)\)\s*\(domain:([^)]+)\)\s*\(signing:(True|False)\)\s*\(SMBv1:(True|False)\)',
    re.IGNORECASE
)

# Successful auth — applied to message field (after [+] already stripped by _LINE_RE)
# Pattern: DOMAIN\user:secret (Pwn3d!)
_AUTH_SUCCESS_RE = re.compile(
    r'([^\\]+)\\([^:]+):(.+?)(\s+\(Pwn3d!\))?$'
)

# Failed auth — applied to message field (after [-] already stripped by _LINE_RE)
# Pattern: DOMAIN\user:secret STATUS_*
_AUTH_FAIL_RE = re.compile(
    r'([^\\]+)\\([^:]+):(.+?)\s+(STATUS_\w+)'
)

# Share line (after "Enumerated shares"):
# SHARENAME    READ/WRITE    Remark
_SHARE_RE = re.compile(
    r'^([\w$\-\.]+)\s+(READ,WRITE|READ|WRITE|NO ACCESS)\s*(.*)?$',
    re.IGNORECASE
)

# Hash line from secretsdump/NTDS: domain\user:RID:LMhash:NThash:::
_HASH_RE = re.compile(
    r'^[^:]+\\[^:]+:\d+:[a-fA-F0-9]{32}:[a-fA-F0-9]{32}:::$'
)

# NT-only hash: user:RID:aad3b...:NThash:::
_NT_HASH_RE = re.compile(
    r'^[^:]+:\d+:[a-fA-F0-9]{32}:[a-fA-F0-9]{32}:::$'
)

# OS string from host discovery
_OS_RE = re.compile(r'(Windows[^\(]+)', re.IGNORECASE)

# User enum line: username  (500) Builtin\...
_USER_RE = re.compile(r'^\s*([\w\.\-]+)\s+\((\d+)\)', re.IGNORECASE)


# ---------------------------------------------------------------------------
# Main extractor class
# ---------------------------------------------------------------------------

class NXCFactExtractor:

    def extract(self, raw_output: str) -> NXCFacts:
        facts             = NXCFacts(raw_output=raw_output)
        lines             = raw_output.splitlines()
        host_map: Dict[str, NXCHost] = {}  # ip -> NXCHost
        in_share_block    = False
        in_user_block     = False
        current_host_ip   = ""
        current_host_name = ""

        for line in lines:
            line = line.rstrip()
            if not line:
                continue

            # ----------------------------------------------------------------
            # Check for secretsdump / NTDS hash lines (no standard NXC prefix)
            # ----------------------------------------------------------------
            if _HASH_RE.match(line) or _NT_HASH_RE.match(line):
                facts.hash_dump.append(line)
                continue

            # ----------------------------------------------------------------
            # Try standard NXC line format
            # ----------------------------------------------------------------
            m = _LINE_RE.match(line)
            if not m:
                # May be a share/user sub-line. Real NXC output keeps the
                # PROTO IP PORT HOSTNAME prefix on every line (including share
                # table rows), so strip it if present before matching.
                plain_m  = _PLAIN_LINE_RE.match(line)
                content  = plain_m.group(2).strip() if plain_m else line.strip()

                if in_share_block and current_host_ip:
                    sm = _SHARE_RE.match(content)
                    if sm:
                        name  = sm.group(1)
                        perms = sm.group(2)
                        remark = (sm.group(3) or "").strip()
                        if name.upper() not in ("SHARE", "-----", "PERMISSIONS"):
                            facts.shares.append(NXCShare(
                                host_ip=current_host_ip,
                                hostname=current_host_name,
                                share_name=name,
                                permissions=perms,
                                remark=remark
                            ))
                if in_user_block and current_host_ip:
                    um = _USER_RE.match(content)
                    if um:
                        facts.users.append(NXCUser(
                            username=um.group(1),
                            host_ip=current_host_ip,
                            hostname=current_host_name,
                            rid=um.group(2)
                        ))
                continue

            proto    = m.group(1)
            ip       = m.group(2)
            port     = m.group(3)
            hostname = m.group(4)
            symbol   = m.group(5)
            message  = m.group(6).strip()

            # Track protocols seen
            if proto not in facts.protocols_seen:
                facts.protocols_seen.append(proto)

            # Reset block tracking when we see a new host
            if ip != current_host_ip:
                in_share_block = False
                in_user_block  = False
            current_host_ip   = ip
            current_host_name = hostname

            # Ensure host entry exists
            if ip not in host_map:
                host_map[ip] = NXCHost(ip=ip, hostname=hostname, port=port, protocol=proto)
            host = host_map[ip]

            # ----------------------------------------------------------------
            # [*] INFO lines
            # ----------------------------------------------------------------
            if symbol == "[*]":
                # Host OS/domain discovery
                hi = _HOST_INFO_RE.search(message)
                if hi:
                    host.hostname = hi.group(1)
                    host.domain   = hi.group(2)
                    host.signing  = hi.group(3).lower() == "true"
                    host.smb_v1   = hi.group(4).lower() == "true"
                    os_m = _OS_RE.search(message)
                    if os_m:
                        host.os = os_m.group(1).strip()
                    if host.domain and host.domain not in facts.domains:
                        facts.domains.append(host.domain)

                # Share block start
                if "enumerated shares" in message.lower():
                    in_share_block = True
                    in_user_block  = False

                # User enum block start
                if "enumerated users" in message.lower():
                    in_user_block  = True
                    in_share_block = False

                # Vulnerability check results — [!] lines embedded in [*] messages
                if "[!]" in message:
                    facts.confirmed_vulns.append(f"{ip} ({hostname}): {message}")

                # Command exec output
                if message and not hi and "enumerated" not in message.lower() and "[!]" not in message:
                    if any(kw in message.lower() for kw in ["command", "stdout"]):
                        facts.exec_output.append(f"{ip} ({hostname}): {message}")

            # ----------------------------------------------------------------
            # [+] SUCCESS lines
            # ----------------------------------------------------------------
            elif symbol == "[+]":
                in_share_block = False
                in_user_block  = False

                # GPP password found
                if "gpp" in message.lower() and ("password" in message.lower() or "name:" in message.lower()):
                    facts.gpp_passwords.append(f"{ip} ({hostname}): {message}")

                # Vulnerability confirmation in [+] line
                vuln_keywords = ["vulnerable", "zerologon", "nopac", "petitpotam", "printnightmare"]
                if any(kw in message.lower() for kw in vuln_keywords):
                    facts.confirmed_vulns.append(f"{ip} ({hostname}): {message}")

                # Auth success pattern: DOMAIN\user:secret (Pwn3d!)
                am = _AUTH_SUCCESS_RE.search(message)
                if am:
                    domain   = am.group(1).strip()
                    username = am.group(2).strip()
                    secret   = am.group(3).strip()
                    pwned    = am.group(4) is not None
                    is_hash  = bool(re.match(r'^[a-fA-F0-9]{32}$', secret))

                    cred = NXCCredential(
                        domain=domain, username=username, secret=secret,
                        host_ip=ip, hostname=hostname,
                        is_hash=is_hash, pwned=pwned, status="SUCCESS"
                    )
                    facts.credentials.append(cred)

                    if pwned:
                        host.admin_access = True
                        if ip not in facts.pwned_hosts:
                            facts.pwned_hosts.append(ip)

                    if domain and domain not in facts.domains:
                        facts.domains.append(domain)

                # Share-level access confirmation
                elif "access" in message.lower():
                    pass

            # ----------------------------------------------------------------
            # [-] FAIL lines
            # ----------------------------------------------------------------
            elif symbol == "[-]":
                in_share_block = False
                in_user_block  = False

                fm = _AUTH_FAIL_RE.search(message)
                if fm:
                    domain   = fm.group(1).strip()
                    username = fm.group(2).strip()
                    secret   = fm.group(3).strip()
                    status_code = fm.group(4)

                    if "LOCKED" in status_code:
                        status = "LOCKED"
                    elif "DISABLED" in status_code:
                        status = "DISABLED"
                    elif "EXPIRED" in status_code:
                        status = "EXPIRED"
                    else:
                        status = "FAIL"

                    facts.credentials.append(NXCCredential(
                        domain=domain, username=username, secret=secret,
                        host_ip=ip, hostname=hostname, status=status
                    ))

        # Finalise hosts list
        facts.hosts = list(host_map.values())

        return facts

    # -----------------------------------------------------------------------
    # facts_to_text: format for LLM context
    # -----------------------------------------------------------------------
    def facts_to_text(self, facts: NXCFacts) -> str:
        lines = []

        # --- Overview ---
        lines.append("=== NXC/NETEXEC SCAN FACTS ===")
        lines.append(f"Protocols used: {', '.join(facts.protocols_seen) if facts.protocols_seen else 'Unknown'}")
        lines.append(f"Domains discovered: {', '.join(facts.domains) if facts.domains else 'None'}")
        lines.append(f"Total hosts: {len(facts.hosts)}")
        lines.append(f"Admin access (Pwn3d!): {len(facts.pwned_hosts)} host(s)")
        lines.append("")

        # --- Hosts ---
        if facts.hosts:
            lines.append("=== DISCOVERED HOSTS ===")
            for h in facts.hosts:
                signing_str = "SIGNING ENABLED" if h.signing else "SIGNING DISABLED (relay possible)"
                admin_str   = "  [ADMIN ACCESS - Pwn3d!]" if h.admin_access else ""
                lines.append(
                    f"  {h.ip} ({h.hostname}) | {h.os or 'Unknown OS'} | "
                    f"Domain: {h.domain or 'Unknown'} | SMB {signing_str} | "
                    f"SMBv1: {'Yes' if h.smb_v1 else 'No'}{admin_str}"
                )
            lines.append("")

        # --- Pwn3d hosts ---
        if facts.pwned_hosts:
            lines.append("=== ADMIN ACCESS (Pwn3d!) ===")
            for ip in facts.pwned_hosts:
                host = next((h for h in facts.hosts if h.ip == ip), None)
                name = host.hostname if host else ip
                lines.append(f"  {ip} ({name}) - FULL ADMIN ACCESS")
            lines.append("")

        # --- Successful credentials ---
        success_creds = [c for c in facts.credentials if c.status == "SUCCESS"]
        if success_creds:
            lines.append("=== VALID CREDENTIALS ===")
            for c in success_creds:
                secret_display = f"[HASH:{c.secret[:8]}...]" if c.is_hash else c.secret
                pwned_flag     = " (Pwn3d! - local admin)" if c.pwned else ""
                lines.append(
                    f"  {c.domain}\\{c.username}:{secret_display} "
                    f"on {c.host_ip} ({c.hostname}){pwned_flag}"
                )
            lines.append("")

        # --- Locked accounts ---
        locked = [c for c in facts.credentials if c.status == "LOCKED"]
        if locked:
            lines.append("=== LOCKED ACCOUNTS (account lockout triggered!) ===")
            for c in locked:
                lines.append(f"  {c.domain}\\{c.username} - LOCKED on {c.host_ip}")
            lines.append("")

        # --- Shares ---
        if facts.shares:
            lines.append("=== ENUMERATED SHARES ===")
            for s in facts.shares:
                lines.append(
                    f"  {s.host_ip} ({s.hostname}) | \\\\{s.hostname}\\{s.share_name} "
                    f"[{s.permissions}]{' - ' + s.remark if s.remark else ''}"
                )
            lines.append("")

        # --- Users ---
        if facts.users:
            lines.append("=== ENUMERATED USERS ===")
            for u in facts.users:
                lines.append(f"  {u.username} (RID:{u.rid}) on {u.host_ip} ({u.hostname})")
            lines.append("")

        # --- Hash dump ---
        if facts.hash_dump:
            lines.append("=== DUMPED HASHES (secretsdump/NTDS) ===")
            lines.append(f"  Total hashes: {len(facts.hash_dump)}")
            for h in facts.hash_dump[:20]:  # show first 20 max
                lines.append(f"  {h}")
            if len(facts.hash_dump) > 20:
                lines.append(f"  ... and {len(facts.hash_dump) - 20} more hashes")
            lines.append("")

        # --- Signing summary ---
        no_signing = [h for h in facts.hosts if not h.signing]
        if no_signing:
            lines.append("=== SMB SIGNING DISABLED (NTLM relay possible) ===")
            for h in no_signing:
                lines.append(f"  {h.ip} ({h.hostname})")
            lines.append("")

        # --- Confirmed vulnerabilities ---
        if facts.confirmed_vulns:
            lines.append("=== CONFIRMED VULNERABILITIES (from scan) ===")
            for v in facts.confirmed_vulns:
                lines.append(f"  [CONFIRMED] {v}")
            lines.append("")

        # --- GPP passwords ---
        if facts.gpp_passwords:
            lines.append("=== GPP PASSWORDS FOUND ===")
            for g in facts.gpp_passwords:
                lines.append(f"  {g}")
            lines.append("")

        # --- Exec output ---
        if facts.exec_output:
            lines.append("=== COMMAND EXECUTION OUTPUT ===")
            for o in facts.exec_output:
                lines.append(f"  {o}")
            lines.append("")

        return "\n".join(lines)
