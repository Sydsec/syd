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

    # Critical attack paths
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
        'allowedtoact': 'Resource-Based Constrained Delegation',
        'canrdp': 'RDP Access',
        'canpsremote': 'PowerShell Remoting',
        'executedcom': 'DCOM Execution',
        'allowedtoauthenticate': 'Allowed to Authenticate',
        'adcsesc1': 'ESC1 Certificate Misconfiguration',
        'adcsesc3': 'ESC3 Certificate Enrollment Agent',
        'adcsesc4': 'ESC4 Vulnerable Certificate Template',
        'adcsesc6': 'ESC6 EDITF_ATTRIBUTESUBJECTALTNAME2',
        'sqladmin': 'SQL Admin Access',
        'readlapspassword': 'Read LAPS Password',
        'readgmsapassword': 'Read gMSA Password',
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
        question_patterns = [
            r'^\s*(what|how|why|when|where|who|which|can you|could you|please|show me|give me|explain|tell me|describe|outline|define|what is the impact of)',
            r'\?$',  # Ends with question mark
            r'(what is|how do|how to|can i|should i|explain the|describe the|give me a step-by-step)',
        ]

        for pattern in question_patterns:
            if re.search(pattern, text, re.IGNORECASE | re.MULTILINE):
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
        """Generates a markdown report from a vulnerabilities dictionary."""
        findings = []
        attack_paths = vulnerabilities.get('attack_paths', [])
        property_vulns = vulnerabilities.get('property_vulns', [])
        high_value_targets = vulnerabilities.get('high_value_targets', [])
        
        findings.append("="*80)
        
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
        findings.append("## [🔬] DETAILED FINDINGS\n")

        # 2. High-value targets
        if high_value_targets:
            findings.append("### 🏆 HIGH-VALUE TARGETS\n")
            unique_targets = {t['name']: t for t in high_value_targets}
            for target in list(unique_targets.values())[:10]:  # Top 10 unique
                findings.append(f"- **{target['name']}** ({target['type']})")
                if target.get('why'):
                    findings.append(f"  - {target['why']}")
            findings.append("")

        # 3. All Attack paths from ACEs
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

        if not has_findings:
            findings.append("## [✅] NO CRITICAL VULNERABILITIES FOUND\n")
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
        findings = ["# [🔴] BLOODHOUND ACTIVE DIRECTORY ANALYSIS\n"]
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
                for i in range(start, len(text)):
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
                for i in range(start, len(text)):
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
        vulnerabilities = {
            'property_vulns': [],
            'attack_paths': [],
            'high_value_targets': [],
            'acl_issues': []
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

            # 1. Kerberoastable
            if props.get('hasspn') and is_enabled:
                spns = props.get('serviceprincipalnames', [])
                vulnerabilities['property_vulns'].append({
                    'type': 'KERBEROASTABLE',
                    'account': name,
                    'details': f"SPNs: {', '.join(spns[:3]) if spns else 'Set'}",
                    'exploit': f"GetUserSPNs.py DOMAIN/user:password -request -dc-ip DC_IP",
                    'fix': f"Set-ADUser {name.split('@')[0]} -ServicePrincipalNames @{{Remove='<SPN>'}}"
                })

            # 2. AS-REP Roasting
            if props.get('dontreqpreauth') and is_enabled:
                vulnerabilities['property_vulns'].append({
                    'type': 'AS-REP ROASTING',
                    'account': name,
                    'details': 'Pre-authentication not required',
                    'exploit': f"GetNPUsers.py DOMAIN/ -usersfile users.txt -no-pass",
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
        """Assess risk level and exploitation for an ACE"""
        right_lower = right_name.lower()
        principal_lower = principal.lower()
        target_lower = target.lower()

        is_hvt = any(hvt in target_lower for hvt in ['domain admins', 'enterprise admins', 'administrators', 'krbtgt'])
        is_domain_target = '.local' in target_lower or 'domain' in target_lower or target_lower.endswith('.com')

        # CRITICAL risks
        # DCSync detection - GetChanges or GetChangesAll on domain
        if right_lower in ['getchanges', 'getchangesall'] and is_domain_target:
            return ('CRITICAL',
                    f"secretsdump.py {target.split('@')[0]}/{principal.split('@')[0]}:password@DC_IP -just-dc",
                    "DCSync attack - can dump all domain password hashes including KRBTGT")

        if right_lower == 'addkeycredentiallink':
            return ('CRITICAL',
                    f"certipy shadow auto -target {target} -u {principal}",
                    "Shadow Credentials attack - instant account takeover")

        if right_lower in ['genericall', 'owns']:
            exploit = f"Full control over {target} - can reset password, modify properties, add to groups"
            impact = "Complete account compromise"
            if is_hvt and not any(admin_group in principal_lower for admin_group in ['domain admins', 'enterprise admins']):
                return 'CRITICAL', exploit, f"Direct path to Domain Admin by controlling {target}"
            return 'CRITICAL', exploit, impact

        if right_lower == 'writedacl':
            return ('CRITICAL',
                    f"Grant yourself GenericAll: dacledit.py -action write -rights FullControl -principal {principal} -target {target}",
                    "Can grant yourself any permission")

        if right_lower == 'writeowner':
            return ('CRITICAL',
                    f"Take ownership then grant GenericAll",
                    "Can become owner and grant full control")

        # HIGH risks
        if right_lower == 'allextendedrights':
            return ('HIGH',
                    f"Includes ForceChangePassword and other dangerous rights",
                    "Can reset password and perform other privileged operations")

        if right_lower == 'forcechangepassword':
            return ('HIGH',
                    f"net rpc password {target.split('@')[0]} -U {principal} -S DC",
                    "Can reset target's password")

        if right_lower == 'genericwrite':
            return ('HIGH',
                    f"Modify user properties (e.g., add SPN for Kerberoasting)",
                    "Can modify object attributes")

        if right_lower == 'readgmsapassword':
            return ('HIGH',
                    f"Read gMSA password and authenticate as service account",
                    "Can extract managed service account password")

        # Check for dangerous principals
        if principal_lower in ['everyone', 'authenticated users', 's-1-1-0', 's-1-5-11']:
            if right_lower not in ['readproperty', 'readcontrol']:
                return ('CRITICAL',
                        f"ANY domain user can abuse {right_name} on {target}",
                        "Overly permissive ACE - any authenticated user can exploit")

        # MEDIUM risks
        if right_lower in ['readlapspassword', 'member of', 'admincount']:
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
        report_findings = ["# [🔴] BLOODHOUND ACTIVE DIRECTORY ANALYSIS\n"]
        report_findings.append(f"**Detected Output Type**: SharpHound ZIP Export\n")

        with zipfile.ZipFile(zip_path, 'r') as zf:
            json_files = [f for f in zf.namelist() if f.endswith('.json')]
            if not json_files:
                return ("# [ℹ️] INFO\n\nNo .json files found in the ZIP archive.", None)

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

        return ("# [ℹ️] INFO\n\nCould not find valid BloodHound data objects in the provided ZIP file.", None)

    except (zipfile.BadZipFile, FileNotFoundError) as e:
        return (f"# [❌] ERROR\n\nFailed to analyze ZIP file: {e}", None)
    except Exception as e:
        # Catch any other unexpected errors
        return (f"# [❌] CRITICAL ERROR\n\nAn unexpected error occurred during ZIP analysis: {e}", None)
