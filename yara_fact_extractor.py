#!/usr/bin/env python3
"""
Deterministic YARA Fact Extractor (Stage A)
Parses YARA output into structured facts - 100% accurate, no AI

This module extracts hard facts from YARA scan output and converts them to Q&A format
for RAG context, enabling precise answers with validation against extracted facts.

Author: Ask Syd Team
Version: 1.0
Date: 2024-01-15
"""

import re
import json
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict
from datetime import datetime


class YaraFactExtractor:
    """
    Extracts structured facts from YARA scan output.
    Supports JSON output, raw text output, and YARA rule files.
    """

    # MITRE ATT&CK mapping for common rule patterns
    MITRE_MAPPINGS = {
        'ransomware': ['T1486', 'T1490'],
        'cobalt': ['T1071.001', 'T1055'],
        'beacon': ['T1071.001', 'T1573'],
        'meterpreter': ['T1055', 'T1071'],
        'mimikatz': ['T1003.001', 'T1003.002'],
        'emotet': ['T1055', 'T1547.001'],
        'trickbot': ['T1055', 'T1547.001'],
        'webshell': ['T1505.003'],
        'inject': ['T1055'],
        'hollow': ['T1055.012'],
        'persist': ['T1547', 'T1053'],
        'keylog': ['T1056.001'],
        'cred': ['T1003', 'T1555'],
        'lolbin': ['T1218'],
        'powershell': ['T1059.001'],
        'wmi': ['T1047'],
        'lateral': ['T1021'],
        'exfil': ['T1041', 'T1048'],
        'rootkit': ['T1014'],
        'exploit': ['T1190', 'T1210'],
    }

    # Severity mapping based on rule characteristics
    SEVERITY_KEYWORDS = {
        'CRITICAL': ['ransomware', 'apt', 'cobalt', 'beacon', 'mimikatz', 'rootkit', 'exploit'],
        'HIGH': ['trojan', 'rat', 'c2', 'inject', 'credential', 'stealer', 'backdoor'],
        'MEDIUM': ['packer', 'suspicious', 'encoded', 'obfuscated'],
        'LOW': ['pup', 'adware', 'generic']
    }

    def extract_facts(self, yara_output: str, input_format: str = 'auto') -> Dict[str, Any]:
        """
        Parse YARA output into structured facts
        Returns dictionary of facts for LLM querying

        Args:
            yara_output: Raw YARA output (JSON, text, or rules)
            input_format: 'json', 'raw', 'rules', or 'auto'

        Returns:
            Dictionary of extracted facts
        """
        facts = {
            "scan_metadata": {},
            "matches": [],
            "rules_triggered": [],
            "files_scanned": [],
            "threat_intelligence": {},
            "mitre_techniques": [],
            "summary": {},
            "qa_pairs": [],
            "iocs": {}  # IOC extraction for professional IR use
        }

        # Auto-detect format
        if input_format == 'auto':
            input_format = self._detect_format(yara_output)

        # Extract based on format
        if input_format == 'json':
            facts = self._extract_from_json(yara_output, facts)
        elif input_format == 'rules':
            facts = self._extract_from_rules(yara_output, facts)
        else:
            facts = self._extract_from_raw(yara_output, facts)

        # Calculate threat score
        facts['threat_intelligence'] = self._calculate_threat_score(facts['matches'])

        # Map to MITRE ATT&CK
        facts['mitre_techniques'] = self._map_to_mitre_attack(facts['matches'])

        # Extract IOCs (IPs, domains, mutexes, pipes, etc.) from matched strings
        facts['iocs'] = self._extract_iocs(facts['matches'])

        # Create summary
        facts['summary'] = self._create_summary(facts)

        # Generate Q&A pairs for RAG
        facts['qa_pairs'] = self._generate_qa_pairs(facts)

        return facts

    def _detect_format(self, data: str) -> str:
        """Detect input format"""
        data_stripped = data.strip()

        # Check JSON
        if data_stripped.startswith('{') or data_stripped.startswith('['):
            try:
                json.loads(data_stripped)
                return 'json'
            except:
                pass

        # Check YARA rules
        if re.search(r'rule\s+\w+\s*[:{]', data):
            return 'rules'

        return 'raw'

    def _extract_from_json(self, json_data: str, facts: Dict) -> Dict[str, Any]:
        """Extract facts from JSON format"""
        try:
            data = json.loads(json_data)
        except json.JSONDecodeError:
            facts['scan_metadata']['error'] = 'Invalid JSON'
            return facts

        facts['scan_metadata']['format'] = 'json'
        facts['scan_metadata']['parse_time'] = datetime.utcnow().isoformat()

        # Extract scan_info if present (contains rules_loaded, yara_version, scan_time, etc.)
        if isinstance(data, dict) and 'scan_info' in data:
            facts['scan_metadata'].update(data['scan_info'])

        # Handle list or dict
        items = data if isinstance(data, list) else [data]
        if isinstance(data, dict) and 'matches' in data:
            items = data['matches']

        for item in items:
            if not isinstance(item, dict):
                continue

            match = {
                'rule_name': item.get('rule', item.get('rule_name', 'Unknown')),
                'file_path': item.get('file', item.get('target', item.get('path', 'Unknown'))),
                'tags': item.get('tags', []),
                'namespace': item.get('namespace', 'default'),
                'metadata': item.get('meta', item.get('metadata', {})),
                'matched_strings': []
            }

            # Extract matched strings
            strings = item.get('strings', item.get('matched_strings', []))
            for s in strings:
                if isinstance(s, dict):
                    match['matched_strings'].append({
                        'identifier': s.get('identifier', s.get('name', '')),
                        'offset': s.get('offset', ''),
                        'data': s.get('data', s.get('value', ''))
                    })
                elif isinstance(s, (list, tuple)) and len(s) >= 3:
                    match['matched_strings'].append({
                        'offset': str(s[0]),
                        'identifier': s[1],
                        'data': str(s[2])
                    })

            facts['matches'].append(match)
            facts['rules_triggered'].append(match['rule_name'])

            if match['file_path'] not in facts['files_scanned']:
                facts['files_scanned'].append(match['file_path'])

        return facts

    def _extract_from_raw(self, raw_data: str, facts: Dict) -> Dict[str, Any]:
        """Extract facts from raw YARA text output"""
        facts['scan_metadata']['format'] = 'raw'
        facts['scan_metadata']['parse_time'] = datetime.utcnow().isoformat()

        lines = raw_data.strip().split('\n')
        current_match = None

        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Match rule line: RuleName path/to/file
            rule_match = re.match(r'^(\w+)\s+(.+?)(?:\s*$)', line)
            if rule_match and not line.startswith('0x') and ':$' not in line:
                # Save previous match
                if current_match:
                    facts['matches'].append(current_match)
                    facts['rules_triggered'].append(current_match['rule_name'])
                    if current_match['file_path'] not in facts['files_scanned']:
                        facts['files_scanned'].append(current_match['file_path'])

                current_match = {
                    'rule_name': rule_match.group(1),
                    'file_path': rule_match.group(2).strip(),
                    'tags': [],
                    'namespace': 'default',
                    'metadata': {},
                    'matched_strings': []
                }
                continue

            # Match string line: 0x1234:$name: data
            string_match = re.match(r'^(0x[0-9a-fA-F]+):(\$\w+):\s*(.*)$', line)
            if string_match and current_match:
                current_match['matched_strings'].append({
                    'offset': string_match.group(1),
                    'identifier': string_match.group(2),
                    'data': string_match.group(3)
                })

        # Don't forget the last match
        if current_match:
            facts['matches'].append(current_match)
            facts['rules_triggered'].append(current_match['rule_name'])
            if current_match['file_path'] not in facts['files_scanned']:
                facts['files_scanned'].append(current_match['file_path'])

        return facts

    def _extract_from_rules(self, rules_text: str, facts: Dict) -> Dict[str, Any]:
        """Extract facts from YARA rule files"""
        facts['scan_metadata']['format'] = 'rules'
        facts['scan_metadata']['parse_time'] = datetime.utcnow().isoformat()

        # Pattern to match rules
        rule_pattern = r'(?:private\s+)?(?:global\s+)?rule\s+(\w+)(?:\s*:\s*([^\{]+))?\s*\{(.*?)\}'

        for match in re.finditer(rule_pattern, rules_text, re.DOTALL):
            rule_name = match.group(1)
            tags_str = match.group(2)
            rule_body = match.group(3)

            tags = [t.strip() for t in tags_str.split()] if tags_str else []

            # Extract metadata
            metadata = {}
            meta_match = re.search(r'meta\s*:\s*(.*?)(?:strings\s*:|condition\s*:)', rule_body, re.DOTALL)
            if meta_match:
                for line in meta_match.group(1).split('\n'):
                    kv_match = re.match(r'\s*(\w+)\s*=\s*["\']?([^"\']+)["\']?\s*$', line)
                    if kv_match:
                        metadata[kv_match.group(1)] = kv_match.group(2).strip()

            # Extract strings
            strings = []
            strings_match = re.search(r'strings\s*:\s*(.*?)condition\s*:', rule_body, re.DOTALL)
            if strings_match:
                for line in strings_match.group(1).split('\n'):
                    str_match = re.match(r'\s*(\$\w+)\s*=\s*(.+)\s*$', line)
                    if str_match:
                        strings.append({
                            'identifier': str_match.group(1),
                            'pattern': str_match.group(2).strip()
                        })

            # Extract condition
            condition = ''
            cond_match = re.search(r'condition\s*:\s*(.*?)$', rule_body, re.DOTALL)
            if cond_match:
                condition = cond_match.group(1).strip()

            rule_info = {
                'rule_name': rule_name,
                'file_path': 'rule_file',
                'tags': tags,
                'namespace': 'default',
                'metadata': metadata,
                'matched_strings': strings,
                'condition': condition
            }

            facts['matches'].append(rule_info)
            facts['rules_triggered'].append(rule_name)

        return facts

    def _build_search_text(self, match: Dict) -> str:
        """Build combined search text from rule name + metadata + tags"""
        parts = [match.get('rule_name', '').lower()]
        metadata = match.get('metadata', {})
        if metadata:
            for key in ('threat', 'family', 'malware_family', 'malware_type', 'threat_actor'):
                val = metadata.get(key, '')
                if val:
                    parts.append(val.lower())
        tags = match.get('tags', [])
        if tags:
            parts.extend([t.lower() for t in tags])
        return ' '.join(parts)

    def _calculate_threat_score(self, matches: List[Dict]) -> Dict[str, Any]:
        """Calculate overall threat score from matches"""
        total_score = 0
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        categories = defaultdict(int)

        for match in matches:
            search_text = self._build_search_text(match)
            metadata = match.get('metadata', {})
            severity = self._determine_severity(search_text, metadata)
            score = {'CRITICAL': 10, 'HIGH': 7, 'MEDIUM': 4, 'LOW': 1}.get(severity, 4)

            total_score += score
            severity_counts[severity] += 1

            # Categorize
            category = self._categorize_rule(search_text, metadata)
            categories[category] += 1

        # Determine overall severity
        if severity_counts['CRITICAL'] > 0:
            overall = 'CRITICAL'
        elif severity_counts['HIGH'] > 0:
            overall = 'HIGH'
        elif severity_counts['MEDIUM'] > 0:
            overall = 'MEDIUM'
        else:
            overall = 'LOW'

        return {
            'total_score': total_score,
            'overall_severity': overall,
            'severity_breakdown': severity_counts,
            'categories': dict(categories),
            'total_matches': len(matches)
        }

    def _determine_severity(self, search_text: str, metadata: Optional[Dict] = None) -> str:
        """Determine severity from rule context (search text + metadata)"""
        # Use meta severity if available and valid
        if metadata:
            meta_sev = metadata.get('severity', '').upper()
            if meta_sev in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'):
                return meta_sev

        text_lower = search_text.lower()

        # CRITICAL - safe keywords (unique enough, no false positive risk)
        if any(kw in text_lower for kw in ['ransomware', 'mimikatz', 'rootkit', 'exploit', 'cobalt']):
            return 'CRITICAL'
        # CRITICAL - 'apt' needs segment boundary to avoid matching 'aptitude', 'apartment'
        if re.search(r'(?:^|[\W_])apt(?:$|[\W_\d])', text_lower):
            return 'CRITICAL'
        # CRITICAL - 'beacon' is safe enough in YARA context (almost always CobaltStrike)
        if 'beacon' in text_lower:
            return 'CRITICAL'

        # HIGH - safe keywords
        if any(kw in text_lower for kw in ['trojan', 'inject', 'credential', 'stealer', 'backdoor']):
            return 'HIGH'
        # HIGH - 'rat' needs boundary to avoid matching inside 'operate', 'generate', etc.
        if re.search(r'(?:^|[\W_])rat(?:$|[\W_])', text_lower):
            return 'HIGH'
        # HIGH - 'c2' needs boundary to avoid matching inside 'rc2', 'c2h5oh'
        if re.search(r'(?:^|[\W_])c2(?:$|[\W_])', text_lower):
            return 'HIGH'

        # MEDIUM
        if any(kw in text_lower for kw in ['packer', 'packed', 'suspicious', 'encoded', 'obfuscated']):
            return 'MEDIUM'

        # LOW
        if any(kw in text_lower for kw in ['pup', 'adware', 'generic']):
            return 'LOW'

        return 'MEDIUM'

    def _categorize_rule(self, search_text: str, metadata: Optional[Dict] = None) -> str:
        """Categorize rule by type using search text and metadata"""
        # Use meta malware_type if available
        if metadata:
            mtype = metadata.get('malware_type', '')
            if mtype:
                return mtype

        text_lower = search_text.lower()

        # Categories with regex patterns - ordered from most specific to most generic
        # Ambiguous words (empire, sliver, rat, shell, cred, pack) use tighter patterns
        category_patterns = [
            ('Ransomware', [r'ransom', r'locker']),
            ('C2 Framework', [
                r'cobalt.?strike', r'cobaltstrike',
                r'metasploit', r'meterpreter',
                r'(?:^|[\W_])c2(?:$|[\W_])',           # segment boundary for 'c2'
                r'command.?(?:and|&).?control',
                # Ambiguous C2 names - require security context prefix or compound pattern
                r'(?:HKTL|C2|HACK|MALWARE)[\W_].*(?:empire|sliver|covenant|mythic)',
                r'(?:empire|sliver|covenant|mythic)[\W_].*(?:agent|stager|c2|beacon|implant|listener)',
                r'invoke[\W_]empire', r'powershell[\W_]empire',
            ]),
            ('Trojan', [r'trojan', r'emotet', r'trickbot', r'qakbot', r'dridex']),
            ('RAT', [
                r'(?:^|[\W_])rat(?:$|[\W_])',           # segment boundary for 'rat'
                r'nanocore', r'njrat', r'quasarrat', r'remcos', r'darkcomet',
                r'remote.?access.?trojan',
                # 'quasar' needs security prefix/suffix (also an astronomy term)
                r'(?:RAT|MALWARE|HKTL|TROJAN)[\W_].*quasar',
                r'quasar[\W_].*(?:rat|remote|trojan|malware|backdoor)',
            ]),
            ('Credential Stealer', [
                r'mimikatz', r'stealer', r'lazagne',
                r'credential',                          # full word, not 'cred' substring
                r'cred[\W_](?:dump|steal|harvest)',      # compound patterns for abbreviated form
            ]),
            ('Webshell', [
                r'webshell', r'web[\W_]shell',           # specific webshell patterns
                r'(?:php|asp|jsp)[\W_]shell',            # language-prefixed shell
                r'c99[\W_]', r'r57[\W_]', r'b374k',     # specific webshell families
            ]),
            ('Packer', [
                r'packer', r'packed',                    # full words, not 'pack' substring
                r'upx', r'themida', r'vmprotect', r'aspack',
            ]),
            ('APT', [
                r'(?:^|[\W_])apt(?:$|[\W_\d])',          # segment boundary for 'apt'
                r'turla', r'fancy[\W_]bear', r'cozy[\W_]bear',
                # 'lazarus' needs security prefix/suffix (also a biblical name)
                r'(?:APT|MALWARE|HKTL|INDICATOR)[\W_].*lazarus',
                r'lazarus[\W_].*(?:group|apt|loader|backdoor|dtrack|malware)',
            ]),
            ('Exploit', [r'exploit', r'cve[\W_]?\d', r'eternal']),
            ('Generic Malware', [r'malware', r'malicious', r'suspicious']),
        ]

        for category, patterns in category_patterns:
            if any(re.search(p, text_lower, re.IGNORECASE) for p in patterns):
                return category

        return 'Unknown'

    def _map_to_mitre_attack(self, matches: List[Dict]) -> List[str]:
        """Map matches to MITRE ATT&CK techniques using rule names, meta, and tags"""
        techniques = set()

        # Ambiguous MITRE keywords that need segment boundaries
        _ambiguous_mitre = {'cred', 'wmi', 'rat', 'lateral'}

        for match in matches:
            # Check meta mitre_attack first (most reliable)
            metadata = match.get('metadata', {})
            meta_mitre = metadata.get('mitre_attack', '')
            if meta_mitre:
                techniques.add(meta_mitre)

            # Build search text for keyword matching
            search_text = self._build_search_text(match)
            text_lower = search_text.lower()

            for keyword, techs in self.MITRE_MAPPINGS.items():
                if keyword in _ambiguous_mitre:
                    # Use segment boundary for ambiguous keywords
                    if re.search(rf'(?:^|[\W_]){keyword}(?:$|[\W_])', text_lower):
                        techniques.update(techs)
                else:
                    # Safe keywords - simple substring match
                    if keyword in text_lower:
                        techniques.update(techs)

        return sorted(list(techniques))

    def _create_summary(self, facts: Dict) -> Dict[str, Any]:
        """Create summary from extracted facts"""
        threat_intel = facts.get('threat_intelligence', {})

        return {
            'total_matches': len(facts.get('matches', [])),
            'unique_rules': len(set(facts.get('rules_triggered', []))),
            'files_scanned': len(facts.get('files_scanned', [])),
            'threat_score': threat_intel.get('total_score', 0),
            'overall_severity': threat_intel.get('overall_severity', 'UNKNOWN'),
            'mitre_techniques_count': len(facts.get('mitre_techniques', [])),
            'categories': threat_intel.get('categories', {}),
            'requires_action': threat_intel.get('overall_severity') in ['CRITICAL', 'HIGH']
        }

    def _generate_qa_pairs(self, facts: Dict) -> List[Dict[str, str]]:
        """Generate Q&A pairs for RAG context"""
        qa_pairs = []
        summary = facts.get('summary', {})
        threat_intel = facts.get('threat_intelligence', {})

        # Basic counts
        qa_pairs.append({
            'question': 'How many YARA rules matched?',
            'answer': f"{summary.get('total_matches', 0)} rules matched against {summary.get('files_scanned', 0)} file(s)."
        })

        # Severity
        qa_pairs.append({
            'question': 'What is the overall threat severity?',
            'answer': f"The overall severity is {summary.get('overall_severity', 'UNKNOWN')} with a threat score of {summary.get('threat_score', 0)}."
        })

        # Rules triggered
        rules = facts.get('rules_triggered', [])
        if rules:
            qa_pairs.append({
                'question': 'What YARA rules were triggered?',
                'answer': f"The following rules matched: {', '.join(set(rules))}"
            })

        # Files scanned
        files = facts.get('files_scanned', [])
        if files:
            qa_pairs.append({
                'question': 'What files were flagged?',
                'answer': f"Files flagged: {', '.join(files[:10])}" + (" ..." if len(files) > 10 else "")
            })

        # MITRE techniques
        mitre = facts.get('mitre_techniques', [])
        if mitre:
            qa_pairs.append({
                'question': 'What MITRE ATT&CK techniques were identified?',
                'answer': f"Mapped MITRE techniques: {', '.join(mitre)}"
            })

        # Categories
        categories = threat_intel.get('categories', {})
        if categories:
            cat_str = ', '.join([f"{k}: {v}" for k, v in categories.items()])
            qa_pairs.append({
                'question': 'What types of threats were detected?',
                'answer': f"Threat categories: {cat_str}"
            })

        # Action required
        if summary.get('requires_action'):
            qa_pairs.append({
                'question': 'Is immediate action required?',
                'answer': f"YES - {summary.get('overall_severity')} severity threats detected. Immediate investigation and containment recommended."
            })

        # Matched strings (if available)
        for match in facts.get('matches', [])[:5]:  # Limit to first 5
            if match.get('matched_strings'):
                strings_info = ', '.join([s.get('identifier', '') for s in match['matched_strings'][:3]])
                qa_pairs.append({
                    'question': f"What strings matched in rule {match.get('rule_name')}?",
                    'answer': f"Matched strings: {strings_info}"
                })

        return qa_pairs

    def _extract_iocs(self, matches: List[Dict]) -> Dict[str, List[str]]:
        """
        Extract Indicators of Compromise (IOCs) from YARA matched strings.
        Professional IR feature - extracts actionable intelligence for blocking/hunting.

        Returns:
            Dictionary with categorized IOCs:
            - ip_addresses: IPv4 addresses
            - domains: Domain names and URLs
            - mutexes: Mutex names (Global\\*, Local\\*, unique strings)
            - named_pipes: Named pipe paths
            - file_extensions: File extensions used by malware
            - registry_keys: Registry key paths
            - urls: Full URLs
            - commands: System commands (vssadmin, sc, etc.)
            - crypto_addresses: Cryptocurrency wallet addresses
            - file_paths: Suspicious file paths
        """
        iocs = {
            'ip_addresses': set(),
            'domains': set(),
            'mutexes': set(),
            'named_pipes': set(),
            'file_extensions': set(),
            'registry_keys': set(),
            'urls': set(),
            'commands': set(),
            'crypto_addresses': set(),
            'file_paths': set()
        }

        # Regex patterns for IOC extraction
        patterns = {
            'ip': re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
            'domain': re.compile(r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b', re.IGNORECASE),
            'mutex': re.compile(r'(?:Global\\|Local\\|\\BaseNamedObjects\\)[^\s]+|\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}|\b[A-Z0-9]{8,32}\b', re.IGNORECASE),
            'named_pipe': re.compile(r'\\\\\.\\pipe\\[\w\-_]+', re.IGNORECASE),
            'file_ext': re.compile(r'\.(?:exe|dll|sys|tmp|log|dat|bin|bat|ps1|vbs|js|hta|scr|pif|com|cmd)(?:\s|$|[^\w])', re.IGNORECASE),
            'registry': re.compile(r'(?:HKEY_|HKLM\\|HKCU\\|HKCR\\|HKU\\|HKCC\\)[\w\\]+', re.IGNORECASE),
            'url': re.compile(r'(?:https?|ftp|ftps)://[^\s<>"{}|\\^`\[\]]+', re.IGNORECASE),
            'command': re.compile(r'\b(?:vssadmin|bcdedit|wmic|sc\.exe|sc|net\.exe|net|reg\.exe|reg|cmd\.exe|cmd|powershell\.exe|powershell|rundll32|regsvr32|mshta|cscript|wscript)\b', re.IGNORECASE),
            'crypto_btc': re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'),  # Bitcoin
            'crypto_eth': re.compile(r'\b0x[a-fA-F0-9]{40}\b'),  # Ethereum
            'crypto_xmr': re.compile(r'\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b'),  # Monero
            'file_path': re.compile(r'(?:[A-Z]:\\|\\\\|/)[^\s<>"*?|]+', re.IGNORECASE)
        }

        # Extract IOCs from all matched strings in all matches
        for match in matches:
            matched_strings = match.get('matched_strings', [])

            for string_match in matched_strings:
                data = string_match.get('data', '')
                if not data:
                    continue

                # IP addresses
                for ip in patterns['ip'].findall(data):
                    # Validate IP (basic check)
                    parts = ip.split('.')
                    if all(0 <= int(p) <= 255 for p in parts if p.isdigit()):
                        iocs['ip_addresses'].add(ip)

                # Domains (exclude IPs and common false positives)
                for domain in patterns['domain'].findall(data):
                    domain_lower = domain.lower()
                    # Skip common false positives and file names
                    if domain_lower in ['example.com', 'localhost', 'test.com', 'domain.com']:
                        continue
                    # Skip if it ends with common executable extensions (likely a file name, not domain)
                    if domain_lower.endswith(('.dll', '.exe', '.sys', '.bin', '.dat', '.txt', '.doc', '.pdf', '.log')):
                        continue
                    # Skip if it contains .net (likely .NET framework reference)
                    if '.net.' in domain_lower or domain_lower.startswith('net.'):
                        continue
                    # Skip ASP/code patterns (e.g., Request.Form, Server.CreateObject, WScript.Shell)
                    # Pattern: CapitalWord.CapitalWord = likely code, not domain
                    if re.match(r'^[A-Z][a-z]+\.[A-Z][a-z]+', domain):
                        continue  # Likely ASP/VB code like Request.Form, Server.CreateObject
                    # Must have at least one dot and valid TLD
                    if '.' in domain and len(domain.split('.')[-1]) >= 2:
                        iocs['domains'].add(domain)

                # Mutexes
                for mutex in patterns['mutex'].findall(data):
                    # Skip obvious false positives
                    if len(mutex) < 8 or mutex.startswith(('0x', '\\x')):
                        continue
                    # Skip common English words and generic terms
                    mutex_lower = mutex.lower()
                    common_words = ['encrypted', 'currently', 'webclient', 'password', 'username',
                                   'administrator', 'scanbrowsers', 'localhost', 'document']
                    if any(word in mutex_lower for word in common_words):
                        continue
                    # Accept: Global\* paths, Local\* paths, GUIDs, or likely hex mutexes
                    is_named_mutex = mutex.startswith(('Global\\', 'Local\\', '\\BaseNamedObjects\\'))
                    is_guid = '{' in mutex and '-' in mutex  # Likely GUID format
                    is_hex_mutex = (mutex.isupper() or mutex.isdigit() or all(c in '0123456789ABCDEF' for c in mutex))

                    if is_named_mutex or is_guid or is_hex_mutex:
                        iocs['mutexes'].add(mutex)

                # Named pipes
                for pipe in patterns['named_pipe'].findall(data):
                    iocs['named_pipes'].add(pipe)

                # File extensions
                for ext_match in patterns['file_ext'].findall(data):
                    ext = ext_match.strip().rstrip(',;:').lower()
                    if ext.startswith('.'):
                        iocs['file_extensions'].add(ext)

                # Registry keys
                for reg_key in patterns['registry'].findall(data):
                    if len(reg_key) > 10:  # Skip too short keys
                        iocs['registry_keys'].add(reg_key)

                # URLs
                for url in patterns['url'].findall(data):
                    iocs['urls'].add(url)

                # Commands
                for cmd in patterns['command'].findall(data):
                    iocs['commands'].add(cmd.lower())

                # Cryptocurrency addresses
                for btc in patterns['crypto_btc'].findall(data):
                    iocs['crypto_addresses'].add(f"BTC:{btc}")
                for eth in patterns['crypto_eth'].findall(data):
                    iocs['crypto_addresses'].add(f"ETH:{eth}")
                for xmr in patterns['crypto_xmr'].findall(data):
                    iocs['crypto_addresses'].add(f"XMR:{xmr}")

                # File paths (filter out hex offsets and obvious false positives)
                for path in patterns['file_path'].findall(data):
                    # Skip hex offsets and very short paths
                    if not path.startswith('0x') and len(path) > 10:
                        # Must contain meaningful path separators
                        if '\\' in path or (path.count('/') >= 2):
                            iocs['file_paths'].add(path)

        # Convert sets to sorted lists for consistent output
        return {k: sorted(list(v)) for k, v in iocs.items()}

    def facts_to_text(self, facts: Dict) -> str:
        """
        Convert facts dictionary to comprehensive text format for LLM context.
        This is used by Ask Syd to get ALL extracted facts in a searchable format.
        """
        lines = []

        # Scan Metadata
        scan_meta = facts.get('scan_metadata', {})
        if scan_meta:
            lines.append("SCAN METADATA:")
            if 'yara_version' in scan_meta:
                lines.append(f"  YARA Version: {scan_meta['yara_version']}")
            if 'scan_time' in scan_meta:
                lines.append(f"  Scan Time: {scan_meta['scan_time']}")
            if 'rules_loaded' in scan_meta:
                lines.append(f"  Rules Loaded: {scan_meta['rules_loaded']}")
            if 'scan_duration_ms' in scan_meta:
                lines.append(f"  Scan Duration: {scan_meta['scan_duration_ms']}ms")
            if 'ruleset' in scan_meta:
                lines.append(f"  Ruleset: {scan_meta['ruleset']}")
            lines.append("")

        # Summary
        summary = facts.get('summary', {})
        if summary:
            lines.append("SUMMARY:")
            lines.append(f"  Total Matches: {summary.get('total_matches', 0)}")
            lines.append(f"  Unique Rules: {summary.get('unique_rules', 0)}")
            lines.append(f"  Files Scanned: {summary.get('files_scanned', 0)}")
            lines.append(f"  Overall Severity: {summary.get('overall_severity', 'UNKNOWN')}")
            lines.append(f"  Threat Score: {summary.get('threat_score', 0)}")
            lines.append("")

        # Rules Triggered
        rules = facts.get('rules_triggered', [])
        if rules:
            lines.append("RULES TRIGGERED:")
            for rule in set(rules):
                lines.append(f"  - {rule}")
            lines.append("")

        # Files Scanned
        files = facts.get('files_scanned', [])
        if files:
            lines.append("FILES SCANNED:")
            for f in files:
                lines.append(f"  - {f}")
            lines.append("")

        # MITRE ATT&CK Techniques
        mitre = facts.get('mitre_techniques', [])
        if mitre:
            lines.append("MITRE ATT&CK TECHNIQUES:")
            for tech in mitre:
                lines.append(f"  - {tech}")
            lines.append("")

        # Detailed Match Information (CRITICAL - includes all string data)
        matches = facts.get('matches', [])
        if matches:
            lines.append("DETAILED MATCH INFORMATION:")
            lines.append("-" * 80)
            for idx, match in enumerate(matches, 1):
                lines.append(f"\n[MATCH {idx}]")
                lines.append(f"  Rule: {match.get('rule_name', 'Unknown')}")
                lines.append(f"  File: {match.get('file_path', 'Unknown')}")

                # Tags
                tags = match.get('tags', [])
                if tags:
                    lines.append(f"  Tags: {', '.join(tags)}")

                # Metadata (author, severity, description, mitre_attack, etc.)
                metadata = match.get('metadata', {})
                if metadata:
                    lines.append("  Metadata:")
                    for key, value in metadata.items():
                        lines.append(f"    - {key}: {value}")

                # Matched Strings (CRITICAL - this is what was missing!)
                matched_strings = match.get('matched_strings', [])
                if matched_strings:
                    lines.append("  Matched Strings:")
                    for s in matched_strings:
                        identifier = s.get('identifier', 'N/A')
                        offset = s.get('offset', 'N/A')
                        data = s.get('data', 'N/A')
                        lines.append(f"    - Identifier: {identifier}")
                        lines.append(f"      Offset: {offset}")
                        lines.append(f"      Data: {data}")

            lines.append("")

        # Threat Intelligence Summary
        threat_intel = facts.get('threat_intelligence', {})
        if threat_intel:
            lines.append("THREAT INTELLIGENCE:")
            severity_breakdown = threat_intel.get('severity_breakdown', {})
            if severity_breakdown:
                lines.append("  Severity Breakdown:")
                for severity, count in severity_breakdown.items():
                    if count > 0:
                        lines.append(f"    - {severity}: {count}")

            categories = threat_intel.get('categories', {})
            if categories:
                lines.append("  Threat Categories:")
                for category, count in categories.items():
                    lines.append(f"    - {category}: {count}")
            lines.append("")

        # Extracted IOCs (Indicators of Compromise)
        iocs = facts.get('iocs', {})
        if iocs:
            total_iocs = sum(len(v) for v in iocs.values() if v)
            if total_iocs > 0:
                lines.append("EXTRACTED INDICATORS OF COMPROMISE (IOCs):")
                lines.append(f"  Total IOCs Extracted: {total_iocs}")
                lines.append("")

                if iocs.get('ip_addresses'):
                    lines.append(f"  IP Addresses ({len(iocs['ip_addresses'])}):")
                    for ip in iocs['ip_addresses'][:20]:
                        lines.append(f"    - {ip}")
                    if len(iocs['ip_addresses']) > 20:
                        lines.append(f"    ... and {len(iocs['ip_addresses']) - 20} more")
                    lines.append("")

                if iocs.get('domains'):
                    lines.append(f"  Domains ({len(iocs['domains'])}):")
                    for domain in iocs['domains'][:20]:
                        lines.append(f"    - {domain}")
                    if len(iocs['domains']) > 20:
                        lines.append(f"    ... and {len(iocs['domains']) - 20} more")
                    lines.append("")

                if iocs.get('urls'):
                    lines.append(f"  URLs ({len(iocs['urls'])}):")
                    for url in iocs['urls'][:15]:
                        lines.append(f"    - {url}")
                    if len(iocs['urls']) > 15:
                        lines.append(f"    ... and {len(iocs['urls']) - 15} more")
                    lines.append("")

                if iocs.get('mutexes'):
                    lines.append(f"  Mutexes ({len(iocs['mutexes'])}):")
                    for mutex in iocs['mutexes'][:15]:
                        lines.append(f"    - {mutex}")
                    if len(iocs['mutexes']) > 15:
                        lines.append(f"    ... and {len(iocs['mutexes']) - 15} more")
                    lines.append("")

                if iocs.get('named_pipes'):
                    lines.append(f"  Named Pipes ({len(iocs['named_pipes'])}):")
                    for pipe in iocs['named_pipes']:
                        lines.append(f"    - {pipe}")
                    lines.append("")

                if iocs.get('file_extensions'):
                    lines.append(f"  File Extensions ({len(iocs['file_extensions'])}):")
                    for ext in iocs['file_extensions']:
                        lines.append(f"    - {ext}")
                    lines.append("")

                if iocs.get('registry_keys'):
                    lines.append(f"  Registry Keys ({len(iocs['registry_keys'])}):")
                    for key in iocs['registry_keys'][:15]:
                        lines.append(f"    - {key}")
                    if len(iocs['registry_keys']) > 15:
                        lines.append(f"    ... and {len(iocs['registry_keys']) - 15} more")
                    lines.append("")

                if iocs.get('commands'):
                    lines.append(f"  System Commands ({len(iocs['commands'])}):")
                    for cmd in iocs['commands']:
                        lines.append(f"    - {cmd}")
                    lines.append("")

                if iocs.get('crypto_addresses'):
                    lines.append(f"  Cryptocurrency Addresses ({len(iocs['crypto_addresses'])}):")
                    for crypto in iocs['crypto_addresses']:
                        lines.append(f"    - {crypto}")
                    lines.append("")

                if iocs.get('file_paths'):
                    lines.append(f"  File Paths ({len(iocs['file_paths'])}):")
                    for path in iocs['file_paths'][:15]:
                        lines.append(f"    - {path}")
                    if len(iocs['file_paths']) > 15:
                        lines.append(f"    ... and {len(iocs['file_paths']) - 15} more")
                    lines.append("")

        return "\n".join(lines)

    def format_facts_report(self, facts: Dict) -> str:
        """Format facts as human-readable report"""
        lines = []
        lines.append("=" * 80)
        lines.append("YARA FACT EXTRACTION REPORT")
        lines.append("=" * 80)
        lines.append("")

        # Summary
        summary = facts.get('summary', {})
        lines.append("SUMMARY:")
        lines.append(f"  Total Matches: {summary.get('total_matches', 0)}")
        lines.append(f"  Unique Rules: {summary.get('unique_rules', 0)}")
        lines.append(f"  Files Scanned: {summary.get('files_scanned', 0)}")
        lines.append(f"  Threat Score: {summary.get('threat_score', 0)}")
        lines.append(f"  Severity: {summary.get('overall_severity', 'UNKNOWN')}")
        lines.append("")

        # Rules triggered
        rules = facts.get('rules_triggered', [])
        if rules:
            lines.append("RULES TRIGGERED:")
            for rule in set(rules):
                lines.append(f"  - {rule}")
            lines.append("")

        # Files
        files = facts.get('files_scanned', [])
        if files:
            lines.append("FILES FLAGGED:")
            for f in files[:20]:
                lines.append(f"  - {f}")
            if len(files) > 20:
                lines.append(f"  ... and {len(files) - 20} more")
            lines.append("")

        # MITRE
        mitre = facts.get('mitre_techniques', [])
        if mitre:
            lines.append("MITRE ATT&CK TECHNIQUES:")
            for tech in mitre:
                lines.append(f"  - {tech}")
            lines.append("")

        # Match details
        matches = facts.get('matches', [])
        if matches:
            lines.append("MATCH DETAILS:")
            lines.append("-" * 40)
            for match in matches[:10]:
                lines.append(f"\nRule: {match.get('rule_name')}")
                lines.append(f"File: {match.get('file_path')}")
                if match.get('tags'):
                    lines.append(f"Tags: {', '.join(match['tags'])}")
                if match.get('matched_strings'):
                    lines.append("Matched Strings:")
                    for s in match['matched_strings'][:5]:
                        lines.append(f"  {s.get('identifier')}: {s.get('data', '')[:50]}")
            lines.append("")

        lines.append("=" * 80)
        return "\n".join(lines)


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def extract_yara_facts(yara_output: str, input_format: str = 'auto') -> Dict[str, Any]:
    """Convenience function to extract facts from YARA output"""
    extractor = YaraFactExtractor()
    return extractor.extract_facts(yara_output, input_format)


def get_qa_context(yara_output: str) -> List[Dict[str, str]]:
    """Get Q&A pairs for RAG context"""
    extractor = YaraFactExtractor()
    facts = extractor.extract_facts(yara_output)
    return facts.get('qa_pairs', [])


# =============================================================================
# MAIN
# =============================================================================

if __name__ == "__main__":
    # Test with sample data
    sample_output = """
CobaltStrike_Beacon /tmp/malware.exe
0x1234:$beacon_str: beacon.dll
0x5678:$config: \\x00\\x01\\x00\\x01

Mimikatz_Credential_Dumper /tmp/mimi.exe
0xABCD:$mimi1: sekurlsa::logonpasswords
    """

    extractor = YaraFactExtractor()
    facts = extractor.extract_facts(sample_output)
    print(extractor.format_facts_report(facts))
