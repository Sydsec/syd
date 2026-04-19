# YARA for Incident Response

## Rapid Triage Scanning

During an incident, speed is critical. YARA enables rapid triage to identify compromised systems.

### Quick Triage Rule Set

```yara
rule IR_Quick_Triage_Malware {
    meta:
        description = "Quick triage for common malware indicators"
        response_priority = "high"

    strings:
        // C2 indicators
        $c2_1 = "beacon" ascii wide nocase
        $c2_2 = "callback" ascii wide nocase

        // Persistence
        $persist1 = "schtasks" ascii wide nocase
        $persist2 = "CurrentVersion\\Run" ascii wide nocase

        // Credential theft
        $cred1 = "mimikatz" ascii wide nocase
        $cred2 = "sekurlsa" ascii wide nocase

        // Ransomware
        $ransom1 = "your files have been encrypted" ascii wide nocase
        $ransom2 = "bitcoin" ascii wide nocase

    condition:
        any of them
}
```

### System-Wide Scanning Script

```python
#!/usr/bin/env python3
"""
IR Rapid Triage Scanner
Quickly scan systems for IOCs during incident response
"""

import yara
import os
import sys
import json
from datetime import datetime
from concurrent.futures import ProcessPoolExecutor

class IRScanner:
    def __init__(self, rules_path):
        self.rules = yara.compile(filepath=rules_path)
        self.results = []

    def scan_file(self, filepath):
        """Scan a single file"""
        try:
            matches = self.rules.match(filepath, timeout=30)
            if matches:
                return {
                    'file': filepath,
                    'matches': [m.rule for m in matches],
                    'timestamp': datetime.now().isoformat()
                }
        except Exception as e:
            pass
        return None

    def scan_directory(self, directory, extensions=None):
        """Scan directory with optional extension filter"""
        files_to_scan = []

        for root, dirs, files in os.walk(directory):
            # Skip system directories
            dirs[:] = [d for d in dirs if d not in ['$Recycle.Bin', 'Windows', 'System32']]

            for filename in files:
                filepath = os.path.join(root, filename)

                if extensions:
                    if not any(filename.lower().endswith(ext) for ext in extensions):
                        continue

                files_to_scan.append(filepath)

        # Parallel scanning
        with ProcessPoolExecutor(max_workers=4) as executor:
            results = executor.map(self.scan_file, files_to_scan)

        return [r for r in results if r is not None]

    def scan_critical_paths(self):
        """Scan paths commonly abused by malware"""
        critical_paths = [
            os.environ.get('TEMP', 'C:\\Windows\\Temp'),
            os.environ.get('APPDATA', ''),
            os.environ.get('LOCALAPPDATA', ''),
            'C:\\ProgramData',
            'C:\\Users\\Public',
        ]

        all_results = []
        for path in critical_paths:
            if path and os.path.exists(path):
                results = self.scan_directory(path)
                all_results.extend(results)

        return all_results

def main():
    scanner = IRScanner('ir_rules.yar')

    print("[*] Starting IR Triage Scan...")
    results = scanner.scan_critical_paths()

    print(f"[+] Found {len(results)} potential threats")
    for result in results:
        print(f"  - {result['file']}: {result['matches']}")

    # Save results
    with open('ir_scan_results.json', 'w') as f:
        json.dump(results, f, indent=2)

if __name__ == '__main__':
    main()
```

## Building Custom Rule Sets for Incidents

### Creating IOC-Based Rules

```yara
rule IR_Incident_2024_001 {
    meta:
        description = "IOCs from Incident 2024-001"
        incident_id = "INC-2024-001"
        created = "2024-01-15"
        author = "IR Team"

    strings:
        // Hashes (partial matches in memory)
        $hash_partial = { 4D 5A 90 00 03 00 00 00 }

        // C2 domains
        $domain1 = "malicious-c2.evil.com" ascii wide
        $domain2 = "backup-c2.bad.net" ascii wide

        // Specific strings from malware
        $str1 = "UNIQUE_MALWARE_STRING_12345" ascii
        $str2 = "config.dat.enc" ascii wide

        // Mutex
        $mutex = "Global\\{ABC12345-1234-1234-1234-123456789ABC}" ascii wide

    condition:
        any of them
}
```

### Dynamic Rule Generation

```python
def generate_ioc_rule(incident_id, iocs):
    """Generate YARA rule from IOC list"""
    rule_template = '''
rule IR_{incident_id} {{
    meta:
        description = "Auto-generated IOC rule for {incident_id}"
        generated = "{timestamp}"

    strings:
{strings}

    condition:
        any of them
}}
'''

    strings = []
    for i, ioc in enumerate(iocs):
        if ioc['type'] == 'domain':
            strings.append(f'        $domain_{i} = "{ioc["value"]}" ascii wide nocase')
        elif ioc['type'] == 'ip':
            strings.append(f'        $ip_{i} = "{ioc["value"]}" ascii wide')
        elif ioc['type'] == 'string':
            strings.append(f'        $str_{i} = "{ioc["value"]}" ascii wide')
        elif ioc['type'] == 'hex':
            strings.append(f'        $hex_{i} = {{ {ioc["value"]} }}')

    return rule_template.format(
        incident_id=incident_id.replace('-', '_'),
        timestamp=datetime.now().isoformat(),
        strings='\n'.join(strings)
    )
```

## Pivoting from Indicators

### Finding Related Samples

```yara
rule IR_Pivot_From_String {
    meta:
        description = "Pivot from unique string found in incident"
        pivot_source = "Initial malware sample"

    strings:
        // Unique string from original sample
        $original = "UniqueConfigString_v2" ascii wide

        // Related strings to find variants
        $variant1 = "UniqueConfigString" ascii wide
        $variant2 = "ConfigString_v" ascii wide

        // Code pattern from original
        $code = { 8B 45 ?? 83 C0 ?? 50 E8 }

    condition:
        any of them
}
```

### Expanding Detection Coverage

```python
def expand_yara_rule(original_rule_path, samples_dir):
    """
    Analyze matching samples to expand rule coverage
    """
    import yara

    rules = yara.compile(filepath=original_rule_path)
    new_strings = set()

    # Scan samples that match original rule
    for root, dirs, files in os.walk(samples_dir):
        for filename in files:
            filepath = os.path.join(root, filename)
            matches = rules.match(filepath)

            if matches:
                # Extract additional strings for rule expansion
                with open(filepath, 'rb') as f:
                    content = f.read()

                # Find unique strings
                strings = extract_unique_strings(content)
                new_strings.update(strings)

    return new_strings

def extract_unique_strings(content, min_length=8):
    """Extract printable strings from binary"""
    import re
    strings = re.findall(b'[\x20-\x7e]{%d,}' % min_length, content)
    return [s.decode('ascii', errors='ignore') for s in strings]
```

## Timeline Correlation

### Time-Based Detection

```yara
import "pe"

rule IR_Recent_Compilation {
    meta:
        description = "Detects recently compiled executables"
        use_case = "Find malware compiled during incident timeframe"

    condition:
        pe.is_pe and
        // Compiled after incident start (Unix timestamp)
        pe.timestamp > 1704067200 and  // Jan 1, 2024
        pe.timestamp < 1704672000       // Jan 8, 2024
}
```

### Correlating with Other Evidence

```python
def correlate_yara_with_timeline(yara_results, event_log_times):
    """
    Correlate YARA matches with event timeline
    """
    correlated = []

    for result in yara_results:
        file_mtime = os.path.getmtime(result['file'])

        # Find nearby events
        for event in event_log_times:
            time_diff = abs(file_mtime - event['timestamp'])
            if time_diff < 3600:  # Within 1 hour
                correlated.append({
                    'yara_match': result,
                    'related_event': event,
                    'time_diff_seconds': time_diff
                })

    return sorted(correlated, key=lambda x: x['time_diff_seconds'])
```

## False Positive Reduction

### Whitelist Integration

```yara
rule IR_Suspicious_With_Whitelist {
    meta:
        description = "Detect suspicious activity excluding known good"

    strings:
        // Suspicious indicators
        $sus1 = "powershell -enc" ascii wide nocase
        $sus2 = "cmd /c" ascii wide nocase

        // Whitelist strings
        $whitelist1 = "Microsoft Corporation" ascii wide
        $whitelist2 = "Legitimate Software Inc" ascii wide

    condition:
        any of ($sus*) and not any of ($whitelist*)
}
```

### Contextual Filtering

```python
def filter_false_positives(yara_results, whitelist_path, context_rules):
    """
    Filter YARA results to reduce false positives
    """
    # Load whitelist
    with open(whitelist_path) as f:
        whitelist = set(line.strip() for line in f)

    filtered = []
    for result in yara_results:
        # Skip whitelisted paths
        if any(wl in result['file'] for wl in whitelist):
            continue

        # Apply context rules
        if passes_context_check(result, context_rules):
            filtered.append(result)

    return filtered

def passes_context_check(result, context_rules):
    """
    Apply additional context-based filtering
    """
    filepath = result['file']

    # Check file location
    suspicious_locations = [
        'Temp', 'AppData', 'Downloads', 'Public'
    ]

    in_suspicious_location = any(loc in filepath for loc in suspicious_locations)

    # Check if file is signed (for PE files)
    # ...additional checks...

    return in_suspicious_location
```

## Automating Response Workflows

### Integration with SOAR

```python
def send_to_soar(yara_results, soar_api_endpoint, api_key):
    """
    Send YARA results to SOAR platform
    """
    import requests

    for result in yara_results:
        alert = {
            'title': f"YARA Match: {result['matches']}",
            'severity': determine_severity(result),
            'source': 'YARA Scanner',
            'artifacts': {
                'file_path': result['file'],
                'rules_matched': result['matches'],
                'timestamp': result['timestamp']
            },
            'recommended_actions': get_recommended_actions(result)
        }

        response = requests.post(
            soar_api_endpoint,
            json=alert,
            headers={'Authorization': f'Bearer {api_key}'}
        )

def determine_severity(result):
    """Determine alert severity based on rules matched"""
    critical_rules = ['Ransomware', 'Mimikatz', 'CobaltStrike']
    high_rules = ['ProcessInjection', 'CredentialDumping']

    for rule in result['matches']:
        if any(crit in rule for crit in critical_rules):
            return 'critical'
        if any(high in rule for high in high_rules):
            return 'high'

    return 'medium'

def get_recommended_actions(result):
    """Generate recommended IR actions"""
    actions = []

    if 'Ransomware' in str(result['matches']):
        actions.extend([
            'Isolate affected system immediately',
            'Check for lateral movement',
            'Preserve memory dump',
            'Begin backup restoration assessment'
        ])

    if 'CobaltStrike' in str(result['matches']):
        actions.extend([
            'Block C2 infrastructure at firewall',
            'Hunt for beacon across environment',
            'Check for persistence mechanisms',
            'Review authentication logs'
        ])

    return actions
```

## Reporting and Documentation

### Generating IR Reports

```python
def generate_ir_report(scan_results, incident_id):
    """Generate comprehensive IR report"""
    report = {
        'incident_id': incident_id,
        'scan_timestamp': datetime.now().isoformat(),
        'summary': {
            'total_files_scanned': scan_results['total_scanned'],
            'total_matches': len(scan_results['matches']),
            'critical_findings': len([m for m in scan_results['matches']
                                     if m['severity'] == 'critical'])
        },
        'findings': [],
        'recommendations': []
    }

    for match in scan_results['matches']:
        finding = {
            'file': match['file'],
            'rules_matched': match['matches'],
            'severity': match['severity'],
            'hash_md5': calculate_hash(match['file'], 'md5'),
            'hash_sha256': calculate_hash(match['file'], 'sha256'),
            'analysis_notes': ''
        }
        report['findings'].append(finding)

    return report
```

## Best Practices Summary

1. **Prepare rule sets in advance** - Don't write rules during an incident
2. **Use tiered scanning** - Quick triage first, deep scan second
3. **Document everything** - Include timestamps and context
4. **Integrate with other tools** - SIEM, SOAR, EDR
5. **Maintain whitelists** - Reduce alert fatigue
6. **Version control rules** - Track changes during incident
7. **Share IOCs** - Contribute to threat intelligence
