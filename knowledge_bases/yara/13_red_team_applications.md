# YARA for Red Team Operations

## Testing Detection Capabilities

Red teams use YARA to evaluate and improve defensive detection capabilities.

### Detection Gap Analysis

```yara
rule RedTeam_Detection_Test_ProcessInjection {
    meta:
        description = "Tests detection of process injection techniques"
        test_technique = "T1055"
        expected_detection = true

    strings:
        $api1 = "VirtualAllocEx" ascii wide
        $api2 = "WriteProcessMemory" ascii wide
        $api3 = "CreateRemoteThread" ascii wide

    condition:
        all of them
}
```

### Generating Detection Reports

```python
def generate_detection_gap_report(rules_path, payload_samples_dir):
    """
    Test defensive rules against red team payloads
    Generate gap analysis report
    """
    rules = yara.compile(filepath=rules_path)
    results = {
        'detected': [],
        'undetected': [],
        'coverage_by_technique': {}
    }

    for sample_file in os.listdir(payload_samples_dir):
        sample_path = os.path.join(payload_samples_dir, sample_file)

        # Extract MITRE technique from filename (e.g., T1055_injection.exe)
        technique = sample_file.split('_')[0] if '_' in sample_file else 'unknown'

        matches = rules.match(sample_path)

        if matches:
            results['detected'].append({
                'sample': sample_file,
                'technique': technique,
                'rules_matched': [m.rule for m in matches]
            })
        else:
            results['undetected'].append({
                'sample': sample_file,
                'technique': technique
            })

        # Track by technique
        if technique not in results['coverage_by_technique']:
            results['coverage_by_technique'][technique] = {'detected': 0, 'total': 0}
        results['coverage_by_technique'][technique]['total'] += 1
        if matches:
            results['coverage_by_technique'][technique]['detected'] += 1

    return results
```

## AV/EDR Evasion Research

### Understanding Detection Boundaries

```yara
rule Research_String_Detection_Boundary {
    meta:
        description = "Research: Find minimum string length for detection"
        purpose = "evasion_research"

    strings:
        // Test different string lengths
        $len5 = "mimik"
        $len6 = "mimika"
        $len7 = "mimikat"
        $len8 = "mimikatz"

    condition:
        any of them
}
```

### Signature Modification Testing

```python
def test_signature_modification(original_payload, modifications):
    """
    Test how payload modifications affect detection
    """
    rules = yara.compile(filepath='detection_rules.yar')
    results = []

    # Test original
    original_matches = rules.match(data=original_payload)
    results.append({
        'modification': 'original',
        'detected': len(original_matches) > 0,
        'rules': [m.rule for m in original_matches]
    })

    # Test modifications
    for mod_name, mod_func in modifications.items():
        modified_payload = mod_func(original_payload)
        matches = rules.match(data=modified_payload)
        results.append({
            'modification': mod_name,
            'detected': len(matches) > 0,
            'rules': [m.rule for m in matches]
        })

    return results

# Example modifications
def xor_encode(data, key=0x41):
    return bytes([b ^ key for b in data])

def string_replace(data):
    return data.replace(b'mimikatz', b'XXXXXXXX')

modifications = {
    'xor_0x41': lambda d: xor_encode(d, 0x41),
    'string_replace': string_replace,
}
```

## C2 Framework Signature Analysis

### Cobalt Strike Detection Testing

```yara
rule RedTeam_CobaltStrike_Default {
    meta:
        description = "Detects default Cobalt Strike patterns"
        purpose = "Red team detection testing"

    strings:
        // Default beacon strings (should be modified)
        $default1 = "beacon.dll" ascii wide
        $default2 = "%s as %s\\%s: %d" ascii

        // Default named pipe
        $pipe = "\\\\%s\\pipe\\msagent_" ascii

        // Default user agent
        $ua = "Mozilla/5.0 (compatible; MSIE" ascii

    condition:
        any of them
}

rule RedTeam_CobaltStrike_Modified {
    meta:
        description = "Detects modified Cobalt Strike (harder to evade)"
        purpose = "Red team detection testing"

    strings:
        // Sleep mask patterns (harder to modify)
        $sleep = { 48 8B 05 B8 00 00 00 4C 8B 05 }

        // Configuration structure
        $config = { 00 01 00 01 00 02 ?? ?? 00 02 00 01 00 02 }

        // Reflective loader patterns
        $reflect = { 4D 5A 41 52 55 48 89 E5 }

    condition:
        any of them
}
```

### Custom C2 Detection

```python
def analyze_c2_signatures(c2_binary_path):
    """
    Analyze C2 framework binaries for detection signatures
    """
    with open(c2_binary_path, 'rb') as f:
        data = f.read()

    signatures = {
        'unique_strings': [],
        'code_patterns': [],
        'config_markers': []
    }

    # Extract strings
    strings = extract_strings(data, min_length=8)
    for s in strings:
        # Check if string is unique (not common)
        if not is_common_string(s):
            signatures['unique_strings'].append(s)

    # Find code patterns
    patterns = find_code_patterns(data)
    signatures['code_patterns'] = patterns

    return signatures

def extract_strings(data, min_length=8):
    import re
    return re.findall(b'[\x20-\x7e]{%d,}' % min_length, data)
```

## Post-Exploitation Artifact Detection

### Detecting Post-Ex Tools

```yara
rule RedTeam_PostEx_Artifacts {
    meta:
        description = "Detects common post-exploitation artifacts"

    strings:
        // SharpHound
        $sharphound1 = "SharpHound" ascii wide
        $sharphound2 = "Invoke-BloodHound" ascii wide

        // Rubeus
        $rubeus1 = "Rubeus" ascii wide
        $rubeus2 = "asktgt" ascii wide nocase

        // Mimikatz modules
        $mimi1 = "sekurlsa" ascii wide
        $mimi2 = "kerberos::list" ascii wide

        // Seatbelt
        $seatbelt = "Seatbelt" ascii wide

    condition:
        any of them
}
```

## Purple Team Exercises

### Collaborative Detection Development

```python
class PurpleTeamExercise:
    def __init__(self, attack_techniques, detection_rules):
        self.techniques = attack_techniques
        self.rules = yara.compile(filepath=detection_rules)

    def run_exercise(self, payload_dir, output_dir):
        """
        Run purple team exercise
        Red team provides payloads, blue team rules are tested
        """
        results = {
            'timestamp': datetime.now().isoformat(),
            'techniques_tested': [],
            'detection_rate': 0,
            'gaps': []
        }

        detected = 0
        total = 0

        for technique in self.techniques:
            payload_path = os.path.join(payload_dir, f"{technique['id']}.bin")
            if os.path.exists(payload_path):
                total += 1
                matches = self.rules.match(payload_path)

                technique_result = {
                    'technique_id': technique['id'],
                    'technique_name': technique['name'],
                    'detected': len(matches) > 0,
                    'rules_triggered': [m.rule for m in matches]
                }

                if matches:
                    detected += 1
                else:
                    results['gaps'].append(technique)

                results['techniques_tested'].append(technique_result)

        results['detection_rate'] = detected / total if total > 0 else 0

        # Save results
        with open(os.path.join(output_dir, 'exercise_results.json'), 'w') as f:
            json.dump(results, f, indent=2)

        return results
```

## Measuring Detection Coverage

### MITRE ATT&CK Mapping

```python
def calculate_attack_coverage(rules_path, attack_matrix_path):
    """
    Calculate MITRE ATT&CK coverage of YARA rules
    """
    # Load ATT&CK matrix
    with open(attack_matrix_path) as f:
        attack_matrix = json.load(f)

    # Parse rules for MITRE mappings
    rules_coverage = {}
    with open(rules_path) as f:
        rule_content = f.read()

    # Extract mitre_attack metadata
    import re
    mitre_pattern = r'mitre_attack\s*=\s*"([^"]+)"'
    matches = re.findall(mitre_pattern, rule_content)

    covered_techniques = set()
    for match in matches:
        techniques = [t.strip() for t in match.split(',')]
        covered_techniques.update(techniques)

    # Calculate coverage
    all_techniques = set(t['id'] for t in attack_matrix['techniques'])
    coverage = len(covered_techniques & all_techniques) / len(all_techniques)

    return {
        'total_techniques': len(all_techniques),
        'covered_techniques': len(covered_techniques & all_techniques),
        'coverage_percentage': coverage * 100,
        'uncovered': list(all_techniques - covered_techniques)
    }
```

## Best Practices for Red Team YARA Usage

1. **Test before deployment** - Verify payloads evade detection
2. **Document findings** - Report detection gaps to blue team
3. **Collaborate** - Purple team exercises improve both sides
4. **Update regularly** - Track detection capability changes
5. **OPSEC awareness** - Understand what triggers alerts
6. **Measure coverage** - Map to MITRE ATT&CK framework
