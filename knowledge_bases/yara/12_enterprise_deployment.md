# YARA Enterprise Deployment

## EDR Integration

### Integrating YARA with EDR Solutions

Most enterprise EDR solutions support YARA rules for enhanced detection.

```python
# Example: EDR YARA Integration Script
class EDRYaraIntegration:
    def __init__(self, edr_api_url, api_key):
        self.api_url = edr_api_url
        self.api_key = api_key

    def upload_rules(self, rules_path):
        """Upload YARA rules to EDR platform"""
        with open(rules_path, 'r') as f:
            rules_content = f.read()

        response = requests.post(
            f"{self.api_url}/yara/rules",
            headers={'Authorization': f'Bearer {self.api_key}'},
            json={'rules': rules_content, 'enabled': True}
        )
        return response.json()

    def trigger_scan(self, target_hosts, rule_ids):
        """Trigger YARA scan on specific hosts"""
        payload = {
            'hosts': target_hosts,
            'rule_ids': rule_ids,
            'scan_type': 'on_demand'
        }
        response = requests.post(
            f"{self.api_url}/scans",
            headers={'Authorization': f'Bearer {self.api_key}'},
            json=payload
        )
        return response.json()
```

### Real-Time File Scanning

```python
import yara
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class YaraFileMonitor(FileSystemEventHandler):
    def __init__(self, rules_path, alert_callback):
        self.rules = yara.compile(filepath=rules_path)
        self.alert_callback = alert_callback

    def on_created(self, event):
        if not event.is_directory:
            self.scan_file(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self.scan_file(event.src_path)

    def scan_file(self, filepath):
        try:
            matches = self.rules.match(filepath, timeout=30)
            if matches:
                self.alert_callback({
                    'file': filepath,
                    'matches': [m.rule for m in matches],
                    'event': 'detection'
                })
        except Exception as e:
            pass

def start_monitoring(watch_paths, rules_path, alert_callback):
    handler = YaraFileMonitor(rules_path, alert_callback)
    observer = Observer()

    for path in watch_paths:
        observer.schedule(handler, path, recursive=True)

    observer.start()
    return observer
```

## Centralized Rule Management

### Rule Repository Structure

```
yara-rules-repo/
├── production/
│   ├── malware/
│   │   ├── ransomware.yar
│   │   ├── trojans.yar
│   │   └── stealers.yar
│   ├── apt/
│   │   ├── apt28.yar
│   │   └── apt29.yar
│   └── generic/
│       ├── packers.yar
│       └── exploits.yar
├── testing/
│   └── new_rules.yar
├── deprecated/
│   └── old_rules.yar
└── config/
    ├── whitelist.txt
    └── deploy_config.yaml
```

### Rule Deployment Pipeline

```yaml
# deploy_config.yaml
rule_sets:
  production:
    path: production/
    auto_deploy: true
    validation_required: true

  testing:
    path: testing/
    auto_deploy: false
    environments: [staging]

deployment:
  targets:
    - name: edr_platform
      type: api
      endpoint: https://edr.company.com/api/yara
      auth: api_key

    - name: endpoint_agents
      type: file_distribution
      path: /opt/yara/rules/

validation:
  test_samples_path: /samples/test/
  max_false_positive_rate: 0.001
  required_detection_rate: 0.95
```

### Automated Rule Testing

```python
def validate_rules_before_deploy(rules_path, test_samples_dir, whitelist_path):
    """
    Validate rules before production deployment
    """
    rules = yara.compile(filepath=rules_path)

    # Load whitelist
    with open(whitelist_path) as f:
        whitelist = set(line.strip() for line in f)

    # Test against malware samples (should detect)
    malware_dir = os.path.join(test_samples_dir, 'malware')
    detections = 0
    total_malware = 0

    for sample in os.listdir(malware_dir):
        total_malware += 1
        matches = rules.match(os.path.join(malware_dir, sample))
        if matches:
            detections += 1

    detection_rate = detections / total_malware if total_malware > 0 else 0

    # Test against clean samples (should NOT detect)
    clean_dir = os.path.join(test_samples_dir, 'clean')
    false_positives = 0
    total_clean = 0

    for sample in os.listdir(clean_dir):
        total_clean += 1
        filepath = os.path.join(clean_dir, sample)
        if filepath not in whitelist:
            matches = rules.match(filepath)
            if matches:
                false_positives += 1

    fp_rate = false_positives / total_clean if total_clean > 0 else 0

    return {
        'detection_rate': detection_rate,
        'false_positive_rate': fp_rate,
        'passed': detection_rate >= 0.95 and fp_rate <= 0.001
    }
```

## Continuous Monitoring

### Alert Management

```python
class YaraAlertManager:
    def __init__(self, siem_endpoint, severity_thresholds):
        self.siem = siem_endpoint
        self.thresholds = severity_thresholds

    def process_alert(self, yara_match):
        """Process YARA match and route appropriately"""
        severity = self.calculate_severity(yara_match)

        alert = {
            'timestamp': datetime.utcnow().isoformat(),
            'source': 'yara_scanner',
            'severity': severity,
            'rule': yara_match['rule'],
            'file': yara_match['file'],
            'host': yara_match.get('host', 'unknown'),
            'metadata': yara_match.get('metadata', {})
        }

        # Route based on severity
        if severity == 'critical':
            self.create_incident(alert)
            self.notify_soc(alert)
        elif severity == 'high':
            self.create_ticket(alert)
            self.notify_soc(alert)
        else:
            self.log_alert(alert)

        # Send to SIEM
        self.send_to_siem(alert)

    def calculate_severity(self, match):
        """Calculate alert severity based on rule metadata"""
        rule_name = match['rule']

        if any(crit in rule_name for crit in ['Ransomware', 'APT', 'Critical']):
            return 'critical'
        elif any(high in rule_name for high in ['Trojan', 'Stealer', 'C2']):
            return 'high'
        elif any(med in rule_name for med in ['Suspicious', 'PUA']):
            return 'medium'
        return 'low'
```

## SIEM Integration

### Splunk Integration

```python
def send_to_splunk(yara_results, splunk_hec_url, token):
    """Send YARA results to Splunk via HEC"""
    headers = {
        'Authorization': f'Splunk {token}',
        'Content-Type': 'application/json'
    }

    for result in yara_results:
        event = {
            'time': int(datetime.now().timestamp()),
            'sourcetype': 'yara:detection',
            'source': 'yara_scanner',
            'event': {
                'rule': result['rule'],
                'file_path': result['file'],
                'matched_strings': result.get('strings', []),
                'severity': result.get('severity', 'unknown'),
                'host': result.get('host', socket.gethostname())
            }
        }

        requests.post(splunk_hec_url, headers=headers, json=event)
```

### Elastic Integration

```python
from elasticsearch import Elasticsearch

def send_to_elastic(yara_results, es_hosts, index_name):
    """Send YARA results to Elasticsearch"""
    es = Elasticsearch(es_hosts)

    for result in yara_results:
        doc = {
            '@timestamp': datetime.utcnow().isoformat(),
            'event.category': 'malware',
            'event.type': 'detection',
            'rule.name': result['rule'],
            'file.path': result['file'],
            'host.name': result.get('host', socket.gethostname()),
            'threat.indicator.matched_strings': result.get('strings', [])
        }

        es.index(index=index_name, document=doc)
```

## Performance Monitoring

### Metrics Collection

```python
import time
import prometheus_client as prom

# Metrics
SCAN_DURATION = prom.Histogram(
    'yara_scan_duration_seconds',
    'Time spent scanning files',
    ['rule_set']
)

SCAN_RESULTS = prom.Counter(
    'yara_scan_results_total',
    'Number of scan results',
    ['result_type', 'severity']
)

FILES_SCANNED = prom.Counter(
    'yara_files_scanned_total',
    'Total files scanned'
)

def instrumented_scan(rules, filepath, rule_set_name):
    """Scan with metrics collection"""
    FILES_SCANNED.inc()

    start_time = time.time()
    matches = rules.match(filepath)
    duration = time.time() - start_time

    SCAN_DURATION.labels(rule_set=rule_set_name).observe(duration)

    if matches:
        for match in matches:
            severity = get_rule_severity(match.rule)
            SCAN_RESULTS.labels(result_type='detection', severity=severity).inc()
    else:
        SCAN_RESULTS.labels(result_type='clean', severity='none').inc()

    return matches
```

## Rule Versioning and Testing

### Git-Based Rule Management

```bash
# Rule development workflow
# 1. Create feature branch
git checkout -b rule/new-ransomware-variant

# 2. Add/modify rules
vim production/malware/ransomware.yar

# 3. Run automated tests
./scripts/test_rules.py --rules production/malware/ransomware.yar

# 4. Submit PR with test results
git add .
git commit -m "Add detection for RansomwareX variant"
git push origin rule/new-ransomware-variant

# 5. After review and approval, merge
git checkout main
git merge rule/new-ransomware-variant
```

### CI/CD Pipeline

```yaml
# .github/workflows/yara-ci.yml
name: YARA Rules CI

on:
  push:
    paths:
      - '**/*.yar'
  pull_request:
    paths:
      - '**/*.yar'

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2

      - name: Install YARA
        run: |
          sudo apt-get update
          sudo apt-get install -y yara

      - name: Validate Syntax
        run: |
          find . -name "*.yar" -exec yara -w {} /dev/null \;

      - name: Run Tests
        run: |
          python scripts/test_rules.py --all

      - name: Check False Positives
        run: |
          python scripts/fp_check.py --samples /samples/clean/

  deploy:
    needs: validate
    if: github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    steps:
      - name: Deploy to Production
        run: |
          python scripts/deploy_rules.py --target production
```

## Best Practices Summary

1. **Centralize rule management** - Single source of truth
2. **Version control everything** - Track all changes
3. **Automate testing** - CI/CD pipeline for rules
4. **Monitor performance** - Track scan times and resource usage
5. **Alert appropriately** - Severity-based routing
6. **Integrate with SIEM** - Centralize security events
7. **Regular updates** - Keep rules current with threats
8. **Document thoroughly** - Maintain rule documentation
