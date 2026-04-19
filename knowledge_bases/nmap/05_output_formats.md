# Nmap Output Formats and Reporting

## Overview

Nmap provides multiple output formats to accommodate different use cases, from human-readable reports to machine-parseable data for integration with other tools. Understanding these formats is essential for effective documentation, analysis, and workflow integration during penetration testing.

## Output Format Options

### Flag: -oN (Normal Output)
**Purpose:** Save human-readable output to a file
**Syntax:** `nmap -oN <filename> <target>`
**Example:**
```bash
nmap -oN scan_results.txt 192.168.1.1
```
**When to use:** Documentation, reports, quick review
**Warnings:** Not suitable for automated parsing

**Sample Output:**
```
Nmap scan report for 192.168.1.1
Host is up (0.0015s latency).
Not shown: 997 closed ports
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https
```

### Flag: -oX (XML Output)
**Purpose:** Save output in XML format for parsing and integration
**Syntax:** `nmap -oX <filename> <target>`
**Example:**
```bash
nmap -oX scan_results.xml 192.168.1.1
```
**When to use:** Importing into vulnerability scanners, SIEM integration, automated processing
**Warnings:** Larger file sizes; requires XML parser to read

**Sample Output:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -oX scan_results.xml 192.168.1.1" start="1634567890">
  <host>
    <status state="up" reason="echo-reply"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh"/>
      </port>
    </ports>
  </host>
</nmaprun>
```

### Flag: -oG (Grepable Output)
**Purpose:** Save output in grep-friendly format for command-line processing
**Syntax:** `nmap -oG <filename> <target>`
**Example:**
```bash
nmap -oG scan_results.gnmap 192.168.1.1
```
**When to use:** Quick parsing with grep, awk, sed; shell scripting
**Warnings:** Deprecated in favor of XML; less detailed than XML

**Sample Output:**
```
# Nmap 7.92 scan initiated Mon Oct 18 10:30:00 2021
Host: 192.168.1.1 ()	Status: Up
Host: 192.168.1.1 ()	Ports: 22/open/tcp//ssh///, 80/open/tcp//http///, 443/open/tcp//https///
# Nmap done at Mon Oct 18 10:30:05 2021 -- 1 IP address (1 host up) scanned
```

### Flag: -oS (Script Kiddie Output)
**Purpose:** Outputs in "leet" speak format (humorous)
**Syntax:** `nmap -oS <filename> <target>`
**Example:**
```bash
nmap -oS leet_scan.txt 192.168.1.1
```
**When to use:** Entertainment only; not for professional use
**Warnings:** Not suitable for documentation or professional reports

**Sample Output:**
```
Nm@p $c4n r3p0rT f0r 192.168.1.1
H0$t 1z Up (0.0015$ l4t3ncy).
P0rt    $t4t3 S3rv1c3
22/tcp  0p3n  $$h
```

### Flag: -oA (All Formats)
**Purpose:** Save output in all three major formats (.nmap, .xml, .gnmap)
**Syntax:** `nmap -oA <basename> <target>`
**Example:**
```bash
nmap -oA comprehensive_scan 192.168.1.1
# Creates: comprehensive_scan.nmap, comprehensive_scan.xml, comprehensive_scan.gnmap
```
**When to use:** Best practice for all professional scans
**Warnings:** Creates three files; ensure adequate disk space

### Flag: -v (Verbose)
**Purpose:** Increase output verbosity
**Syntax:** `nmap -v <target>` or `nmap -vv <target>`
**Example:**
```bash
# Standard verbose
nmap -v 192.168.1.1

# Very verbose
nmap -vv 192.168.1.1

# Maximum verbosity
nmap -vvv 192.168.1.1
```
**When to use:** Debugging, real-time progress monitoring
**Warnings:** Significantly increases output volume

### Flag: -d (Debug)
**Purpose:** Enable debugging output
**Syntax:** `nmap -d <target>` or `nmap -d2 <target>` (up to -d9)
**Example:**
```bash
# Basic debugging
nmap -d 192.168.1.1

# More detailed debugging
nmap -d3 192.168.1.1
```
**When to use:** Troubleshooting scan issues, understanding Nmap internals
**Warnings:** Extremely verbose; may slow down scans

### Flag: --reason
**Purpose:** Show reason for each port state
**Syntax:** `nmap --reason <target>`
**Example:**
```bash
nmap --reason 192.168.1.1
```
**When to use:** Understanding why ports are classified as open/closed/filtered
**Warnings:** None

**Sample Output:**
```
PORT    STATE  SERVICE REASON
22/tcp  open   ssh     syn-ack ttl 64
80/tcp  open   http    syn-ack ttl 64
443/tcp closed https   reset ttl 64
```

### Flag: --open
**Purpose:** Only show open ports in output
**Syntax:** `nmap --open <target>`
**Example:**
```bash
nmap --open 192.168.1.0/24
```
**When to use:** Large network scans, focusing on actionable results
**Warnings:** May hide filtered ports that indicate firewall presence

### Flag: --packet-trace
**Purpose:** Show all packets sent and received
**Syntax:** `nmap --packet-trace <target>`
**Example:**
```bash
nmap --packet-trace -p 80 192.168.1.1
```
**When to use:** Low-level debugging, understanding scan mechanics
**Warnings:** Extremely verbose; only for single port/host debugging

### Flag: --iflist
**Purpose:** List network interfaces and routes
**Syntax:** `nmap --iflist`
**Example:**
```bash
nmap --iflist
```
**When to use:** Troubleshooting network configuration issues
**Warnings:** None

### Flag: --stats-every <time>
**Purpose:** Print status every X seconds/minutes
**Syntax:** `nmap --stats-every <time> <target>`
**Example:**
```bash
# Status every 30 seconds
nmap --stats-every 30s -p- 192.168.1.1

# Status every 2 minutes
nmap --stats-every 2m -p- 192.168.1.1
```
**When to use:** Long scans requiring progress monitoring
**Warnings:** None

### Flag: --resume <filename>
**Purpose:** Resume aborted scan from log file
**Syntax:** `nmap --resume <filename>`
**Example:**
```bash
# Original scan (interrupted)
nmap -oN partial_scan.txt 192.168.1.0/24
# Ctrl+C to interrupt

# Resume scan
nmap --resume partial_scan.txt
```
**When to use:** Continuing interrupted scans
**Warnings:** Only works with normal output (-oN); requires original target specification

### Flag: --append-output
**Purpose:** Append to output files instead of overwriting
**Syntax:** `nmap --append-output -oN <filename> <target>`
**Example:**
```bash
nmap --append-output -oN cumulative_scan.txt 192.168.1.1
nmap --append-output -oN cumulative_scan.txt 192.168.1.2
```
**When to use:** Building cumulative scan records
**Warnings:** May create confusing merged results if not organized properly

### Flag: --stylesheet <path/URL>
**Purpose:** Apply XSL stylesheet to XML output
**Syntax:** `nmap --stylesheet <stylesheet> -oX <file> <target>`
**Example:**
```bash
# Use Nmap's default web stylesheet
nmap --stylesheet https://nmap.org/svn/docs/nmap.xsl -oX scan.xml 192.168.1.1

# Use local stylesheet
nmap --stylesheet /path/to/custom.xsl -oX scan.xml 192.168.1.1
```
**When to use:** Creating HTML reports from XML
**Warnings:** Requires stylesheet to be accessible when viewing

### Flag: --webxml
**Purpose:** Reference Nmap.org stylesheet for web-viewable XML
**Syntax:** `nmap --webxml -oX <file> <target>`
**Example:**
```bash
nmap --webxml -oX web_viewable_scan.xml 192.168.1.1
```
**When to use:** Creating XML that renders nicely in browsers
**Warnings:** Requires internet access to fetch stylesheet when viewing

### Flag: --no-stylesheet
**Purpose:** Prevent associating XSL stylesheet with XML output
**Syntax:** `nmap --no-stylesheet -oX <file> <target>`
**Example:**
```bash
nmap --no-stylesheet -oX raw_scan.xml 192.168.1.1
```
**When to use:** Pure XML for automated processing
**Warnings:** None

## Parsing Nmap Output

### Parsing Grepable Output

```bash
# Find all hosts with open SSH
grep "22/open" scan.gnmap

# Extract IPs with open HTTP
grep "80/open" scan.gnmap | cut -d" " -f2

# Find hosts with specific service
grep -E "http|https" scan.gnmap

# Count open ports per host
awk '/Ports:/ {print $2, gsub(/open/,"")}' scan.gnmap

# Extract all open ports
grep -oP '\d+/open' scan.gnmap | sort -u
```

### Parsing XML Output with xmllint

```bash
# Extract all IP addresses
xmllint --xpath "//address/@addr" scan.xml

# Get open ports
xmllint --xpath "//port[@protocol='tcp']/state[@state='open']/../@portid" scan.xml

# Extract service names
xmllint --xpath "//service/@name" scan.xml
```

### Parsing XML Output with Python

```python
#!/usr/bin/env python3
import xml.etree.ElementTree as ET

tree = ET.parse('scan.xml')
root = tree.getroot()

for host in root.findall('host'):
    ip = host.find('address').get('addr')
    print(f"Host: {ip}")

    ports = host.find('ports')
    if ports is not None:
        for port in ports.findall('port'):
            portid = port.get('portid')
            state = port.find('state').get('state')
            service = port.find('service')
            svc_name = service.get('name') if service is not None else 'unknown'
            print(f"  {portid}/tcp - {state} - {svc_name}")
```

### Using python-nmap Library

```python
#!/usr/bin/env python3
import nmap

nm = nmap.PortScanner()
nm.scan('192.168.1.0/24', '22,80,443')

for host in nm.all_hosts():
    print(f"Host: {host} ({nm[host].hostname()})")
    print(f"State: {nm[host].state()}")

    for proto in nm[host].all_protocols():
        ports = nm[host][proto].keys()
        for port in sorted(ports):
            state = nm[host][proto][port]['state']
            name = nm[host][proto][port]['name']
            print(f"  {port}/{proto} - {state} - {name}")
```

### Parsing with xsltproc (XML to HTML)

```bash
# Convert XML to HTML using Nmap's stylesheet
xsltproc /usr/share/nmap/nmap.xsl scan.xml -o scan_report.html

# Using custom stylesheet
xsltproc custom_report.xsl scan.xml -o custom_report.html
```

## Integration with Other Tools

### Importing into Metasploit

```bash
# Inside Metasploit console
msf> db_import /path/to/scan.xml

# Verify import
msf> hosts
msf> services
```

### Importing into Nessus

1. Export Nmap scan as XML
2. In Nessus: Settings > Import > Select XML file
3. Nessus will use discovered hosts/ports for targeted scanning

### Importing into OpenVAS

```bash
# Convert to OpenVAS format if needed
# Or import XML directly through OpenVAS web interface
```

### Importing into Splunk

```bash
# Use Splunk Add-on for Nmap
# Or parse XML/grepable directly with Splunk inputs

# Example props.conf for grepable
[nmap_grepable]
TIME_FORMAT = %a %b %d %H:%M:%S %Y
TIME_PREFIX = Nmap done at
```

### Using with Searchsploit

```bash
# Export services from scan
nmap -sV -oX services.xml 192.168.1.1

# Parse and search for exploits
nmap -sV 192.168.1.1 -oX - | searchsploit --nmap -
```

### Converting Formats

```bash
# XML to Grepable (using ndiff)
ndiff scan.xml --text > scan.gnmap

# Multiple XMLs to single report
nmap-merge.py scan1.xml scan2.xml -o merged.xml
```

## Output Best Practices

### Naming Conventions

```bash
# Include date, target, and scan type
nmap -oA scans/2024-01-15_192.168.1.0-24_full_tcp 192.168.1.0/24

# Organized directory structure
mkdir -p scans/{discovery,ports,services,vulns}
nmap -sn -oA scans/discovery/network_discovery 192.168.1.0/24
nmap -sS -oA scans/ports/tcp_scan 192.168.1.0/24
nmap -sV -oA scans/services/service_detection 192.168.1.0/24
nmap --script vuln -oA scans/vulns/vuln_scan 192.168.1.0/24
```

### Comprehensive Scan Documentation

```bash
# Always use -oA for completeness
nmap -sS -sV -sC -O -T4 -p- \
     --reason --open \
     --stats-every 60s \
     -oA scans/comprehensive_scan \
     192.168.1.0/24
```

### Log Rotation

```bash
# Keep scans organized by date
DATE=$(date +%Y-%m-%d_%H%M%S)
nmap -oA "scans/${DATE}_target" 192.168.1.1
```

## Common Mistakes

- **WRONG:** Not saving output at all
- **CORRECT:** Always use -oA to capture all formats

- **WRONG:** Using only -oN for automated processing
- **CORRECT:** Use -oX for parsing, -oG for quick grep operations

- **WRONG:** Overwriting previous scans
- **CORRECT:** Use timestamped filenames or --append-output

- **WRONG:** Ignoring verbose output during long scans
- **CORRECT:** Use --stats-every to monitor progress

- **WRONG:** Mixing output from different scans in one file
- **CORRECT:** Use separate files with clear naming conventions

- **WRONG:** Deleting scan files after analysis
- **CORRECT:** Archive scans for comparison and audit trail

## Practical Examples

### Complete Penetration Test Scan with Full Documentation

```bash
#!/bin/bash
TARGET="192.168.1.0/24"
DATE=$(date +%Y-%m-%d)
OUTDIR="pentest_${DATE}"

mkdir -p ${OUTDIR}/{discovery,ports,services,vulns,reports}

# Phase 1: Discovery
echo "[*] Phase 1: Host Discovery"
nmap -sn -oA ${OUTDIR}/discovery/host_discovery ${TARGET}

# Extract live hosts
grep "Up" ${OUTDIR}/discovery/host_discovery.gnmap | cut -d" " -f2 > ${OUTDIR}/live_hosts.txt

# Phase 2: Port Scanning
echo "[*] Phase 2: Port Scanning"
nmap -sS -p- -T4 --open -iL ${OUTDIR}/live_hosts.txt \
     -oA ${OUTDIR}/ports/full_tcp_scan

# Phase 3: Service Detection
echo "[*] Phase 3: Service Detection"
nmap -sV -sC -O --version-intensity 5 \
     -iL ${OUTDIR}/live_hosts.txt \
     -oA ${OUTDIR}/services/service_detection

# Phase 4: Vulnerability Scanning
echo "[*] Phase 4: Vulnerability Scanning"
nmap --script vuln -iL ${OUTDIR}/live_hosts.txt \
     -oA ${OUTDIR}/vulns/vulnerability_scan

echo "[+] Scan complete. Results in ${OUTDIR}/"
```

### Quick Status Report Script

```bash
#!/bin/bash
# Generate quick summary from grepable output

GNMAP_FILE=$1

if [ -z "$GNMAP_FILE" ]; then
    echo "Usage: $0 <scan.gnmap>"
    exit 1
fi

echo "=== Nmap Scan Summary ==="
echo ""
echo "Total hosts scanned: $(grep -c "Host:" $GNMAP_FILE)"
echo "Hosts up: $(grep -c "Status: Up" $GNMAP_FILE)"
echo ""
echo "=== Open Ports Summary ==="
grep -oP '\d+/open' $GNMAP_FILE | sort | uniq -c | sort -rn | head -20
echo ""
echo "=== Hosts with Most Open Ports ==="
awk -F'Ports:' '/Ports:/ {print $1, gsub(/open/,"",$2)}' $GNMAP_FILE | sort -t' ' -k2 -rn | head -10
```

### Real-Time Monitoring Dashboard

```bash
# Run scan with real-time updates
nmap -sS -sV -T4 -p- \
     --stats-every 10s \
     -v \
     --open \
     -oA live_scan \
     192.168.1.0/24 2>&1 | tee scan_progress.log
```

## Output Size Considerations

### Large Network Scans

```bash
# Split large scans into chunks
for subnet in $(seq 0 255); do
    nmap -sS -p 22,80,443 -oA chunk_${subnet} 10.0.${subnet}.0/24
done

# Merge results
cat chunk_*.gnmap > complete_scan.gnmap
```

### Reducing Output Size

```bash
# Only open ports
nmap --open -oA minimal_scan 192.168.1.0/24

# Specific ports only
nmap -p 22,80,443 -oA targeted_scan 192.168.1.0/24

# Skip reverse DNS
nmap -n -oA no_dns_scan 192.168.1.0/24
```

## Comparison and Diff

### Using ndiff for Scan Comparison

```bash
# Compare two scans
ndiff scan_baseline.xml scan_current.xml

# Output differences only
ndiff scan1.xml scan2.xml --text

# Machine-readable diff
ndiff scan1.xml scan2.xml --xml > diff.xml
```

### Automated Change Detection

```bash
#!/bin/bash
# Daily scan comparison script

TODAY=$(date +%Y-%m-%d)
YESTERDAY=$(date -d "yesterday" +%Y-%m-%d)

# Run today's scan
nmap -sS -p- -oX scans/${TODAY}.xml 192.168.1.0/24

# Compare with yesterday
if [ -f "scans/${YESTERDAY}.xml" ]; then
    ndiff scans/${YESTERDAY}.xml scans/${TODAY}.xml > changes/${TODAY}_changes.txt

    if [ -s "changes/${TODAY}_changes.txt" ]; then
        echo "Changes detected. Review changes/${TODAY}_changes.txt"
        # Could send email alert here
    fi
fi
```
