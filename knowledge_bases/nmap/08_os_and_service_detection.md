# OS and Service Detection

## Overview

Accurate identification of operating systems and service versions is crucial for vulnerability assessment and exploitation. Nmap uses sophisticated fingerprinting techniques to identify the OS stack and application versions running on target systems. This information directly feeds into vulnerability research and exploit selection.

## Service Version Detection

### Flag: -sV (Service Version Detection)
**Purpose:** Probe open ports to determine service/version info
**Syntax:** `nmap -sV <target>`
**Example:**
```bash
nmap -sV 192.168.1.1
nmap -sV -p 22,80,443 192.168.1.1
```
**How it works:**
1. Sends carefully crafted probes to open ports
2. Analyzes responses against nmap-service-probes database
3. Matches signatures to identify service and version

**When to use:** Always during security assessments; essential for vulnerability identification
**Warnings:** Generates additional traffic; may be logged; slightly slower than port-only scanning

**Sample Output:**
```
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http    Apache httpd 2.4.41 ((Ubuntu))
443/tcp open  ssl/http Apache httpd 2.4.41
3306/tcp open mysql   MySQL 5.7.32-0ubuntu0.18.04.1
```

### Flag: --version-intensity <0-9>
**Purpose:** Control aggressiveness of version detection probes
**Syntax:** `nmap -sV --version-intensity <level> <target>`
**Example:**
```bash
# Light probing (faster, less accurate)
nmap -sV --version-intensity 0 192.168.1.1

# Default intensity (level 7)
nmap -sV 192.168.1.1

# Maximum probing (slowest, most accurate)
nmap -sV --version-intensity 9 192.168.1.1
```

**Intensity Levels:**
| Level | Description | Probes Used |
|-------|-------------|-------------|
| 0 | Light | Only NULL probe and probes registered for specific port |
| 1-2 | Light | Few common probes |
| 3-5 | Medium | Moderate probe selection |
| 6-7 | Default | Most probes |
| 8-9 | All | Every possible probe |

**When to use:**
- Level 0: Quick recon, time-limited assessments
- Level 7: Standard assessments (default)
- Level 9: When you need maximum accuracy and have time

**Warnings:** Higher levels generate more traffic and take longer

### Flag: --version-light
**Purpose:** Equivalent to --version-intensity 2
**Syntax:** `nmap -sV --version-light <target>`
**Example:**
```bash
nmap -sV --version-light 192.168.1.0/24
```
**When to use:** Large network scanning where speed matters
**Warnings:** May miss version details for unusual services

### Flag: --version-all
**Purpose:** Equivalent to --version-intensity 9
**Syntax:** `nmap -sV --version-all <target>`
**Example:**
```bash
nmap -sV --version-all 192.168.1.1
```
**When to use:** Single host detailed analysis
**Warnings:** Slowest option; significant traffic generation

### Flag: --version-trace
**Purpose:** Show detailed version scan activity
**Syntax:** `nmap -sV --version-trace <target>`
**Example:**
```bash
nmap -sV --version-trace -p 80 192.168.1.1
```
**When to use:** Debugging version detection; understanding probe/response
**Warnings:** Very verbose output

## Operating System Detection

### Flag: -O (OS Detection)
**Purpose:** Enable OS detection
**Syntax:** `nmap -O <target>`
**Example:**
```bash
nmap -O 192.168.1.1
nmap -O -v 192.168.1.1  # More detailed output
```
**How it works:**
1. Sends series of TCP and UDP packets
2. Analyzes responses for OS-specific TCP/IP stack behaviors
3. Matches against nmap-os-db database
4. Reports confidence levels

**When to use:** Identifying target systems; exploit selection; network inventory
**Warnings:** Requires root/admin; needs at least one open and one closed port for best results

**Sample Output:**
```
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.6
Network Distance: 1 hop
```

### Flag: --osscan-limit
**Purpose:** Only attempt OS detection on promising targets
**Syntax:** `nmap -O --osscan-limit <target>`
**Example:**
```bash
nmap -O --osscan-limit 192.168.1.0/24
```
**When to use:** Large network scans; skip hosts without open+closed TCP ports
**Warnings:** May skip some hosts that could be fingerprinted

### Flag: --osscan-guess (or --fuzzy)
**Purpose:** Guess OS when exact match not found
**Syntax:** `nmap -O --osscan-guess <target>`
**Example:**
```bash
nmap -O --osscan-guess 192.168.1.1
```
**When to use:** When precise fingerprint unavailable; older/rare systems
**Warnings:** Lower confidence results; may be incorrect

**Sample Output with Guessing:**
```
Aggressive OS guesses: Linux 4.15 - 5.6 (95%), Linux 3.2 - 4.9 (93%),
Linux 2.6.32 (91%), Linux 3.10 (90%)
```

### Flag: --max-os-tries <number>
**Purpose:** Limit OS detection probe retransmissions
**Syntax:** `nmap -O --max-os-tries <number> <target>`
**Example:**
```bash
# Faster but potentially less accurate
nmap -O --max-os-tries 1 192.168.1.1

# More thorough (default is 5)
nmap -O --max-os-tries 10 192.168.1.1
```
**When to use:** Speed optimization; unreliable networks
**Warnings:** Fewer tries may reduce accuracy

## OS Detection Methodology

### Required Conditions

For reliable OS detection, Nmap needs:
1. At least one **open** TCP port
2. At least one **closed** TCP port
3. Root/admin privileges

```bash
# Verify conditions with port scan first
nmap -sS 192.168.1.1

# If no closed ports, try full range
nmap -O -p- 192.168.1.1
```

### TCP/IP Fingerprinting Probes

Nmap sends these test categories:

| Test | Purpose |
|------|---------|
| SEQ | TCP sequence prediction |
| OPS | TCP options order |
| WIN | TCP initial window size |
| ECN | Explicit congestion notification |
| T1-T7 | TCP response tests |
| U1 | UDP response test |
| IE | ICMP echo test |

### Understanding Confidence Levels

```
OS details: Linux 4.15 - 5.6 (95%)
```

- 100%: Perfect match to known fingerprint
- 85-99%: High confidence match
- 70-84%: Good match but could be variant
- <70%: Low confidence; use --osscan-guess

## CPE Identification

### What is CPE?

Common Platform Enumeration (CPE) is a standardized method for describing and identifying classes of applications, operating systems, and hardware devices.

### CPE Format

```
cpe:/<part>:<vendor>:<product>:<version>:<update>:<edition>:<language>
```

**Parts:**
- `a` = Application
- `o` = Operating System
- `h` = Hardware

### CPE in Nmap Output

```bash
nmap -sV -O 192.168.1.1
```

**Sample Output:**
```
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 8.2p1 Ubuntu
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

80/tcp  open  http    Apache httpd 2.4.41
Service Info: CPE: cpe:/a:apache:http_server:2.4.41

OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
```

### Using CPE for Vulnerability Research

```bash
# Extract CPEs from XML output
grep -oP 'cpe:[^"<]+' scan.xml | sort -u

# Search vulnerabilities using CPE
searchsploit --cve "cpe:/a:apache:http_server:2.4.41"
```

## Combined Detection

### Flag: -A (Aggressive Scan)
**Purpose:** Enable OS detection, version detection, scripts, and traceroute
**Syntax:** `nmap -A <target>`
**Example:**
```bash
nmap -A 192.168.1.1
# Equivalent to:
nmap -O -sV -sC --traceroute 192.168.1.1
```
**When to use:** Comprehensive single-host analysis
**Warnings:**
- Generates significant traffic
- Easily detected by IDS
- Takes longer than individual options

## NSE Version Detection

### Version Detection Scripts

```bash
# Scripts that enhance version detection
nmap -sV --script version 192.168.1.1

# Specific version scripts
nmap -sV --script http-server-header,ssh-hostkey 192.168.1.1
```

### Common Version-Related Scripts

| Script | Purpose |
|--------|---------|
| `http-server-header` | HTTP server identification |
| `ssh-hostkey` | SSH host key fingerprinting |
| `ssl-cert` | SSL certificate details |
| `smb-os-discovery` | Windows OS via SMB |
| `nbstat` | NetBIOS information |
| `http-headers` | All HTTP response headers |

### SMB-Based OS Detection

```bash
# More accurate for Windows systems
nmap --script smb-os-discovery -p 445 192.168.1.1
```

**Sample Output:**
```
Host script results:
| smb-os-discovery:
|   OS: Windows Server 2019 Standard 17763 (Windows Server 2019 Standard 6.3)
|   Computer name: DC01
|   NetBIOS computer name: DC01\x00
|   Domain name: contoso.local
|   Forest name: contoso.local
|   FQDN: DC01.contoso.local
```

## Troubleshooting Detection Failures

### OS Detection Issues

**Problem: "Too many fingerprints match"**
```bash
# Solution: Increase probe intensity
nmap -O --max-os-tries 10 192.168.1.1
```

**Problem: "No exact OS matches"**
```bash
# Solution: Use aggressive guessing
nmap -O --osscan-guess 192.168.1.1
```

**Problem: "Insufficient open/closed ports"**
```bash
# Solution: Scan more ports
nmap -O -p- 192.168.1.1
```

**Problem: "OS detection requires root"**
```bash
# Solution: Run as root
sudo nmap -O 192.168.1.1
```

### Version Detection Issues

**Problem: "Could not determine service/version"**
```bash
# Solution 1: Increase intensity
nmap -sV --version-all 192.168.1.1

# Solution 2: Try specific scripts
nmap -sV --script default 192.168.1.1

# Solution 3: Manual banner grab
nmap -sV --script banner 192.168.1.1
```

**Problem: "Version detection taking too long"**
```bash
# Solution: Reduce intensity
nmap -sV --version-light 192.168.1.1
```

### Submitting New Fingerprints

When Nmap cannot identify a system:
```
Nmap needs more information...
Please submit fingerprint to:
https://nmap.org/cgi-bin/submit.cgi?new-os
```

```bash
# Get fingerprint for submission
nmap -O -sV --osscan-limit --version-all -p- 192.168.1.1
```

## Common Mistakes

- **WRONG:** Running -O without root/admin privileges
- **CORRECT:** Use sudo/admin: `sudo nmap -O 192.168.1.1`

- **WRONG:** Expecting OS detection on heavily filtered hosts
- **CORRECT:** Need open AND closed ports; use `-p-` or ensure port variety

- **WRONG:** Using -A for large network scans
- **CORRECT:** Use targeted detection: `nmap -sV --version-light 192.168.1.0/24`

- **WRONG:** Trusting low-confidence OS guesses
- **CORRECT:** Verify with additional methods (SMB scripts, banner analysis)

- **WRONG:** Running version detection on all 65535 ports
- **CORRECT:** Detect versions on discovered open ports only

- **WRONG:** Ignoring CPE information
- **CORRECT:** Use CPE for vulnerability database correlation

## Practical Examples

### Comprehensive Host Fingerprinting

```bash
# Full fingerprinting workflow
nmap -sS -sV -O --version-all --osscan-guess \
     --script smb-os-discovery,nbstat,http-server-header \
     -p- -T4 -oA full_fingerprint 192.168.1.1
```

### Quick Network Inventory

```bash
# Fast inventory with version info
nmap -sV --version-light -O --osscan-limit \
     -T4 --top-ports 100 \
     -oA inventory 192.168.1.0/24
```

### Windows Domain Enumeration

```bash
# Windows-specific detection
nmap -sV -O --script smb-os-discovery,smb-enum-domains,nbstat \
     -p 135,139,445,389,636 \
     -oA windows_enum 192.168.1.0/24
```

### Web Server Identification

```bash
# Detailed web server fingerprinting
nmap -sV --version-intensity 9 \
     --script http-server-header,http-headers,http-enum \
     -p 80,443,8080,8443 \
     -oA web_servers 192.168.1.0/24
```

### SSL/TLS Service Analysis

```bash
# SSL service version and certificate
nmap -sV --script ssl-cert,ssl-enum-ciphers \
     -p 443,8443,993,995,465,636 \
     -oA ssl_analysis 192.168.1.1
```

### Scripted Detection Pipeline

```bash
#!/bin/bash
# Comprehensive detection script

TARGET=$1
OUTDIR="detection_$(date +%Y%m%d)"
mkdir -p $OUTDIR

echo "[*] Phase 1: Quick port discovery"
nmap -sS -T4 --top-ports 1000 $TARGET -oA $OUTDIR/ports

echo "[*] Phase 2: Service version detection"
PORTS=$(grep -oP '\d+/open' $OUTDIR/ports.gnmap | cut -d/ -f1 | tr '\n' ',' | sed 's/,$//')
nmap -sV --version-intensity 7 -p "$PORTS" $TARGET -oA $OUTDIR/versions

echo "[*] Phase 3: OS detection"
nmap -O --osscan-guess $TARGET -oA $OUTDIR/os

echo "[*] Phase 4: Script enumeration"
nmap -sV -sC -p "$PORTS" $TARGET -oA $OUTDIR/scripts

echo "[+] Results saved to $OUTDIR/"
```

### Database Version Detection

```bash
# Database-specific fingerprinting
nmap -sV --version-all \
     --script mysql-info,ms-sql-info,oracle-tns-version,mongodb-info \
     -p 1433,1521,3306,5432,27017,6379 \
     -oA databases 192.168.1.0/24
```

## Advanced Detection Techniques

### Combining Multiple Methods

```bash
# Multi-vector identification
nmap -sV -O --osscan-guess \
     --script smb-os-discovery,nbstat,http-server-header,banner \
     --version-all \
     -p- -T4 \
     192.168.1.1
```

### Detecting Virtual Machines

```bash
# VM detection indicators
nmap -O -sV --script smb-os-discovery,vmware-version \
     -p 445,902,443 \
     192.168.1.1

# Look for VM-related MAC addresses (VMware: 00:50:56, 00:0C:29)
# Or Hyper-V, VirtualBox patterns in OS fingerprint
```

### Container Detection

```bash
# Docker/container indicators
# Look for:
# - Multiple services on unusual ports
# - Linux fingerprint on Windows infrastructure
# - Missing kernel information

nmap -O -sV --version-all -p- 192.168.1.1
```

### IoT Device Fingerprinting

```bash
# IoT common ports and signatures
nmap -sV --version-all -O \
     --script http-title,upnp-info,hnap-info \
     -p 80,443,554,5000,8080,49152 \
     192.168.1.0/24
```
