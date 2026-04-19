# Advanced Port Scanning Techniques

## Overview

Beyond the basic SYN and Connect scans, Nmap provides specialized scanning techniques for specific situations: evading firewalls, scanning through proxy hosts, identifying operating systems through TCP behavior, and using custom packet configurations. These advanced techniques are essential for thorough security assessments in complex network environments.

## Specialized TCP Scan Types

### Flag: -sW (Window Scan)
**Purpose:** TCP Window scan exploits implementation details in TCP RST packets
**Syntax:** `nmap -sW <target>`
**Example:**
```bash
nmap -sW 192.168.1.1
nmap -sW -p 1-1000 192.168.1.1
```
**How it works:** Examines the TCP window field of RST packets returned. On some systems, open ports use a positive window size while closed ports use zero.
**When to use:** When SYN scan returns mostly "filtered"; may differentiate between open and closed
**Warnings:**
- Only works on certain OS implementations (older BSDs, some Windows)
- Most modern systems return consistent window values
- Results often unreliable

### Flag: -sM (Maimon Scan)
**Purpose:** FIN/ACK scan named after discoverer Uriel Maimon
**Syntax:** `nmap -sM <target>`
**Example:**
```bash
nmap -sM 192.168.1.1
nmap -sM -p 80,443 192.168.1.1
```
**How it works:** Sends TCP packet with FIN and ACK flags. Per RFC, should receive RST for open or closed ports. Some BSD-derived systems drop packet if port is open.
**When to use:** Against older BSD systems; bypassing certain firewall rules
**Warnings:**
- Very limited effectiveness on modern systems
- Most systems respond identically for open and closed ports
- Requires root/admin privileges

### Flag: -sN (NULL Scan)
**Purpose:** TCP scan with no flags set
**Syntax:** `nmap -sN <target>`
**Example:**
```bash
nmap -sN 192.168.1.1
nmap -sN -p 1-1000 192.168.1.1
```
**How it works:** Per RFC 793, closed ports respond with RST; open ports should not respond
**When to use:** Bypassing non-stateful firewalls that only check SYN flag
**Warnings:**
- Does not work against Windows (sends RST regardless)
- May be detected by IDS
- Cannot distinguish open from filtered

### Flag: -sF (FIN Scan)
**Purpose:** TCP scan with only FIN flag set
**Syntax:** `nmap -sF <target>`
**Example:**
```bash
nmap -sF 192.168.1.1
nmap -sF -p 22,80,443 192.168.1.1
```
**How it works:** Sends FIN packet; closed ports reply with RST; open/filtered ports don't respond
**When to use:** Firewall evasion when SYN is blocked
**Warnings:**
- Does not work against Windows systems
- Cannot distinguish open from filtered
- Requires root/admin privileges

### Flag: -sX (Xmas Scan)
**Purpose:** TCP scan with FIN, PSH, and URG flags set
**Syntax:** `nmap -sX <target>`
**Example:**
```bash
nmap -sX 192.168.1.1
nmap -sX -p 1-100 192.168.1.1
```
**How it works:** "Lights up" packet like a Christmas tree; per RFC, closed ports respond with RST
**When to use:** Firewall evasion; OS fingerprinting behavior
**Warnings:**
- Does not work against Windows, Cisco, BSDI, HP/UX, MVS, IRIX
- Easily detected by IDS
- Cannot distinguish open from filtered

### Flag: -sA (ACK Scan)
**Purpose:** TCP ACK scan for firewall rule mapping
**Syntax:** `nmap -sA <target>`
**Example:**
```bash
nmap -sA 192.168.1.1
nmap -sA -p 1-1000 192.168.1.1
```
**How it works:** Sends only ACK flag; determines if port is filtered (no response/ICMP error) or unfiltered (RST response)
**When to use:**
- Mapping firewall rules
- Determining if firewall is stateful
- Finding unfiltered ports for later exploitation
**Warnings:**
- Cannot determine if port is open (only filtered vs unfiltered)
- RST response means unfiltered, not open
- Requires root/admin privileges

## Advanced Scanning Techniques

### Flag: -sI (Idle Scan / Zombie Scan)
**Purpose:** Completely blind TCP port scan using a "zombie" host
**Syntax:** `nmap -sI <zombie-host>[:<probe-port>] <target>`
**Example:**
```bash
# Basic idle scan using zombie
nmap -sI zombie.example.com 192.168.1.1

# Specify zombie probe port
nmap -sI zombie.example.com:80 192.168.1.1

# Verbose to see IP ID progression
nmap -sI zombie.example.com -v 192.168.1.1
```
**How it works:**
1. Probe zombie to get current IP ID
2. Send spoofed SYN from zombie IP to target
3. Probe zombie again to check if IP ID incremented
4. If incremented by 2, target responded to zombie (port open)

**When to use:**
- Ultimate stealth (no packets from your IP to target)
- Bypassing IP-based access controls
- Legal penetration testing scenarios

**Warnings:**
- Requires finding suitable zombie (incremental IP ID, idle)
- Modern systems often use random IP IDs
- Slower than direct scanning
- Complex to troubleshoot
- Ethical concerns about using third-party systems

**Finding suitable zombies:**
```bash
# Check if host has incremental IP ID
nmap -O -v 192.168.1.100

# Look for "IP ID Sequence Generation: Incremental"
```

### Flag: -b (FTP Bounce Scan)
**Purpose:** Scan through vulnerable FTP servers
**Syntax:** `nmap -b <ftp-relay-host> <target>`
**Example:**
```bash
nmap -b anonymous@ftp.example.com 192.168.1.1
nmap -b user:pass@ftp.example.com:21 192.168.1.1
```
**How it works:** Exploits FTP PORT command to request FTP server connect to arbitrary ports on target
**When to use:** When FTP server is in trusted network zone
**Warnings:**
- Most modern FTP servers patched against this
- Very rare to find vulnerable servers
- May be illegal to use without authorization

### Flag: -sO (IP Protocol Scan)
**Purpose:** Determine which IP protocols are supported
**Syntax:** `nmap -sO <target>`
**Example:**
```bash
nmap -sO 192.168.1.1
```
**How it works:** Iterates through IP protocol numbers (1-255); determines which protocols (TCP, UDP, ICMP, etc.) are supported
**When to use:**
- Identifying unusual protocols (GRE, ESP, SCTP)
- Finding tunneling services
- Router/firewall fingerprinting

**Warnings:**
- Not a port scan; scans protocol numbers
- Slow (cycles through 256 protocols)
- Requires root/admin privileges

**Sample Output:**
```
PROTOCOL STATE         SERVICE
1        open          icmp
6        open          tcp
17       open          udp
47       open|filtered gre
50       open|filtered esp
```

## Custom TCP Flag Configuration

### Flag: --scanflags <flags>
**Purpose:** Create custom scans by specifying TCP flags
**Syntax:** `nmap --scanflags <flags> <target>`
**Example:**
```bash
# PSH-only scan
nmap --scanflags PSH 192.168.1.1

# SYN+FIN (unusual combination)
nmap --scanflags SYNFIN 192.168.1.1

# SYN+URG+PSH
nmap --scanflags SYNURGPSH 192.168.1.1

# Combine with base scan type for result interpretation
nmap --scanflags SYNFIN -sS 192.168.1.1
```

**Available flags:**
| Flag | Description |
|------|-------------|
| URG | Urgent pointer |
| ACK | Acknowledgment |
| PSH | Push |
| RST | Reset |
| SYN | Synchronize |
| FIN | Finish |

**When to use:**
- Firewall evasion with unusual flag combinations
- IDS/IPS testing
- Research and experimentation

**Warnings:**
- Unusual combinations may be dropped or flagged
- Results interpretation depends on base scan type
- Requires root/admin privileges

### Numeric Flag Specification

```bash
# Flags can also be specified numerically (bitmask)
# URG=32, ACK=16, PSH=8, RST=4, SYN=2, FIN=1

# SYN = 2
nmap --scanflags 2 192.168.1.1

# SYN+FIN = 2+1 = 3
nmap --scanflags 3 192.168.1.1

# SYN+PSH+FIN = 2+8+1 = 11
nmap --scanflags 11 192.168.1.1
```

## Port Specification and Selection

### Flag: -p (Port Specification)
**Purpose:** Specify ports to scan
**Syntax:** `nmap -p <port-ranges> <target>`
**Example:**
```bash
# Single port
nmap -p 80 192.168.1.1

# Multiple ports
nmap -p 22,80,443 192.168.1.1

# Port range
nmap -p 1-1000 192.168.1.1

# All 65535 ports
nmap -p- 192.168.1.1

# All ports explicitly
nmap -p 1-65535 192.168.1.1

# Protocol-specific ports
nmap -p T:80,443,U:53,161 192.168.1.1

# Exclude ports
nmap -p 1-1000 --exclude-ports 80,443 192.168.1.1
```
**When to use:** Targeting specific services, comprehensive scans, protocol-specific testing
**Warnings:** Scanning all ports (-p-) takes significantly longer

### Flag: -F (Fast Scan)
**Purpose:** Scan top 100 most common ports (instead of default 1000)
**Syntax:** `nmap -F <target>`
**Example:**
```bash
nmap -F 192.168.1.1
```
**When to use:** Quick reconnaissance; time-limited assessments
**Warnings:** May miss services on uncommon ports

### Flag: --top-ports <number>
**Purpose:** Scan the most common N ports
**Syntax:** `nmap --top-ports <number> <target>`
**Example:**
```bash
# Top 10 ports
nmap --top-ports 10 192.168.1.1

# Top 100 ports
nmap --top-ports 100 192.168.1.1

# Top 5000 ports
nmap --top-ports 5000 192.168.1.1
```
**When to use:** Balancing coverage vs. speed
**Warnings:** Rankings based on Nmap's port frequency data

**Top 10 TCP ports:**
1. 80 (http)
2. 23 (telnet)
3. 443 (https)
4. 21 (ftp)
5. 22 (ssh)
6. 25 (smtp)
7. 3389 (ms-wbt-server)
8. 110 (pop3)
9. 445 (microsoft-ds)
10. 139 (netbios-ssn)

### Flag: --port-ratio <ratio>
**Purpose:** Scan ports with probability above given ratio
**Syntax:** `nmap --port-ratio <0.0-1.0> <target>`
**Example:**
```bash
# Ports with >0.1 probability of being open
nmap --port-ratio 0.1 192.168.1.1

# Ports with >0.5 probability (very common only)
nmap --port-ratio 0.5 192.168.1.1
```
**When to use:** Statistical port selection
**Warnings:** Based on empirical data; may not match specific environment

### Flag: --exclude-ports <ports>
**Purpose:** Exclude specific ports from scan
**Syntax:** `nmap --exclude-ports <port-ranges> <target>`
**Example:**
```bash
# Scan all ports except 80 and 443
nmap -p- --exclude-ports 80,443 192.168.1.1

# Scan common ports except certain ranges
nmap --top-ports 1000 --exclude-ports 1-100 192.168.1.1
```
**When to use:** Avoiding known honeypots; skipping authorized services
**Warnings:** None

### Flag: -r (Sequential Port Scan)
**Purpose:** Scan ports in sequential order (disable randomization)
**Syntax:** `nmap -r <target>`
**Example:**
```bash
nmap -r -p 1-1000 192.168.1.1
```
**When to use:** Debugging; reproducible results; testing firewall responses
**Warnings:**
- More detectable by IDS (pattern recognition)
- Default randomization is more stealthy

## UDP Scanning

### Flag: -sU (UDP Scan)
**Purpose:** Scan UDP ports
**Syntax:** `nmap -sU <target>`
**Example:**
```bash
# Basic UDP scan
nmap -sU 192.168.1.1

# UDP scan of common ports
nmap -sU --top-ports 100 192.168.1.1

# Combined TCP and UDP
nmap -sS -sU 192.168.1.1

# Fast UDP scan
nmap -sU -T4 -F 192.168.1.1
```
**How it works:** Sends UDP packet; no response means open|filtered; ICMP unreachable means closed
**When to use:** Finding DNS, SNMP, DHCP, TFTP, NTP, and other UDP services
**Warnings:**
- Much slower than TCP (no handshake confirmation)
- Many systems rate-limit ICMP unreachable responses
- Requires root/admin privileges

### UDP Scan Optimization

```bash
# Speed up UDP with version detection (confirms open)
nmap -sU -sV --version-intensity 0 --top-ports 100 192.168.1.1

# Combine with service-specific scripts
nmap -sU -p 53,161,123 --script dns-nsid,snmp-info,ntp-info 192.168.1.1
```

## SCTP Scanning

### Flag: -sY (SCTP INIT Scan)
**Purpose:** SCTP equivalent of TCP SYN scan
**Syntax:** `nmap -sY <target>`
**Example:**
```bash
nmap -sY 192.168.1.1
nmap -sY -p 2905,2945,9084 192.168.1.1
```
**When to use:** Telecom networks; SS7/Diameter protocol scanning
**Warnings:** SCTP not widely deployed; requires root/admin

### Flag: -sZ (SCTP Cookie Echo Scan)
**Purpose:** More advanced SCTP scan using COOKIE-ECHO chunk
**Syntax:** `nmap -sZ <target>`
**Example:**
```bash
nmap -sZ 192.168.1.1
```
**When to use:** Evading certain firewalls that only check INIT chunks
**Warnings:** Very specialized use case; requires root/admin

## Common Mistakes

- **WRONG:** Using -sW expecting reliable results on all systems
- **CORRECT:** Window scan only works on specific OS implementations; use -sS for reliability

- **WRONG:** Using idle scan (-sI) with random IP ID hosts
- **CORRECT:** Verify zombie has incremental IP ID: `nmap -O -v zombie_ip`

- **WRONG:** Using NULL/FIN/Xmas scans against Windows
- **CORRECT:** These scans don't work against Windows; use SYN scan instead

- **WRONG:** Expecting -sA to show open ports
- **CORRECT:** ACK scan only shows filtered vs unfiltered; use -sS for open ports

- **WRONG:** Running UDP scans with default timing
- **CORRECT:** Optimize UDP scans: `nmap -sU -T4 --max-retries 1 --top-ports 100`

- **WRONG:** Using `--scanflags` without understanding TCP
- **CORRECT:** Study TCP flags before using custom configurations

## Practical Examples

### Comprehensive Internal Network Scan

```bash
# Full TCP with service detection
nmap -sS -sV -p- -T4 --open -oA full_tcp 192.168.1.0/24

# Top UDP ports
nmap -sU -sV --top-ports 50 -T4 -oA top_udp 192.168.1.0/24

# Combined scan of critical hosts
nmap -sS -sU -sV -p T:1-1000,U:53,67,68,69,123,161,162,500 -oA combined 192.168.1.1
```

### Firewall Rule Analysis

```bash
# Compare SYN scan vs ACK scan to find firewall behavior
nmap -sS -p 1-1000 -oA syn_scan 192.168.1.1
nmap -sA -p 1-1000 -oA ack_scan 192.168.1.1

# Analyze differences
diff syn_scan.nmap ack_scan.nmap
```

### Stealth Scanning Through Zombie

```bash
# Step 1: Find suitable zombie
nmap -O -v 192.168.1.0/24 | grep -B5 "Incremental"

# Step 2: Verify zombie is idle
nmap -sI zombie_ip -v --packet-trace -p 80 target_ip

# Step 3: Full scan through zombie
nmap -sI zombie_ip -p- target_ip
```

### Protocol Discovery

```bash
# Find all supported protocols
nmap -sO 192.168.1.1

# Scan for VPN/Tunnel protocols
nmap -sO -p 47,50,51 192.168.1.1  # GRE, ESP, AH

# Check SCTP support
nmap -sY 192.168.1.1
```

### Custom Scan for IDS Evasion

```bash
# Unusual flag combinations
nmap --scanflags SYNPSH -p 80,443 192.168.1.1

# Fragmented with custom flags
nmap --scanflags SYNFIN -f --mtu 16 -p 80 192.168.1.1

# With decoys
nmap --scanflags SYN -D RND:5 -p 80 192.168.1.1
```

### Fast Network Sweep

```bash
# Quick sweep of common ports
nmap -T4 --top-ports 20 192.168.0.0/16

# Critical services only
nmap -T4 -p 21,22,23,25,80,443,445,3389 192.168.0.0/16
```

## Advanced Combination Techniques

### Full Reconnaissance Workflow

```bash
#!/bin/bash
TARGET=$1

echo "[*] Phase 1: Quick discovery"
nmap -sn $TARGET -oG - | grep "Up" | cut -d" " -f2 > live.txt

echo "[*] Phase 2: Quick port scan"
nmap -sS -T4 --top-ports 100 -iL live.txt -oA quick_ports

echo "[*] Phase 3: Full TCP on live hosts"
nmap -sS -T4 -p- -iL live.txt -oA full_tcp

echo "[*] Phase 4: UDP scan"
nmap -sU --top-ports 50 -iL live.txt -oA udp_scan

echo "[*] Phase 5: Version detection on open ports"
# Parse open ports from quick scan
nmap -sV -sC -O -iL live.txt -oA detailed_scan

echo "[+] Complete"
```

### Firewall Evasion Progression

```bash
# Try increasingly stealthy methods
# Level 1: Standard SYN
nmap -sS 192.168.1.1

# Level 2: Fragmentation
nmap -sS -f 192.168.1.1

# Level 3: NULL/FIN/Xmas
nmap -sN 192.168.1.1
nmap -sF 192.168.1.1

# Level 4: Custom flags
nmap --scanflags PSH 192.168.1.1

# Level 5: Idle scan
nmap -sI zombie_ip 192.168.1.1
```
