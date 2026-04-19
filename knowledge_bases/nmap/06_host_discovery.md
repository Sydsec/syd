# Host Discovery and Ping Scanning

## Overview

Host discovery is the first step in any network scan, determining which IP addresses are active before detailed port scanning. Nmap uses multiple techniques to detect live hosts, each with different characteristics for stealth, speed, and reliability across various network environments.

Understanding host discovery is critical because:
- Skipping dead hosts dramatically reduces scan time
- Different networks require different discovery techniques
- Firewalls may block certain discovery methods
- Some methods work only with root/admin privileges

## Host Discovery Methods

### Flag: -sn (Ping Scan / No Port Scan)
**Purpose:** Discover live hosts without port scanning
**Syntax:** `nmap -sn <target>`
**Example:**
```bash
# Basic host discovery
nmap -sn 192.168.1.0/24

# Discover hosts in multiple ranges
nmap -sn 192.168.1.0/24 10.0.0.0/24
```
**When to use:** Initial reconnaissance, network mapping, quick inventory
**Warnings:** Some hosts may not respond to ping; use -Pn to scan regardless

**Default behavior:**
- With root/admin: ICMP echo + TCP SYN to 443 + TCP ACK to 80 + ICMP timestamp
- Without root: TCP connect to ports 80 and 443

### Flag: -Pn (No Ping / Skip Host Discovery)
**Purpose:** Skip host discovery, assume all hosts are up
**Syntax:** `nmap -Pn <target>`
**Example:**
```bash
# Scan host that blocks ping
nmap -Pn 192.168.1.1

# Full port scan without ping
nmap -Pn -p- 192.168.1.1
```
**When to use:**
- When hosts block ICMP/ping
- When scanning through firewalls
- When you know the host is up
**Warnings:** Significantly slower for large ranges (scans every IP); wastes time on dead hosts

### Flag: -sL (List Scan)
**Purpose:** List targets without sending any packets
**Syntax:** `nmap -sL <target>`
**Example:**
```bash
# List all IPs in range
nmap -sL 192.168.1.0/24

# List with reverse DNS
nmap -sL 10.0.0.0/8 | grep "example.com"
```
**When to use:** Verifying target ranges, DNS reconnaissance, passive enumeration
**Warnings:** Does not discover hosts; only lists potential targets

### Flag: -sP (Legacy Ping Scan)
**Purpose:** Old alias for -sn (deprecated)
**Syntax:** `nmap -sP <target>`
**Example:**
```bash
# Deprecated - use -sn instead
nmap -sP 192.168.1.0/24
```
**When to use:** Avoid using; use -sn instead
**Warnings:** Deprecated in modern Nmap versions

## ICMP Discovery Methods

### Flag: -PE (ICMP Echo Request)
**Purpose:** Send ICMP type 8 (echo request) packets
**Syntax:** `nmap -PE <target>`
**Example:**
```bash
nmap -sn -PE 192.168.1.0/24
```
**When to use:** Standard ping discovery
**Warnings:** Often blocked by firewalls; requires root/admin

### Flag: -PP (ICMP Timestamp Request)
**Purpose:** Send ICMP type 13 (timestamp request) packets
**Syntax:** `nmap -PP <target>`
**Example:**
```bash
nmap -sn -PP 192.168.1.0/24
```
**When to use:** Alternative when echo is blocked; may bypass some firewalls
**Warnings:** Less commonly supported; requires root/admin

### Flag: -PM (ICMP Address Mask Request)
**Purpose:** Send ICMP type 17 (address mask request) packets
**Syntax:** `nmap -PM <target>`
**Example:**
```bash
nmap -sn -PM 192.168.1.0/24
```
**When to use:** Rarely used; most systems don't respond
**Warnings:** Low success rate; requires root/admin

## TCP Discovery Methods

### Flag: -PS (TCP SYN Ping)
**Purpose:** Send TCP SYN to specified ports for discovery
**Syntax:** `nmap -PS<port-list> <target>`
**Example:**
```bash
# Default: SYN to port 80
nmap -sn -PS 192.168.1.0/24

# SYN to port 22
nmap -sn -PS22 192.168.1.0/24

# SYN to multiple ports
nmap -sn -PS22,80,443,8080 192.168.1.0/24
```
**When to use:** Discovering hosts with open services; bypassing ICMP blocks
**Warnings:** May be logged by IDS; requires root/admin for raw packets

### Flag: -PA (TCP ACK Ping)
**Purpose:** Send TCP ACK to specified ports for discovery
**Syntax:** `nmap -PA<port-list> <target>`
**Example:**
```bash
# Default: ACK to port 80
nmap -sn -PA 192.168.1.0/24

# ACK to multiple ports
nmap -sn -PA22,80,443 192.168.1.0/24
```
**When to use:** Discovering hosts behind stateless firewalls; RST response indicates host is up
**Warnings:** Stateful firewalls will block; requires root/admin

### Flag: -PY (SCTP INIT Ping)
**Purpose:** Send SCTP INIT chunk for discovery
**Syntax:** `nmap -PY<port-list> <target>`
**Example:**
```bash
nmap -sn -PY 192.168.1.0/24
nmap -sn -PY2905,5060 192.168.1.0/24
```
**When to use:** Discovering SCTP-enabled hosts (telecom, SS7)
**Warnings:** SCTP not common; requires root/admin

## UDP Discovery Methods

### Flag: -PU (UDP Ping)
**Purpose:** Send UDP packets to specified ports for discovery
**Syntax:** `nmap -PU<port-list> <target>`
**Example:**
```bash
# Default: UDP to port 40125
nmap -sn -PU 192.168.1.0/24

# UDP to common ports
nmap -sn -PU53,161,500 192.168.1.0/24
```
**When to use:** Discovering hosts with open UDP services
**Warnings:** Slower than TCP; may not receive response; requires root/admin

## ARP Discovery

### Flag: -PR (ARP Ping)
**Purpose:** Use ARP requests for local network discovery
**Syntax:** `nmap -PR <target>`
**Example:**
```bash
nmap -sn -PR 192.168.1.0/24
```
**When to use:** Local network scanning; most reliable for LAN
**Warnings:** Only works on local subnet; cannot cross routers

**Note:** ARP discovery is automatic on local networks when running as root/admin. It's more reliable than ICMP because hosts must respond to ARP to participate in the network.

### ARP-Only Scan

```bash
# Force ARP-only discovery (local network)
nmap -sn -PR --send-eth 192.168.1.0/24
```

## Advanced Discovery Options

### Flag: --disable-arp-ping
**Purpose:** Disable ARP discovery even on local network
**Syntax:** `nmap --disable-arp-ping <target>`
**Example:**
```bash
nmap -sn --disable-arp-ping 192.168.1.0/24
```
**When to use:** Testing ICMP/TCP discovery on local network; consistency across networks
**Warnings:** May miss hosts that only respond to ARP

### Flag: --discovery-ignore-rst
**Purpose:** Ignore RST packets during host discovery
**Syntax:** `nmap --discovery-ignore-rst <target>`
**Example:**
```bash
nmap -sn --discovery-ignore-rst 192.168.1.0/24
```
**When to use:** Networks with devices that send RST for all probes
**Warnings:** May increase false negatives

### Flag: --traceroute
**Purpose:** Trace hop path to each host
**Syntax:** `nmap --traceroute <target>`
**Example:**
```bash
nmap -sn --traceroute 192.168.1.1
```
**When to use:** Network mapping, identifying routing paths
**Warnings:** Increases scan time; requires root/admin

### Flag: -n (No DNS Resolution)
**Purpose:** Never do reverse DNS resolution
**Syntax:** `nmap -n <target>`
**Example:**
```bash
nmap -sn -n 192.168.1.0/24
```
**When to use:** Speed improvement; avoiding DNS traffic; stealth
**Warnings:** Lose hostname information

### Flag: -R (Always Resolve DNS)
**Purpose:** Always do reverse DNS resolution
**Syntax:** `nmap -R <target>`
**Example:**
```bash
nmap -sn -R 192.168.1.0/24
```
**When to use:** Maximum host information; PTR record enumeration
**Warnings:** Slower; generates DNS traffic

### Flag: --dns-servers <servers>
**Purpose:** Specify custom DNS servers
**Syntax:** `nmap --dns-servers <server1,server2> <target>`
**Example:**
```bash
nmap -sn --dns-servers 8.8.8.8,8.8.4.4 192.168.1.0/24
```
**When to use:** Using target's internal DNS; avoiding local DNS
**Warnings:** May reveal scanning activity to specified DNS servers

### Flag: --system-dns
**Purpose:** Use OS DNS resolver
**Syntax:** `nmap --system-dns <target>`
**Example:**
```bash
nmap -sn --system-dns 192.168.1.0/24
```
**When to use:** When Nmap's resolver fails; using system DNS cache
**Warnings:** Slower; limited parallelism

## Combining Discovery Methods

### Multiple Discovery Probes

```bash
# Combine ICMP, TCP, and UDP for thorough discovery
nmap -sn -PE -PS22,80,443 -PA80,443 -PU53,161 192.168.1.0/24
```

### Bypass Firewall Discovery

```bash
# Try multiple methods when hosts filter packets
nmap -sn -PE -PP -PM -PS21,22,23,25,80,443,3389 192.168.1.0/24
```

### Local Network Comprehensive Discovery

```bash
# ARP (most reliable) + TCP + ICMP
nmap -sn -PR -PE -PS22,80,443 192.168.1.0/24
```

## Discovery Performance Tuning

### Flag: --min-hostgroup, --max-hostgroup
**Purpose:** Control parallel host scanning
**Syntax:** `nmap --min-hostgroup <size> <target>`
**Example:**
```bash
# Scan at least 64 hosts in parallel
nmap -sn --min-hostgroup 64 192.168.0.0/16
```
**When to use:** Large network discovery; speeding up scans
**Warnings:** High parallelism may trigger IDS

### Flag: --min-rate, --max-rate
**Purpose:** Control packet rate during discovery
**Syntax:** `nmap --min-rate <rate> <target>`
**Example:**
```bash
# Fast discovery
nmap -sn --min-rate 1000 192.168.0.0/16

# Slow, stealthy discovery
nmap -sn --max-rate 10 192.168.1.0/24
```
**When to use:** Balancing speed vs. stealth
**Warnings:** Too fast may drop packets; too slow takes forever

## Discovery in Different Environments

### Corporate Networks

```bash
# Multiple protocols for best coverage
nmap -sn -PE -PP -PS21,22,23,25,80,110,139,443,445,3389 \
     -PA80,443 -PU53,67,161 192.168.0.0/16
```

### Cloud Environments

```bash
# Skip ICMP (often blocked), use TCP on common cloud ports
nmap -sn -PS22,80,443,8080,8443 10.0.0.0/8
```

### Industrial/SCADA Networks

```bash
# Include OT-specific ports
nmap -sn -PS102,502,1089-1091,4000,20000 \
     -PU47808,34962-34964 192.168.1.0/24
```

### IoT Networks

```bash
# IoT-specific ports
nmap -sn -PS80,443,8080,8443,1883,8883,5683 \
     -PU5353,1900,5683 192.168.1.0/24
```

## Common Mistakes

- **WRONG:** Using -Pn for large network ranges
- **CORRECT:** Use proper discovery first, then -Pn only for known live hosts that block ping

- **WRONG:** Assuming -sn sends only ICMP
- **CORRECT:** -sn uses multiple probes (ICMP + TCP) when run as root

- **WRONG:** Using `-iR` thinking it adds delays to ping scan
- **CORRECT:** `-iR` scans RANDOM INTERNET HOSTS - use `--scan-delay` for timing

- **WRONG:** Running discovery without root and expecting ICMP to work
- **CORRECT:** Run as root for full ICMP functionality, or use TCP-only probes

- **WRONG:** Relying only on ICMP ping for discovery
- **CORRECT:** Combine multiple methods: `-PE -PS22,80,443 -PA80`

- **WRONG:** Using -sL to discover hosts
- **CORRECT:** -sL only lists targets; use -sn for actual discovery

## Practical Examples

### Quick Network Inventory

```bash
# Fast discovery of /24 network
nmap -sn -T4 192.168.1.0/24

# Output with hostnames
nmap -sn -R 192.168.1.0/24

# Save to file
nmap -sn 192.168.1.0/24 -oG - | grep "Up" | cut -d" " -f2 > live_hosts.txt
```

### Stealthy Discovery

```bash
# Slow, randomized discovery
nmap -sn -T2 --randomize-hosts --scan-delay 500ms 192.168.1.0/24

# TCP-only to avoid ICMP logging
nmap -sn -PS80,443 --scan-delay 1s 192.168.1.0/24
```

### Firewall Bypass Discovery

```bash
# Try all methods to find responsive hosts
nmap -sn -Pn -PE -PP -PM -PS1-1000 -PA1-1000 192.168.1.1

# Use non-standard ports
nmap -sn -PS21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,1521,3306,3389,5432,5900,8080,8443 192.168.1.0/24
```

### Scripted Network Mapping

```bash
#!/bin/bash
# Comprehensive network discovery script

NETWORK="192.168.1.0/24"
OUTDIR="discovery_$(date +%Y%m%d)"
mkdir -p $OUTDIR

# Phase 1: ARP discovery (local only)
echo "[*] ARP Discovery"
nmap -sn -PR --send-eth $NETWORK -oA $OUTDIR/arp_discovery 2>/dev/null

# Phase 2: ICMP discovery
echo "[*] ICMP Discovery"
nmap -sn -PE -PP $NETWORK -oA $OUTDIR/icmp_discovery

# Phase 3: TCP discovery
echo "[*] TCP Discovery"
nmap -sn -PS22,80,443,445,3389 -PA80,443 $NETWORK -oA $OUTDIR/tcp_discovery

# Combine results
echo "[*] Combining results"
cat $OUTDIR/*.gnmap | grep "Up" | cut -d" " -f2 | sort -u > $OUTDIR/all_live_hosts.txt

echo "[+] Found $(wc -l < $OUTDIR/all_live_hosts.txt) live hosts"
```

### Large Network Discovery

```bash
# Scan Class B network efficiently
nmap -sn -T4 --min-hostgroup 256 --min-rate 1000 \
     -PS22,80,443 -n 172.16.0.0/16 \
     -oA large_network_discovery
```

### Discovery with Service Identification

```bash
# Discover and identify common services in one pass
nmap -sn -sV --version-light -PS22,80,443 192.168.1.0/24
```

## Discovery Behind NAT/Load Balancers

### Detecting Load Balancers

```bash
# Multiple scans may reveal different backend servers
for i in {1..5}; do
    nmap -sn -PS80 target.example.com
    sleep 5
done
```

### NAT Traversal

```bash
# May need to target specific ports that are forwarded
nmap -sn -PS80,443,8080,8443 external_ip

# Use traceroute to understand network path
nmap -sn --traceroute external_ip
```

## IPv6 Host Discovery

### Flag: -6 (IPv6 Scanning)
**Purpose:** Enable IPv6 scanning
**Syntax:** `nmap -6 <target>`
**Example:**
```bash
# Discover IPv6 hosts
nmap -6 -sn fe80::1/64

# Discover using ICMPv6
nmap -6 -sn -PE 2001:db8::/64
```
**When to use:** IPv6 networks; dual-stack environments
**Warnings:** IPv6 address space is enormous; enumerate carefully

### IPv6-Specific Discovery

```bash
# ICMPv6 echo request
nmap -6 -sn -PE 2001:db8::1

# Multicast ping for local link discovery
ping6 -c 1 ff02::1%eth0
```
