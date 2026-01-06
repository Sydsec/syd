# Nmap Basics

## What is Nmap?

Nmap (Network Mapper) is a free and open-source network discovery and security auditing tool. It uses raw IP packets to determine:
- What hosts are available on the network
- What services (application name and version) those hosts are offering
- What operating systems they are running
- What type of packet filters/firewalls are in use

## Basic Syntax

```bash
nmap [Scan Type] [Options] {target specification}
```

## Common Scan Types

### TCP SYN Scan (-sS)
- Default scan type (requires root/admin)
- Sends SYN packet, waits for SYN-ACK
- Never completes TCP handshake (stealth)
- Fast and unobtrusive

```bash
nmap -sS 192.168.1.1
```

### TCP Connect Scan (-sT)
- Completes full TCP handshake
- Used when SYN scan not available
- More easily detected

```bash
nmap -sT 192.168.1.1
```

### UDP Scan (-sU)
- Scans UDP ports
- Slower than TCP scans
- Important for DNS, SNMP, DHCP

```bash
nmap -sU 192.168.1.1
```

### Version Detection (-sV)
- Probes open ports to determine service/version
- Essential for vulnerability assessment

```bash
nmap -sV 192.168.1.1
```

### OS Detection (-O)
- Attempts to identify target OS
- Requires root/admin privileges

```bash
nmap -O 192.168.1.1
```

### Aggressive Scan (-A)
- Enables OS detection, version detection, script scanning, traceroute
- Combines -O -sV -sC --traceroute

```bash
nmap -A 192.168.1.1
```

## Target Specification

### Single IP
```bash
nmap 192.168.1.1
```

### IP Range
```bash
nmap 192.168.1.1-254
```

### CIDR Notation
```bash
nmap 192.168.1.0/24
```

### Hostname
```bash
nmap scanme.nmap.org
```

### Multiple Targets
```bash
nmap 192.168.1.1 192.168.1.5 192.168.1.10
```

### Input from File
```bash
nmap -iL targets.txt
```

## Port Specification

### Single Port
```bash
nmap -p 80 192.168.1.1
```

### Multiple Ports
```bash
nmap -p 22,80,443 192.168.1.1
```

### Port Range
```bash
nmap -p 1-1000 192.168.1.1
```

### All Ports
```bash
nmap -p- 192.168.1.1
```

### Top Ports
```bash
nmap --top-ports 100 192.168.1.1
```

## Timing Templates

Nmap offers timing templates (-T0 through -T5) to control scan speed:

- **T0 (Paranoid)**: Extremely slow, IDS evasion
- **T1 (Sneaky)**: Slow, IDS evasion
- **T2 (Polite)**: Slows down to use less bandwidth
- **T3 (Normal)**: Default speed
- **T4 (Aggressive)**: Fast scan, assumes fast network
- **T5 (Insane)**: Very fast, may sacrifice accuracy

```bash
nmap -T4 192.168.1.1
```

## Output Formats

### Normal Output (-oN)
```bash
nmap -oN scan.txt 192.168.1.1
```

### XML Output (-oX)
```bash
nmap -oX scan.xml 192.168.1.1
```

### Grepable Output (-oG)
```bash
nmap -oG scan.gnmap 192.168.1.1
```

### All Formats (-oA)
```bash
nmap -oA scan 192.168.1.1
```

## Common Use Cases

### Quick Scan
Fast scan of most common ports:
```bash
nmap -T4 -F 192.168.1.1
```

### Comprehensive Scan
Detailed scan with service detection:
```bash
nmap -T4 -A -v 192.168.1.1
```

### Stealth Scan
Slow, stealthy scan to avoid detection:
```bash
nmap -sS -T2 -f 192.168.1.1
```

### Network Discovery
Find live hosts without port scanning:
```bash
nmap -sn 192.168.1.0/24
```

### Vulnerability Scanning
Scan for known vulnerabilities using NSE scripts:
```bash
nmap --script vuln 192.168.1.1
```

## Common Options

- `-v`: Verbose output
- `-vv`: Very verbose output
- `-Pn`: Skip host discovery, assume host is up
- `-n`: No DNS resolution
- `-R`: Always resolve DNS
- `--reason`: Show reason for port state
- `--open`: Only show open ports
- `--packet-trace`: Show all packets sent/received

## Example Pentesting Workflow

1. **Discovery**: Find live hosts
   ```bash
   nmap -sn 192.168.1.0/24
   ```

2. **Port Scan**: Identify open ports
   ```bash
   nmap -sV -p- 192.168.1.5
   ```

3. **Service Enumeration**: Detailed service info
   ```bash
   nmap -sV -sC -A 192.168.1.5
   ```

4. **Vulnerability Scanning**: Check for vulns
   ```bash
   nmap --script vuln 192.168.1.5
   ```

5. **Exploitation**: Use findings to exploit

## Tips

- Always get authorization before scanning
- Use `-v` to see progress during long scans
- Combine options: `nmap -sV -sC -O -T4 -p- target`
- Save output with `-oA` for later analysis
- Use `--reason` to understand why ports are open/closed
