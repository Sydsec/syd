# Practical Pentesting Scenarios

## Overview

This document covers real-world scanning scenarios that pentesters encounter during engagements. Each scenario includes the challenge, approach, and specific Nmap commands with explanations. These techniques should only be used with proper authorization.

## Scanning Behind Firewalls

### Challenge
Firewalls filter many ports, block ICMP, and may rate-limit connections. Standard scans return mostly "filtered" results.

### Firewall Detection

```bash
# Identify firewall presence
nmap -sA -p 80,443 192.168.1.1

# Compare SYN vs ACK responses
nmap -sS -p 1-1000 -oA syn_results 192.168.1.1
nmap -sA -p 1-1000 -oA ack_results 192.168.1.1
# Ports that differ between scans indicate stateful firewall
```

### Firewall Bypass Techniques

```bash
# Fragment packets to evade inspection
nmap -sS -f --mtu 16 192.168.1.1

# Use uncommon source port (DNS often allowed)
nmap -sS --source-port 53 192.168.1.1

# Try NULL/FIN/Xmas scans (may bypass stateless filters)
nmap -sN -p 1-1000 192.168.1.1
nmap -sF -p 1-1000 192.168.1.1

# Use decoys to confuse firewall logs
nmap -sS -D RND:10 192.168.1.1

# Skip host discovery (target blocks ping)
nmap -Pn -sS 192.168.1.1
```

### Behind NAT

```bash
# Scan for common forwarded ports
nmap -Pn -sS -p 21,22,25,80,443,3389,8080 external_ip

# Trace route to understand network path
nmap --traceroute external_ip

# Use version detection to identify services behind NAT
nmap -Pn -sV -p 80,443 external_ip
```

## Scanning Rate-Limited Targets

### Challenge
Target systems or network devices limit connection rates, causing scans to miss ports or get blocked.

### Identifying Rate Limiting

```bash
# Monitor dropped connections
nmap -sS -p 1-1000 --reason 192.168.1.1

# If seeing many "no-response" or timeouts, rate limiting is likely
```

### Rate-Controlled Scanning

```bash
# Hard limit on packets per second
nmap -sS --max-rate 10 192.168.1.1

# Minimum delay between probes
nmap -sS --scan-delay 500ms 192.168.1.1

# Combined approach for 100 requests/minute limit
# 100/60 = 1.67/sec, so use 1 packet/second
nmap -sS --max-rate 1 -T2 192.168.1.1

# For 10 requests/minute
nmap -sS --scan-delay 6s 192.168.1.1

# Very conservative scanning
nmap -sS -T1 --max-rate 0.5 --scan-delay 2s 192.168.1.1
```

### CRITICAL: Correct Flags for Rate Limiting

```bash
# CORRECT rate limiting flags:
nmap --max-rate 10 192.168.1.1      # Max 10 packets/second
nmap --scan-delay 1s 192.168.1.1    # Wait 1 second between probes
nmap -T2 192.168.1.1                 # Polite timing template

# WRONG (These are NOT for rate limiting):
# -iR       # SCANS RANDOM INTERNET HOSTS - NOT for delays!
# -rT       # DOES NOT EXIST
# -rP       # DOES NOT EXIST
# -rH       # DOES NOT EXIST

# For randomizing host order (different from rate limiting):
nmap --randomize-hosts 192.168.1.0/24
```

## Detecting Load Balancers

### Challenge
Load balancers distribute traffic across multiple backend servers, which can cause inconsistent scan results.

### Detection Techniques

```bash
# Multiple version scans may show different servers
for i in {1..5}; do
    echo "=== Scan $i ==="
    nmap -sV -p 80,443 --version-all target.example.com
    sleep 10
done

# Check for load balancer headers
nmap --script http-headers -p 80,443 target.example.com

# Look for inconsistent server versions
nmap -sV -p 80 --max-retries 10 target.example.com

# Compare TTL values (different backends may have different TTLs)
nmap --traceroute target.example.com
```

### Load Balancer Scripts

```bash
# HAProxy, F5, and other detection
nmap --script http-headers,http-server-header -p 80,443 target.example.com

# SSL certificate analysis (may differ per backend)
nmap --script ssl-cert -p 443 target.example.com
```

## Identifying WAFs (Web Application Firewalls)

### Challenge
WAFs block or modify malicious-looking requests, causing false negatives in vulnerability scans.

### WAF Detection

```bash
# Dedicated WAF detection scripts
nmap --script http-waf-detect -p 80,443 target.example.com

# WAF fingerprinting
nmap --script http-waf-fingerprint -p 80,443 target.example.com

# Both together
nmap --script http-waf-detect,http-waf-fingerprint -p 80,443 target.example.com
```

### WAF Evasion for Scanning

```bash
# Custom user agent
nmap --script http-enum --script-args http.useragent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)" -p 80 target.example.com

# Slow scanning to avoid rate limits
nmap --script http-enum --scan-delay 2s -p 80 target.example.com

# Fragment HTTP requests (limited effectiveness)
nmap -f --script http-headers -p 80 target.example.com
```

### Common WAF Indicators

```
Server: cloudflare
Server: Imperva
X-Sucuri-ID:
X-CDN:
X-Powered-By-Plesk:
Via: 1.1 akamai
```

## Cloud Environment Scanning

### AWS Considerations

```bash
# AWS security groups may block ICMP
nmap -Pn -sS 10.0.0.0/24

# Common AWS ports
nmap -Pn -sV -p 22,80,443,3306,5432,6379,11211,27017 10.0.0.0/24

# Metadata service (if inside AWS)
nmap -sV -p 80 169.254.169.254

# ELB detection
nmap --script http-headers -p 80,443 elb-dns-name.amazonaws.com
```

### Azure Considerations

```bash
# Azure NSGs similar to AWS security groups
nmap -Pn -sS 10.0.0.0/24

# Azure-specific services
nmap -Pn -sV -p 22,80,443,1433,3389,5432 10.0.0.0/24

# IMDS (if inside Azure)
nmap -sV -p 80 169.254.169.254
```

### GCP Considerations

```bash
# GCP firewall rules
nmap -Pn -sS 10.0.0.0/24

# Common GCP services
nmap -Pn -sV -p 22,80,443,3306,5432 10.0.0.0/24
```

### Cloud Scanning Best Practices

```bash
# Always skip host discovery in cloud (ping often blocked)
nmap -Pn <target>

# Use TCP ping for discovery instead
nmap -sn -PS22,80,443 10.0.0.0/24

# Rate limit to avoid triggering cloud security
nmap --max-rate 100 -T3 10.0.0.0/24

# Check for cloud metadata services (internal only)
nmap -sV -p 80 169.254.169.254
```

## IPv6 Scanning

### Challenge
IPv6 address space is enormous; cannot scan entire ranges like IPv4.

### IPv6 Discovery

```bash
# Scan known IPv6 address
nmap -6 2001:db8::1

# Local link multicast discovery
ping6 -c 1 ff02::1%eth0

# DNS-based discovery
nmap -6 -sL target.example.com

# IPv6 with service detection
nmap -6 -sV 2001:db8::1
```

### IPv6-Specific Techniques

```bash
# Full scan of single host
nmap -6 -sS -sV -p- 2001:db8::1

# Common ports on IPv6
nmap -6 -Pn -sS -p 22,80,443,445 2001:db8::1

# IPv6 host discovery methods
nmap -6 -sn -PE 2001:db8::/64  # May take very long!

# Use scripts for IPv6
nmap -6 --script ipv6-ra-flood 2001:db8::1
```

### Dual-Stack Testing

```bash
# Compare IPv4 and IPv6 services
nmap -sV -p 80,443 target.example.com
nmap -6 -sV -p 80,443 target.example.com

# Both in one command (if target has both)
nmap -sV -p 80,443 192.168.1.1
nmap -6 -sV -p 80,443 2001:db8::1
```

## VPN Scanning

### Challenge
VPNs may have different security postures than main network; internal services may be accessible.

### Scanning Through VPN

```bash
# After VPN connection, scan internal range
# Identify VPN-assigned network
ip addr show tun0  # Linux
ipconfig /all      # Windows

# Scan local network via VPN
nmap -sn 10.10.0.0/24

# Full internal scan
nmap -sS -sV -p- 10.10.0.0/24
```

### VPN Server Detection

```bash
# Common VPN ports
nmap -sU -sS -p T:443,1194,1723,500,4500,U:500,4500,1194 vpn.example.com

# IKE detection
nmap --script ike-version -sU -p 500 vpn.example.com

# OpenVPN detection
nmap -sU -p 1194 vpn.example.com

# SSL VPN
nmap -sV -p 443 --script ssl-cert vpn.example.com
```

### Split Tunnel Testing

```bash
# Compare routing
ip route  # Check which networks go through VPN

# Test internal vs external access
nmap -sS 10.10.0.1      # Internal
nmap -sS 8.8.8.8         # External (should this be tunneled?)
```

## Authenticated Scanning

### Challenge
Some services require authentication to properly enumerate; default scans miss authenticated-only content.

### Authenticated SMB Scanning

```bash
# SMB with credentials
nmap --script smb-enum-shares,smb-enum-users \
     --script-args smbuser=admin,smbpass=password,smbdomain=CORP \
     -p 445 192.168.1.1

# SMB with NTLM hash
nmap --script smb-enum-shares \
     --script-args smbuser=admin,smbhash=aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c \
     -p 445 192.168.1.1
```

### Authenticated HTTP Scanning

```bash
# Basic auth
nmap --script http-enum,http-methods \
     --script-args http.username=admin,http.password=password \
     -p 80 192.168.1.1

# Cookie-based auth
nmap --script http-enum \
     --script-args 'http.cookie="SESSIONID=abc123"' \
     -p 80 192.168.1.1
```

### Authenticated Database Scanning

```bash
# MySQL with credentials
nmap --script mysql-databases,mysql-users \
     --script-args mysqluser=admin,mysqlpass=password \
     -p 3306 192.168.1.1

# PostgreSQL
nmap --script pgsql-brute \
     --script-args userdb=users.txt,passdb=pass.txt \
     -p 5432 192.168.1.1
```

### SSH Key-Based Access

```bash
# Cannot directly use SSH keys in Nmap
# But can use SSH tunneling then scan localhost

# Step 1: Create SSH tunnel
ssh -L 3306:localhost:3306 user@target

# Step 2: Scan through tunnel
nmap -sV -p 3306 localhost
```

## Active Directory Reconnaissance

### Domain Controller Discovery

```bash
# Find domain controllers
nmap -sV -p 53,88,135,389,445,464,636,3268,3269 192.168.1.0/24

# LDAP enumeration
nmap --script ldap-rootdse -p 389 192.168.1.1

# Kerberos enumeration
nmap --script krb5-enum-users --script-args krb5-enum-users.realm=CONTOSO.LOCAL \
     -p 88 192.168.1.1
```

### AD-Specific Scripts

```bash
# Full AD enumeration
nmap --script smb-os-discovery,smb-enum-domains,smb-enum-users,smb-enum-shares \
     -p 445 192.168.1.1

# MSRPC enumeration
nmap --script msrpc-enum -p 135 192.168.1.1

# DNS zone transfer attempt
nmap --script dns-zone-transfer \
     --script-args dns-zone-transfer.domain=contoso.local \
     -p 53 192.168.1.1
```

## Industrial Control Systems (ICS/SCADA)

### CRITICAL WARNING

Scanning ICS/SCADA systems can cause operational disruptions. Always:
1. Get explicit written authorization
2. Coordinate with system operators
3. Scan during maintenance windows
4. Have rollback procedures ready

### ICS Protocol Detection

```bash
# Common ICS ports (scan with extreme care)
nmap -sV -p 102,502,20000,44818,47808 192.168.1.1

# Modbus detection
nmap --script modbus-discover -p 502 192.168.1.1

# S7 (Siemens) detection
nmap --script s7-info -p 102 192.168.1.1

# BACnet detection
nmap --script bacnet-info -sU -p 47808 192.168.1.1

# DNP3 detection
nmap -sV -p 20000 192.168.1.1
```

### ICS Scanning Best Practices

```bash
# VERY slow scanning to avoid disruption
nmap -T1 --scan-delay 5s --max-retries 1 -p 502 192.168.1.1

# Version detection with minimal probing
nmap -sV --version-light -p 102,502 192.168.1.1

# Passive identification preferred
# Use -sV with low intensity only
```

## Segmented Network Testing

### Identifying Network Segments

```bash
# Traceroute to understand network topology
nmap --traceroute 192.168.1.1 10.0.0.1 172.16.0.1

# Scan for common segment sizes
nmap -sn 192.168.0.0/16 10.0.0.0/8 172.16.0.0/12
```

### Pivot Point Scanning

```bash
# After compromising internal host, scan from there
# Using proxychains or similar

# From compromised Linux host
nmap -sS 10.10.0.0/24

# Through SOCKS proxy
proxychains nmap -sT -Pn 10.10.0.0/24
```

### VLAN Hopping Detection

```bash
# Look for trunk ports / VLAN tags
nmap --script broadcast-listener -e eth0

# Check for CDP/LLDP
nmap --script cdp -sU -p 67 192.168.1.1
```

## Comprehensive Engagement Workflow

### Phase 1: External Reconnaissance

```bash
#!/bin/bash
TARGET="target.example.com"
OUTDIR="external_$(date +%Y%m%d)"
mkdir -p $OUTDIR

# DNS enumeration
nmap -sL $TARGET > $OUTDIR/dns_lookup.txt

# Top ports, version detection
nmap -Pn -sS -sV --top-ports 1000 -T4 \
     -oA $OUTDIR/external_ports $TARGET

# SSL/TLS analysis
nmap --script ssl-cert,ssl-enum-ciphers \
     -p 443 -oA $OUTDIR/ssl_analysis $TARGET

# WAF detection
nmap --script http-waf-detect,http-waf-fingerprint \
     -p 80,443 -oA $OUTDIR/waf_detect $TARGET
```

### Phase 2: Internal Network Discovery

```bash
#!/bin/bash
RANGE="192.168.0.0/16"
OUTDIR="internal_$(date +%Y%m%d)"
mkdir -p $OUTDIR

# Host discovery
nmap -sn -PE -PS22,80,443 $RANGE -oA $OUTDIR/discovery

# Extract live hosts
grep "Up" $OUTDIR/discovery.gnmap | cut -d" " -f2 > $OUTDIR/live.txt

# Port scanning
nmap -sS -T4 --top-ports 1000 \
     -iL $OUTDIR/live.txt \
     -oA $OUTDIR/ports
```

### Phase 3: Service Enumeration

```bash
#!/bin/bash
OUTDIR="internal_$(date +%Y%m%d)"

# Version detection on open ports
nmap -sV -sC -O \
     -iL $OUTDIR/live.txt \
     -oA $OUTDIR/services

# Vulnerability scanning
nmap --script vuln \
     -iL $OUTDIR/live.txt \
     -oA $OUTDIR/vulns
```

## Common Mistakes in Pentesting Scenarios

- **WRONG:** Using -iR when you mean to add delays
- **CORRECT:** -iR scans RANDOM INTERNET HOSTS; use --scan-delay or --max-rate

- **WRONG:** Scanning ICS without coordination
- **CORRECT:** Always coordinate with operators; use T1 timing; test during maintenance

- **WRONG:** Using -T5 on sensitive networks
- **CORRECT:** Use T3 or T2 for most engagements; T4 only on fast internal networks

- **WRONG:** Ignoring cloud security rate limits
- **CORRECT:** Use --max-rate to avoid triggering automated blocks

- **WRONG:** Scanning IPv6 subnets like IPv4
- **CORRECT:** IPv6 space is too large; use targeted discovery methods

- **WRONG:** Authenticated scanning with credentials in command line
- **CORRECT:** Use --script-args-file to avoid history logging

## Quick Reference: Scenario Cheat Sheet

| Scenario | Key Flags |
|----------|-----------|
| Firewall bypass | `-f`, `-D RND:10`, `--source-port 53`, `-Pn` |
| Rate limiting | `--max-rate`, `--scan-delay`, `-T2` |
| Cloud scanning | `-Pn`, `-PS22,80,443`, `--max-rate 100` |
| WAF detection | `--script http-waf-detect,http-waf-fingerprint` |
| Load balancer | Multiple `-sV` runs, `--script http-headers` |
| IPv6 | `-6`, `-PE` for ICMPv6 |
| VPN | `-sU -p 500,4500,1194`, `--script ike-version` |
| Authenticated | `--script-args user=,pass=` |
| ICS/SCADA | `-T1`, `--scan-delay 5s`, `--max-retries 1` |
