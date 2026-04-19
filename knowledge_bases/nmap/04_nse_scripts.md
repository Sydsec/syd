# Nmap Scripting Engine (NSE)

## Overview

The Nmap Scripting Engine (NSE) is one of Nmap's most powerful and flexible features. It allows users to write and share scripts that automate a wide variety of networking tasks, from advanced network discovery to vulnerability detection, backdoor detection, and even exploitation.

NSE scripts are written in Lua programming language and have access to Nmap's networking APIs to perform various operations.

## How NSE Works

NSE scripts execute in the following phases:
1. **Prerule scripts** - Run before any scanning occurs
2. **Host scripts** - Run after host discovery
3. **Service scripts** - Run after service/version detection
4. **Postrule scripts** - Run after all hosts have been scanned

Scripts receive information about discovered hosts, ports, and services, and can probe targets for additional information.

## Script Categories

NSE organizes scripts into categories for easier selection:

| Category | Description |
|----------|-------------|
| `auth` | Authentication and credential handling |
| `broadcast` | Discovery via broadcast messages |
| `brute` | Brute force password attacks |
| `default` | Safe scripts run with -sC |
| `discovery` | Active discovery of network services |
| `dos` | Denial of Service testing (dangerous!) |
| `exploit` | Active exploitation (dangerous!) |
| `external` | Scripts using external resources |
| `fuzzer` | Fuzz testing |
| `intrusive` | May crash targets or be logged |
| `malware` | Malware/backdoor detection |
| `safe` | Won't crash services or abuse bandwidth |
| `version` | Service version detection |
| `vuln` | Vulnerability checking |

## Basic NSE Usage

### Flag: -sC (Default Scripts)
**Purpose:** Run default NSE scripts (equivalent to --script=default)
**Syntax:** `nmap -sC <target>`
**Example:**
```bash
nmap -sC 192.168.1.1
```
**When to use:** Initial reconnaissance when you want basic enumeration without aggressive testing
**Warnings:** Default scripts are considered safe but will still generate network traffic and may be logged

### Flag: --script <script-name>
**Purpose:** Run specific script(s)
**Syntax:** `nmap --script <script-name|category|expression> <target>`
**Example:**
```bash
# Single script
nmap --script http-title 192.168.1.1

# Multiple scripts
nmap --script http-title,http-headers 192.168.1.1

# All scripts in a category
nmap --script vuln 192.168.1.1

# Wildcard matching
nmap --script "http-*" 192.168.1.1

# Boolean expressions
nmap --script "default and safe" 192.168.1.1
nmap --script "vuln and not intrusive" 192.168.1.1
```
**When to use:** When you need specific functionality or targeted testing
**Warnings:** Some scripts are intrusive or can cause denial of service

### Flag: --script-args <args>
**Purpose:** Provide arguments to scripts
**Syntax:** `nmap --script <script> --script-args <n1>=<v1>,<n2>=<v2> <target>`
**Example:**
```bash
# HTTP basic auth
nmap --script http-brute --script-args http-brute.path=/admin 192.168.1.1

# Custom user agent
nmap --script http-enum --script-args http.useragent="Mozilla/5.0" 192.168.1.1

# Credentials for authenticated scanning
nmap --script smb-enum-shares --script-args smbuser=admin,smbpass=password 192.168.1.1
```
**When to use:** Customizing script behavior
**Warnings:** Passing credentials via command line may be logged in shell history

### Flag: --script-args-file <filename>
**Purpose:** Load script arguments from file
**Syntax:** `nmap --script <script> --script-args-file args.txt <target>`
**Example:**
```bash
nmap --script http-brute --script-args-file http-creds.txt 192.168.1.1
```
**When to use:** When passing sensitive arguments or complex configurations
**Warnings:** Ensure file permissions are restrictive

### Flag: --script-trace
**Purpose:** Show all data sent and received by scripts
**Syntax:** `nmap --script <script> --script-trace <target>`
**Example:**
```bash
nmap --script http-title --script-trace 192.168.1.1
```
**When to use:** Debugging script behavior or analyzing protocols
**Warnings:** Produces very verbose output

### Flag: --script-updatedb
**Purpose:** Update the script database
**Syntax:** `nmap --script-updatedb`
**Example:**
```bash
nmap --script-updatedb
```
**When to use:** After adding new scripts to the scripts directory
**Warnings:** Requires write access to Nmap installation directory

### Flag: --script-help <script-name>
**Purpose:** Show help for specific script(s)
**Syntax:** `nmap --script-help <script-name>`
**Example:**
```bash
nmap --script-help http-vuln-cve2017-5638
nmap --script-help "smb-*"
```
**When to use:** Learning about script capabilities before using them
**Warnings:** None

## Vulnerability Scanning Scripts

### SMB Vulnerability Scripts

```bash
# Check for MS17-010 (EternalBlue)
nmap --script smb-vuln-ms17-010 -p 445 192.168.1.1

# Check for MS08-067 (Conficker)
nmap --script smb-vuln-ms08-067 -p 445 192.168.1.1

# Run all SMB vulnerability scripts
nmap --script "smb-vuln-*" -p 445 192.168.1.1

# SMB security mode analysis
nmap --script smb-security-mode -p 445 192.168.1.1

# Full SMB enumeration
nmap --script smb-enum-shares,smb-enum-users,smb-enum-domains -p 445 192.168.1.1
```

### HTTP Vulnerability Scripts

```bash
# Shellshock detection
nmap --script http-shellshock --script-args uri=/cgi-bin/test.cgi -p 80 192.168.1.1

# Apache Struts RCE (CVE-2017-5638)
nmap --script http-vuln-cve2017-5638 -p 80 192.168.1.1

# WordPress vulnerabilities
nmap --script http-wordpress-enum -p 80 192.168.1.1

# SQL Injection testing
nmap --script http-sql-injection -p 80 192.168.1.1

# Cross-site scripting detection
nmap --script http-stored-xss,http-dombased-xss -p 80 192.168.1.1

# Directory enumeration
nmap --script http-enum -p 80 192.168.1.1
```

### SSL/TLS Vulnerability Scripts

```bash
# Heartbleed (CVE-2014-0160)
nmap --script ssl-heartbleed -p 443 192.168.1.1

# POODLE (CVE-2014-3566)
nmap --script ssl-poodle -p 443 192.168.1.1

# SSL certificate information
nmap --script ssl-cert -p 443 192.168.1.1

# Supported SSL/TLS ciphers
nmap --script ssl-enum-ciphers -p 443 192.168.1.1

# Comprehensive SSL check
nmap --script "ssl-*" -p 443 192.168.1.1
```

### Other Service Vulnerabilities

```bash
# FTP anonymous access
nmap --script ftp-anon -p 21 192.168.1.1

# SSH algorithms
nmap --script ssh2-enum-algos -p 22 192.168.1.1

# DNS zone transfer
nmap --script dns-zone-transfer -p 53 --script-args dns-zone-transfer.domain=example.com 192.168.1.1

# MySQL empty password
nmap --script mysql-empty-password -p 3306 192.168.1.1

# Redis unauthorized access
nmap --script redis-info -p 6379 192.168.1.1

# MongoDB info
nmap --script mongodb-info -p 27017 192.168.1.1
```

## Authentication and Brute Force Scripts

### Brute Force Examples

```bash
# SSH brute force
nmap --script ssh-brute -p 22 192.168.1.1

# FTP brute force
nmap --script ftp-brute -p 21 192.168.1.1

# HTTP form brute force
nmap --script http-form-brute --script-args http-form-brute.path=/login,http-form-brute.uservar=username,http-form-brute.passvar=password -p 80 192.168.1.1

# SMB brute force
nmap --script smb-brute -p 445 192.168.1.1

# MySQL brute force
nmap --script mysql-brute -p 3306 192.168.1.1
```

### Custom Wordlists

```bash
# Using custom username/password lists
nmap --script ssh-brute --script-args userdb=users.txt,passdb=passwords.txt -p 22 192.168.1.1

# Limiting brute force attempts
nmap --script ssh-brute --script-args brute.threads=5,brute.delay=1s -p 22 192.168.1.1
```

## Information Gathering Scripts

### Network Discovery

```bash
# Banner grabbing
nmap --script banner -p 1-1000 192.168.1.1

# WHOIS lookup
nmap --script whois-domain --script-args whois.whodb=arin 192.168.1.1

# Traceroute geolocation
nmap --script traceroute-geolocation --traceroute 192.168.1.1

# ARP discovery (local network)
nmap --script arp-discovery -sn 192.168.1.0/24
```

### Service Enumeration

```bash
# HTTP methods allowed
nmap --script http-methods -p 80 192.168.1.1

# HTTP server header
nmap --script http-server-header -p 80 192.168.1.1

# SNMP information
nmap --script snmp-info -p 161 -sU 192.168.1.1

# SNMP brute force community strings
nmap --script snmp-brute -p 161 -sU 192.168.1.1

# NTP information
nmap --script ntp-info -p 123 -sU 192.168.1.1

# DNS service discovery
nmap --script dns-service-discovery -p 53 192.168.1.1
```

### Web Application Analysis

```bash
# Web application firewall detection
nmap --script http-waf-detect,http-waf-fingerprint -p 80 192.168.1.1

# Robots.txt retrieval
nmap --script http-robots.txt -p 80 192.168.1.1

# Sitemap retrieval
nmap --script http-sitemap-generator -p 80 192.168.1.1

# HTTP authentication info
nmap --script http-auth,http-auth-finder -p 80 192.168.1.1

# Cookie information
nmap --script http-cookie-flags -p 80 192.168.1.1
```

## Script Location and Management

### Default Script Locations

**Linux:**
```
/usr/share/nmap/scripts/
/usr/local/share/nmap/scripts/
```

**Windows:**
```
C:\Program Files (x86)\Nmap\scripts\
```

**macOS (Homebrew):**
```
/usr/local/share/nmap/scripts/
/opt/homebrew/share/nmap/scripts/
```

### Listing Available Scripts

```bash
# List all scripts
ls /usr/share/nmap/scripts/

# Search for specific scripts
ls /usr/share/nmap/scripts/ | grep smb

# Get script count
ls /usr/share/nmap/scripts/*.nse | wc -l
```

### Installing Custom Scripts

```bash
# Download a script
wget https://example.com/custom-script.nse -O /usr/share/nmap/scripts/custom-script.nse

# Update script database
nmap --script-updatedb

# Verify script is available
nmap --script-help custom-script
```

## Writing Custom Scripts (Basics)

### Simple Script Template

```lua
-- Script header
description = [[
A simple script that demonstrates NSE basics.
]]

author = "Your Name"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

-- Required libraries
local shortport = require "shortport"
local stdnse = require "stdnse"

-- Port rule: when should this script run?
portrule = shortport.http

-- Main action function
action = function(host, port)
    return "Script executed successfully on " .. host.ip .. ":" .. port.number
end
```

### Key NSE Libraries

| Library | Purpose |
|---------|---------|
| `shortport` | Port matching rules |
| `stdnse` | Standard NSE functions |
| `http` | HTTP requests |
| `nmap` | Core Nmap functions |
| `comm` | Network communication |
| `brute` | Brute force framework |
| `creds` | Credential management |
| `vulns` | Vulnerability reporting |

### Script Development Tips

```bash
# Test script with debugging
nmap --script custom-script --script-trace -d 192.168.1.1

# Check script syntax
nmap --script-help custom-script

# Run with verbose output
nmap --script custom-script -v 192.168.1.1
```

## Common Mistakes

- **WRONG:** Running exploit scripts without authorization
- **CORRECT:** Only run exploit/dos category scripts in authorized tests with explicit permission

- **WRONG:** Using `nmap --script all` on production networks
- **CORRECT:** Use specific scripts or safe categories: `nmap --script "default and safe"`

- **WRONG:** Assuming -sC is aggressive scanning
- **CORRECT:** -sC runs only default (safe) scripts, but still generates traffic

- **WRONG:** Running brute force scripts with default settings
- **CORRECT:** Configure rate limiting: `--script-args brute.threads=2,brute.delay=1s`

- **WRONG:** Ignoring script output
- **CORRECT:** Use XML output for parsing: `nmap --script vuln -oX results.xml`

## Practical Examples

### Comprehensive Web Server Audit

```bash
nmap -sV -sC --script "http-* and safe" -p 80,443,8080,8443 \
     --script-args http.useragent="Mozilla/5.0" \
     -oA web_audit 192.168.1.0/24
```

### Quick Vulnerability Assessment

```bash
nmap -sV --script vuln --script-args vulns.showall \
     -p- -T4 -oA vuln_scan 192.168.1.1
```

### Authenticated SMB Enumeration

```bash
nmap --script smb-enum-shares,smb-enum-users,smb-ls \
     --script-args smbuser=admin,smbpass=password,smbdomain=CORP \
     -p 445 -oA smb_enum 192.168.1.1
```

### Stealthy Script Scan

```bash
nmap -sS -sV -T2 --script "default and not intrusive" \
     --scan-delay 500ms -p 22,80,443 192.168.1.1
```

### Full Network Discovery

```bash
nmap -sn --script broadcast-ping,broadcast-dhcp-discover,broadcast-netbios-master-browser \
     192.168.1.0/24
```

## CRITICAL WARNINGS

### Dangerous Script Categories

| Category | Risk | Mitigation |
|----------|------|------------|
| `exploit` | Active exploitation | Only use in isolated labs with explicit authorization |
| `dos` | Denial of service | Never use on production; test only |
| `intrusive` | May crash services | Get explicit approval; have rollback plan |
| `fuzzer` | May cause instability | Test in isolated environment |

### Script Categories to Avoid in Production

```bash
# DANGEROUS - Can exploit vulnerabilities
nmap --script exploit 192.168.1.1  # DO NOT RUN

# DANGEROUS - Can crash services
nmap --script dos 192.168.1.1      # DO NOT RUN

# DANGEROUS - Runs everything including dangerous scripts
nmap --script all 192.168.1.1      # DO NOT RUN
```

### Safe Alternatives

```bash
# Safe vulnerability checking (no exploitation)
nmap --script "vuln and safe" 192.168.1.1

# Information gathering only
nmap --script "discovery and safe" 192.168.1.1

# Default safe scripts
nmap -sC 192.168.1.1
```

## Script Performance Tuning

### Timeout Configuration

```bash
# Increase script timeout for slow targets
nmap --script-timeout 60s --script http-enum 192.168.1.1

# Parallel script execution
nmap --script "http-*" --min-parallelism 10 192.168.1.1
```

### Resource Management

```bash
# Limit concurrent scripts
nmap --script vuln --max-hostgroup 10 192.168.1.0/24

# Reduce memory usage for large scans
nmap --script "default" --max-parallelism 5 192.168.1.0/24
```
