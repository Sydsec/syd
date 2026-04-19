# Nmap Firewall and IDS Evasion Techniques

## Stealth Scanning

### TCP SYN Scan (-sS)
- Half-open scanning
- Sends SYN, receives SYN-ACK, sends RST
- Less likely to be logged by applications
```bash
nmap -sS 192.168.1.1
```

### NULL, FIN, and Xmas Scans
Exploit RFC793 loopholes:

#### NULL Scan (-sN)
No flags set:
```bash
nmap -sN 192.168.1.1
```

#### FIN Scan (-sF)
Only FIN flag set:
```bash
nmap -sF 192.168.1.1
```

#### Xmas Scan (-sX)
FIN, PSH, and URG flags set:
```bash
nmap -sX 192.168.1.1
```

**Note:** These work against RFC-compliant systems but fail against Windows.

## Packet Fragmentation

### -f (Fragment Packets)
Split IP packets into tiny fragments:
```bash
nmap -f 192.168.1.1
```

### --mtu <number>
Specify Maximum Transmission Unit:
```bash
# MTU must be multiple of 8:
nmap --mtu 16 192.168.1.1
```

## Decoy Scanning

### -D (Decoy)
Make it appear that multiple hosts are scanning:
```bash
# Manual decoys:
nmap -D 192.168.1.5,192.168.1.10,ME 192.168.1.1

# Random decoys:
nmap -D RND:10 192.168.1.1
```

**Note:** ME represents your real IP address position in the decoy list.

## Source Port Manipulation

### -g <port> or --source-port <port>
Spoof source port (some firewalls trust specific ports):
```bash
# Spoof DNS traffic:
nmap -g 53 192.168.1.1

# Spoof HTTP traffic:
nmap --source-port 80 192.168.1.1
```

## MAC Address Spoofing

### --spoof-mac <MAC|vendor|0>
```bash
# Specific MAC:
nmap --spoof-mac 00:11:22:33:44:55 192.168.1.1

# Random MAC from vendor:
nmap --spoof-mac Dell 192.168.1.1

# Random MAC:
nmap --spoof-mac 0 192.168.1.1
```

## Bad Checksums

### --badsum
Send packets with incorrect checksums (firewalls may not validate):
```bash
nmap --badsum 192.168.1.1
```

## Randomization Options

### --randomize-hosts
**CORRECT FLAG** for randomizing host scan order:
```bash
nmap --randomize-hosts 192.168.1.0/24
```

### -r (Disable Port Randomization)
By default, Nmap randomizes port scan order. Use -r to scan sequentially:
```bash
# Sequential port scanning:
nmap -r 192.168.1.1
```

**Note:** There is NO -rP, -rT, or -rH flag. These do not exist in Nmap.

## Proxy Chains

### --proxies <url1,[url2],…>
Route scans through SOCKS4, SOCKS5, or HTTP proxies:
```bash
nmap --proxies socks4://proxy:1080 192.168.1.1
```

## Data Length Manipulation

### --data-length <number>
Append random data to packets:
```bash
nmap --data-length 25 192.168.1.1
```

## IP Options

### --ip-options <options>
Manually set IP options:
```bash
nmap --ip-options "S 192.168.1.5 192.168.1.10" 192.168.1.1
```

## TTL Manipulation

### --ttl <value>
Set IP time-to-live field:
```bash
nmap --ttl 64 192.168.1.1
```

## Combined Evasion Example

### Professional IDS/IPS Evasion Scan
```bash
nmap -sS -T2 -f --randomize-hosts --data-length 25 \
     -D RND:5 --source-port 53 192.168.1.0/24
```

Explanation:
- `-sS`: SYN stealth scan
- `-T2`: Polite timing (slower)
- `-f`: Fragment packets
- `--randomize-hosts`: Random scan order
- `--data-length 25`: Add random data
- `-D RND:5`: Use 5 random decoys
- `--source-port 53`: Appear as DNS traffic

## CRITICAL CORRECTIONS

### ❌ WRONG FLAGS (DO NOT EXIST)
These flags are **NOT REAL** and will cause errors:
- `-rT` (Randomize Timing) - **FAKE**
- `-rP` (Randomize Ports) - **FAKE**
- `-rH` (Randomize Hosts) - **FAKE**

### ✅ CORRECT FLAGS
- Randomize hosts: `--randomize-hosts`
- Randomize ports: **Default behavior** (use `-r` to disable)
- Control timing: Use `-T0` through `-T5` or `--scan-delay`

## Modern IDS/IPS Reality

**Important:** Modern security systems detect even "stealth" scans:
1. SYN scans are logged just like connect scans
2. Fragmentation triggers alerts
3. Timing templates alone won't bypass IDS

**Best practices:**
1. Use authorized pentesting
2. Coordinate with Blue Team
3. Slow scanning (`-T2` or lower)
4. Rate limiting (`--max-rate`)
5. Time your scans (off-hours)

## Legal Warning

⚠️ **CRITICAL**: Using evasion techniques on networks without authorization is illegal in most jurisdictions. Always:
1. Get written permission
2. Define scope clearly
3. Document all activities
4. Coordinate with system owners
