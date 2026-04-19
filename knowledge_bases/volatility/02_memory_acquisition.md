# Memory Acquisition for Forensic Analysis

## Why Memory Acquisition Matters

**Volatile data exists only in RAM:**
- Running processes and threads
- Network connections and open sockets
- Encryption keys and passwords in plaintext
- Recently executed commands
- Malware running in memory (fileless malware)
- Kernel rootkits and bootkits

**Once the system is powered off, this evidence is GONE.**

## Legal and Ethical Considerations

### Chain of Custody
1. **Document everything**:
   - Time of acquisition (UTC timestamp)
   - Who performed the acquisition
   - System state (running, hibernating, powered off)
   - Tool used and version
   - Hash of memory dump (SHA-256)

2. **Write-protect evidence**:
   - Use write-blockers for disk forensics
   - For memory: save dump to external media, not local disk
   - Immediately calculate cryptographic hash

3. **Maintain forensic soundness**:
   - Minimize changes to target system
   - Use trusted forensic tools
   - Document any changes made (e.g., driver installation)

### Authorization Requirements
- **Corporate**: Get written authorization from IT management
- **Law Enforcement**: Obtain proper warrant or consent
- **Incident Response**: Ensure contractual agreement covers memory acquisition
- **Personal Systems**: Owner consent required

**NEVER acquire memory without proper authorization - legal consequences are severe.**

## Memory Acquisition Tools

### 1. FTK Imager (Free, GUI-based)
**Platform**: Windows only
**Use Case**: Quick acquisition, beginner-friendly

**Pros:**
- Free download from AccessData
- GUI interface (click-to-capture)
- Creates .mem files with metadata
- Trusted by law enforcement

**Cons:**
- Windows only
- Requires GUI access (not remote-friendly)
- Limited automation

**Command Line:**
```cmd
ftkimager.exe --memory-dump "C:\Evidence\memory.raw" --verify
```

**GUI Steps:**
1. Run FTK Imager as Administrator
2. File → Capture Memory
3. Specify destination path
4. Check "Include pagefile"
5. Click "Capture Memory"

**Output**: `memory.raw` + `memory.raw.txt` (metadata file with timestamps/hash)

### 2. WinPmem (Open-source, Command-line)
**Platform**: Windows
**Use Case**: Remote acquisition, scripting, incident response

**Pros:**
- Open-source (Velocidex project)
- Kernel driver signed by Microsoft
- Fast acquisition (1GB/second on modern systems)
- Command-line scriptable

**Cons:**
- Requires Administrator privileges
- Must load kernel driver (may trigger EDR alerts)

**Installation:**
```powershell
# Download from https://github.com/Velocidex/WinPmem/releases
# Extract winpmem_mini_x64_rc2.exe
```

**Acquisition Command:**
```powershell
# Acquire memory to file
winpmem_mini_x64_rc2.exe memory.raw

# Verify acquisition
Get-FileHash memory.raw -Algorithm SHA256
```

**Output**: `memory.raw` (raw physical memory dump)

### 3. LiME (Linux Memory Extractor)
**Platform**: Linux only
**Use Case**: Linux server forensics, cloud VM analysis

**Pros:**
- Kernel module for raw memory acquisition
- Works on any Linux kernel version
- Minimal footprint

**Cons:**
- Requires kernel headers to compile
- Must be compiled for target kernel version

**Compilation:**
```bash
# Install kernel headers
sudo apt-get install linux-headers-$(uname -r)

# Clone LiME
git clone https://github.com/504ensicsLabs/LiME.git
cd LiME/src

# Compile for current kernel
make

# Load module and acquire memory
sudo insmod lime-$(uname -r).ko "path=/tmp/memory.lime format=raw"
```

**Output**: `/tmp/memory.lime` (raw Linux memory dump)

### 4. Magnet RAM Capture (Free, Windows)
**Platform**: Windows only
**Use Case**: Quick triage, no installation required

**Pros:**
- Portable executable (no installation)
- Free for law enforcement and corporate IR
- Automatic hashing

**Cons:**
- Windows only
- GUI only (no command-line)

**Usage:**
1. Run MagnetRAMCapture.exe as Administrator
2. Select destination folder
3. Click "Capture Memory"

**Output**: `<ComputerName>-<Timestamp>.raw` + `.txt` metadata

### 5. DumpIt (Comae Technologies)
**Platform**: Windows, Linux, macOS
**Use Case**: Cross-platform, remote acquisition

**Pros:**
- Single executable (no installation)
- Cross-platform support
- Fast acquisition

**Cons:**
- Proprietary (not open-source)
- Commercial licensing for corporate use

**Usage:**
```bash
# Windows
DumpIt.exe /O memory.dmp

# Linux
sudo ./DumpIt /O memory.lime

# macOS
sudo ./DumpIt /O memory.mem
```

### 6. Belkasoft Live RAM Capturer (Free)
**Platform**: Windows
**Use Case**: Quick acquisition with minimal footprint

**Pros:**
- Portable, no installation
- Minimal memory footprint
- Automatic hashing

**Cons:**
- Windows only
- Closed-source

**Usage:**
```cmd
RamCapture64.exe memory.mem
```

## Acquisition Methods

### Method 1: Live System Acquisition (Recommended)
**Scenario**: System is running, attacker may still be active

**Advantages:**
- Captures volatile data (network connections, decrypted data)
- Can acquire multiple snapshots over time
- Processes are in known-good state

**Disadvantages:**
- Acquisition tool modifies memory (small footprint)
- Attacker may detect acquisition
- System must remain powered on

**Best Practices:**
```bash
# 1. Document system state
date -u  # Record timestamp (UTC)
uname -a  # Linux system info
systeminfo  # Windows system info

# 2. Acquire memory FIRST (most volatile)
winpmem_mini_x64_rc2.exe memory.raw

# 3. Calculate hash immediately
sha256sum memory.raw > memory.raw.sha256

# 4. Acquire disk image SECOND (less volatile)
```

### Method 2: Hibernation File (hiberfil.sys)
**Scenario**: Windows system was hibernated

**Advantages:**
- No acquisition tool needed
- Perfect snapshot of memory at hibernation time
- No risk of detection

**Disadvantages:**
- Only available if system was hibernated
- May be compressed (requires conversion)
- Timestamp is hibernation time, not current time

**Location:**
```
C:\hiberfil.sys  (Windows)
```

**Conversion to Raw:**
```bash
# Using Volatility imageinfo
vol -f hiberfil.sys windows.info

# Hibernation files are usually compatible with Volatility
# No conversion needed for Volatility 3
```

**Use Case Example:**
```bash
# Suspect hibernated laptop before border crossing
# Acquire hiberfil.sys during forensic imaging
# Analyze with Volatility to find encryption keys, browser history
```

### Method 3: Crash Dump (Memory.dmp)
**Scenario**: Windows crashed (BSOD) and wrote crash dump

**Advantages:**
- Already on disk (no acquisition needed)
- Perfect memory snapshot at crash time
- Includes kernel debugging information

**Disadvantages:**
- Only kernel memory (not full RAM on some systems)
- Compressed/filtered (some data removed)
- Only available if system crashed

**Location:**
```
C:\Windows\MEMORY.DMP  (Complete memory dump)
C:\Windows\Minidump\*.dmp  (Kernel dump only - limited use)
```

**Configuration:**
```powershell
# Enable complete memory dumps (before crash)
# System Properties → Advanced → Startup and Recovery → Settings
# Write debugging information: Complete memory dump
```

**Volatility Analysis:**
```bash
vol -f MEMORY.DMP windows.pslist
```

### Method 4: Virtual Machine Snapshots
**Scenario**: Target is a VM (VMware, VirtualBox, Hyper-V)

**Advantages:**
- Can pause VM without shutting down
- Memory state saved automatically
- Can acquire from hypervisor (no guest tool needed)

**Disadvantages:**
- Requires hypervisor access
- May alert monitoring systems

**VMware:**
```bash
# Suspend VM (creates .vmem file)
# Location: <VM_folder>/<VM_name>.vmem

# Analyze with Volatility
vol -f VM_snapshot.vmem windows.pslist
```

**VirtualBox:**
```bash
# Save state (creates .sav file)
# Must convert to raw

# Use vboxmanage
VBoxManage debugvm "<VM_name>" dumpvmcore --filename=memory.raw
```

**Hyper-V:**
```powershell
# Export VM (includes .bin memory file)
# Convert to raw using Volatility convert plugin
```

### Method 5: Cloud VM Acquisition
**Scenario**: Target is EC2, Azure VM, GCP instance

**Challenges:**
- Cannot install kernel drivers on cloud VMs (usually)
- Hypervisor memory acquisition requires provider support
- Snapshots may not include RAM

**Solutions:**

**AWS EC2:**
```bash
# Use EC2 Instance Metadata Service
# Acquire from within VM using WinPmem/LiME

# Or request AWS forensic support (Enterprise Support required)
```

**Azure:**
```powershell
# Use Azure Serial Console to acquire memory
# Or run acquisition tool inside VM

# Azure Memory Analysis Tool (preview)
# Requires Azure Security Center integration
```

**GCP:**
```bash
# Use gcloud compute instances to create snapshot
# Memory dump requires custom acquisition script
```

## Acquisition Order of Volatility

**From MOST volatile to LEAST volatile:**

1. **CPU Registers and Cache** (lost on power cycle)
2. **RAM Contents** (lost on power cycle)
3. **Network connections** (lost when network card resets)
4. **Running processes** (lost on shutdown)
5. **Swap/Pagefile** (persists on disk)
6. **Disk data** (persists until overwritten)
7. **Backup media** (most persistent)

**Forensic Acquisition Priority:**
```
1. Capture RAM (volatile)
2. Capture network traffic (volatile)
3. Capture running process list (volatile)
4. Acquire disk image (less volatile)
5. Acquire logs from remote systems (persistent)
```

## Practical Scenarios

### Scenario 1: Ransomware Incident (Live System)
**Goal**: Capture encryption keys from memory before shutdown

**Steps:**
```powershell
# 1. DO NOT SHUTDOWN (keys will be lost)
# 2. Acquire memory immediately
winpmem_mini_x64_rc2.exe C:\Evidence\ransomware_memory.raw

# 3. Analyze for encryption keys
vol -f ransomware_memory.raw windows.filescan | grep -i "aes\|crypt\|key"

# 4. Extract keys using bulk_extractor
bulk_extractor -o extracted/ ransomware_memory.raw
```

### Scenario 2: APT Investigation (Stealthy Acquisition)
**Goal**: Acquire memory without alerting attacker

**Steps:**
```bash
# Use stealthy tool (avoid EDR detection)
# Acquire to network share (avoid disk writes)

net use Z: \\forensics-server\evidence /user:admin password
winpmem_mini_x64_rc2.exe Z:\victim-2024-01-18.raw

# If network unavailable, use external USB
winpmem_mini_x64_rc2.exe E:\memory.raw
```

### Scenario 3: Remote Acquisition Over Network
**Goal**: Acquire memory from remote system without physical access

**Steps:**
```powershell
# Using PsExec (Sysinternals)
PsExec.exe \\remote-system -u admin -p password -c winpmem.exe C:\Windows\Temp\memory.raw

# Copy back over network
xcopy \\remote-system\C$\Windows\Temp\memory.raw C:\Evidence\ /C

# Calculate hash
Get-FileHash C:\Evidence\memory.raw -Algorithm SHA256
```

### Scenario 4: Encrypted Disk Investigation
**Goal**: Find disk encryption keys in memory

**Steps:**
```bash
# 1. Acquire memory from running system (keys in RAM)
sudo insmod lime.ko "path=/tmp/memory.lime format=raw"

# 2. Search for BitLocker/LUKS keys
vol -f memory.lime linux.bash  # Find recent commands
strings memory.lime | grep -i "password\|passphrase"

# 3. Extract encryption keys using specialized tools
# Example: FindAES (searches for AES key schedules)
```

## Common Pitfalls

### ❌ Pitfall 1: Acquiring to Same Disk
```bash
# WRONG: Overwrites evidence on target disk
winpmem.exe C:\memory.raw  # Writing to C: may overwrite deleted files
```

**✅ Correct:**
```bash
# Write to external media or network share
winpmem.exe E:\memory.raw  # External USB drive
winpmem.exe \\server\evidence\memory.raw  # Network share
```

### ❌ Pitfall 2: Not Hashing Immediately
```bash
# WRONG: Acquiring without hash
winpmem.exe memory.raw
# (Later, how do you prove it wasn't modified?)
```

**✅ Correct:**
```bash
# Calculate hash immediately after acquisition
winpmem.exe memory.raw
sha256sum memory.raw > memory.raw.sha256
# Document hash in case notes
```

### ❌ Pitfall 3: Using Untrusted Tools
```bash
# WRONG: Using random memory acquisition tool from internet
# (Could be trojanized, compromising investigation)
```

**✅ Correct:**
```bash
# Use well-known, trusted tools
# - FTK Imager (AccessData)
# - WinPmem (Google/Velocidex)
# - LiME (504ENSICS Labs)
# - Magnet RAM Capture (Magnet Forensics)
```

### ❌ Pitfall 4: Waiting Too Long
```bash
# WRONG: Imaging disk first, RAM second
# (Suspect reboots during disk imaging → RAM evidence lost)
```

**✅ Correct:**
```bash
# Acquire most volatile evidence first
1. Memory dump (5 minutes)
2. Network traffic capture (ongoing)
3. Disk image (hours)
```

## Key Takeaways

1. **Acquire RAM first** - most volatile evidence
2. **Use trusted tools** - FTK Imager, WinPmem, LiME
3. **Document everything** - timestamps, hashes, chain of custody
4. **Acquire to external media** - never write to target system disk
5. **Hash immediately** - proves integrity of evidence
6. **Get authorization** - legal requirement, not optional

## What's Next?

- **Module 03**: Process analysis techniques
- **Module 04**: Network forensics and malware C2 detection
- **Module 05**: Advanced malware detection using Volatility

---

**Legal Disclaimer**: Memory acquisition may be illegal without proper authorization. Always obtain written consent or legal authority before acquiring memory from any system.
