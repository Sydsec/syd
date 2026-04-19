# Volatility Framework Basics

## What is Volatility?

Volatility is an open-source memory forensics framework used for incident response and malware analysis. It extracts digital artifacts from volatile memory (RAM) dumps, revealing information that may not be available from traditional disk-based forensics.

**Why Memory Forensics Matters:**
- **Volatile Evidence**: RAM contains running processes, network connections, encryption keys, and malware that may not exist on disk
- **Rootkit Detection**: Memory analysis can detect kernel-level malware that hides from disk-based tools
- **Incident Response**: Captures the live state of a compromised system
- **Malware Analysis**: Reveals malware behavior, code injection, and process hollowing

## Volatility 2 vs Volatility 3

### Volatility 2 (Legacy)
- Python 2.7 (deprecated)
- Profile-based (requires exact OS version match)
- Command format: `vol.py -f memory.dump --profile=Win7SP1x64 pslist`
- Large collection of community plugins

### Volatility 3 (Current)
- Python 3.6+
- **Symbol tables** (auto-detection, no profile needed)
- Unified plugin architecture
- Command format: `vol.py -f memory.dump windows.pslist`
- Better performance, cleaner codebase

**Key Difference**: Volatility 3 uses **symbol tables** instead of profiles, making analysis faster and more reliable.

## Installation

### Method 1: pip (Recommended)
```bash
pip3 install volatility3
```

### Method 2: GitHub (Latest Development)
```bash
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
python3 setup.py install
```

### Method 3: Standalone Binary
Download pre-built binaries from: https://github.com/volatilityfoundation/volatility3/releases

### Verify Installation
```bash
vol -h
vol --version
```

## Basic Command Structure

### Volatility 3 Syntax
```bash
vol -f <memory_dump> <plugin_name> [options]
```

**Example:**
```bash
vol -f memory.raw windows.pslist
```

### Common Options
- `-f FILE`: Memory dump file
- `-o OFFSET`: Physical memory offset
- `-v`: Verbose output
- `--pid PID`: Filter by Process ID
- `-r json`: Output as JSON
- `-r pretty_json`: Human-readable JSON

## Core Concepts

### 1. Memory Dump
A **memory dump** (also called **RAM capture** or **memory image**) is a snapshot of physical RAM at a specific point in time.

**File Extensions:**
- `.raw` - Raw memory dump
- `.dmp` - Windows crash dump
- `.mem` - VMware memory file
- `.vmem` - VMware snapshot
- `.bin` - Generic binary

**Typical Size:**
- 4GB RAM system → 4GB dump file
- 16GB RAM system → 16GB dump file
- Cloud VM → Can be 64GB+

### 2. Virtual vs Physical Addresses
- **Virtual Address**: Memory address seen by processes (isolated per-process)
- **Physical Address**: Actual RAM location (system-wide)
- Volatility translates between these using **page tables**

### 3. EPROCESS Structure
Windows kernel data structure representing a process. Contains:
- Process ID (PID)
- Parent Process ID (PPID)
- Image name (executable filename)
- Creation time
- Exit time
- VAD (Virtual Address Descriptor) tree
- Token (security context)
- Handle table

**Why it matters**: Volatility parses EPROCESS to extract process information.

### 4. VAD (Virtual Address Descriptor)
Tree structure tracking all memory regions for a process:
- Executable code (.exe, .dll)
- Heap allocations
- Stack memory
- Memory-mapped files

**Use case**: Detecting code injection (e.g., malware injecting into legitimate processes)

### 5. Kernel vs User Mode
- **Kernel Mode (Ring 0)**: OS core, drivers, privileged operations
- **User Mode (Ring 3)**: Applications, limited privileges

**Forensics impact**: Kernel rootkits operate in Ring 0, harder to detect but leave memory artifacts.

## Essential Plugins (Quick Reference)

### Process Analysis
- `windows.pslist` - List all processes (EPROCESS linked list)
- `windows.pstree` - Process tree (parent-child relationships)
- `windows.psscan` - Scan for hidden/terminated processes
- `windows.cmdline` - Command-line arguments for each process

### Network Analysis
- `windows.netscan` - Network connections (TCP/UDP/listeners)
- `windows.netstat` - Active network connections (Volatility 2 syntax)

### Malware Detection
- `windows.malfind` - Detect code injection (VirtualAllocEx, WriteProcessMemory)
- `windows.ldrmodules` - Find hidden DLLs (unlinked from PEB)
- `windows.callbacks` - Kernel callbacks (rootkit detection)

### Registry
- `windows.registry.hivelist` - List registry hives in memory
- `windows.registry.printkey` - Read registry keys/values

### File Analysis
- `windows.filescan` - Scan for file objects in memory
- `windows.handles` - List open file/registry/mutex handles

### System Information
- `windows.info` - OS version, architecture, timestamp
- `windows.modules` - Loaded kernel drivers
- `windows.driverscan` - Scan for driver objects

## Basic Workflow Example

### 1. Validate the Dump
```bash
vol -f memory.dmp windows.info
```
**Output**: OS version, architecture, kernel address space

### 2. List Running Processes
```bash
vol -f memory.dmp windows.pslist
```
**Look for**:
- Suspicious process names (svchost.exe with unusual PID)
- Processes without parent (PPID = 0)
- Executables in wrong paths (calc.exe in C:\Temp)

### 3. Check Network Connections
```bash
vol -f memory.dmp windows.netscan
```
**Look for**:
- Unknown external IPs
- High-numbered ports (e.g., 4444, 8080)
- Processes listening on all interfaces (0.0.0.0)

### 4. Detect Malware
```bash
vol -f memory.dmp windows.malfind
```
**Look for**:
- Executable memory regions (MEM_COMMIT + PAGE_EXECUTE_READWRITE)
- Processes with injected code
- Shellcode patterns (assembly instructions)

### 5. Extract Suspicious Files
```bash
vol -f memory.dmp windows.filescan | grep malware.exe
vol -f memory.dmp windows.dumpfiles --pid <PID> --outdir extracted/
```

## Common Beginner Mistakes

### ❌ Wrong: Using Volatility 2 commands with Volatility 3
```bash
vol.py -f memory.dmp --profile=Win10x64 pslist  # Volatility 2 syntax
```
✅ **Correct:**
```bash
vol -f memory.dmp windows.pslist  # Volatility 3 syntax
```

### ❌ Wrong: Not specifying plugin namespace
```bash
vol -f memory.dmp pslist  # Ambiguous
```
✅ **Correct:**
```bash
vol -f memory.dmp windows.pslist  # Clear namespace
```

### ❌ Wrong: Expecting instant results on large dumps
```bash
vol -f 64GB_dump.raw windows.psscan  # May take 30+ minutes
```
✅ **Better:**
```bash
# Use targeted plugins first
vol -f 64GB_dump.raw windows.pslist  # Faster (uses linked list)
```

### ❌ Wrong: Ignoring timestamps
```bash
# Finding svchost.exe at PID 1234 - is it suspicious?
```
✅ **Correct:**
```bash
# Check creation time - was it created AFTER system boot?
# Check parent process - is it services.exe?
# Check path - is it C:\Windows\System32?
```

## Key Takeaways (Beginner Level)

1. **Volatility extracts RAM artifacts** - processes, network, malware, registry
2. **Volatility 3 is current** - uses symbol tables, simpler syntax
3. **Basic command**: `vol -f dump.raw windows.pluginname`
4. **Start with pslist/netscan/malfind** for quick triage
5. **Memory forensics reveals volatile evidence** unavailable on disk

## What's Next?

- **Module 02**: Memory acquisition techniques and tools
- **Module 03**: Deep dive into process analysis
- **Module 04**: Network forensics and malware C2 detection
- **Module 05**: Advanced malware detection techniques

---

**Reference**: Volatility 3 Documentation - https://volatility3.readthedocs.io/
