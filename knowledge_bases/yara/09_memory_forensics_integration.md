# YARA and Memory Forensics Integration

## YARA with Volatility

Volatility is the most popular memory forensics framework, and YARA integrates seamlessly for threat detection in memory dumps.

### Basic Volatility YARA Scanning

```bash
# Volatility 2
volatility -f memory.dmp --profile=Win10x64 yarascan -y rules.yar

# Volatility 3
vol.py -f memory.dmp windows.yarascan --yara-rules rules.yar
```

### Scanning Specific Processes

```bash
# Scan specific PID (Volatility 2)
volatility -f memory.dmp --profile=Win10x64 yarascan -y rules.yar -p 1234

# Scan multiple PIDs
volatility -f memory.dmp --profile=Win10x64 yarascan -y rules.yar -p 1234,5678

# Volatility 3
vol.py -f memory.dmp windows.yarascan --yara-rules rules.yar --pid 1234
```

### Python Integration

```python
import volatility3
from volatility3.framework import contexts, automagic
from volatility3.framework.configuration import requirements
from volatility3.plugins.windows import yarascan

def scan_memory_with_yara(dump_path, yara_rules_path):
    """Scan memory dump with YARA rules using Volatility 3"""
    context = contexts.Context()

    # Set up the memory layer
    single_location = "file://" + dump_path
    context.config['automagic.LayerStacker.single_location'] = single_location

    # Run YARA scan
    automagics = automagic.available(context)
    plugin = yarascan.YaraScan(
        context,
        config_path='plugins.YaraScan',
        yara_rules=yara_rules_path
    )

    results = []
    for match in plugin.run():
        results.append({
            'rule': match.Rule,
            'owner': match.Owner,
            'pid': match.PID,
            'offset': match.Offset,
            'data': match.Data
        })

    return results
```

## Process Injection Detection

### Detecting Injected Code

```yara
rule Memory_Injection_RWX {
    meta:
        description = "Detects RWX memory regions typical of injection"
        memory_only = true

    strings:
        // Common shellcode patterns
        $shellcode1 = { FC E8 ?? 00 00 00 }     // CLD; CALL
        $shellcode2 = { E8 00 00 00 00 }        // CALL $+5
        $shellcode3 = { 31 C0 50 68 }           // XOR EAX,EAX; PUSH EAX; PUSH

        // API resolution patterns
        $api_hash1 = { 89 ?? 68 ?? ?? ?? ?? FF 15 }
        $api_hash2 = { 31 C0 AC 41 C1 C9 0D 41 01 C1 }

    condition:
        any of them
}

rule Memory_Reflective_DLL {
    meta:
        description = "Detects reflective DLL injection in memory"
        memory_only = true

    strings:
        // Reflective loader signatures
        $reflect1 = "ReflectiveLoader" ascii
        $reflect2 = { 4D 5A 41 52 55 48 89 E5 }  // MZ + RDI shellcode stub

        // PE in memory without proper mapping
        $mz = { 4D 5A }
        $pe = { 50 45 00 00 }

        // Stephen Fewer's hash
        $hash = { 81 ?? ?? ?? ?? ?? 74 }

    condition:
        $reflect1 or $reflect2 or ($mz and $pe and $hash)
}
```

### Detecting Process Hollowing

```yara
rule Memory_Process_Hollowing {
    meta:
        description = "Detects process hollowing indicators in memory"
        memory_only = true
        mitre_attack = "T1055.012"

    strings:
        // Unmapped PE header
        $mz = { 4D 5A }
        $pe = { 50 45 00 00 }

        // NtUnmapViewOfSection pattern
        $unmap = { 68 ?? ?? ?? ?? 6A FF }

        // Typical hollowing APIs
        $api1 = "NtUnmapViewOfSection" ascii wide
        $api2 = "ZwUnmapViewOfSection" ascii wide

    condition:
        $mz at 0 and $pe and (any of ($api*) or $unmap)
}
```

## Shellcode Identification

### Generic Shellcode Detection

```yara
rule Shellcode_Generic_x86 {
    meta:
        description = "Detects generic x86 shellcode patterns"
        memory_only = true

    strings:
        // GetPC techniques
        $getpc1 = { E8 00 00 00 00 (58|59|5A|5B|5D|5E|5F) }  // CALL $+5; POP reg
        $getpc2 = { D9 EE D9 74 24 F4 }                       // FPU GetPC

        // PEB access (fs:[30])
        $peb1 = { 64 A1 30 00 00 00 }           // MOV EAX, FS:[0x30]
        $peb2 = { 64 8B (1D|0D|15|35) 30 00 00 00 }

        // Kernel32 base resolution
        $k32_1 = { 8B 40 0C 8B 70 1C AD 8B 40 08 }

        // WinExec/CreateProcess
        $exec = { 68 ?? ?? ?? ?? (50|51|52|53) FF }

    condition:
        any of ($getpc*) and ($peb1 or $peb2) and ($k32_1 or $exec)
}

rule Shellcode_Generic_x64 {
    meta:
        description = "Detects generic x64 shellcode patterns"
        memory_only = true

    strings:
        // x64 GetPC
        $getpc = { 48 8D 05 00 00 00 00 }       // LEA RAX, [RIP]

        // x64 PEB access (gs:[60])
        $peb = { 65 48 8B 04 25 60 00 00 00 }   // MOV RAX, GS:[0x60]

        // API hashing loop
        $hash = { 48 31 C0 AC 41 C1 C9 0D 41 01 C1 }

        // Syscall patterns
        $syscall = { 0F 05 }

    condition:
        $peb and ($hash or $syscall or $getpc)
}
```

### Meterpreter Detection

```yara
rule Shellcode_Meterpreter {
    meta:
        description = "Detects Meterpreter shellcode in memory"
        memory_only = true

    strings:
        // Meterpreter stage patterns
        $stage1 = { FC E8 82 00 00 00 60 89 E5 31 C0 64 8B 50 30 }
        $stage2 = { FC E8 89 00 00 00 60 89 E5 31 D2 64 8B 52 30 }

        // Reverse TCP
        $rev_tcp = { 6A 00 53 56 68 ?? ?? ?? ?? 68 02 00 }

        // Meterpreter strings
        $metsrv = "metsrv" ascii
        $stdapi = "stdapi" ascii

        // Reflective DLL loader
        $reflect = { 4D 5A 52 E8 00 00 00 00 }

    condition:
        any of them
}
```

## Detecting Packed/Encrypted Memory

### High Entropy Regions

```yara
import "math"

rule Memory_High_Entropy_Region {
    meta:
        description = "Detects high-entropy memory regions (packed/encrypted)"
        memory_only = true

    condition:
        math.entropy(0, filesize) > 7.5
}
```

### Packed Code Detection

```yara
rule Memory_Packed_Executable {
    meta:
        description = "Detects packed executable code in memory"
        memory_only = true

    strings:
        // UPX in memory
        $upx = "UPX!" ascii

        // Themida/WinLicense
        $themida = ".themida" ascii

        // VMProtect
        $vmp = ".vmp" ascii

        // Common unpacking stub
        $stub = { 60 E8 00 00 00 00 58 }  // PUSHAD; CALL $+5; POP EAX

    condition:
        any of them
}
```

## DLL Hollowing Detection

```yara
rule Memory_DLL_Hollowing {
    meta:
        description = "Detects DLL hollowing (module stomping)"
        memory_only = true
        mitre_attack = "T1055.001"

    strings:
        // MZ header
        $mz = { 4D 5A }

        // Suspicious strings in normally benign DLLs
        $sus1 = "CreateRemoteThread" ascii
        $sus2 = "VirtualAllocEx" ascii
        $sus3 = "WriteProcessMemory" ascii

        // Beacon patterns
        $beacon = { 00 01 00 01 00 02 }

    condition:
        $mz at 0 and (2 of ($sus*) or $beacon)
}
```

## Memory-Resident Malware

### Fileless Malware Detection

```yara
rule Memory_Fileless_Malware {
    meta:
        description = "Detects fileless malware patterns in memory"
        memory_only = true

    strings:
        // PowerShell in memory
        $ps1 = "System.Management.Automation" ascii wide
        $ps2 = "Invoke-Expression" ascii wide
        $ps3 = "IEX" ascii wide

        // .NET in memory
        $net1 = "mscorlib" ascii wide
        $net2 = "System.Reflection" ascii wide

        // Script hosts
        $wsh1 = "WScript.Shell" ascii wide
        $wsh2 = "Scripting.FileSystemObject" ascii wide

        // Base64 blobs
        $b64 = /[A-Za-z0-9+\/]{100,}={0,2}/ ascii

    condition:
        (any of ($ps*) or any of ($net*) or any of ($wsh*)) and $b64
}
```

### Cobalt Strike in Memory

```yara
rule Memory_CobaltStrike_Beacon {
    meta:
        description = "Detects Cobalt Strike beacon in memory"
        memory_only = true

    strings:
        // Configuration block
        $config = { 00 01 00 01 00 02 ?? ?? 00 02 00 01 00 02 }

        // Beacon strings
        $str1 = "%s as %s\\%s: %d" ascii
        $str2 = "beacon.dll" ascii wide
        $str3 = "beacon.x64.dll" ascii wide

        // Sleep mask
        $sleep = { 48 8B 05 B8 00 00 00 4C 8B 05 }

        // Named pipes
        $pipe = "\\\\.\\pipe\\" ascii wide

    condition:
        $config or 2 of ($str*) or ($sleep and $pipe)
}
```

## Volatility-Specific Rules

### Rules for Malfind Plugin

```yara
rule Malfind_RWX_Suspicious {
    meta:
        description = "Enhanced detection for malfind RWX regions"
        plugin = "malfind"

    strings:
        // Shellcode indicators
        $sc1 = { FC E8 }           // CLD; CALL
        $sc2 = { E8 00 00 00 00 }  // CALL $+5
        $sc3 = { 31 C9 }           // XOR ECX, ECX

        // Not legitimate code
        $not_legit1 = "Microsoft" ascii wide
        $not_legit2 = "Copyright" ascii wide

    condition:
        any of ($sc*) and not any of ($not_legit*)
}
```

### VAD Analysis Rules

```yara
rule VAD_Suspicious_Allocation {
    meta:
        description = "Detects suspicious VAD allocations"
        plugin = "vadinfo"

    strings:
        // MZ header in VAD
        $mz = { 4D 5A }

        // Executable code patterns
        $code1 = { 55 8B EC }      // push ebp; mov ebp, esp
        $code2 = { 48 89 5C 24 }   // mov [rsp+X], rbx

    condition:
        $mz and any of ($code*)
}
```

## Best Practices for Memory Scanning

### Performance Optimization

```python
def efficient_memory_scan(dump_path, rules_path):
    """Efficiently scan memory with YARA"""
    import yara
    import mmap

    # Compile rules once
    rules = yara.compile(filepath=rules_path)

    # Memory-map the dump for efficiency
    with open(dump_path, 'rb') as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

        # Scan in chunks for large dumps
        chunk_size = 100 * 1024 * 1024  # 100MB chunks
        offset = 0

        while offset < len(mm):
            end = min(offset + chunk_size, len(mm))
            matches = rules.match(data=mm[offset:end])

            for match in matches:
                yield {
                    'rule': match.rule,
                    'offset': offset + match.strings[0][0] if match.strings else offset,
                    'strings': match.strings
                }

            offset += chunk_size - 4096  # Overlap to catch cross-boundary matches

        mm.close()
```

### Memory Forensics Workflow

1. **Acquire Memory Dump**
   - Use WinPMEM, FTK Imager, or similar tools

2. **Initial Triage**
   - Run volatility pslist/pstree
   - Identify suspicious processes

3. **YARA Scanning**
   - Scan full dump for known threats
   - Scan specific process memory

4. **Deep Analysis**
   - Extract suspicious regions
   - Analyze with additional tools

5. **Report Findings**
   - Document matches with context
   - Correlate with other artifacts
