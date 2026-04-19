# YARA Modules and External Variables

## Introduction to YARA Modules

YARA modules extend the core functionality by providing specialized capabilities for analyzing different file formats and extracting metadata. Modules allow you to access structured information about files that would be impossible to detect with simple pattern matching.

## PE Module (Windows Executables)

The PE module is the most commonly used module for analyzing Windows executables.

### Importing the Module

```yara
import "pe"

rule PE_Example {
    condition:
        pe.is_pe
}
```

### Basic PE Checks

```yara
import "pe"

rule Basic_PE_Checks {
    condition:
        // Check if file is a valid PE
        pe.is_pe

        // Check if 32-bit or 64-bit
        pe.is_32bit() or pe.is_64bit()

        // Check machine type
        pe.machine == pe.MACHINE_AMD64
        pe.machine == pe.MACHINE_I386
}
```

### PE Header Fields

```yara
import "pe"

rule PE_Header_Analysis {
    condition:
        // Timestamp analysis
        pe.timestamp > 1609459200  // After Jan 1, 2021
        pe.timestamp < 1640995200  // Before Jan 1, 2022

        // Number of sections
        pe.number_of_sections >= 3 and pe.number_of_sections <= 10

        // Entry point
        pe.entry_point > 0x1000

        // Image base
        pe.image_base == 0x400000  // Default for 32-bit

        // Subsystem
        pe.subsystem == pe.SUBSYSTEM_WINDOWS_GUI
        pe.subsystem == pe.SUBSYSTEM_WINDOWS_CUI

        // Characteristics
        pe.characteristics & pe.DLL
        pe.characteristics & pe.EXECUTABLE_IMAGE
}
```

### Section Analysis

```yara
import "pe"

rule Section_Analysis {
    condition:
        // Check for UPX sections
        for any i in (0..pe.number_of_sections-1) : (
            pe.sections[i].name == "UPX0" or
            pe.sections[i].name == "UPX1"
        )

        // Executable and writable section (suspicious)
        for any i in (0..pe.number_of_sections-1) : (
            pe.sections[i].characteristics & 0x20000000 and  // Executable
            pe.sections[i].characteristics & 0x80000000      // Writable
        )

        // High entropy section (packed/encrypted)
        for any i in (0..pe.number_of_sections-1) : (
            math.entropy(pe.sections[i].raw_data_offset,
                        pe.sections[i].raw_data_size) > 7.5
        )

        // Section with no name (suspicious)
        for any i in (0..pe.number_of_sections-1) : (
            pe.sections[i].name == ""
        )
}
```

### Import Analysis

```yara
import "pe"

rule Import_Analysis {
    condition:
        // Check for specific imports
        pe.imports("kernel32.dll", "VirtualAlloc")
        pe.imports("kernel32.dll", "WriteProcessMemory")
        pe.imports("kernel32.dll", "CreateRemoteThread")

        // Number of imports
        pe.number_of_imports > 10

        // Check all imports from a DLL
        pe.imports("ws2_32.dll")  // Any import from ws2_32.dll

        // Suspicious import combinations
        pe.imports("kernel32.dll", "VirtualAllocEx") and
        pe.imports("kernel32.dll", "WriteProcessMemory") and
        (pe.imports("kernel32.dll", "CreateRemoteThread") or
         pe.imports("ntdll.dll", "NtCreateThreadEx"))
}
```

### Export Analysis

```yara
import "pe"

rule Export_Analysis {
    condition:
        // Check for DLL exports
        pe.exports("DllRegisterServer")
        pe.exports("ServiceMain")

        // Number of exports
        pe.number_of_exports > 0

        // DLL with no exports (suspicious loader)
        pe.characteristics & pe.DLL and
        pe.number_of_exports == 0
}
```

### Resource Analysis

```yara
import "pe"

rule Resource_Analysis {
    condition:
        // Check for embedded resources
        pe.number_of_resources > 0

        // Resource by type
        for any i in (0..pe.number_of_resources-1) : (
            pe.resources[i].type == pe.RESOURCE_TYPE_RCDATA
        )

        // Large resource (embedded payload)
        for any i in (0..pe.number_of_resources-1) : (
            pe.resources[i].length > 100000
        )
}
```

### Signature Verification

```yara
import "pe"

rule Signature_Analysis {
    condition:
        // Check if signed
        pe.is_signed

        // Specific certificate issuer
        for any i in (0..pe.number_of_signatures-1) : (
            pe.signatures[i].issuer contains "Microsoft"
        )

        // Unsigned executable (suspicious for enterprise software)
        not pe.is_signed and
        pe.number_of_imports > 50

        // Check certificate validity (timestamp)
        pe.signatures[0].not_after > 1640995200
}
```

### Version Information

```yara
import "pe"

rule Version_Info {
    condition:
        // Check company name
        pe.version_info["CompanyName"] contains "Microsoft"

        // Check product name
        pe.version_info["ProductName"] == "Windows Operating System"

        // Mismatch between claimed and actual
        pe.version_info["CompanyName"] contains "Microsoft" and
        not pe.is_signed
}
```

## ELF Module (Linux Executables)

```yara
import "elf"

rule ELF_Analysis {
    condition:
        // Check if valid ELF
        elf.type == elf.ET_EXEC or elf.type == elf.ET_DYN

        // Check architecture
        elf.machine == elf.EM_X86_64
        elf.machine == elf.EM_386

        // Number of sections
        elf.number_of_sections > 0

        // Check for specific section
        for any i in (0..elf.number_of_sections-1) : (
            elf.sections[i].name == ".text"
        )

        // Entry point
        elf.entry_point != 0
}

rule ELF_Suspicious {
    condition:
        // Stripped binary (no symbol table)
        elf.symtab_entries == 0

        // Section with unusual flags
        for any i in (0..elf.number_of_sections-1) : (
            elf.sections[i].flags & elf.SHF_WRITE and
            elf.sections[i].flags & elf.SHF_EXECINSTR
        )
}
```

## Math Module

The math module provides mathematical functions for analysis.

```yara
import "math"

rule Math_Analysis {
    condition:
        // Calculate entropy of entire file
        math.entropy(0, filesize) > 7.0

        // Entropy of specific section
        math.entropy(0, 1000) > 6.5

        // Mean byte value
        math.mean(0, filesize) > 100 and math.mean(0, filesize) < 150

        // Serial correlation (randomness indicator)
        math.serial_correlation(0, filesize) < 0.1

        // Monte Carlo Pi estimation (randomness check)
        math.monte_carlo_pi(0, filesize) > 3.0 and
        math.monte_carlo_pi(0, filesize) < 3.3

        // Deviation from expected value
        math.deviation(0, filesize, 128) < 30
}

rule High_Entropy_Executable {
    strings:
        $mz = { 4D 5A }
    condition:
        $mz at 0 and
        math.entropy(0, filesize) > 7.5
}
```

## Hash Module

The hash module computes cryptographic hashes.

```yara
import "hash"

rule Hash_Analysis {
    condition:
        // Match specific MD5
        hash.md5(0, filesize) == "d41d8cd98f00b204e9800998ecf8427e"

        // Match specific SHA1
        hash.sha1(0, filesize) == "da39a3ee5e6b4b0d3255bfef95601890afd80709"

        // Match specific SHA256
        hash.sha256(0, filesize) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

        // Hash of specific range
        hash.md5(0, 1000) == "abc123..."

        // Hash of section
        hash.sha256(pe.sections[0].raw_data_offset,
                   pe.sections[0].raw_data_size) == "..."

        // CRC32 checksum
        hash.crc32(0, filesize) == 0x12345678
}
```

## Magic Module (File Type Detection)

```yara
import "magic"

rule Magic_Detection {
    condition:
        // Check MIME type
        magic.mime_type() == "application/x-executable"
        magic.mime_type() == "application/pdf"
        magic.mime_type() == "application/zip"

        // Check file type description
        magic.type() contains "PE32 executable"
        magic.type() contains "ELF 64-bit"
}

rule Mismatched_Extension {
    condition:
        // PDF magic but executable content
        magic.mime_type() == "application/pdf" and
        uint16(0) == 0x5A4D  // MZ header
}
```

## Dotnet Module (.NET Assemblies)

```yara
import "dotnet"

rule Dotnet_Analysis {
    condition:
        // Check if .NET assembly
        dotnet.is_dotnet

        // Version information
        dotnet.version == "v4.0.30319"

        // Module name
        dotnet.module_name == "malware.exe"

        // Number of streams
        dotnet.number_of_streams > 0

        // Check for specific type
        for any i in (0..dotnet.number_of_user_strings-1) : (
            dotnet.user_strings[i] contains "malicious"
        )

        // Assembly references
        dotnet.number_of_assembly_refs > 0

        // GUID
        dotnet.typelib == "12345678-1234-1234-1234-123456789012"
}

rule Dotnet_Obfuscated {
    condition:
        dotnet.is_dotnet and
        // Many user strings (often obfuscated)
        dotnet.number_of_user_strings > 1000
}
```

## Time Module

```yara
import "time"

rule Time_Based_Detection {
    condition:
        // Current time comparisons
        time.now() > 1609459200  // After specific timestamp

        // PE timestamp analysis with time module
        pe.timestamp > time.now() - 86400  // Modified in last 24 hours
        pe.timestamp < time.now() + 86400  // Not from the future (with tolerance)
}
```

## External Variables

External variables allow passing values to YARA at runtime.

### Defining External Variables

In the rule file:
```yara
rule External_Variable_Example {
    condition:
        // String variable
        filename == "suspicious.exe"

        // Integer variable
        file_age < 7

        // Boolean variable
        is_production_scan

        // Multiple externals
        filename contains ".exe" and
        file_age < 30 and
        is_production_scan
}
```

### Using External Variables at Runtime

Command line:
```bash
# Define external variables
yara -d filename="test.exe" -d file_age=5 -d is_production_scan=true rules.yar target

# Multiple files
yara -d scan_type="full" -d max_size=10000 rules.yar /path/to/scan/
```

Python:
```python
import yara

rules = yara.compile(filepath='rules.yar')

# Pass external variables
matches = rules.match('/path/to/file',
    externals={
        'filename': 'suspicious.exe',
        'file_age': 5,
        'is_production_scan': True
    })
```

### Practical External Variable Examples

```yara
rule Conditional_Scan {
    strings:
        $suspicious = "malware"
        $benign = "Microsoft"

    condition:
        $suspicious and
        (quick_scan or not $benign)  // External: quick_scan
}

rule Size_Limited_Scan {
    strings:
        $pattern = "payload"

    condition:
        filesize < max_filesize and  // External: max_filesize
        $pattern
}

rule Environment_Specific {
    strings:
        $prod_indicator = "production"
        $dev_indicator = "development"

    condition:
        (environment == "production" and not $dev_indicator) or
        (environment == "development" and $dev_indicator)
}
```

## Module Combinations

### Comprehensive PE Analysis

```yara
import "pe"
import "math"
import "hash"

rule Suspicious_PE_Comprehensive {
    meta:
        description = "Comprehensive suspicious PE detection"

    strings:
        $mz = { 4D 5A }
        $inject_api1 = "VirtualAllocEx" ascii wide
        $inject_api2 = "WriteProcessMemory" ascii wide

    condition:
        // Basic PE check
        pe.is_pe and
        $mz at 0 and

        // High entropy (packed/encrypted)
        math.entropy(0, filesize) > 7.0 and

        // Suspicious imports
        ($inject_api1 and $inject_api2) and

        // Not signed or suspicious signature
        (not pe.is_signed or
         pe.signatures[0].issuer contains "Unknown") and

        // Unusual section characteristics
        for any i in (0..pe.number_of_sections-1) : (
            pe.sections[i].characteristics & 0xE0000000 == 0xE0000000
        )
}
```

### Cross-Platform Binary Analysis

```yara
import "pe"
import "elf"
import "magic"
import "math"

rule Cross_Platform_Suspicious {
    condition:
        (
            // Windows PE
            (pe.is_pe and math.entropy(0, filesize) > 7.0) or
            // Linux ELF
            (elf.type == elf.ET_EXEC and math.entropy(0, filesize) > 7.0)
        ) and
        // General high entropy check
        math.mean(0, filesize) > 120
}
```

## Best Practices

1. **Always check module availability**: Not all YARA installations include all modules
2. **Use modules for structure**: Raw hex patterns for behavior
3. **Combine modules strategically**: PE + Math for packed detection
4. **Validate module data**: Check for null/invalid values
5. **Performance consideration**: Some module functions are expensive
6. **Version compatibility**: Module features vary by YARA version
