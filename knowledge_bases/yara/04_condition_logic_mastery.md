# YARA Condition Logic Mastery

## Boolean Operators

The condition section is where YARA's power truly shines. Understanding boolean logic is essential for writing precise detection rules.

### AND Operator

Both conditions must be true:

```yara
rule And_Example {
    strings:
        $mz = { 4D 5A }
        $pe = { 50 45 00 00 }
    condition:
        $mz and $pe
}
```

### OR Operator

At least one condition must be true:

```yara
rule Or_Example {
    strings:
        $mal1 = "malware1"
        $mal2 = "malware2"
    condition:
        $mal1 or $mal2
}
```

### NOT Operator

Condition must NOT be true:

```yara
rule Not_Example {
    strings:
        $legit = "Microsoft Corporation"
        $suspicious = "CreateRemoteThread"
    condition:
        $suspicious and not $legit
}
```

### Complex Boolean Expressions

```yara
rule Complex_Boolean {
    strings:
        $mz = { 4D 5A }
        $pe = { 50 45 00 00 }
        $packed = "UPX"
        $signed = "Authenticode"
        $suspicious = "VirtualAlloc"

    condition:
        $mz and $pe and
        ($suspicious or $packed) and
        not $signed
}
```

### Operator Precedence

From highest to lowest:
1. `not`
2. `and`
3. `or`

Use parentheses for clarity:

```yara
// Ambiguous
$a or $b and $c      // Interpreted as: $a or ($b and $c)

// Clear
($a or $b) and $c    // Different result!
$a or ($b and $c)    // Explicit
```

## Comparison Operators

### Numeric Comparisons

```yara
condition:
    // Equal to
    filesize == 1024

    // Not equal to
    filesize != 0

    // Less than
    filesize < 10000

    // Less than or equal
    filesize <= 10MB

    // Greater than
    filesize > 100

    // Greater than or equal
    filesize >= 1KB
```

### Size Units

```yara
condition:
    // Bytes (default)
    filesize < 100

    // Kilobytes
    filesize < 100KB

    // Megabytes
    filesize < 10MB

    // Gigabytes
    filesize < 1GB
```

## String Counting and Offsets

### Counting String Occurrences

The `#` operator counts how many times a string appears:

```yara
strings:
    $nop = { 90 }
    $api = "GetProcAddress"

condition:
    // More than 100 NOP instructions
    #nop > 100

    // Exactly 5 API calls
    #api == 5

    // Between 2 and 10 occurrences
    #api >= 2 and #api <= 10
```

### String Offsets

The `@` operator returns the offset of a string occurrence:

```yara
strings:
    $mz = { 4D 5A }
    $pe = { 50 45 00 00 }

condition:
    // MZ at start of file
    @mz == 0

    // PE signature within first 1024 bytes
    @pe < 1024

    // Multiple offset checks
    @mz == 0 and @pe < 512
```

### Indexed Occurrences

Access specific occurrences with index:

```yara
strings:
    $str = "pattern"

condition:
    // First occurrence at offset 100
    @str[1] == 100

    // Second occurrence before offset 500
    @str[2] < 500

    // Third occurrence exists
    #str >= 3 and @str[3] > 0
```

### String Length

The `!` operator returns the length of a matched string:

```yara
strings:
    $regex = /password[0-9]+/

condition:
    // Matched regex is at least 12 characters
    !regex >= 12
```

## Filesize Conditions

### Basic Filesize Checks

```yara
condition:
    // Typical malware size constraints
    filesize < 5MB and filesize > 1KB

    // Very small files (often droppers)
    filesize < 10KB

    // Avoid scanning huge files
    filesize < 100MB
```

### Combining with Strings

```yara
rule Small_Executable {
    strings:
        $mz = { 4D 5A }
        $suspicious = "cmd.exe /c"

    condition:
        $mz at 0 and
        $suspicious and
        filesize < 50KB
}
```

## Entry Point Detection

The `entrypoint` variable gives the offset to the entry point in PE/ELF files.

### Basic Entry Point Checks

```yara
strings:
    $code = { 55 8B EC }  // push ebp; mov ebp, esp

condition:
    $code at entrypoint
```

### Entry Point Range

```yara
strings:
    $packer_stub = { 60 E8 00 00 00 00 }

condition:
    // Packer stub within 100 bytes of entry point
    $packer_stub in (entrypoint..entrypoint+100)
```

### Suspicious Entry Points

```yara
rule Suspicious_Entry_Point {
    strings:
        $mz = { 4D 5A }

    condition:
        $mz at 0 and
        // Entry point in last section (common in packed files)
        entrypoint > filesize - 0x1000
}
```

## String Location Tracking

### Using 'at' Operator

Match string at specific offset:

```yara
strings:
    $mz = { 4D 5A }
    $pe = { 50 45 00 00 }

condition:
    $mz at 0                    // MZ at file start
    $pe at 0x80                 // PE at typical offset
```

### Using 'in' Range Operator

Match string within a range:

```yara
strings:
    $signature = "SIGNATURE"

condition:
    // Signature in first 1024 bytes
    $signature in (0..1024)

    // Signature in last 256 bytes
    $signature in (filesize-256..filesize)
```

### Complex Location Logic

```yara
rule Complex_Location {
    strings:
        $header = { 4D 5A }
        $marker = "MARKER"
        $payload = { E8 00 00 00 00 }

    condition:
        $header at 0 and
        $marker in (0..1000) and
        $payload in (@marker..@marker+500)
}
```

## For Loops and Iterations

### Basic For Loop

```yara
strings:
    $s1 = "string1"
    $s2 = "string2"
    $s3 = "string3"

condition:
    // All strings must occur more than twice
    for all of ($s*) : (# > 2)
```

### For Any

```yara
condition:
    // At least one string at offset less than 100
    for any of them : (@ < 100)
```

### For X of

```yara
condition:
    // At least 2 strings appear more than once
    for 2 of them : (# > 1)

    // Exactly 3 strings at offset > 1000
    for 3 of them : (@ > 1000)
```

### Iterating with Index

```yara
strings:
    $a = "pattern"

condition:
    // First occurrence in range
    for any i in (1..#a) : (@a[i] < 1000)

    // Check all occurrences
    for all i in (1..#a) : (@a[i] >= 100 and @a[i] <= filesize - 100)
```

## Complex Nested Conditions

### Multi-Level Nesting

```yara
rule Nested_Logic {
    strings:
        $mz = { 4D 5A }
        $pe = { 50 45 00 00 }
        $upx = "UPX"
        $aspack = "ASPack"
        $api1 = "VirtualAlloc"
        $api2 = "WriteProcessMemory"
        $api3 = "CreateRemoteThread"

    condition:
        ($mz at 0) and
        ($pe in (0..1024)) and
        (
            ($upx or $aspack) or
            (
                2 of ($api*) and
                filesize < 100KB
            )
        )
}
```

### Conditional Chains

```yara
rule Conditional_Chain {
    strings:
        $header = { 4D 5A }
        $dll_export = "DllEntryPoint"
        $exe_entry = { 55 8B EC }
        $suspicious = "CreateRemoteThread"

    condition:
        $header at 0 and
        (
            // If DLL, check for DLL-specific patterns
            ($dll_export and $suspicious) or
            // If EXE, check for EXE-specific patterns
            ($exe_entry at entrypoint and $suspicious and filesize < 50KB)
        )
}
```

## Using 'of' Operator

### Basic 'of' Usage

```yara
strings:
    $a = "string1"
    $b = "string2"
    $c = "string3"

condition:
    // Any of the strings
    any of them

    // All of the strings
    all of them

    // None of the strings
    none of them

    // 2 or more
    2 of them

    // Between 2 and 4
    2 of them and not (all of them)
```

### 'of' with String Sets

```yara
strings:
    $api1 = "VirtualAlloc"
    $api2 = "VirtualProtect"
    $api3 = "WriteProcessMemory"
    $str1 = "http://"
    $str2 = "cmd.exe"

condition:
    // 2 of the API strings
    2 of ($api*)

    // Any of the strings starting with $str
    any of ($str*)

    // All APIs or any string
    all of ($api*) or any of ($str*)
```

### Percentage-Based Matching

```yara
strings:
    $s1 = "indicator1"
    $s2 = "indicator2"
    $s3 = "indicator3"
    $s4 = "indicator4"
    $s5 = "indicator5"

condition:
    // 60% of strings must match (3 out of 5)
    3 of them

    // Custom percentage calculation
    // (#s1 + #s2 + #s3 + #s4 + #s5) >= 3 // Alternative approach
```

## Rule Dependencies

### Referencing Other Rules

```yara
rule Is_PE {
    strings:
        $mz = { 4D 5A }
        $pe = { 50 45 00 00 }
    condition:
        $mz at 0 and $pe
}

rule Suspicious_PE {
    strings:
        $shellcode = { E8 00 00 00 00 }
    condition:
        Is_PE and $shellcode
}

rule Malicious_PE {
    strings:
        $c2 = "evil-domain.com"
    condition:
        Suspicious_PE and $c2
}
```

### Private Rules

Rules that don't produce output but can be referenced:

```yara
private rule PE_File {
    strings:
        $mz = { 4D 5A }
    condition:
        $mz at 0
}

rule Malware_Detection {
    strings:
        $malicious = "malware_payload"
    condition:
        PE_File and $malicious
}
```

### Global Rules

Rules that are automatically added to all other rules:

```yara
global rule Size_Limit {
    condition:
        filesize < 100MB
}

rule Actual_Detection {
    strings:
        $s = "pattern"
    condition:
        $s
    // Implicitly also requires: filesize < 100MB
}
```

## Practical Condition Examples

### Detecting Process Injection

```yara
rule Process_Injection {
    strings:
        $api1 = "OpenProcess" ascii wide
        $api2 = "VirtualAllocEx" ascii wide
        $api3 = "WriteProcessMemory" ascii wide
        $api4 = "CreateRemoteThread" ascii wide
        $api5 = "NtCreateThreadEx" ascii wide

    condition:
        $api1 and $api2 and $api3 and ($api4 or $api5)
}
```

### Detecting Packers

```yara
rule Packed_Executable {
    strings:
        $mz = { 4D 5A }
        $upx = "UPX" ascii
        $high_entropy_section = /[A-Za-z0-9+\/=]{500,}/

    condition:
        $mz at 0 and
        (
            $upx or
            $high_entropy_section or
            // Low number of imports suggests packing
            #mz == 1
        )
}
```

### Detecting Ransomware

```yara
rule Ransomware_Indicators {
    strings:
        // Shadow copy deletion
        $vss1 = "vssadmin" nocase
        $vss2 = "delete shadows" nocase
        $vss3 = "wmic shadowcopy" nocase

        // File encryption APIs
        $crypto1 = "CryptEncrypt" ascii wide
        $crypto2 = "CryptGenKey" ascii wide
        $crypto3 = "CryptAcquireContext" ascii wide

        // Ransom note patterns
        $note1 = "your files have been encrypted" nocase
        $note2 = "bitcoin" nocase
        $note3 = "decrypt" nocase

    condition:
        (any of ($vss*)) or
        (2 of ($crypto*) and any of ($note*))
}
```

### Detecting Credential Stealers

```yara
rule Credential_Stealer {
    strings:
        // Browser credential paths
        $chrome = "Login Data" ascii wide
        $firefox = "logins.json" ascii wide
        $edge = "Web Data" ascii wide

        // Credential APIs
        $cred1 = "CredEnumerate" ascii wide
        $cred2 = "CryptUnprotectData" ascii wide

        // Registry paths
        $reg1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" ascii wide

    condition:
        (2 of ($chrome, $firefox, $edge)) or
        ($cred1 and $cred2) or
        any of ($reg*)
}
```

## Performance Tips

### Efficient Conditions

```yara
// Good: Check cheap conditions first
condition:
    filesize < 1MB and expensive_string_check

// Bad: Check expensive conditions first
condition:
    expensive_string_check and filesize < 1MB
```

### Using Short-Circuit Evaluation

```yara
// YARA uses short-circuit evaluation
condition:
    // If false, second check is skipped
    false and expensive_check

    // Use this to optimize
    filesize < 100KB and $rare_string and $common_string
```

### Avoiding Inefficient Patterns

```yara
// Avoid: Unbounded iterations
condition:
    for all i in (1..1000) : (@string[i] > 0)

// Better: Use bounded checks
condition:
    #string > 0 and #string < 100
```
