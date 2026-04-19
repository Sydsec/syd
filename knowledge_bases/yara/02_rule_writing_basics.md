# YARA Rule Writing Basics

## Rule Anatomy

Every YARA rule consists of three main sections: meta, strings, and condition. Understanding each section is essential for writing effective detection rules.

```yara
rule ExampleRule : tag1 tag2 {
    meta:
        // Descriptive information about the rule
        author = "Security Analyst"
        description = "Detects Example Malware"
        reference = "https://example.com/analysis"
        date = "2024-01-15"
        hash = "abc123..."

    strings:
        // Patterns to search for
        $text1 = "malicious string"
        $hex1 = { 4D 5A 90 00 }
        $regex1 = /pattern[0-9]+/

    condition:
        // Logic that determines a match
        any of them
}
```

## The Meta Section

The meta section contains descriptive information about the rule. While optional, it's considered best practice to include comprehensive metadata.

### Common Meta Fields

```yara
meta:
    // Required fields (best practice)
    author = "Your Name"
    description = "Brief description of what this rule detects"
    date = "2024-01-15"

    // Recommended fields
    reference = "URL to analysis or report"
    hash = "SHA256 hash of original sample"
    version = "1.0"

    // Optional fields
    tlp = "white"           // Traffic Light Protocol
    severity = "high"       // Risk level
    category = "ransomware" // Malware category
    mitre_attack = "T1486"  // MITRE ATT&CK technique

    // Boolean metadata
    in_the_wild = true

    // Integer metadata
    score = 85
```

### Metadata Best Practices

1. **Always include author**: Allows contact for questions
2. **Detailed description**: Explain what malware family or behavior
3. **Include references**: Link to analysis, blog posts, or reports
4. **Add sample hashes**: Document the original sample used
5. **Version tracking**: Helps track rule evolution

## The Strings Section

The strings section defines the patterns YARA searches for. There are three types of strings: text, hexadecimal, and regular expressions.

### Text Strings

Basic ASCII text patterns:

```yara
strings:
    // Simple text string
    $a = "This is a string"

    // With escape sequences
    $b = "Line1\nLine2"       // Newline
    $c = "Tab\there"          // Tab
    $d = "Quote\"inside"      // Escaped quote
    $e = "Backslash\\"        // Backslash

    // Hexadecimal escape
    $f = "Value\x00\x01"      // Null and SOH bytes
```

### Hexadecimal Strings

Binary patterns defined as hex bytes:

```yara
strings:
    // DOS header magic bytes
    $mz = { 4D 5A }

    // PE signature
    $pe = { 50 45 00 00 }

    // With spaces or without
    $with_spaces = { 4D 5A 90 00 }
    $no_spaces = {4D5A9000}

    // Wildcards
    $wildcard = { 4D 5A ?? ?? }          // Any two bytes
    $nibble = { 4D 5? }                   // Any value 50-5F

    // Jumps
    $jump = { 4D 5A [0-100] 50 45 }      // 0 to 100 bytes between
    $jump2 = { E8 [4] 83 C4 }            // Exactly 4 bytes

    // Alternatives
    $alt = { 4D 5A ( 90 | 00 ) 00 }     // 90 OR 00
```

### Regular Expression Strings

Perl-compatible regular expressions:

```yara
strings:
    // Basic regex
    $r1 = /malware[0-9]+/

    // Case insensitive
    $r2 = /malware/i

    // With modifiers
    $r3 = /http:\/\/[a-z0-9\-\.]+\.[a-z]{2,}/i

    // Character classes
    $r4 = /[A-Za-z0-9_]+\.exe/

    // Quantifiers
    $r5 = /password.{0,50}[0-9]+/

    // Anchors
    $r6 = /^MZ/                          // Start of file
    $r7 = /\.exe$/                        // End of string
```

## String Modifiers

Modifiers change how strings are matched:

### nocase - Case Insensitive

```yara
strings:
    $a = "MaLwArE" nocase    // Matches: malware, MALWARE, Malware, etc.
```

### wide - UTF-16 Encoding

```yara
strings:
    $a = "malware" wide       // Matches: m.a.l.w.a.r.e (UTF-16LE)
```

### ascii - ASCII Encoding (Default)

```yara
strings:
    $a = "malware" ascii      // Explicitly ASCII
```

### Combining Modifiers

```yara
strings:
    // Match both ASCII and Unicode, case insensitive
    $a = "password" ascii wide nocase

    // Common combination for malware strings
    $b = "CreateProcess" ascii wide
```

### fullword - Match Whole Words

```yara
strings:
    $a = "mal" fullword       // Matches "mal" but not "malware" or "animal"
```

### xor - XOR Encoded

```yara
strings:
    // XOR with all single-byte keys (0x00-0xFF)
    $a = "password" xor

    // XOR with specific key range
    $b = "secret" xor(0x01-0x20)

    // XOR with specific key
    $c = "hidden" xor(0x55)
```

### base64 - Base64 Encoded

```yara
strings:
    // Standard base64
    $a = "malicious" base64

    // Base64 with custom alphabet
    $b = "secret" base64("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")

    // Base64 wide (UTF-16 then base64)
    $c = "payload" base64wide
```

### private - Don't Report String

```yara
strings:
    $internal = "helper" private    // Used in condition but not reported
    $reported = "malware"           // Reported in output
```

## The Condition Section

The condition section defines the logic that determines when the rule matches.

### Basic Conditions

```yara
condition:
    // Match if $a is found
    $a

    // Match if all strings are found
    all of them

    // Match if any string is found
    any of them

    // Match if none are found
    none of them
```

### Boolean Operators

```yara
condition:
    // AND - both must match
    $a and $b

    // OR - either must match
    $a or $b

    // NOT - must not match
    $a and not $b

    // Complex combinations
    ($a or $b) and $c and not $d
```

### Counting Strings

```yara
condition:
    // At least 2 of the strings
    2 of ($a, $b, $c)

    // All strings in the set
    all of ($a*)           // All starting with $a

    // Any string in the set
    any of ($http*)        // Any starting with $http

    // Specific count
    #a > 5                 // $a appears more than 5 times
    #a == 3                // $a appears exactly 3 times
```

### String Sets

```yara
strings:
    $str1 = "one"
    $str2 = "two"
    $str3 = "three"
    $other = "different"

condition:
    // 2 of the first three
    2 of ($str*)

    // All strings defined
    all of them

    // Specific subset
    any of ($str1, $str2)
```

## Comments and Documentation

### Single Line Comments

```yara
rule Example {
    // This is a single line comment
    strings:
        $a = "test"     // Inline comment
    condition:
        $a
}
```

### Multi-Line Comments

```yara
rule Example {
    /*
     * This is a multi-line comment
     * explaining the purpose of this rule
     * and providing additional context
     */
    strings:
        $a = "test"
    condition:
        $a
}
```

## Rule Naming Conventions

### Recommended Naming Patterns

```yara
// By malware family
rule Emotet_Loader { ... }
rule TrickBot_Module_pwgrab { ... }

// By behavior
rule Ransomware_Shadow_Delete { ... }
rule Credential_Dumper_Generic { ... }

// By threat actor
rule APT28_Dropper { ... }
rule Lazarus_Loader_v2 { ... }

// By CVE
rule CVE_2021_44228_Log4j { ... }

// By category
rule Webshell_Generic_PHP { ... }
rule Packer_UPX { ... }
```

### Naming Best Practices

1. Use descriptive names
2. Include version numbers for variants
3. Use underscores for spaces
4. Prefix with category (optional but helpful)
5. Be consistent across rule sets

## Tags

Tags categorize rules for filtering and organization:

```yara
rule Emotet : trojan banker email {
    meta:
        description = "Detects Emotet banking trojan"
    strings:
        $a = "emotet"
    condition:
        $a
}
```

Usage in scanning:
```bash
# Only run rules with specific tag
yara -t banker rules.yar target

# Exclude rules with tag
yara --negate -t testing rules.yar target
```

## Complete Example Rules

### Basic Malware Rule

```yara
rule Suspicious_PowerShell_Download {
    meta:
        author = "Security Team"
        description = "Detects PowerShell download cradles"
        severity = "medium"

    strings:
        $ps1 = "powershell" nocase
        $ps2 = "pwsh" nocase
        $dl1 = "DownloadString" nocase
        $dl2 = "DownloadFile" nocase
        $dl3 = "Invoke-WebRequest" nocase
        $dl4 = "wget" nocase
        $dl5 = "curl" nocase
        $iex = "IEX" nocase

    condition:
        ($ps1 or $ps2) and any of ($dl*) and $iex
}
```

### Ransomware Detection Rule

```yara
rule Ransomware_Shadow_Delete {
    meta:
        author = "Security Team"
        description = "Detects ransomware shadow copy deletion"
        severity = "critical"
        mitre_attack = "T1490"

    strings:
        $vss1 = "vssadmin" nocase
        $vss2 = "delete shadows" nocase
        $vss3 = "wmic shadowcopy delete" nocase
        $bcdedit1 = "bcdedit" nocase
        $bcdedit2 = "recoveryenabled no" nocase

    condition:
        ($vss1 and $vss2) or $vss3 or ($bcdedit1 and $bcdedit2)
}
```

### C2 Beacon Detection

```yara
rule CobaltStrike_Beacon {
    meta:
        author = "Security Team"
        description = "Detects Cobalt Strike beacon patterns"
        severity = "critical"

    strings:
        $beacon1 = "%s as %s\\%s: %d" ascii wide
        $beacon2 = "beacon.dll" ascii wide
        $beacon3 = "ReflectiveLoader" ascii wide
        $config = { 00 01 00 01 00 02 ?? ?? 00 02 00 01 00 02 ?? ?? }

    condition:
        2 of them
}
```

## Best Practices Summary

1. **Clear Metadata**: Always document author, date, description
2. **Specific Strings**: Choose unique patterns to minimize false positives
3. **Test Rules**: Validate against malware samples AND clean files
4. **Use Modifiers**: Apply nocase, wide, ascii as appropriate
5. **Logical Conditions**: Combine strings intelligently
6. **Performance**: Consider scan speed with complex patterns
7. **Maintain Rules**: Update when malware variants appear
8. **Share Knowledge**: Contribute to community rule repositories
