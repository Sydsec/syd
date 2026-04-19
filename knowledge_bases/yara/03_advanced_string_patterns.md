# Advanced String Patterns in YARA

## Hexadecimal Patterns Deep Dive

Hexadecimal patterns are essential for detecting binary malware artifacts. Understanding advanced hex patterns enables detection of packed, obfuscated, and polymorphic malware.

### Basic Hex Syntax

```yara
strings:
    // Simple byte sequence
    $basic = { 4D 5A 90 00 03 00 00 00 }

    // DOS MZ header check
    $mz_header = { 4D 5A }

    // PE signature
    $pe_sig = { 50 45 00 00 }
```

### Wildcards in Hex Patterns

#### Full Byte Wildcards (??)

Match any single byte:

```yara
strings:
    // Match any two bytes after MZ
    $pattern1 = { 4D 5A ?? ?? }

    // Match PE header at variable offset
    $pattern2 = { 4D 5A ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 50 45 00 00 }
```

#### Nibble Wildcards (?)

Match half-byte (single hex digit):

```yara
strings:
    // Match any value from 0x50-0x5F
    $nibble1 = { 5? }

    // Match 0xA0-0xAF followed by 0xB0-0xBF
    $nibble2 = { A? B? }

    // Combine with full wildcards
    $mixed = { 4D 5? ?? 00 }
```

### Jump Instructions

Jumps allow matching patterns separated by variable amounts of data.

#### Fixed Jumps

```yara
strings:
    // Exactly 4 bytes between patterns
    $fixed = { E8 [4] 83 C4 }

    // Exactly 100 bytes between
    $fixed2 = { 4D 5A [100] 50 45 }
```

#### Range Jumps

```yara
strings:
    // 0 to 100 bytes between MZ and PE
    $range1 = { 4D 5A [0-100] 50 45 00 00 }

    // 10 to 50 bytes between patterns
    $range2 = { C7 45 [10-50] E8 }

    // Minimum of 5 bytes
    $range3 = { 48 8B [5-] C3 }

    // Maximum of 20 bytes
    $range4 = { E8 [-20] 83 C4 }
```

#### Unbounded Jumps

```yara
strings:
    // Any number of bytes between (use carefully - performance impact)
    $unbounded = { 4D 5A [-] 50 45 00 00 }
```

### Alternatives in Hex Patterns

Match multiple possible byte sequences:

```yara
strings:
    // Either 90 or 00 after 4D 5A
    $alt1 = { 4D 5A ( 90 | 00 ) 00 }

    // Multiple alternatives
    $alt2 = { E8 ( 00 | 01 | 02 | 03 ) 00 00 00 }

    // Combined with wildcards
    $alt3 = { ( 4D | 4E ) 5A ?? ( 00 | 90 ) }

    // Longer alternatives
    $alt4 = { ( 48 8B 05 | 48 8B 0D ) [4] }
```

### Negation in Hex Patterns

Match bytes that are NOT specific values:

```yara
strings:
    // Not 00 after 4D 5A
    $neg1 = { 4D 5A ~00 }

    // Not in range (match anything except 00-0F)
    $neg2 = { 4D 5A ~(00|01|02|03|04|05|06|07|08|09|0A|0B|0C|0D|0E|0F) }
```

## Regular Expressions in Depth

YARA uses a subset of Perl-compatible regular expressions (PCRE).

### Character Classes

```yara
strings:
    // Predefined classes
    $digit = /[0-9]+/
    $alpha = /[A-Za-z]+/
    $alnum = /[A-Za-z0-9]+/
    $word = /\w+/              // [A-Za-z0-9_]
    $space = /\s+/             // Whitespace
    $nonspace = /\S+/          // Non-whitespace

    // Custom classes
    $hex_chars = /[0-9A-Fa-f]+/
    $path_chars = /[A-Za-z0-9_\-\.\\\/]+/

    // Negated classes
    $not_digit = /[^0-9]+/
    $not_alpha = /[^A-Za-z]+/
```

### Quantifiers

```yara
strings:
    // Zero or more
    $star = /a*/

    // One or more
    $plus = /a+/

    // Zero or one
    $question = /a?/

    // Exact count
    $exact = /a{5}/            // Exactly 5 'a's

    // Range
    $range = /a{2,5}/          // 2 to 5 'a's

    // Minimum
    $min = /a{3,}/             // At least 3 'a's

    // Maximum (rarely used)
    $max = /a{,5}/             // Up to 5 'a's

    // Non-greedy (match minimum)
    $lazy = /a+?/
    $lazy2 = /a*?/
```

### Anchors and Boundaries

```yara
strings:
    // Start of data
    $start = /^MZ/

    // End of data
    $end = /\.exe$/

    // Word boundary
    $word_bound = /\bpassword\b/

    // Not at word boundary
    $in_word = /\Bpass\B/
```

### Groups and Captures

```yara
strings:
    // Basic group
    $group1 = /(ab)+/          // One or more "ab"

    // Non-capturing group
    $group2 = /(?:http|https):\/\//

    // Alternation in groups
    $group3 = /(GET|POST|PUT) \/[^\s]+/
```

### Special Sequences

```yara
strings:
    // IP address pattern
    $ip = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/

    // URL pattern
    $url = /https?:\/\/[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(\/[^\s]*)?/

    // Email pattern
    $email = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/

    // File path (Windows)
    $win_path = /[A-Za-z]:\\[^\x00-\x1f"<>|]+/

    // File path (Unix)
    $unix_path = /\/[a-zA-Z0-9_\-\.\/]+/
```

### Regex Modifiers

```yara
strings:
    // Case insensitive
    $case = /malware/i

    // Dot matches newline
    $dotall = /start.*end/s

    // Multi-line mode
    $multi = /^line/m
```

## Case-Insensitive Matching

### Using nocase Modifier

```yara
strings:
    // Text strings
    $text = "CreateProcess" nocase

    // Matches: CreateProcess, CREATEPROCESS, createprocess, etc.
```

### Regex Case Insensitivity

```yara
strings:
    // Using /i modifier
    $regex = /CreateProcess/i

    // Character class alternative
    $manual = /[Cc]reate[Pp]rocess/
```

### Performance Consideration

`nocase` is more efficient than character class alternatives:

```yara
// Preferred
$good = "password" nocase

// Less efficient
$bad = /[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]/
```

## Wide and ASCII String Combinations

### Understanding Encodings

```
ASCII:   M  a  l  w  a  r  e
Hex:     4D 61 6C 77 61 72 65

Wide:    M     a     l     w     a     r     e
Hex:     4D 00 61 00 6C 00 77 00 61 00 72 00 65 00
```

### Matching Both Encodings

```yara
strings:
    // Match ASCII only (default)
    $ascii_only = "malware"

    // Match UTF-16LE only
    $wide_only = "malware" wide

    // Match both ASCII and UTF-16
    $both = "malware" ascii wide

    // All modifiers combined
    $all = "malware" ascii wide nocase
```

### Common API Functions

Windows API often uses both A (ASCII) and W (Wide) variants:

```yara
strings:
    $create_file = "CreateFile" ascii wide nocase
    $reg_open = "RegOpenKey" ascii wide nocase
    $write_file = "WriteFile" ascii wide nocase
```

## XOR Encoded Strings

Malware often XOR-encodes strings to evade detection.

### Basic XOR Matching

```yara
strings:
    // Match with any single-byte XOR key
    $xor1 = "password" xor

    // Specific key range
    $xor2 = "secret" xor(0x01-0x7f)

    // Specific key
    $xor3 = "hidden" xor(0x55)
```

### XOR with Other Modifiers

```yara
strings:
    // XOR + wide
    $xor_wide = "malware" xor wide

    // XOR + nocase
    $xor_nocase = "password" xor nocase

    // All combined
    $xor_all = "credential" xor ascii wide nocase
```

### XOR Key Range Strategies

```yara
strings:
    // Printable ASCII keys only
    $printable = "secret" xor(0x20-0x7e)

    // Single-byte keys (common)
    $single = "hidden" xor(0x01-0xff)

    // Small keys (fast)
    $small = "data" xor(0x01-0x20)
```

## Base64 Encoded Strings

### Standard Base64

```yara
strings:
    // Match base64-encoded "malicious"
    $b64 = "malicious" base64

    // This matches: bWFsaWNpb3Vz
```

### Base64 Variants

```yara
strings:
    // Standard base64
    $standard = "secret" base64

    // URL-safe base64 (uses - and _ instead of + and /)
    $url_safe = "secret" base64("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")

    // Custom alphabet
    $custom = "data" base64("./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
```

### Base64 Wide (UTF-16 then Base64)

```yara
strings:
    // Match base64-encoded UTF-16 string
    $b64wide = "password" base64wide
```

## String Sets and Arrays

### Defining String Sets

```yara
strings:
    $api1 = "CreateProcess"
    $api2 = "VirtualAlloc"
    $api3 = "WriteProcessMemory"
    $api4 = "CreateRemoteThread"

condition:
    // 2 or more of the API strings
    2 of ($api*)
```

### Anonymous Strings

```yara
strings:
    $ = "pattern1"
    $ = "pattern2"
    $ = "pattern3"

condition:
    any of them
```

### String Iterations

```yara
strings:
    $s1 = "string1"
    $s2 = "string2"
    $s3 = "string3"

condition:
    // Iterate over all strings
    for all of ($s*) : (# > 2)  // Each string appears more than twice

    // Iterate over some strings
    for any of ($s*) : (@ < 1000)  // Any string at offset < 1000
```

## Practical Pattern Examples

### Detecting Shellcode Patterns

```yara
strings:
    // Common shellcode stubs
    $shellcode1 = { FC E8 ?? ?? ?? ?? }           // CLD; CALL
    $shellcode2 = { 60 89 E5 31 D2 64 8B 52 30 }  // Pushad; standard PEB access
    $shellcode3 = { E8 00 00 00 00 }              // Call next instruction
    $shellcode4 = { 31 C0 50 68 2F 2F 73 68 }     // Linux execve shellcode

    // API hashing patterns
    $api_hash = { 89 ?? 68 ?? ?? ?? ?? FF }       // Push hash; Call
```

### Detecting Packers

```yara
strings:
    // UPX signatures
    $upx1 = { 55 50 58 30 }    // UPX0
    $upx2 = { 55 50 58 31 }    // UPX1
    $upx3 = { 55 50 58 21 }    // UPX!

    // Themida patterns
    $themida1 = { 60 E8 00 00 00 00 58 }

    // ASPack
    $aspack = { 60 E8 03 00 00 00 E9 EB }
```

### Detecting Encryption Constants

```yara
strings:
    // AES S-box first row
    $aes_sbox = { 63 7C 77 7B F2 6B 6F C5 }

    // RC4 key scheduling
    $rc4_init = { 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F }

    // DES initial permutation
    $des_ip = { 3A 32 2A 22 1A 12 0A 02 }
```

### Detecting C2 Patterns

```yara
strings:
    // HTTP User-Agent patterns
    $ua1 = "Mozilla/5.0" ascii wide nocase
    $ua2 = "User-Agent:" ascii wide nocase

    // Beacon intervals (hex)
    $beacon = { 00 00 ?? ?? 00 00 00 00 }

    // Common C2 commands
    $cmd1 = "shell" ascii wide
    $cmd2 = "download" ascii wide
    $cmd3 = "upload" ascii wide
    $cmd4 = "execute" ascii wide
```

## Performance Optimization for Patterns

### Efficient Pattern Design

```yara
// Good: Specific patterns
$good = { 4D 5A 90 00 03 00 00 00 04 00 }

// Bad: Too many wildcards
$bad = { 4D 5A ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 50 45 }

// Good: Bounded jumps
$bounded = { E8 [4] 83 C4 }

// Bad: Unbounded jumps
$unbounded = { E8 [-] 83 C4 }
```

### Atom Optimization

YARA uses "atoms" for fast pre-filtering. Longer fixed sequences = faster scanning:

```yara
// Good: Long fixed sequence
$long = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF }

// Less efficient: Short fixed sequences
$short = { 4D 5A [10] 50 45 [10] 00 }
```

### Regex Performance

```yara
// Efficient: Specific patterns
$good_regex = /password[0-9]{4}/

// Slow: Greedy with long range
$slow_regex = /password.*/

// Very slow: Backtracking heavy
$very_slow = /a*a*a*a*b/
```
