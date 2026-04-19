# YARA Performance Optimization

## Understanding YARA's Scanning Engine

YARA uses a sophisticated multi-pattern matching algorithm based on the Aho-Corasick algorithm. Understanding how YARA processes rules is essential for writing high-performance rules.

### How YARA Scans

1. **Atom Extraction**: YARA extracts "atoms" (short fixed byte sequences) from patterns
2. **Pre-filtering**: Uses atoms to quickly identify potential matches
3. **Verification**: Verifies full pattern match only for potential candidates
4. **Condition Evaluation**: Evaluates conditions after string matching

## Rule Optimization Techniques

### String Selection Strategies

#### Use Unique, Long Strings

```yara
// Good: Long, unique string
strings:
    $good = "ThisIsAVerySpecificMalwareString_v2.1"

// Bad: Short, common string
strings:
    $bad = "exe"
```

#### Prefer Fixed Patterns Over Regex

```yara
// Good: Fixed pattern (fast)
strings:
    $fixed = { 4D 5A 90 00 03 00 00 00 04 00 00 00 }

// Slower: Regex equivalent
strings:
    $regex = /MZ.{10}/
```

#### Minimize Wildcards

```yara
// Good: Few wildcards, long fixed sections
strings:
    $good = { 4D 5A 90 00 ?? ?? 00 00 04 00 00 00 FF FF 00 00 }

// Bad: Many wildcards, short fixed sections
strings:
    $bad = { 4D ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 50 45 }
```

### Atom Optimization

YARA extracts atoms for fast pre-filtering. Rules with good atoms scan faster.

#### What Makes a Good Atom

- At least 4 consecutive fixed bytes
- Unique byte sequences
- Not common padding (00 00 00 00, 90 90 90 90)

```yara
// Good atoms
strings:
    $has_good_atom = { 48 8B 05 12 34 56 78 }  // 7 fixed bytes

// Poor atoms
strings:
    $poor_atom = { ?? ?? 90 90 ?? ?? }  // Only 2 consecutive fixed bytes
```

#### Checking Atom Quality

```bash
# Show atoms YARA extracts
yara --print-strings --print-namespace rules.yar /dev/null
```

### Avoiding Slow Patterns

#### Regex Performance Killers

```yara
// SLOW: Greedy quantifiers with broad matches
strings:
    $slow1 = /.*malware/           // Greedy .* is slow
    $slow2 = /.+malware/           // .+ similarly slow
    $slow3 = /a.*b.*c.*d/          // Multiple greedy quantifiers

// FAST: Specific patterns
strings:
    $fast1 = /malware/             // Simple literal
    $fast2 = /mal[a-z]{4}e/        // Bounded quantifier
    $fast3 = /a.{0,50}b/           // Bounded range
```

#### Bounded Jumps

```yara
// Good: Bounded jump
strings:
    $bounded = { E8 [4] 83 C4 [0-10] C3 }

// Bad: Unbounded jump (avoid if possible)
strings:
    $unbounded = { E8 [-] 83 C4 }

// Reasonable maximum
strings:
    $reasonable = { 4D 5A [0-1024] 50 45 00 00 }
```

### Condition Ordering

YARA uses short-circuit evaluation. Order conditions from cheapest to most expensive.

```yara
rule Efficient_Ordering {
    strings:
        $common = "common_string"
        $rare = "very_rare_unique_string"
        $regex = /complex[0-9]+pattern/

    condition:
        // Good: Check filesize first (instant)
        filesize < 1MB and

        // Then check for rare string (likely to fail fast)
        $rare and

        // Then common string
        $common and

        // Expensive regex last
        $regex
}
```

### Using Private Strings

Private strings are used in conditions but not reported, reducing output overhead:

```yara
rule Optimized_Private {
    strings:
        $indicator = "malware" private  // Not included in output
        $report_this = "payload"        // Included in output

    condition:
        $indicator and $report_this
}
```

## Memory Considerations

### Large File Handling

```yara
rule Size_Limited {
    strings:
        $pattern = "suspicious"

    condition:
        // Skip files that are too large
        filesize < 50MB and
        $pattern
}
```

### String Count Limits

```yara
rule Count_Limited {
    strings:
        $nop = { 90 }

    condition:
        // Avoid counting millions of occurrences
        filesize < 10MB and
        #nop > 100 and #nop < 10000
}
```

### Memory Mapping

For very large files, consider streaming approaches or splitting scans:

```python
import yara
import os

def scan_large_file(filepath, rules, chunk_size=100*1024*1024):
    """Scan large files in chunks"""
    file_size = os.path.getsize(filepath)

    if file_size < chunk_size:
        return rules.match(filepath)

    matches = []
    with open(filepath, 'rb') as f:
        offset = 0
        while offset < file_size:
            data = f.read(chunk_size)
            chunk_matches = rules.match(data=data)
            # Adjust offsets
            for match in chunk_matches:
                matches.append(match)
            offset += chunk_size

    return matches
```

## Scanning Large Datasets Efficiently

### Parallel Processing

```python
import yara
from concurrent.futures import ProcessPoolExecutor
import os

def scan_file(args):
    filepath, rules_path = args
    rules = yara.compile(filepath=rules_path)
    try:
        matches = rules.match(filepath)
        return (filepath, matches)
    except Exception as e:
        return (filepath, str(e))

def parallel_scan(directory, rules_path, workers=4):
    files = []
    for root, dirs, filenames in os.walk(directory):
        for filename in filenames:
            files.append((os.path.join(root, filename), rules_path))

    with ProcessPoolExecutor(max_workers=workers) as executor:
        results = list(executor.map(scan_file, files))

    return results
```

### Compiled Rules

Pre-compiling rules significantly speeds up repeated scans:

```python
import yara

# Compile once
rules = yara.compile(filepath='rules.yar')

# Save compiled rules
rules.save('rules.yarc')

# Load compiled rules (much faster)
compiled_rules = yara.load('rules.yarc')
```

Command line:
```bash
# Compile rules
yarac rules.yar rules.yarc

# Use compiled rules
yara rules.yarc target_directory/
```

### Filtering Before Scanning

```python
import os
import yara

def should_scan(filepath):
    """Pre-filter files before YARA scan"""
    # Skip very large files
    if os.path.getsize(filepath) > 100 * 1024 * 1024:
        return False

    # Skip known safe extensions
    skip_extensions = {'.txt', '.log', '.md', '.json', '.xml', '.csv'}
    if os.path.splitext(filepath)[1].lower() in skip_extensions:
        return False

    # Quick magic number check for executables
    try:
        with open(filepath, 'rb') as f:
            header = f.read(4)
            # MZ (PE), ELF, Mach-O
            if header[:2] in [b'MZ', b'\x7fE'] or header[:4] == b'\xcf\xfa\xed\xfe':
                return True
    except:
        pass

    return False

def efficient_scan(directory, rules):
    results = []
    for root, dirs, files in os.walk(directory):
        for filename in files:
            filepath = os.path.join(root, filename)
            if should_scan(filepath):
                matches = rules.match(filepath)
                if matches:
                    results.append((filepath, matches))
    return results
```

## Profiling YARA Rules

### Measuring Rule Performance

```python
import yara
import time
import os

def profile_rules(rules_path, test_directory, iterations=3):
    """Profile YARA rules performance"""
    rules = yara.compile(filepath=rules_path)

    # Get test files
    test_files = []
    for root, dirs, files in os.walk(test_directory):
        for f in files:
            test_files.append(os.path.join(root, f))

    total_size = sum(os.path.getsize(f) for f in test_files)

    print(f"Profiling {len(test_files)} files ({total_size / 1024 / 1024:.2f} MB)")

    times = []
    for i in range(iterations):
        start = time.time()
        for filepath in test_files:
            rules.match(filepath)
        elapsed = time.time() - start
        times.append(elapsed)
        print(f"  Iteration {i+1}: {elapsed:.3f}s")

    avg_time = sum(times) / len(times)
    throughput = total_size / avg_time / 1024 / 1024

    print(f"\nAverage: {avg_time:.3f}s")
    print(f"Throughput: {throughput:.2f} MB/s")
```

### Identifying Slow Rules

```python
import yara
import time

def find_slow_rules(rules_path, test_file):
    """Identify which rules are slow"""
    with open(rules_path, 'r') as f:
        content = f.read()

    # Parse individual rules
    import re
    rule_pattern = r'(private\s+)?rule\s+(\w+)\s*(?::\s*[^\{]+)?\s*\{[^}]+\}'

    results = []
    for match in re.finditer(rule_pattern, content, re.DOTALL):
        rule_text = match.group(0)
        rule_name = match.group(2)

        try:
            single_rule = yara.compile(source=rule_text)

            start = time.time()
            for _ in range(10):
                single_rule.match(test_file)
            elapsed = time.time() - start

            results.append((rule_name, elapsed))
        except Exception as e:
            results.append((rule_name, f"Error: {e}"))

    # Sort by time
    results.sort(key=lambda x: x[1] if isinstance(x[1], float) else 999)

    print("Rules by execution time:")
    for name, timing in results[-10:]:  # Show slowest 10
        print(f"  {name}: {timing:.4f}s" if isinstance(timing, float) else f"  {name}: {timing}")
```

## Best Practices Summary

### DO

1. Use long, unique strings
2. Prefer fixed hex patterns over regex
3. Use bounded jumps and ranges
4. Order conditions cheaply to expensive
5. Pre-compile rules for production
6. Filter files before scanning
7. Use parallel processing for large datasets

### DON'T

1. Use unbounded wildcards in hex patterns
2. Use greedy regex quantifiers (.*) without limits
3. Scan unnecessarily large files
4. Count occurrences without limits
5. Recompile rules for each scan
6. Use overly broad conditions

### Performance Checklist

```
[ ] All strings have at least 4 consecutive fixed bytes
[ ] No unbounded jumps in hex patterns
[ ] Regex patterns use bounded quantifiers
[ ] Conditions ordered by cost (cheap first)
[ ] Filesize checks included for large file protection
[ ] Rules are pre-compiled for production use
[ ] Parallel processing used for large scans
[ ] File filtering implemented to skip non-targets
```

## Performance Benchmarks

Expected throughput on modern hardware:

| Scenario | Throughput |
|----------|-----------|
| Simple string rules | 500+ MB/s |
| Complex regex rules | 50-100 MB/s |
| PE module analysis | 100-200 MB/s |
| High-entropy calculation | 50-100 MB/s |
| Combined complex rules | 20-50 MB/s |

Note: Actual performance varies based on:
- Hardware (CPU, storage speed)
- Rule complexity
- File characteristics
- Number of rules
