# Nmap Timing and Performance Options

## Timing Templates (-T0 to -T5)

Nmap offers six timing templates that control scan speed and stealth:

### -T0 (Paranoid)
- Extremely slow (5 minutes between probes)
- IDS evasion
- Serial scanning only
```bash
nmap -T0 192.168.1.1
```

### -T1 (Sneaky)
- Very slow (15 seconds between probes)
- IDS evasion
- Serial scanning
```bash
nmap -T1 192.168.1.1
```

### -T2 (Polite)
- Slows down scan to use less bandwidth
- 0.4 second delay between probes
- Less likely to crash target
```bash
nmap -T2 192.168.1.1
```

### -T3 (Normal)
- Default timing
- Balances speed and stealth
```bash
nmap -T3 192.168.1.1
# or simply:
nmap 192.168.1.1
```

### -T4 (Aggressive)
- Faster scan
- Assumes fast, reliable network
- 10ms between probes
```bash
nmap -T4 192.168.1.1
```

### -T5 (Insane)
- Extremely fast
- May miss results
- 5ms between probes
- Sacrifices accuracy for speed
```bash
nmap -T5 192.168.1.1
```

## Fine-Grained Timing Control

### --min-rtt-timeout, --max-rtt-timeout, --initial-rtt-timeout
Control probe round-trip time expectations:
```bash
nmap --max-rtt-timeout 100ms 192.168.1.1
```

### --min-rate <number>
Send at least X packets per second:
```bash
nmap --min-rate 100 192.168.1.1
```

### --max-rate <number>
**CRITICAL FOR RATE LIMITING**
Send at most X packets per second:
```bash
# For 100 requests per minute limit (1.67 per second):
nmap --max-rate 1 192.168.1.1
```

### --scan-delay <time>
**CRITICAL FOR RATE LIMITING**
Wait at least X time between probes:
```bash
# Wait 1 second between each probe:
nmap --scan-delay 1s 192.168.1.1

# Wait 500 milliseconds:
nmap --scan-delay 500ms 192.168.1.1
```

### --max-scan-delay <time>
Maximum time between probes (Nmap may go faster):
```bash
nmap --max-scan-delay 2s 192.168.1.1
```

## Host Parallelization

### --min-hostgroup, --max-hostgroup
Control parallel host scanning:
```bash
nmap --min-hostgroup 10 192.168.1.0/24
```

### --min-parallelism, --max-parallelism
Control parallel probes:
```bash
nmap --max-parallelism 1 192.168.1.1
```

## Practical Examples

### Rate-Limited Firewall (100 requests/minute)
```bash
# Stay under 100/min (1.67/sec), use 1 packet per second:
nmap --max-rate 1 -p 8080 192.168.1.1
```

### Slow, Stealthy Scan
```bash
nmap -T1 --scan-delay 1s 192.168.1.1
```

### Fast Scan on Reliable Network
```bash
nmap -T4 --min-rate 1000 192.168.1.0/24
```

## IMPORTANT WARNINGS

### ⚠️ WRONG: Do NOT use -iR for delays
**-iR means "Input Random" - it scans RANDOM INTERNET TARGETS**
```bash
# DANGEROUS - Will scan random IPs globally:
nmap -iR 100  # Scans 100 random internet hosts

# CORRECT - For delays, use --scan-delay:
nmap --scan-delay 1s 192.168.1.1
```

### ⚠️ Rate Limiting Best Practices
1. Use `--max-rate` for hard limits
2. Use `--scan-delay` for minimum delays
3. Combine with `-T2` for polite scanning
4. Monitor with `--stats-every 10s`

```bash
# Professional rate-limited scan:
nmap -T2 --max-rate 10 --scan-delay 100ms -p- 192.168.1.1
```
