# Command and Control (C2) Detection in PCAP

## Overview of C2 Communication

Command and Control infrastructure allows attackers to maintain persistent access to compromised systems, issue commands, and receive results. Detecting C2 traffic in packet captures is one of the highest-value activities for blue team analysts. C2 communication maps to MITRE ATT&CK Tactic TA0011 (Command and Control) and encompasses numerous techniques including T1071 (Application Layer Protocol), T1573 (Encrypted Channel), T1568 (Dynamic Resolution), and T1572 (Protocol Tunneling).

## Beaconing Detection

Beaconing is the most common C2 communication pattern. An implant periodically contacts its C2 server at regular intervals to check for new commands. Detecting beacons in PCAP requires statistical analysis of connection timing.

### Regular Interval Analysis

- Calculate the time delta between consecutive connections from a host to the same destination.
- Consistent intervals (e.g., exactly 60 seconds, 300 seconds) are strong indicators of automated C2 beaconing.
- Standard deviation of inter-connection times approaching zero indicates machine-generated timing.
- Human-initiated browsing produces irregular, unpredictable timing patterns.

### Jitter Analysis

Sophisticated C2 frameworks add randomised jitter to beacon intervals to evade detection. Cobalt Strike, for example, supports configurable jitter percentages (typically 10-50%). Detection approaches include:

- Calculate the mean and standard deviation of inter-connection intervals. Even with jitter, the mean will cluster around the base interval.
- A 60-second beacon with 20% jitter will produce intervals between 48 and 72 seconds. The mean remains approximately 60 seconds.
- Look for connections where the coefficient of variation (standard deviation divided by mean) is between 0.05 and 0.50, as this range is characteristic of jittered beacons.
- Legitimate applications rarely produce regular timing patterns with controlled jitter.

### Packet Size Consistency

C2 check-in packets (when no commands are pending) tend to have consistent sizes because the implant sends the same heartbeat payload each time. Look for:

- Repeated connections to the same destination with nearly identical request and response sizes.
- Small, consistent request sizes (check-in) with occasional large responses (command delivery).
- Small, consistent response sizes (no pending commands) with occasional large requests (data upload or command output).

## HTTP/HTTPS C2 Detection

HTTP and HTTPS are the most common C2 transport protocols because they blend with normal web traffic and pass through most firewalls.

### User Agent String Analysis

- Missing User-Agent headers are uncommon in legitimate browsers and may indicate custom C2 implants.
- Outdated or unusual User-Agent strings that do not match the operating system of the source host are suspicious. A Windows 10 machine sending a Linux Firefox User-Agent warrants investigation.
- Known C2 User-Agent strings include default strings from Cobalt Strike (e.g., "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)"), Metasploit, and other frameworks.
- Multiple hosts sending identical, uncommon User-Agent strings suggests a shared implant.

### URI Pattern Analysis

- C2 frameworks use configurable URI paths. Default Cobalt Strike Malleable C2 profiles often use paths like `/submit.php`, `/pixel`, `/updates`, or paths mimicking CDN traffic.
- Repetitive requests to the same small set of URIs from a host, especially without corresponding web page resources (CSS, JavaScript, images), indicate C2 rather than browsing.
- URIs with encoded or random-looking path components may carry encoded commands or session identifiers.
- POST requests to the same URI with consistent body sizes suggest command result uploads.

### JA3 and JA3S Fingerprinting

JA3 fingerprints are MD5 hashes derived from TLS Client Hello parameters (TLS version, cipher suites, extensions, elliptic curves). JA3S fingerprints the Server Hello response.

- Known C2 framework JA3 hashes are published in threat intelligence feeds. Cobalt Strike with default settings produces recognisable JA3 fingerprints.
- A single JA3 hash used by multiple internal hosts to contact the same external destination is a strong indicator of a shared implant.
- JA3 hashes that do not match any known browser or application fingerprint warrant investigation.
- JA3S fingerprints can identify C2 servers even when the domain changes, because the TLS server configuration remains consistent.

### Certificate Analysis

- Self-signed certificates with default or random subject fields are common in hastily deployed C2 infrastructure.
- Certificates with very short validity periods, unusual issuer names, or mismatched Common Name and Subject Alternative Name fields are suspicious.
- Certificate serial numbers and issuer information can be correlated across multiple C2 servers to identify infrastructure clusters.

## DNS C2 Detection

DNS is frequently used as a C2 channel because DNS traffic is rarely blocked and often not inspected. See `06_dns_analysis.md` for comprehensive DNS analysis techniques. Key C2-specific indicators include:

- **High-frequency DNS queries** to a single domain from one host, far exceeding normal resolution patterns.
- **Long subdomain labels** (over 30 characters) that contain encoded data. Legitimate subdomains are typically short and human-readable.
- **TXT record queries and responses** with large payloads. TXT records can carry encoded commands and data, and legitimate TXT queries are relatively rare from endpoints.
- **Domain Generation Algorithm (DGA) detection**: Queries for domains with high entropy, consonant-heavy strings, or algorithmically generated patterns. DGA domains are used to make C2 infrastructure resilient to takedowns. MITRE ATT&CK T1568.002.
- **DNS tunneling**: Sustained, high-volume DNS query/response traffic to a single authoritative domain. Tools like dnscat2, iodine, and dns2tcp embed bidirectional data in DNS queries and responses.

## Known C2 Framework Signatures

### Cobalt Strike

- Default beaconing intervals of 60 seconds with 0-50% jitter.
- HTTP C2 uses configurable Malleable C2 profiles, but default profiles have recognisable URI patterns and response structures.
- Named pipe patterns: `\\.\pipe\msagent_*` (default), `\\.\pipe\MSSE-*`, `\\.\pipe\status_*`, `\\.\pipe\postex_*`.
- Default JA3 fingerprint: `72a589da586844d7f0818ce684948eea` (varies by Java version).
- DNS beaconing uses A record queries with encoded data in the subdomain.
- Beacon metadata in HTTP Cookie or Authorization headers.

### Metasploit / Meterpreter

- Reverse TCP connections often to port 4444, 4443, or 8443 (defaults).
- HTTP/HTTPS stager URIs follow patterns like `/random_4chars` (e.g., `/aB3d`).
- Meterpreter TLV (Type-Length-Value) protocol structure in TCP payloads.
- Reverse HTTP handlers use predictable URI checksum patterns based on payload architecture.

### Sliver

- Default mTLS C2 on port 8888 or 443.
- HTTP C2 uses configurable paths but defaults include `/start`, `/session`, `/poll`.
- WireGuard-based C2 on UDP port 51820.
- DNS C2 with configurable parent domains.

### Havoc

- Default HTTPS C2 with custom protocol layered inside TLS.
- Configurable sleep and jitter intervals.
- Demon agent produces recognisable HTTP header patterns in default configuration.

## MITRE ATT&CK Mapping

- **T1071.001** (Web Protocols): HTTP/HTTPS C2 communication.
- **T1071.004** (DNS): DNS-based C2 channels.
- **T1573.001** (Symmetric Cryptography): Encrypted C2 payloads within HTTP or custom protocols.
- **T1573.002** (Asymmetric Cryptography): TLS/mTLS C2 channels.
- **T1568.002** (Domain Generation Algorithms): DGA for resilient C2 infrastructure.
- **T1572** (Protocol Tunneling): DNS tunneling, ICMP tunneling, SSH tunneling for C2.
- **T1571** (Non-Standard Port): C2 on unusual ports to evade port-based filtering.
- **T1090** (Proxy): C2 through proxy infrastructure, redirectors, or CDN fronting.

## Detection Priorities

When analysing PCAP for C2, prioritise the following in order:

1. Identify all external destinations contacted by internal hosts and check against threat intelligence.
2. Perform beaconing analysis on connections to external hosts, looking for regular intervals.
3. Analyse HTTP traffic for anomalous User-Agent strings, URI patterns, and request/response size consistency.
4. Generate JA3 fingerprints for all TLS connections and compare against known C2 hashes.
5. Analyse DNS traffic for tunneling, DGA, and high-frequency query patterns.
6. Investigate any protocol running on a non-standard port.

## Related Topics

For DNS-specific detection techniques, see `06_dns_analysis.md`. For data leaving the network via C2 channels, see `07_data_exfiltration_detection.md`. For malware-specific traffic patterns, see `08_malware_traffic_patterns.md`.
