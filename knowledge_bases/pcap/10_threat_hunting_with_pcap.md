# Threat Hunting with PCAP

## Overview

Threat hunting is the proactive search for adversary activity that has evaded automated detection. Unlike incident response, which is triggered by alerts, threat hunting begins with a hypothesis and uses available data to confirm or refute it. Network packet captures provide rich, objective data for hypothesis-driven hunting. Proactive hunting maps to the "assume breach" security model and leverages the MITRE ATT&CK framework to structure search activities.

## Hypothesis-Driven Hunting

### The Hunting Process

1. **Form a hypothesis**: Based on threat intelligence, industry trends, or MITRE ATT&CK techniques. Example: "An adversary may be using DNS tunneling to exfiltrate data from our environment."
2. **Identify data sources**: Determine which PCAPs, logs, and telemetry sources can confirm or refute the hypothesis.
3. **Develop search queries**: Create specific filters, statistical analyses, or detection logic to test the hypothesis against available data.
4. **Execute and analyse**: Run queries, review results, investigate anomalies.
5. **Document findings**: Record the hypothesis, methodology, data analysed, findings, and any resulting actions regardless of whether threats were found.

### Example Hypotheses for PCAP Hunting

- "Adversaries are beaconing to external C2 infrastructure using HTTPS on standard ports." Test by performing statistical analysis of connection intervals to external hosts.
- "Compromised hosts are performing internal reconnaissance via SMB." Test by identifying hosts making SMB connections to an unusual number of internal destinations.
- "An attacker is exfiltrating data via DNS." Test by analysing DNS query lengths, volumes, and encoding patterns per internal host.
- "Malware is using domain generation algorithms." Test by measuring entropy of queried domain names and NXDOMAIN response rates.
- "Lateral movement is occurring via WinRM." Test by identifying WinRM connections between hosts that do not have a historical WinRM communication pattern.

## Long-Term Traffic Baselining

Effective threat hunting requires understanding what is normal so that anomalies can be identified:

### Establishing Baselines

- **Connection frequency**: How many connections does each host typically make per hour to external destinations? To internal destinations?
- **Protocol distribution**: What percentage of traffic is HTTP/HTTPS, DNS, SMB, RDP, SSH? Significant shifts in protocol distribution may indicate new activity.
- **Destination diversity**: How many unique external IPs or domains does each host contact daily? A sudden increase may indicate compromise.
- **Data volume patterns**: What are normal upload and download volumes per host? Per department? Per time of day?
- **DNS query patterns**: What is the normal query rate per host? What TLDs and domains are normally queried?

### Anomaly Detection Against Baselines

- **New destinations**: Internal hosts contacting external IPs or domains never seen before in the environment. First-seen analysis is a powerful hunting technique.
- **Volume anomalies**: Hosts transferring significantly more data than their historical average, especially in the outbound direction.
- **Temporal anomalies**: Network activity during unusual hours (late night, weekends) from hosts that are normally inactive during those periods.
- **Protocol anomalies**: Hosts using protocols they have never used before (e.g., a workstation suddenly generating SSH traffic to an external IP).

## Hunting for Living-off-the-Land Network Activity

Living-off-the-Land Binaries (LOLBins) use legitimate system tools for malicious purposes. Their network activity blends with normal traffic but exhibits subtle anomalies:

### PowerShell Remoting

- WinRM traffic (ports 5985/5986) from workstations to other workstations is unusual. Most legitimate WinRM usage flows from administrative jump boxes to servers.
- High-volume WinRM sessions (many HTTP POST requests) may indicate PowerShell scripts executing remotely.
- Correlate WinRM traffic with endpoint PowerShell logging for complete visibility.

### BITS Transfer

- Background Intelligent Transfer Service (BITS) uses HTTP/HTTPS for file transfers. Attackers use `bitsadmin.exe` or PowerShell `Start-BitsTransfer` to download tools.
- BITS traffic uses specific HTTP headers (`BITS-Packet-Type`, `BITS-Session-Id`) identifiable in unencrypted captures.
- Downloads from unusual external sources using BITS deserve investigation.

### Certutil Download

- `certutil.exe -urlcache -split -f URL` downloads files via HTTP. The HTTP requests appear as standard GET requests but are initiated by certutil.
- Correlate HTTP download timestamps with endpoint process creation logs to identify certutil-initiated downloads.

### Windows Admin Tools

- `net use` commands generate SMB traffic for share mapping.
- `sc.exe` generates SCM traffic (svcctl named pipe) for remote service management.
- `reg.exe` generates remote registry traffic (winreg named pipe).
- These generate legitimate traffic patterns, so hunting focuses on unusual source-destination pairs and timing.

## Hunting Encrypted C2

Modern C2 frameworks use TLS encryption, requiring metadata-based hunting techniques:

### JA3/JA3S Fingerprinting

- Generate JA3 hashes for all outbound TLS connections in the PCAP.
- Compare against databases of known C2 JA3 hashes (available from threat intelligence providers and open-source repositories).
- Identify JA3 hashes that do not match any known legitimate application. Unknown JA3 hashes warrant investigation.
- Look for the same uncommon JA3 hash appearing across multiple internal hosts, which may indicate a shared implant.
- JA3S (server-side) fingerprints can identify C2 server software regardless of domain or IP changes.

### Certificate Hunting

- Extract certificate metadata from TLS handshakes: issuer, subject, validity period, serial number.
- Hunt for self-signed certificates used in connections to external hosts. Legitimate services overwhelmingly use CA-signed certificates.
- Certificates with default or generic subject fields (e.g., "localhost", "server", random strings) are suspicious.
- Short validity periods (under 90 days) combined with other suspicious indicators warrant investigation.
- Certificates issued by free CAs (Let's Encrypt) are legitimate but are also heavily used by attackers for quick infrastructure deployment.

### TLS Metadata Analysis

- **Connection duration**: C2 connections are often persistent or regularly recurring. Legitimate HTTPS connections are typically short-lived (page load) or match known long-lived services (streaming, websockets).
- **Packet size patterns**: C2 beacons produce consistent request sizes. Legitimate HTTPS traffic has variable request sizes.
- **SNI analysis**: The Server Name Indication field reveals the intended hostname. Missing SNI or SNI that does not match DNS resolution results is suspicious.

## MITRE ATT&CK-Based Hunting

Structure hunting campaigns around ATT&CK techniques:

### Initial Access (TA0001)

- **T1190 (Exploit Public-Facing Application)**: Hunt for inbound connections to public-facing services followed by anomalous outbound connections from those servers.
- **T1566.002 (Spearphishing Link)**: Hunt for endpoint connections to recently registered domains or domains with low reputation scores.

### Execution (TA0002)

- **T1059.001 (PowerShell)**: Hunt for WinRM traffic indicating remote PowerShell execution.

### Command and Control (TA0011)

- **T1071.001 (Web Protocols)**: Hunt for HTTP/HTTPS beaconing using statistical interval analysis.
- **T1071.004 (DNS)**: Hunt for DNS tunneling using query length and volume analysis.
- **T1573 (Encrypted Channel)**: Hunt using JA3 fingerprinting and certificate analysis.
- **T1571 (Non-Standard Port)**: Hunt for known protocols on unexpected ports.

### Exfiltration (TA0010)

- **T1048 (Exfiltration Over Alternative Protocol)**: Hunt for DNS and ICMP data channels.
- **T1567 (Exfiltration Over Web Service)**: Hunt for connections to cloud storage services.

## Network Traffic Analysis Tools

### Zeek (formerly Bro)

Zeek processes PCAP files and produces structured log files for each protocol (conn.log, dns.log, http.log, ssl.log, files.log). These logs are optimised for hunting and analysis:

- `conn.log` provides connection metadata: duration, bytes, packets, protocol, service.
- `dns.log` provides parsed DNS queries and responses.
- `ssl.log` provides TLS metadata including JA3 hashes, certificate information, and SNI.
- `files.log` identifies files transferred over the network with hashes.

### Suricata

Suricata performs signature-based and protocol-based detection on PCAP:

- Rule-based detection using Emerging Threats and other rule sets.
- Protocol identification regardless of port (application-layer detection).
- File extraction from HTTP, SMB, and other protocols.
- JSON-formatted EVE log output for integration with SIEM platforms.

### NetworkMiner

NetworkMiner extracts artefacts from PCAP for forensic analysis:

- Reconstructs transferred files (images, documents, executables).
- Extracts credentials from cleartext protocols.
- Identifies operating systems via passive OS fingerprinting.
- Maps host communication patterns graphically.

### Arkime (formerly Moloch)

Arkime provides indexed full packet capture with a web interface:

- Supports petabyte-scale PCAP storage and retrieval.
- SPI (Session Profile Information) enables rapid searching across large capture sets.
- Integration with Suricata and Zeek for enriched metadata.

## Practical Hunting Workflow

1. Start with Zeek logs generated from the PCAP for high-level analysis.
2. Identify anomalies in connection patterns, DNS queries, or TLS metadata.
3. Drill into specific sessions using Wireshark or tshark for deep packet inspection.
4. Extract IOCs (IPs, domains, hashes, JA3 fingerprints) from confirmed malicious traffic.
5. Search the full PCAP dataset for additional connections matching extracted IOCs.
6. Correlate network findings with endpoint telemetry for complete picture.
7. Document findings and update detection rules to catch similar activity in the future.

## Related Topics

For C2-specific detection patterns, see `03_c2_detection.md`. For DNS hunting techniques, see `06_dns_analysis.md`. For using PCAP findings in incident response, see `09_incident_response_pcap.md`. For fundamental PCAP concepts and capture methods, see `01_pcap_fundamentals.md`.
