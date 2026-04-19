# Using PCAP in Incident Response

## Overview

Packet captures are among the most valuable evidence sources during incident response. PCAP provides an objective, timestamped record of network communications that cannot be easily tampered with by an attacker who has compromised endpoints. This file covers the practical application of PCAP analysis within the incident response workflow.

## PCAP in the IR Workflow

### Evidence Collection and Preservation

Before analysis begins, evidence integrity must be established:

- **Hash the original PCAP file** using SHA-256 immediately upon collection. Record the hash in the evidence log.
- **Work on copies**, never the original. Create a working copy and verify its hash matches the original.
- **Chain of custody**: Document who collected the capture, from which device, when, and how it was transferred and stored.
- **Storage**: PCAP files should be stored on encrypted, write-protected media. Large captures may require dedicated storage infrastructure.
- **Legal considerations**: Ensure packet capture was authorised. Full packet capture may contain sensitive data (personal information, credentials, proprietary data) that has privacy implications.

### Capture Sources During an Incident

- **Existing captures**: Full packet capture appliances (Arkime, Stenographer), NDR platforms (Zeek logs with PCAP), and SIEM-triggered captures provide historical data.
- **On-demand captures**: Deploy targeted captures on key network segments once an incident is identified. Prioritise segments connecting compromised hosts to the internet and to other internal systems.
- **Endpoint captures**: Windows `netsh trace` or `pktmon` can capture traffic on compromised hosts if the endpoint is still accessible and trustworthy.
- **Cloud environments**: AWS VPC Flow Logs provide metadata (not full PCAP). VPC Traffic Mirroring provides full packet capture. Azure Network Watcher and GCP Packet Mirroring offer similar capabilities.

## Building an Attack Timeline

PCAP timestamps provide microsecond-precision event ordering, making packet captures ideal for timeline construction.

### Timeline Construction Steps

1. **Identify the earliest known indicator**: Start with a known-compromised host or a confirmed malicious IP and find the earliest connection between them.
2. **Trace backwards**: From the first C2 connection, look for preceding events: the initial compromise (exploit delivery, phishing payload download), reconnaissance activity, or vulnerability scanning.
3. **Trace forwards**: From the initial compromise, follow the attacker's actions: C2 establishment, internal reconnaissance, credential theft, lateral movement, privilege escalation, data staging, and exfiltration.
4. **Correlate across sources**: Align PCAP timestamps with Windows Event Log timestamps, Sysmon events, EDR detections, and firewall logs. Ensure all sources are synchronised via NTP.

### Key Timeline Events to Extract from PCAP

- First connection to known-malicious IP or domain (initial compromise or C2).
- DNS queries for attacker infrastructure (pre-connection resolution).
- File downloads (malware staging, tools transfer) via HTTP, SMB, or FTP.
- Authentication events (NTLM, Kerberos) indicating credential use.
- Lateral movement connections (SMB to ADMIN$/IPC$, RDP, WinRM, WMI).
- Data exfiltration connections (large outbound transfers, DNS tunneling).
- Last known attacker activity (most recent C2 communication or lateral movement).

## Identifying Patient Zero

The initial point of compromise is critical for understanding how the attacker gained access:

### Web-Based Compromise

- Look for HTTP requests that downloaded executable content, scripts, or documents with macros from external sources.
- Identify redirect chains from legitimate sites through compromised intermediaries to exploit kit landing pages.
- Check for drive-by download patterns: a single GET request followed by executable content delivery and then outbound C2 connections.

### Email-Based Compromise

- If email traverses a network segment with PCAP coverage, look for SMTP traffic containing malicious attachments or URLs.
- More commonly, identify the first endpoint to establish a C2 connection after receiving a phishing email. Correlate the C2 connection timestamp with email delivery logs.

### Direct Exploitation

- Look for inbound connections to public-facing services followed by anomalous behaviour from the target host (new outbound connections, internal scanning).
- Identify exploit traffic patterns: connections to vulnerable services followed by shellcode delivery and reverse shell establishment.

## Scoping the Breach

Determining which systems were compromised is essential for containment and recovery:

### Communication Mapping

- Extract all internal hosts that communicated with known C2 infrastructure.
- Map all internal-to-internal connections from confirmed compromised hosts, focusing on administrative protocols (SMB, RDP, WinRM, SSH, WMI).
- Identify all authentication events originating from compromised hosts to determine which credentials were used and which systems were accessed.

### Tshark Commands for Scoping

- `tshark -r capture.pcap -Y "ip.addr==MALICIOUS_IP" -T fields -e ip.src -e ip.dst -e tcp.dstport | sort -u` identifies all hosts communicating with a known-malicious IP.
- `tshark -r capture.pcap -Y "ip.src==COMPROMISED_IP && tcp.dstport==445" -T fields -e ip.dst | sort -u` lists all SMB targets from a compromised host.
- `tshark -r capture.pcap -Y "ip.src==COMPROMISED_IP && (tcp.dstport==5985 || tcp.dstport==5986)" -T fields -e ip.dst | sort -u` lists WinRM targets.
- `tshark -r capture.pcap -Y "ip.src==COMPROMISED_IP && tcp.dstport==3389" -T fields -e ip.dst | sort -u` lists RDP targets.
- `tshark -r capture.pcap -Y "ip.src==COMPROMISED_IP" -T fields -e ip.dst -e tcp.dstport | sort | uniq -c | sort -rn` provides a frequency analysis of all outbound connections from a compromised host.

### Data Exposure Assessment

- Identify all data transferred from internal systems to external destinations.
- Calculate total bytes exfiltrated using TCP conversation statistics.
- Reconstruct transferred files from HTTP and SMB streams where possible.
- Identify which internal file shares, databases, or applications were accessed by compromised accounts.

## Correlating PCAP with Other Evidence Sources

### Windows Event Logs

- Logon events (Event ID 4624, 4625) correlate with NTLM and Kerberos authentication in PCAP.
- Service creation events (Event ID 7045) correlate with SCM activity visible in SMB named pipe traffic.
- Process creation events (Event ID 4688) correlate with execution following lateral movement connections.
- PowerShell events (Event ID 4103, 4104) correlate with WinRM traffic timestamps.

### Sysmon

- Network connection events (Sysmon Event ID 3) map directly to PCAP connections, adding the responsible process name and ID.
- DNS query events (Sysmon Event ID 22) complement DNS traffic analysis with the querying process.
- File creation events (Sysmon Event ID 11) correlate with file transfers visible in SMB or HTTP traffic.

### EDR and Antivirus

- EDR alert timestamps can be correlated with PCAP to understand the network context of detected malicious activity.
- False negative analysis: PCAP may reveal compromised hosts that EDR did not detect, identifying gaps in endpoint coverage.

### Firewall and Proxy Logs

- Firewall connection logs validate PCAP findings and extend visibility to segments without packet capture.
- Proxy logs provide URL-level detail for HTTP/HTTPS connections, complementing PCAP metadata analysis for encrypted traffic.

## Key Questions PCAP Answers During IR

1. **When did the compromise begin?** First connection to attacker infrastructure.
2. **How did the attacker get in?** Exploit delivery, malware download, or credential theft visible in traffic.
3. **What systems are compromised?** All hosts communicating with C2 or targeted by lateral movement.
4. **What credentials were used?** Usernames visible in NTLM and Kerberos authentication.
5. **What data was taken?** Volume and destination of outbound transfers from compromised hosts.
6. **Is the attacker still active?** Ongoing C2 beaconing indicates continued access.
7. **What tools did the attacker use?** Network signatures of C2 frameworks, remote access tools, and exploitation tools.

## Evidence Handling Best Practices

- Never modify the original capture files.
- Document all analysis steps and findings with timestamps.
- Export relevant packet subsets as separate PCAP files for inclusion in the investigation report.
- Screen captures of Wireshark displays showing key evidence are useful for non-technical stakeholders.
- Retain all PCAP evidence according to the organisation's evidence retention policy and any applicable legal hold requirements.

## Related Topics

For specific attack detection techniques to apply during IR, see `03_c2_detection.md` through `08_malware_traffic_patterns.md`. For proactive hunting that may prevent future incidents, see `10_threat_hunting_with_pcap.md`. For fundamental PCAP concepts, see `01_pcap_fundamentals.md`.
