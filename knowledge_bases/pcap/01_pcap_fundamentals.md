# PCAP Fundamentals

## What Are PCAP Files

PCAP (Packet Capture) files are binary recordings of raw network traffic captured at the packet level. Every packet traversing a monitored network interface is recorded with full header information and payload data, providing a complete forensic record of network communications. PCAP files are the gold standard for network forensics and are admissible as digital evidence in incident response investigations.

The PCAP format was originally defined by the libpcap library used in tcpdump. A newer variant, PCAPNG (PCAP Next Generation), extends the format with additional metadata such as interface information, name resolution records, and custom comment blocks. Most modern tools support both formats transparently.

## Capture Methods

### tcpdump

tcpdump is the most widely deployed command-line packet capture tool on Unix and Linux systems. Common capture commands for blue team use include:

- `tcpdump -i eth0 -w capture.pcap` captures all traffic on interface eth0.
- `tcpdump -i eth0 -w capture.pcap -c 100000` captures the first 100,000 packets.
- `tcpdump -i eth0 -w capture.pcap host 10.0.0.50` captures traffic to or from a specific host.
- `tcpdump -i eth0 -w capture.pcap -s 0` captures full packet contents with no snaplen truncation.
- `tcpdump -i eth0 -w capture.pcap port 445 or port 139` filters for SMB traffic only.

### Wireshark and tshark

Wireshark provides a graphical interface for live capture and analysis. Its command-line equivalent, tshark, is preferred for automated or scripted capture on servers. Both use the same dissector engine and support identical display filters.

- `tshark -i eth0 -w capture.pcap -b filesize:100000` performs ring-buffer capture with 100MB file rotation.
- `tshark -i eth0 -w capture.pcap -f "tcp port 443"` applies a BPF capture filter for HTTPS traffic.

### Network Taps and SPAN Ports

In enterprise environments, traffic is typically captured using dedicated hardware or switch configuration:

- **Network Taps** are passive hardware devices inserted inline on a network segment. They copy all traffic to a monitoring port without introducing latency or packet loss. Taps are preferred for forensic-grade capture because they do not drop packets under load.
- **SPAN (Switched Port Analyzer) Ports** are configured on managed switches to mirror traffic from one or more ports to a designated monitoring port. SPAN ports may drop packets under heavy load and can miss certain traffic types such as local VLAN traffic or errored frames.
- **Virtual Taps** capture traffic in virtualized or cloud environments. AWS VPC Traffic Mirroring, Azure Network Watcher, and GCP Packet Mirroring provide cloud-native capture capabilities.

### Enterprise Capture Architectures

Large organizations typically deploy full packet capture (FPC) appliances that record all traffic continuously and retain it for days or weeks. Products such as Arkime (formerly Moloch), Stenographer, and commercial solutions index captured traffic for rapid retrieval. Network Detection and Response (NDR) platforms like Zeek and Suricata process traffic in real time and can trigger targeted PCAP capture on detected events.

## PCAP File Format Structure

### Global Header

Every PCAP file begins with a 24-byte global header containing:

- **Magic Number** (4 bytes): `0xA1B2C3D4` for standard byte ordering or `0xD4C3B2A1` for reversed. This tells parsers the endianness of the file.
- **Version** (4 bytes): Major and minor version numbers, typically 2.4.
- **Timezone Offset** (4 bytes): GMT offset in seconds, usually set to 0.
- **Timestamp Accuracy** (4 bytes): Accuracy of timestamps, usually 0.
- **Snap Length** (4 bytes): Maximum bytes captured per packet. A value of 65535 or 262144 indicates full packet capture.
- **Link-Layer Type** (4 bytes): Identifies the data link layer, with 1 representing Ethernet.

### Packet Records

Each captured packet is stored as a record with a 16-byte header followed by the raw packet data:

- **Timestamp Seconds** (4 bytes): Unix epoch seconds when the packet was captured.
- **Timestamp Microseconds** (4 bytes): Microsecond precision within the second.
- **Captured Length** (4 bytes): Number of bytes actually stored (may be less than original if snaplen was applied).
- **Original Length** (4 bytes): Original packet size on the wire.
- **Packet Data** (variable): Raw bytes of the captured packet including all protocol headers.

## Key Fields for Analysis

When analysing PCAP data for security purposes, the following fields are critical:

- **Timestamps**: Establish precise event timelines. Microsecond precision allows ordering of events across multiple captures.
- **Source and Destination IP Addresses**: Identify communicating endpoints. Internal-to-external flows may indicate C2 or exfiltration. Unexpected internal-to-internal flows may indicate lateral movement.
- **Source and Destination Ports**: Reveal the services involved. Well-known ports (22, 80, 443, 445, 3389) indicate standard services, while ephemeral ports (1024-65535) are typically client-side.
- **Protocol**: TCP, UDP, ICMP, and others at Layer 4. Application protocols (HTTP, DNS, SMB, Kerberos) at Layer 7.
- **Payload Data**: Contains application-layer content such as HTTP requests, DNS queries, and SMB commands. Payloads may contain indicators of compromise, credentials, or exfiltrated data.
- **TCP Flags**: SYN, ACK, RST, FIN, PSH, and URG flags indicate connection states and can reveal scanning activity or connection manipulation.
- **Packet Size**: Anomalous sizes can indicate tunneling, beaconing, or exfiltration patterns.

## Limitations of PCAP Analysis

### Encrypted Traffic

TLS/SSL encryption renders payload inspection impossible without the session keys. Modern environments with TLS 1.3 and perfect forward secrecy cannot be decrypted even with the server private key. Analysts must rely on metadata analysis including connection timing, packet sizes, JA3/JA3S fingerprints, certificate information, and SNI (Server Name Indication) fields.

### Partial Captures

Captures that begin after a connection is established will miss the TCP handshake and early protocol negotiation. Captures with snaplen truncation will have incomplete payloads. SPAN port oversubscription may cause dropped packets, creating gaps in the forensic record.

### Large File Sizes

Full packet capture generates substantial data volumes. A saturated 1 Gbps link produces approximately 450 GB of PCAP data per hour. Analysis tools may struggle with files exceeding several gigabytes. Splitting captures by time window, host, or protocol is often necessary for practical analysis.

### Encryption Evasion

Attackers increasingly use encrypted channels, legitimate cloud services, and domain fronting to evade PCAP-based detection. Analysts must combine PCAP analysis with endpoint telemetry, log analysis, and threat intelligence for comprehensive visibility.

### Timestamp Accuracy

If capture systems are not synchronised using NTP, timestamp comparisons across multiple capture points become unreliable. Clock drift can distort event timelines and complicate multi-source correlation.

## Related Topics

For protocol-specific analysis techniques, see `02_network_protocol_analysis.md`. For detection of specific attack patterns within PCAP data, see `03_c2_detection.md` through `08_malware_traffic_patterns.md`. For using PCAP in investigations, see `09_incident_response_pcap.md`.
