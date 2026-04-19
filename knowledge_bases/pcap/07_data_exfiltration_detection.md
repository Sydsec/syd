# Data Exfiltration Detection in PCAP

## Overview

Data exfiltration is the unauthorized transfer of data from the compromised environment to attacker-controlled infrastructure. Detecting exfiltration in packet captures is a critical blue team capability, as it directly determines whether a breach resulted in data loss. Exfiltration maps to MITRE ATT&CK Tactic TA0010 and includes techniques T1041 (Exfiltration Over C2 Channel), T1048 (Exfiltration Over Alternative Protocol), and T1567 (Exfiltration Over Web Service).

## Volume-Based Detection

### Large Outbound Transfers

The simplest exfiltration indicator is an anomalously large volume of data leaving the network:

- Calculate total bytes uploaded per internal host to each external destination.
- Compare against historical baselines for each host. A developer workstation uploading 500 MB to GitHub is normal; an accounting workstation uploading 500 MB to an unknown IP is not.
- Focus on connections where the upload volume significantly exceeds the download volume. Normal web browsing downloads far more than it uploads.
- Aggregate by destination: large transfers to a single external IP or small set of IPs over time may indicate staged exfiltration.

### Upload-to-Download Ratio Analysis

- Normal HTTP browsing produces ratios of roughly 1:10 or higher (downloading 10x more than uploading).
- Interactive applications (video conferencing, cloud sync) produce more balanced ratios.
- Exfiltration produces inverted ratios where upload exceeds download.
- Calculate the upload:download byte ratio for each internal host's connections to external destinations. Ratios above 1:1 to external hosts warrant investigation.

### Sustained Transfer Detection

- Exfiltration may occur as a continuous stream rather than a single burst.
- Look for long-duration TCP connections with sustained data flow in the outbound direction.
- Calculate throughput (bytes per second) for long-duration connections. Sustained upload throughput suggests automated data transfer rather than interactive use.

## DNS Exfiltration

DNS exfiltration encodes stolen data within DNS queries, typically in subdomain labels. This technique is stealthy because DNS traffic is rarely blocked and often unmonitored. MITRE ATT&CK: T1048.003.

### Detection Indicators

- **Encoded subdomain labels**: Base64, base32, or hexadecimal encoded strings in subdomain labels. Legitimate subdomains use readable words; encoded data uses character patterns matching specific encoding schemes.
- **High query rates to a single domain**: DNS exfiltration requires one query per data chunk. Exfiltrating even a small file generates dozens to hundreds of queries to the same parent domain.
- **Large query sizes**: DNS queries with subdomain labels near the maximum length (63 characters per label, 253 characters total) maximise data throughput per query.
- **TXT record responses**: The C2 server may return commands or acknowledgements in TXT records, creating bidirectional communication.
- **Query timing patterns**: Automated exfiltration produces queries at regular intervals or in rapid bursts as data is chunked and transmitted.

### Calculating Exfiltration Volume

- Each DNS query can encode approximately 150-200 bytes of data in subdomain labels.
- 1000 DNS queries can exfiltrate approximately 150-200 KB of data.
- While bandwidth is limited, DNS exfiltration is effective for stealing credentials, configuration files, database exports, and documents.
- Calculate total unique subdomain bytes per parent domain per host to estimate exfiltrated data volume.

## HTTP/HTTPS Exfiltration

### HTTP POST Exfiltration

- POST requests with large request bodies to external hosts may contain exfiltrated data.
- Look for POST requests to URLs that do not correspond to legitimate web applications used by the organisation.
- Repeated POST requests to the same endpoint with varying body sizes suggest ongoing exfiltration.
- Content-Type headers may indicate the data format: `application/octet-stream` for binary data, `multipart/form-data` for file uploads, `application/json` for structured data.

### HTTPS Exfiltration

- HTTPS encrypts the payload, preventing content inspection. Detection relies on metadata.
- Large TLS record sizes in the client-to-server direction indicate data upload.
- Connection duration and total bytes transferred can be calculated from TLS record headers without decryption.
- JA3 fingerprinting can identify the application making the connection, distinguishing browsers from custom exfiltration tools.
- SNI (Server Name Indication) reveals the destination hostname even in encrypted connections.
- Certificate analysis can identify suspicious destinations (self-signed certs, short validity, hosting providers).

### Steganographic and Encoded Exfiltration

- Attackers may encode data within seemingly normal HTTP traffic: cookies, custom headers, URL parameters, or response bodies.
- Large or unusual cookies, especially those that change with each request, may contain encoded data.
- Custom HTTP headers not standard to any protocol (X-Data, X-Session, X-Token with large values) warrant inspection.

## ICMP Tunneling and Exfiltration

ICMP can carry data within echo request/reply payloads. MITRE ATT&CK: T1048.003.

- **Payload size**: Standard ping payloads are 32-56 bytes of padding data. ICMP packets with payloads exceeding 100 bytes are unusual and may contain exfiltrated data.
- **Payload content**: Legitimate ICMP echo payloads contain repeating patterns (Windows uses `abcdefghijklmnopqrstuvwabcdefghi`). Non-standard payload content indicates data smuggling.
- **Frequency**: Normal ICMP traffic is sporadic (occasional pings). High-frequency ICMP between an internal host and an external IP indicates tunneling.
- **Bidirectional communication**: ICMP tunneling tools like icmpsh use both echo requests and echo replies to create a bidirectional channel for commands and data.

## Cloud Storage Exfiltration

Attackers increasingly use legitimate cloud services to exfiltrate data because traffic to major cloud providers is typically allowed through firewalls. MITRE ATT&CK: T1567.002.

### Service Identification

- **Dropbox**: Connections to `*.dropbox.com`, `*.dropboxapi.com`. API uploads via `content.dropboxapi.com`.
- **Google Drive**: Connections to `*.googleapis.com`, specifically `www.googleapis.com/upload/drive/`.
- **OneDrive**: Connections to `*.onedrive.live.com`, `*.sharepoint.com`, `*.live.com`.
- **AWS S3**: Connections to `*.s3.amazonaws.com` or `s3.*.amazonaws.com`.
- **Mega.nz**: Connections to `*.mega.co.nz`, `*.mega.nz`.
- **Pastebin/paste sites**: Connections to `pastebin.com`, `paste.ee`, `ghostbin.com` with POST requests.

### Detection Approach

- Identify DNS queries and connections to cloud storage domains.
- Determine whether the organisation uses these services legitimately. If not, any traffic is suspicious.
- If the service is in use, analyse volume and timing. Large uploads during off-hours from hosts that do not normally use the service are suspicious.
- Monitor for new cloud storage services not previously seen in the environment.

## Timing-Based Exfiltration Detection

Sophisticated attackers use slow, low-volume exfiltration to avoid volume-based detection. MITRE ATT&CK: T1029 (Scheduled Transfer).

### Slow Drip Exfiltration

- Data is sent in small chunks over extended periods (days or weeks).
- Each individual transfer is too small to trigger volume alerts.
- Detection requires aggregating transfer volumes over longer time windows and comparing against baselines.
- Persistent connections to the same external destination over many days, each transferring small amounts of data, are suspicious.

### Scheduled Exfiltration

- Data is exfiltrated at specific times, often during business hours to blend with normal traffic or during off-hours when monitoring may be reduced.
- Repeated data transfers at the same time each day to the same destination indicate automated, scheduled exfiltration.
- Correlate with C2 beaconing patterns. Exfiltration may occur immediately after specific beacon check-ins.

### Burst Exfiltration

- All targeted data is exfiltrated in a single rapid transfer, often just before the attacker expects discovery.
- Detect by monitoring for unusually large single connections or short bursts of high-throughput transfers.

## Practical Analysis Commands

- `tshark -r capture.pcap -qz conv,tcp` generates TCP conversation statistics showing bytes transferred in each direction.
- `tshark -r capture.pcap -Y "http.request.method==POST" -T fields -e ip.src -e ip.dst -e http.host -e http.request.uri -e http.content_length` lists POST requests with content lengths.
- `tshark -r capture.pcap -Y "icmp.type==8" -T fields -e ip.src -e ip.dst -e data.len | awk '$3>100'` finds ICMP echo requests with oversized payloads.
- `tshark -r capture.pcap -Y "dns.qry.name contains '.'" -T fields -e ip.src -e dns.qry.name -e dns.qry.name.len | awk '$3>50'` identifies DNS queries with long names for tunneling detection.

## Related Topics

For DNS-specific exfiltration analysis, see `06_dns_analysis.md`. For C2 channels used as exfiltration paths, see `03_c2_detection.md`. For exfiltration in the context of incident response, see `09_incident_response_pcap.md`.
