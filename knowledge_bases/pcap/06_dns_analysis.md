# DNS Traffic Analysis for Threat Hunting

## Overview

DNS (Domain Name System) traffic is one of the most valuable data sources in PCAP analysis. Almost all network activity generates DNS queries, making DNS a comprehensive record of which domains were contacted. Attackers also abuse DNS for C2 communication, data exfiltration, and infrastructure resilience. DNS analysis maps to MITRE ATT&CK techniques T1071.004 (DNS), T1568.002 (Domain Generation Algorithms), and T1048.003 (Exfiltration Over Unencrypted Non-C2 Protocol).

## DNS Traffic Baseline

Before identifying anomalies, analysts must understand normal DNS patterns:

- Internal hosts should query only internal DNS resolvers (recursive resolvers configured via DHCP or GPO).
- Direct DNS queries from endpoints to external resolvers (8.8.8.8, 1.1.1.1) bypass internal security controls and are suspicious in managed environments.
- Normal DNS query volume is typically 1,000-10,000 queries per host per day, depending on user activity and applications.
- Query types are predominantly A (IPv4 address) and AAAA (IPv6 address), with occasional MX, SRV, PTR, and SOA queries.
- TXT record queries from endpoints are relatively rare in normal operations.

## Domain Generation Algorithm (DGA) Detection

DGAs generate large numbers of pseudo-random domain names algorithmically. Malware queries these domains until it finds one that resolves, indicating an active C2 server. DGA detection is critical for identifying compromised hosts. MITRE ATT&CK: T1568.002.

### Entropy Analysis

- Legitimate domain names have moderate entropy because they use recognisable words and patterns (e.g., `mail.google.com`, `cdn.example.org`).
- DGA domains have high character entropy because they are generated from hashes or PRNG output (e.g., `xkqjr7mzpw.com`, `a3b9f2e1d.net`).
- Calculate Shannon entropy for each queried domain label. Entropy above 3.5-4.0 bits per character is suspicious.
- Exception: CDN and cloud service domains may have high-entropy subdomains that are legitimate (e.g., `d3xxxxxxxxxx.cloudfront.net`).

### Character Distribution Patterns

- Legitimate domains use common letter frequencies similar to natural language.
- DGA domains often have unusual character distributions: excessive consonant clusters, uniform character distribution, or lack of vowels.
- Bigram analysis (frequency of two-character pairs) can distinguish DGA from legitimate domains. Legitimate domains contain common bigrams like "th", "er", "in", while DGA domains contain rare combinations.

### NXDomain (NXDOMAIN) Rate

- DGA domains that have not been registered by the attacker return NXDOMAIN responses.
- A host generating a high rate of NXDOMAIN responses is a strong indicator of DGA activity.
- Normal NXDOMAIN rates are below 5% of total queries. DGA-infected hosts may produce 50-90% NXDOMAIN rates.
- Track NXDOMAIN rates per source IP to identify individual compromised hosts.

### Temporal Patterns

- DGA queries often occur in bursts as the malware iterates through its domain list.
- Some DGA algorithms are time-based, generating different domains daily. Queries for yesterday's DGA domains mixed with today's indicate the malware has been active for multiple days.

## DNS Tunneling Detection

DNS tunneling encodes arbitrary data within DNS queries and responses, creating a covert communication channel. Tools include dnscat2, iodine, dns2tcp, and Cobalt Strike DNS beacons. MITRE ATT&CK: T1071.004, T1572.

### Query Length Analysis

- Normal DNS queries have short labels (average 10-15 characters per subdomain label).
- DNS tunneling uses long subdomain labels (30-63 characters, the maximum label length) to maximise data throughput.
- Calculate the average and maximum subdomain label lengths per queried domain. Labels consistently near the 63-character maximum indicate tunneling.

### Query Volume Analysis

- Normal DNS produces sporadic queries as users browse and applications resolve addresses.
- DNS tunneling produces sustained, high-volume queries to a single parent domain because every data transfer requires a DNS query.
- A single host querying the same parent domain hundreds or thousands of times per hour is a strong tunneling indicator.
- Volume per domain per hour exceeding normal thresholds warrants investigation.

### Record Type Analysis

- DNS tunneling preferentially uses TXT records (maximum response size ~4000 bytes), CNAME records, MX records, or NULL records.
- A host making an unusual number of TXT or NULL record queries to a single domain is suspicious.
- Legitimate TXT queries are primarily for SPF records, DKIM verification, and service discovery, and are typically initiated by mail servers, not endpoints.

### Encoding Detection

- Tunneled data is typically encoded in base32, base64, or hexadecimal within subdomain labels.
- Base32 encoding produces strings using characters A-Z and 2-7 with possible padding (=).
- Base64 encoding in DNS uses URL-safe variants (replacing + and / with - and _).
- Hexadecimal encoding produces labels using only characters 0-9 and a-f.
- Detect by checking if subdomain labels match encoding character set patterns and have high entropy.

## DNS Beaconing

DNS beaconing uses periodic DNS queries to a C2 domain to check for commands, similar to HTTP beaconing:

- Regular interval queries to the same domain, with or without jitter.
- Query content may vary (encoded data in subdomains) but the parent domain remains constant.
- Response content varies based on whether the C2 server has pending commands.
- Calculate inter-query intervals for each (source, destination domain) pair. Consistent intervals indicate automated beaconing.
- Correlate DNS beacon timing with HTTP or TCP beaconing to the resolved IP addresses.

## Suspicious TLD and Domain Analysis

### Newly Registered Domains

- Domains registered within the past 30 days are significantly more likely to be malicious.
- WHOIS age checking is performed outside PCAP analysis but domain lists extracted from PCAP should be checked against domain age databases.
- Threat intelligence feeds provide lists of newly observed domains.

### Suspicious TLDs

- While no TLD is inherently malicious, certain TLDs have higher abuse rates: `.tk`, `.ml`, `.ga`, `.cf`, `.gq` (free registration), `.top`, `.xyz`, `.pw`, `.cc`, `.icu`.
- Queries to uncommon TLDs from hosts that normally only access mainstream domains warrant attention.

### Domain Reputation

- Extract all unique domains from DNS queries and check against threat intelligence feeds.
- Domains that resolve to known malicious IP ranges, hosting providers associated with bulletproof hosting, or IP addresses listed in abuse databases are high priority.

## DNS over HTTPS (DoH) Evasion

Attackers use DoH to encrypt DNS queries, bypassing traditional DNS monitoring:

- DoH traffic appears as standard HTTPS connections to known DoH providers (dns.google, cloudflare-dns.com, doh.opendns.com).
- Detect by identifying HTTPS connections to known DoH resolver IP addresses.
- SNI (Server Name Indication) in TLS Client Hello reveals the destination as a DoH provider.
- Endpoints in managed environments should not be making direct DoH queries if internal DNS is configured.
- MITRE ATT&CK: T1071.001 (Web Protocols) when DNS is tunneled over HTTPS.

## Reverse DNS for Attacker Identification

- Perform reverse DNS lookups on external IP addresses found in PCAP to identify attacker infrastructure.
- PTR records may reveal hosting provider information, VPS providers, or Tor exit nodes.
- Cluster external IPs by ASN (Autonomous System Number) to identify infrastructure patterns.
- IPs resolving to known cloud providers (AWS, Azure, DigitalOcean, Linode) used for C2 are common in modern attacks.

## Practical Analysis Commands

- `tshark -r capture.pcap -Y "dns.qry.type==1" -T fields -e ip.src -e dns.qry.name | sort | uniq -c | sort -rn` lists A record queries by frequency.
- `tshark -r capture.pcap -Y "dns.flags.rcode==3" -T fields -e ip.src -e dns.qry.name` extracts NXDOMAIN responses to identify DGA.
- `tshark -r capture.pcap -Y "dns.qry.type==16" -T fields -e ip.src -e dns.qry.name` lists TXT record queries for tunneling detection.
- `tshark -r capture.pcap -Y "dns" -T fields -e dns.qry.name | awk -F. '{print $(NF-1)"."$NF}' | sort | uniq -c | sort -rn` counts queries per parent domain.

## Related Topics

For C2 communication that uses DNS channels, see `03_c2_detection.md`. For DNS-based data exfiltration techniques, see `07_data_exfiltration_detection.md`. For integrating DNS analysis into threat hunting workflows, see `10_threat_hunting_with_pcap.md`.
