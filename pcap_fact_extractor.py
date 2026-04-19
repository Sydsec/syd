"""
PCAP Fact Extractor for Syd V3 - Blue Team Edition
Analyses packet capture files and extracts structured facts for LLM consumption.
Uses scapy for parsing - no external tools required.
"""

import os
import re
import math
import struct
import socket
import collections
import ipaddress
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Tuple
from pathlib import Path
from datetime import datetime

# ── Import scapy (lazy - only when needed) ────────────────────────────────────
def _get_scapy():
    try:
        from scapy.all import rdpcap, IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR, DNSRR
        from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
        from scapy.layers.l2 import Ether
        return True
    except ImportError:
        return False

# ── Data structures ───────────────────────────────────────────────────────────

@dataclass
class HostInfo:
    ip: str
    mac: str = ""
    hostname: str = ""
    ports_seen: Set[int] = field(default_factory=set)
    protocols: Set[str] = field(default_factory=set)
    bytes_sent: int = 0
    bytes_recv: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    is_internal: bool = False

@dataclass
class DNSQuery:
    timestamp: float
    src_ip: str
    query: str
    qtype: str
    response: str = ""
    nx_domain: bool = False

@dataclass
class HTTPRequest:
    timestamp: float
    src_ip: str
    dst_ip: str
    dst_port: int
    method: str
    host: str
    uri: str
    user_agent: str
    content_length: int = 0
    response_code: int = 0

@dataclass
class NetworkFlow:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    packet_count: int = 0
    byte_count: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    flags_seen: Set[str] = field(default_factory=set)

@dataclass
class BeaconCandidate:
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str
    interval_avg: float      # seconds
    interval_jitter: float   # std dev
    packet_count: int
    confidence: str          # HIGH / MEDIUM / LOW

@dataclass
class SuspiciousActivity:
    timestamp: float
    src_ip: str
    dst_ip: str
    category: str            # C2_BEACON / LATERAL_MOVEMENT / EXFIL / PORT_SCAN / DNS_TUNNEL / CREDENTIAL / RECON
    description: str
    severity: str            # CRITICAL / HIGH / MEDIUM / LOW
    mitre_technique: str = ""
    evidence: str = ""

@dataclass
class CredentialCapture:
    timestamp: float
    src_ip: str
    dst_ip: str
    protocol: str
    username: str = ""
    hash_value: str = ""
    cleartext: str = ""
    auth_type: str = ""      # NTLM / Kerberos / Basic / FTP / Telnet

@dataclass
class PCAPFacts:
    # File metadata
    filename: str = ""
    file_size_mb: float = 0.0
    total_packets: int = 0
    capture_start: float = 0.0
    capture_end: float = 0.0
    capture_duration_s: float = 0.0

    # Hosts
    hosts: Dict[str, HostInfo] = field(default_factory=dict)
    internal_ranges: List[str] = field(default_factory=list)

    # Protocol breakdown
    protocol_counts: Dict[str, int] = field(default_factory=dict)

    # DNS
    dns_queries: List[DNSQuery] = field(default_factory=list)
    unique_domains: Set[str] = field(default_factory=set)
    nx_domains: Set[str] = field(default_factory=set)
    suspicious_domains: Set[str] = field(default_factory=set)
    dga_candidates: List[str] = field(default_factory=list)

    # HTTP
    http_requests: List[HTTPRequest] = field(default_factory=list)
    user_agents: Dict[str, int] = field(default_factory=dict)
    suspicious_user_agents: List[str] = field(default_factory=list)

    # Flows
    flows: Dict[str, NetworkFlow] = field(default_factory=dict)
    top_talkers: List[Tuple[str, int]] = field(default_factory=list)

    # Beaconing
    beacon_candidates: List[BeaconCandidate] = field(default_factory=list)

    # Suspicious activity
    suspicious_activities: List[SuspiciousActivity] = field(default_factory=list)

    # Credentials
    credential_captures: List[CredentialCapture] = field(default_factory=list)

    # Lateral movement
    smb_connections: List[Dict] = field(default_factory=list)
    rdp_connections: List[Dict] = field(default_factory=list)
    winrm_connections: List[Dict] = field(default_factory=list)
    wmi_connections: List[Dict] = field(default_factory=list)

    # Exfiltration indicators
    large_transfers: List[Dict] = field(default_factory=list)   # > 10MB outbound
    dns_tunnel_candidates: List[str] = field(default_factory=list)
    dns_tunnel_decoded: List[Dict] = field(default_factory=list)  # {domain, decoded, src_ip}

    # Port scans
    port_scan_sources: List[Dict] = field(default_factory=list)

    # Suspicious HTTP URIs (hash-based, encoded payloads)
    suspicious_uris: List[Dict] = field(default_factory=list)  # {src, dst, uri, reason}

    # Jump boxes (receive external mgmt traffic AND initiate internal lateral movement)
    jump_boxes: List[Dict] = field(default_factory=list)  # {ip, inbound_from, outbound_to, protocols}

    # Raw output for reference
    raw_summary: str = ""

    # Parse errors/warnings
    warnings: List[str] = field(default_factory=list)


# ── Internal IP ranges ────────────────────────────────────────────────────────
INTERNAL_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]

def _is_internal(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in INTERNAL_RANGES)
    except ValueError:
        return False

# ── Known suspicious user agents ─────────────────────────────────────────────
SUSPICIOUS_UA_PATTERNS = [
    r'python-requests',
    r'curl/',
    r'wget/',
    r'Go-http-client',
    r'okhttp',
    r'libwww-perl',
    r'masscan',
    r'nmap',
    r'sqlmap',
    r'nikto',
    r'cobalt.strike',
    r'^-$',          # blank/dash UA
    r'Mozilla/4\.0 \(compatible;\)$',  # CobaltStrike default
    # Anachronistic UAs - modern systems spoofing obsolete browsers (domain fronting / C2)
    r'MSIE [1-8]\.',          # IE 8 and below - no modern OS should send these
    r'Windows NT 5\.[01]',    # Windows XP (NT 5.1) or 2000 (NT 5.0)
    r'Windows NT 6\.0',       # Windows Vista - extremely rare legitimately
    r'Trident/4\.0',          # IE8 rendering engine
    r'Trident/5\.0',          # IE9 rendering engine
]

SUSPICIOUS_UA_RE = [re.compile(p, re.IGNORECASE) for p in SUSPICIOUS_UA_PATTERNS]

# ── Known C2 ports ────────────────────────────────────────────────────────────
KNOWN_C2_PORTS = {4444, 4445, 8080, 8443, 8888, 9001, 9002, 1080, 3128, 6666, 6667, 6668}
LATERAL_PORTS = {445: "SMB", 135: "WMI/RPC", 3389: "RDP", 5985: "WinRM-HTTP",
                 5986: "WinRM-HTTPS", 22: "SSH", 23: "Telnet", 139: "NetBIOS"}
CLEARTEXT_PORTS = {21: "FTP", 23: "Telnet", 80: "HTTP", 110: "POP3",
                   143: "IMAP", 389: "LDAP", 25: "SMTP"}

# ── DGA detection heuristics ──────────────────────────────────────────────────
def _entropy(s: str) -> float:
    """Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = collections.Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())

def _is_dga_candidate(domain: str) -> bool:
    """Heuristic DGA detection on domain label."""
    parts = domain.rstrip(".").split(".")
    if len(parts) < 2:
        return False
    label = parts[-2]  # second-level domain
    if len(label) < 8:
        return False
    ent = _entropy(label)
    # High entropy + mostly consonants = likely DGA
    vowels = sum(1 for c in label.lower() if c in "aeiou")
    vowel_ratio = vowels / len(label)
    return ent > 3.5 and vowel_ratio < 0.25

# ── DNS tunnel detection ──────────────────────────────────────────────────────
def _is_dns_tunnel_candidate(query: str) -> bool:
    """Detect potential DNS tunneling."""
    label = query.split(".")[0]
    # Long subdomains, base64-like content
    if len(label) > 40:
        return True
    if re.match(r'^[a-zA-Z0-9+/=]{20,}$', label):
        return True
    # Hex encoded
    if re.match(r'^[a-f0-9]{20,}$', label):
        return True
    return False

# ── Beaconing detection ───────────────────────────────────────────────────────
def _detect_beaconing(flow_timestamps: Dict[str, List[float]]) -> List[BeaconCandidate]:
    """Detect beaconing by analysing inter-packet intervals."""
    candidates = []
    for flow_key, timestamps in flow_timestamps.items():
        if len(timestamps) < 5:
            continue
        timestamps_sorted = sorted(timestamps)
        intervals = [timestamps_sorted[i+1] - timestamps_sorted[i]
                     for i in range(len(timestamps_sorted)-1)]
        if not intervals:
            continue
        avg = sum(intervals) / len(intervals)
        if avg < 1.0:  # too frequent - not beaconing
            continue
        variance = sum((x - avg)**2 for x in intervals) / len(intervals)
        std_dev = math.sqrt(variance)
        jitter_pct = (std_dev / avg) if avg > 0 else 1.0

        # Low jitter (< 20%) with regular intervals = beaconing
        if jitter_pct < 0.20 and 5 <= avg <= 3600:
            confidence = "HIGH"
        elif jitter_pct < 0.35 and 5 <= avg <= 3600:
            confidence = "MEDIUM"
        elif jitter_pct < 0.50 and 5 <= avg <= 7200:
            confidence = "LOW"
        else:
            continue

        parts = flow_key.split(":")
        if len(parts) == 4:
            candidates.append(BeaconCandidate(
                src_ip=parts[0], dst_ip=parts[1],
                dst_port=int(parts[3]),
                protocol="TCP",
                interval_avg=avg, interval_jitter=std_dev,
                packet_count=len(timestamps),
                confidence=confidence
            ))
    return candidates

# ── Port scan detection ───────────────────────────────────────────────────────
def _detect_port_scans(syn_targets: Dict[str, Set[int]]) -> List[Dict]:
    """Detect port scanning based on SYN packets to many ports."""
    results = []
    for src_ip, dst_ports_dict in syn_targets.items():
        for dst_ip, ports in dst_ports_dict.items():
            if len(ports) >= 15:
                results.append({
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "ports_scanned": len(ports),
                    "sample_ports": sorted(list(ports))[:20],
                    "severity": "HIGH" if len(ports) > 100 else "MEDIUM"
                })
    return results


# ── Main extraction function ──────────────────────────────────────────────────

def extract(pcap_path: str) -> PCAPFacts:
    """
    Parse a PCAP file and return structured PCAPFacts.
    Uses scapy for parsing.
    """
    facts = PCAPFacts()
    facts.filename = Path(pcap_path).name
    facts.file_size_mb = os.path.getsize(pcap_path) / (1024 * 1024)

    try:
        from scapy.all import rdpcap, IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR, DNSRR, Raw
        from scapy.layers.l2 import Ether
    except ImportError:
        facts.warnings.append("scapy not installed - cannot parse PCAP")
        return facts

    # ── Load packets ──────────────────────────────────────────────────────────
    try:
        packets = rdpcap(pcap_path)
    except Exception as e:
        facts.warnings.append(f"Failed to read PCAP: {e}")
        return facts

    facts.total_packets = len(packets)
    if not packets:
        facts.warnings.append("PCAP file is empty")
        return facts

    # ── Timing ────────────────────────────────────────────────────────────────
    timestamps = [float(p.time) for p in packets if hasattr(p, 'time')]
    if timestamps:
        facts.capture_start = min(timestamps)
        facts.capture_end   = max(timestamps)
        facts.capture_duration_s = facts.capture_end - facts.capture_start

    # ── Tracking structures ───────────────────────────────────────────────────
    flow_timestamps: Dict[str, List[float]] = collections.defaultdict(list)
    # syn_targets[src_ip][dst_ip] = set of dst_ports
    syn_targets: Dict[str, Dict[str, Set[int]]] = collections.defaultdict(
        lambda: collections.defaultdict(set)
    )
    host_bytes: Dict[str, Dict[str, int]] = collections.defaultdict(
        lambda: {"sent": 0, "recv": 0}
    )
    dns_query_times: Dict[str, List[float]] = collections.defaultdict(list)

    # ── Packet loop ───────────────────────────────────────────────────────────
    for pkt in packets:
        ts = float(pkt.time) if hasattr(pkt, 'time') else 0.0
        pkt_len = len(pkt)

        if not pkt.haslayer(IP):
            continue

        ip = pkt[IP]
        src = ip.src
        dst = ip.dst

        # ── Host tracking ─────────────────────────────────────────────────────
        for ip_addr in (src, dst):
            if ip_addr not in facts.hosts:
                facts.hosts[ip_addr] = HostInfo(
                    ip=ip_addr,
                    is_internal=_is_internal(ip_addr),
                    first_seen=ts,
                    last_seen=ts
                )
            h = facts.hosts[ip_addr]
            h.last_seen = max(h.last_seen, ts)

        # MAC addresses
        if pkt.haslayer(Ether):
            eth = pkt[Ether]
            if src in facts.hosts and not facts.hosts[src].mac:
                facts.hosts[src].mac = eth.src
            if dst in facts.hosts and not facts.hosts[dst].mac:
                facts.hosts[dst].mac = eth.dst

        host_bytes[src]["sent"] += pkt_len
        host_bytes[dst]["recv"] += pkt_len

        # ── Protocol ──────────────────────────────────────────────────────────
        proto = "OTHER"
        sport = dport = 0

        if pkt.haslayer(TCP):
            proto = "TCP"
            tcp = pkt[TCP]
            sport, dport = tcp.sport, tcp.dport
            facts.hosts[src].ports_seen.add(sport)
            facts.hosts[dst].ports_seen.add(dport)
            facts.hosts[src].protocols.add("TCP")
            facts.hosts[dst].protocols.add("TCP")

            # SYN scan detection
            if tcp.flags & 0x02 and not (tcp.flags & 0x10):  # SYN only
                syn_targets[src][dst].add(dport)

            # Flow key for beaconing (group by src->dst:dport, ignore sport so
            # repeated connections to same C2 port are seen as one flow)
            flow_key = f"{src}:{dst}:{sport}:{dport}"
            beacon_key = f"{src}:{dst}:0:{dport}"
            flow_timestamps[beacon_key].append(ts)

            if flow_key not in facts.flows:
                facts.flows[flow_key] = NetworkFlow(
                    src_ip=src, dst_ip=dst, src_port=sport, dst_port=dport,
                    protocol="TCP", first_seen=ts, last_seen=ts
                )
            flow = facts.flows[flow_key]
            flow.packet_count += 1
            flow.byte_count += pkt_len
            flow.last_seen = ts

            # Named service
            svc_name = None
            for p in (dport, sport):
                if p in LATERAL_PORTS:
                    svc_name = LATERAL_PORTS[p]
                    facts.hosts[src].protocols.add(svc_name)
                    facts.hosts[dst].protocols.add(svc_name)

        elif pkt.haslayer(UDP):
            proto = "UDP"
            udp = pkt[UDP]
            sport, dport = udp.sport, udp.dport
            facts.hosts[src].protocols.add("UDP")

        elif pkt.haslayer(ICMP):
            proto = "ICMP"
            facts.hosts[src].protocols.add("ICMP")
            facts.hosts[dst].protocols.add("ICMP")

        facts.protocol_counts[proto] = facts.protocol_counts.get(proto, 0) + 1

        # ── DNS ───────────────────────────────────────────────────────────────
        if pkt.haslayer(DNS):
            dns = pkt[DNS]
            facts.protocol_counts["DNS"] = facts.protocol_counts.get("DNS", 0) + 1
            facts.hosts[src].protocols.add("DNS")

            if dns.qr == 0 and dns.qdcount > 0:  # Query
                try:
                    qname = dns[DNSQR].qname.decode("utf-8", errors="replace").rstrip(".")
                    qtype_num = dns[DNSQR].qtype
                    qtype = {1: "A", 28: "AAAA", 15: "MX", 16: "TXT",
                             5: "CNAME", 6: "SOA", 33: "SRV"}.get(qtype_num, str(qtype_num))

                    facts.unique_domains.add(qname)
                    dns_query_times[f"{src}:{qname}"].append(ts)

                    is_tunnel = _is_dns_tunnel_candidate(qname)
                    is_dga    = _is_dga_candidate(qname)

                    q = DNSQuery(
                        timestamp=ts, src_ip=src,
                        query=qname, qtype=qtype,
                        nx_domain=False
                    )
                    facts.dns_queries.append(q)

                    if is_dga:
                        facts.dga_candidates.append(qname)
                        facts.suspicious_domains.add(qname)
                    if is_tunnel:
                        facts.dns_tunnel_candidates.append(qname)
                        facts.suspicious_domains.add(qname)
                        # Try to decode the base64 label to reveal exfiltrated content
                        label = qname.split(".")[0]
                        try:
                            import base64 as _b64
                            # Pad to multiple of 4
                            padded = label + "=" * (-len(label) % 4)
                            decoded_bytes = _b64.b64decode(padded)
                            decoded_str = decoded_bytes.decode("utf-8", errors="replace")
                            if decoded_str.isprintable() or ":" in decoded_str:
                                facts.dns_tunnel_decoded.append({
                                    "domain": qname,
                                    "decoded": decoded_str,
                                    "src_ip": src
                                })
                        except Exception:
                            pass

                except Exception:
                    pass

            elif dns.qr == 1:  # Response
                if dns.rcode == 3:  # NXDOMAIN
                    try:
                        qname = dns[DNSQR].qname.decode("utf-8", errors="replace").rstrip(".")
                        facts.nx_domains.add(qname)
                        # High NXDOMAIN rate = DGA
                        for q in reversed(facts.dns_queries):
                            if q.query == qname:
                                q.nx_domain = True
                                break
                    except Exception:
                        pass

        # ── HTTP (raw payload inspection) ─────────────────────────────────────
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            try:
                payload = pkt[Raw].load
                payload_str = payload.decode("utf-8", errors="replace")

                # HTTP Request
                if re.match(r'^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) ', payload_str):
                    lines = payload_str.split("\r\n")
                    method_line = lines[0].split(" ")
                    method = method_line[0] if method_line else ""
                    uri    = method_line[1] if len(method_line) > 1 else ""
                    host   = ""
                    ua     = ""
                    content_len = 0

                    for line in lines[1:]:
                        ll = line.lower()
                        if ll.startswith("host:"):
                            host = line.split(":", 1)[1].strip()
                        elif ll.startswith("user-agent:"):
                            ua = line.split(":", 1)[1].strip()
                            facts.user_agents[ua] = facts.user_agents.get(ua, 0) + 1
                        elif ll.startswith("content-length:"):
                            try:
                                content_len = int(line.split(":", 1)[1].strip())
                            except ValueError:
                                pass

                    facts.protocol_counts["HTTP"] = facts.protocol_counts.get("HTTP", 0) + 1
                    facts.hosts[src].protocols.add("HTTP")

                    req = HTTPRequest(
                        timestamp=ts, src_ip=src, dst_ip=dst, dst_port=dport,
                        method=method, host=host, uri=uri,
                        user_agent=ua, content_length=content_len
                    )
                    facts.http_requests.append(req)

                    # Suspicious user agent
                    for pattern in SUSPICIOUS_UA_RE:
                        if pattern.search(ua):
                            if ua not in facts.suspicious_user_agents:
                                facts.suspicious_user_agents.append(ua)
                            break

                    # Flag MD5/SHA hash strings in URIs (e.g. /upload/d41d8cd98f00b204e9800998ecf8427e)
                    _MD5_EMPTY = "d41d8cd98f00b204e9800998ecf8427e"
                    _hash_match = re.search(r'[a-f0-9]{32,64}', uri.lower())
                    if _hash_match:
                        _h = _hash_match.group(0)
                        _reason = "MD5 of empty file in URI (null-payload beacon)" if _h == _MD5_EMPTY \
                                  else f"Hash-like string in URI ({len(_h)*4}-bit)"
                        facts.suspicious_uris.append({
                            "src": src, "dst": dst, "host": host,
                            "method": method, "uri": uri,
                            "hash": _h, "reason": _reason
                        })

                    # Cleartext Basic Auth
                    for line in lines[1:]:
                        if line.lower().startswith("authorization: basic "):
                            b64 = line.split(" ", 2)[-1].strip()
                            try:
                                import base64
                                decoded = base64.b64decode(b64).decode("utf-8", errors="replace")
                                facts.credential_captures.append(CredentialCapture(
                                    timestamp=ts, src_ip=src, dst_ip=dst,
                                    protocol="HTTP-Basic",
                                    cleartext=decoded,
                                    auth_type="Basic"
                                ))
                            except Exception:
                                pass

                # FTP cleartext credentials
                if dport == 21 or sport == 21:
                    for cmd in ["USER ", "PASS "]:
                        if payload_str.upper().startswith(cmd):
                            value = payload_str[len(cmd):].strip()
                            if cmd == "USER ":
                                facts.credential_captures.append(CredentialCapture(
                                    timestamp=ts, src_ip=src, dst_ip=dst,
                                    protocol="FTP", username=value, auth_type="FTP"
                                ))
                            else:
                                # Update last FTP cred with password
                                for c in reversed(facts.credential_captures):
                                    if c.protocol == "FTP" and c.src_ip == src and not c.cleartext:
                                        c.cleartext = value
                                        break

                # NTLM detection (SMB/HTTP)
                if b"NTLMSSP" in payload:
                    facts.credential_captures.append(CredentialCapture(
                        timestamp=ts, src_ip=src, dst_ip=dst,
                        protocol="NTLM",
                        auth_type="NTLM",
                        evidence="NTLMSSP signature detected in payload"
                    ))
                    facts.protocol_counts["NTLM"] = facts.protocol_counts.get("NTLM", 0) + 1

            except Exception:
                pass

        # ── Lateral movement ──────────────────────────────────────────────────
        if pkt.haslayer(TCP):
            if dport == 445 or dport == 139:
                # SMB connection
                existing = any(
                    s["src"] == src and s["dst"] == dst
                    for s in facts.smb_connections
                )
                if not existing:
                    facts.smb_connections.append({
                        "src": src, "dst": dst, "port": dport,
                        "timestamp": ts, "internal_to_internal":
                            _is_internal(src) and _is_internal(dst)
                    })
                facts.hosts[src].protocols.add("SMB")
                facts.protocol_counts["SMB"] = facts.protocol_counts.get("SMB", 0) + 1

            elif dport == 3389:
                if not any(r["src"] == src and r["dst"] == dst for r in facts.rdp_connections):
                    facts.rdp_connections.append({"src": src, "dst": dst, "timestamp": ts})
                facts.hosts[src].protocols.add("RDP")
                facts.protocol_counts["RDP"] = facts.protocol_counts.get("RDP", 0) + 1

            elif dport in (5985, 5986):
                if not any(w["src"] == src and w["dst"] == dst for w in facts.winrm_connections):
                    facts.winrm_connections.append({
                        "src": src, "dst": dst, "port": dport, "timestamp": ts
                    })
                facts.hosts[src].protocols.add("WinRM")
                facts.protocol_counts["WinRM"] = facts.protocol_counts.get("WinRM", 0) + 1

            elif dport == 135:
                if not any(w["src"] == src and w["dst"] == dst for w in facts.wmi_connections):
                    facts.wmi_connections.append({"src": src, "dst": dst, "timestamp": ts})
                facts.protocol_counts["WMI/RPC"] = facts.protocol_counts.get("WMI/RPC", 0) + 1

    # ── Post-processing ───────────────────────────────────────────────────────

    # Apply host byte counts
    for ip_addr, counts in host_bytes.items():
        if ip_addr in facts.hosts:
            facts.hosts[ip_addr].bytes_sent = counts["sent"]
            facts.hosts[ip_addr].bytes_recv = counts["recv"]

    # Top talkers
    facts.top_talkers = sorted(
        [(ip, h.bytes_sent + h.bytes_recv) for ip, h in facts.hosts.items()],
        key=lambda x: x[1], reverse=True
    )[:10]

    # Beaconing detection
    facts.beacon_candidates = _detect_beaconing(flow_timestamps)

    # Port scan detection
    facts.port_scan_sources = _detect_port_scans(syn_targets)

    # Large transfers (> 5MB outbound to external)
    for ip_addr, h in facts.hosts.items():
        if _is_internal(ip_addr) and h.bytes_sent > 5 * 1024 * 1024:
            # Check if sending to external hosts
            external_sent = sum(
                facts.flows[k].byte_count
                for k in facts.flows
                if k.startswith(f"{ip_addr}:")
                and not _is_internal(k.split(":")[1])
            )
            if external_sent > 5 * 1024 * 1024:
                facts.large_transfers.append({
                    "src_ip": ip_addr,
                    "bytes": external_sent,
                    "mb": round(external_sent / (1024*1024), 1)
                })

    # Jump box detection: internal host that receives external mgmt connections
    # AND initiates lateral movement to other internal hosts
    _MGMT_PORTS = {22, 3389, 5985, 5986, 5900}
    ext_mgmt_targets: Dict[str, Dict] = {}  # internal_ip -> {inbound_from, protocols}
    for conn_list, proto in [
        (facts.rdp_connections,   "RDP"),
        (facts.winrm_connections, "WinRM"),
    ]:
        for c in conn_list:
            src_c, dst_c = c["src"], c["dst"]
            if not _is_internal(src_c) and _is_internal(dst_c):
                entry = ext_mgmt_targets.setdefault(dst_c, {"inbound_from": set(), "protocols": set()})
                entry["inbound_from"].add(src_c)
                entry["protocols"].add(proto)

    # Also check SSH from external via raw connections (tracked in flows)
    for flow_key, flow in facts.flows.items():
        parts = flow_key.split(":")
        if len(parts) < 4:
            continue
        f_src, f_dst, _, f_dport = parts[0], parts[1], parts[2], parts[3]
        try:
            dport_i = int(f_dport)
        except ValueError:
            continue
        if dport_i == 22 and not _is_internal(f_src) and _is_internal(f_dst):
            entry = ext_mgmt_targets.setdefault(f_dst, {"inbound_from": set(), "protocols": set()})
            entry["inbound_from"].add(f_src)
            entry["protocols"].add("SSH")

    # Find which of those hosts also initiates lateral movement outbound
    for host_ip, info in ext_mgmt_targets.items():
        outbound_to = set()
        for c in facts.smb_connections:
            if c["src"] == host_ip and _is_internal(c["dst"]):
                outbound_to.add(c["dst"])
        for c in facts.rdp_connections:
            if c["src"] == host_ip and _is_internal(c["dst"]):
                outbound_to.add(c["dst"])
        for c in facts.winrm_connections:
            if c["src"] == host_ip and _is_internal(c["dst"]):
                outbound_to.add(c["dst"])
        if outbound_to:
            facts.jump_boxes.append({
                "ip": host_ip,
                "inbound_from": sorted(info["inbound_from"]),
                "outbound_to": sorted(outbound_to),
                "protocols": sorted(info["protocols"])
            })

    # Build suspicious activity list
    _build_suspicious_activities(facts)

    # Build raw summary
    facts.raw_summary = _build_raw_summary(facts)

    return facts


def _build_suspicious_activities(facts: PCAPFacts):
    """Compile all findings into a prioritised suspicious activity list."""

    # Beaconing
    for bc in facts.beacon_candidates:
        sev = "CRITICAL" if bc.confidence == "HIGH" else "HIGH" if bc.confidence == "MEDIUM" else "MEDIUM"
        mitre = "T1071 - Application Layer Protocol"
        if bc.dst_port in (80, 443, 8080, 8443):
            mitre = "T1071.001 - Web Protocols"
        facts.suspicious_activities.append(SuspiciousActivity(
            timestamp=0,
            src_ip=bc.src_ip,
            dst_ip=bc.dst_ip,
            category="C2_BEACON",
            description=f"Beaconing detected: {bc.packet_count} packets to {bc.dst_ip}:{bc.dst_port} "
                       f"every {bc.interval_avg:.0f}s (jitter: {bc.interval_jitter:.0f}s) - {bc.confidence} confidence",
            severity=sev,
            mitre_technique=mitre,
            evidence=f"Avg interval: {bc.interval_avg:.1f}s, StdDev: {bc.interval_jitter:.1f}s"
        ))

    # DGA
    for domain in facts.dga_candidates[:20]:
        facts.suspicious_activities.append(SuspiciousActivity(
            timestamp=0, src_ip="", dst_ip="",
            category="C2_BEACON",
            description=f"DGA domain candidate: {domain}",
            severity="HIGH",
            mitre_technique="T1568.002 - Domain Generation Algorithms",
            evidence=f"High entropy label, low vowel ratio"
        ))

    # DNS tunneling
    for domain in facts.dns_tunnel_candidates[:10]:
        facts.suspicious_activities.append(SuspiciousActivity(
            timestamp=0, src_ip="", dst_ip="",
            category="DNS_TUNNEL",
            description=f"DNS tunneling candidate: {domain}",
            severity="HIGH",
            mitre_technique="T1071.004 - DNS",
            evidence="Long subdomain or base64-encoded label"
        ))

    # Port scans
    for scan in facts.port_scan_sources:
        facts.suspicious_activities.append(SuspiciousActivity(
            timestamp=0,
            src_ip=scan["src_ip"],
            dst_ip=scan["dst_ip"],
            category="PORT_SCAN",
            description=f"Port scan: {scan['src_ip']} -> {scan['dst_ip']}, {scan['ports_scanned']} ports",
            severity=scan["severity"],
            mitre_technique="T1046 - Network Service Discovery",
            evidence=f"Sample ports: {scan['sample_ports'][:10]}"
        ))

    # Lateral movement - internal SMB
    for smb in facts.smb_connections:
        if smb.get("internal_to_internal"):
            facts.suspicious_activities.append(SuspiciousActivity(
                timestamp=smb["timestamp"],
                src_ip=smb["src"], dst_ip=smb["dst"],
                category="LATERAL_MOVEMENT",
                description=f"Internal SMB connection: {smb['src']} -> {smb['dst']}:{smb['port']}",
                severity="HIGH",
                mitre_technique="T1021.002 - SMB/Windows Admin Shares",
                evidence="Internal-to-internal SMB - potential lateral movement"
            ))

    # WinRM
    for winrm in facts.winrm_connections:
        if _is_internal(winrm["src"]) and _is_internal(winrm["dst"]):
            facts.suspicious_activities.append(SuspiciousActivity(
                timestamp=winrm["timestamp"],
                src_ip=winrm["src"], dst_ip=winrm["dst"],
                category="LATERAL_MOVEMENT",
                description=f"WinRM connection: {winrm['src']} -> {winrm['dst']}:{winrm['port']}",
                severity="MEDIUM",
                mitre_technique="T1021.006 - Windows Remote Management",
                evidence="PowerShell remoting / Evil-WinRM potential"
            ))

    # Large exfiltration
    for xfer in facts.large_transfers:
        facts.suspicious_activities.append(SuspiciousActivity(
            timestamp=0,
            src_ip=xfer["src_ip"], dst_ip="EXTERNAL",
            category="EXFIL",
            description=f"Large outbound transfer: {xfer['mb']}MB from {xfer['src_ip']} to external hosts",
            severity="HIGH",
            mitre_technique="T1041 - Exfiltration Over C2 Channel",
            evidence=f"{xfer['bytes']:,} bytes sent externally"
        ))

    # Suspicious user agents
    for ua in facts.suspicious_user_agents:
        facts.suspicious_activities.append(SuspiciousActivity(
            timestamp=0, src_ip="", dst_ip="",
            category="RECON",
            description=f"Suspicious HTTP user agent: {ua}",
            severity="MEDIUM",
            mitre_technique="T1071.001 - Web Protocols",
            evidence="Known tool/scanner user agent string"
        ))

    # NTLM captures
    for cred in facts.credential_captures:
        if cred.auth_type == "NTLM":
            facts.suspicious_activities.append(SuspiciousActivity(
                timestamp=cred.timestamp,
                src_ip=cred.src_ip, dst_ip=cred.dst_ip,
                category="CREDENTIAL",
                description=f"NTLM authentication captured: {cred.src_ip} -> {cred.dst_ip}",
                severity="HIGH",
                mitre_technique="T1557.001 - LLMNR/NBT-NS Poisoning and SMB Relay",
                evidence="NTLMSSP signature in packet payload"
            ))

    # Sort by severity
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    facts.suspicious_activities.sort(key=lambda x: sev_order.get(x.severity, 4))


def _build_raw_summary(facts: PCAPFacts) -> str:
    """Build a human-readable summary of all findings."""
    lines = []
    start_dt = datetime.fromtimestamp(facts.capture_start).strftime("%Y-%m-%d %H:%M:%S") if facts.capture_start else "Unknown"
    end_dt   = datetime.fromtimestamp(facts.capture_end).strftime("%Y-%m-%d %H:%M:%S") if facts.capture_end else "Unknown"

    lines.append(f"=== PCAP ANALYSIS: {facts.filename} ===")
    lines.append(f"File size: {facts.file_size_mb:.1f} MB | Packets: {facts.total_packets:,}")
    lines.append(f"Capture period: {start_dt} to {end_dt} ({facts.capture_duration_s:.0f}s)")
    lines.append("")

    lines.append("=== HOSTS DISCOVERED ===")
    for ip, h in sorted(facts.hosts.items(), key=lambda x: x[1].bytes_sent + x[1].bytes_recv, reverse=True)[:20]:
        role = "INTERNAL" if h.is_internal else "EXTERNAL"
        mb_sent = h.bytes_sent / (1024*1024)
        mb_recv = h.bytes_recv / (1024*1024)
        hostname = f" ({h.hostname})" if h.hostname else ""
        lines.append(f"  {ip}{hostname} [{role}] sent:{mb_sent:.1f}MB recv:{mb_recv:.1f}MB protocols:{','.join(sorted(h.protocols))}")
    lines.append("")

    lines.append("=== PROTOCOL BREAKDOWN ===")
    for proto, count in sorted(facts.protocol_counts.items(), key=lambda x: x[1], reverse=True):
        lines.append(f"  {proto}: {count:,} packets")
    lines.append("")

    if facts.suspicious_activities:
        lines.append("=== SUSPICIOUS ACTIVITY (prioritised) ===")
        for act in facts.suspicious_activities[:30]:
            lines.append(f"  [{act.severity}] [{act.category}] {act.description}")
            if act.mitre_technique:
                lines.append(f"    MITRE: {act.mitre_technique}")
        lines.append("")

    if facts.jump_boxes:
        lines.append("=== JUMP BOX IDENTIFIED ===")
        for jb in facts.jump_boxes:
            lines.append(f"  {jb['ip']} is a JUMP BOX:")
            lines.append(f"    Receives external management from: {', '.join(jb['inbound_from'])} via {', '.join(jb['protocols'])}")
            lines.append(f"    Initiates lateral movement to: {', '.join(jb['outbound_to'])}")
        lines.append("")

    if facts.beacon_candidates:
        lines.append("=== BEACONING DETECTED ===")
        for bc in facts.beacon_candidates:
            lines.append(f"  [{bc.confidence}] {bc.src_ip} -> {bc.dst_ip}:{bc.dst_port} "
                        f"every ~{bc.interval_avg:.0f}s ({bc.packet_count} packets)")
        lines.append("")

    if facts.dns_queries:
        lines.append(f"=== DNS ANALYSIS ({len(facts.unique_domains)} unique domains) ===")
        if facts.dga_candidates:
            lines.append(f"  DGA CANDIDATES ({len(facts.dga_candidates)}):")
            for d in facts.dga_candidates[:10]:
                lines.append(f"    [DGA] {d}")
        if facts.dns_tunnel_candidates:
            lines.append(f"  DNS TUNNEL CANDIDATES ({len(facts.dns_tunnel_candidates)}):")
            for d in facts.dns_tunnel_candidates[:5]:
                lines.append(f"    [TUNNEL] {d}")
        if facts.dns_tunnel_decoded:
            lines.append(f"  DNS TUNNEL DECODED CONTENT (base64):")
            for entry in facts.dns_tunnel_decoded[:10]:
                lines.append(f"    {entry['src_ip']} exfiltrated: \"{entry['decoded']}\" (via {entry['domain'][:40]}...)")
        if facts.nx_domains:
            lines.append(f"  NXDOMAIN responses: {len(facts.nx_domains)} unique domains failed")
        lines.append("")

    if facts.smb_connections or facts.rdp_connections or facts.winrm_connections:
        lines.append("=== LATERAL MOVEMENT INDICATORS ===")
        if facts.smb_connections:
            lines.append(f"  SMB connections: {len(facts.smb_connections)}")
            for s in facts.smb_connections[:10]:
                tag = " [INTERNAL->INTERNAL]" if s.get("internal_to_internal") else ""
                lines.append(f"    {s['src']} -> {s['dst']}:{s['port']}{tag}")
        if facts.rdp_connections:
            lines.append(f"  RDP connections: {len(facts.rdp_connections)}")
            for r in facts.rdp_connections[:5]:
                lines.append(f"    {r['src']} -> {r['dst']}")
        if facts.winrm_connections:
            lines.append(f"  WinRM connections: {len(facts.winrm_connections)}")
            for w in facts.winrm_connections[:5]:
                lines.append(f"    {w['src']} -> {w['dst']}:{w['port']}")
        lines.append("")

    if facts.credential_captures:
        lines.append("=== CREDENTIALS CAPTURED ===")
        for c in facts.credential_captures[:20]:
            if c.cleartext:
                lines.append(f"  [{c.protocol}] {c.src_ip} -> {c.dst_ip}: {c.cleartext}")
            elif c.username:
                lines.append(f"  [{c.protocol}] {c.src_ip} -> {c.dst_ip}: user={c.username}")
            else:
                lines.append(f"  [{c.auth_type}] {c.src_ip} -> {c.dst_ip}: {c.evidence}")
        lines.append("")

    if facts.large_transfers:
        lines.append("=== POTENTIAL DATA EXFILTRATION ===")
        for xfer in facts.large_transfers:
            lines.append(f"  {xfer['src_ip']}: {xfer['mb']}MB sent to external hosts")
        lines.append("")

    if facts.port_scan_sources:
        lines.append("=== PORT SCANS DETECTED ===")
        for scan in facts.port_scan_sources:
            lines.append(f"  {scan['src_ip']} -> {scan['dst_ip']}: {scan['ports_scanned']} ports scanned")
        lines.append("")

    if facts.http_requests:
        lines.append(f"=== HTTP TRAFFIC ({len(facts.http_requests)} requests) ===")
        if facts.suspicious_user_agents:
            lines.append("  SUSPICIOUS USER AGENTS:")
            for ua in facts.suspicious_user_agents:
                lines.append(f"    {ua}")
        if facts.suspicious_uris:
            lines.append("  SUSPICIOUS URIs (hash/encoded payload in path):")
            for u in facts.suspicious_uris[:5]:
                lines.append(f"    {u['method']} {u['host']}{u['uri']}")
                lines.append(f"    Reason: {u['reason']}")
        lines.append("")

    return "\n".join(lines)


def facts_to_text(facts: PCAPFacts) -> str:
    """Convert PCAPFacts to LLM-consumable text (for Ask Syd context)."""
    return facts.raw_summary


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python pcap_fact_extractor.py <file.pcap>")
        sys.exit(1)
    result = extract(sys.argv[1])
    print(result.raw_summary)
    print(f"\nSuspicious activities: {len(result.suspicious_activities)}")
    print(f"Beacon candidates: {len(result.beacon_candidates)}")
    print(f"Credential captures: {len(result.credential_captures)}")
