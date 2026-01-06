#!/usr/bin/env python3
"""
Deterministic Nmap Fact Extractor (Stage A)
Parses Nmap output into structured facts - 100% accurate, no AI
"""

import re
import json
from typing import Dict, List, Any, Optional


class NmapFactExtractor:
    """Extracts structured facts from Nmap scan output"""

    def extract_facts(self, scan_text: str) -> Dict[str, Any]:
        """
        Parse Nmap scan into structured facts
        Returns a dictionary of facts that can be queried by LLM
        """
        facts = {
            "targets": [],
            "scan_metadata": {},
            "hosts": [],
            "summary": {}
        }

        # Extract scan metadata
        facts["scan_metadata"] = self._extract_scan_metadata(scan_text)

        # Extract host information
        facts["hosts"] = self._extract_hosts(scan_text)

        # Extract targets (IPs/hostnames scanned)
        facts["targets"] = self._extract_targets(scan_text)

        # Create summary
        facts["summary"] = self._create_summary(facts)

        return facts

    def _extract_scan_metadata(self, scan_text: str) -> Dict[str, Any]:
        """Extract Nmap version, scan time, arguments - COMPREHENSIVE"""
        metadata = {}

        # Nmap version and scan initiation
        version_match = re.search(r'# Nmap ([\d.]+) scan initiated (.+)', scan_text)
        if version_match:
            metadata["nmap_version"] = version_match.group(1)
            metadata["scan_initiated"] = version_match.group(2)

        # Scan completion time
        done_match = re.search(r'Nmap done: .+ scanned in ([\d.]+) seconds', scan_text)
        if done_match:
            metadata["scan_duration_seconds"] = float(done_match.group(1))

        # Scan arguments/command (if present)
        args_match = re.search(r'nmap (.+?)(?:\n|$)', scan_text, re.IGNORECASE)
        if args_match:
            metadata["scan_arguments"] = args_match.group(1).strip()

        # Number of hosts scanned
        hosts_match = re.search(r'Nmap done: (\d+) IP address', scan_text)
        if hosts_match:
            metadata["hosts_scanned"] = int(hosts_match.group(1))

        # Timing template
        timing_match = re.search(r'Using (.+ timing template)', scan_text, re.IGNORECASE)
        if timing_match:
            metadata["timing_template"] = timing_match.group(1)

        # Service detection info
        if 'Service detection performed' in scan_text:
            metadata["service_detection"] = "performed"

        # Raw packets sent/received (if verbose)
        packets_sent = re.search(r'(?:Raw )?packets sent: (\d+)', scan_text, re.IGNORECASE)
        if packets_sent:
            metadata["packets_sent"] = int(packets_sent.group(1))

        packets_recv = re.search(r'(?:Rcvd|received): (\d+)', scan_text, re.IGNORECASE)
        if packets_recv:
            metadata["packets_received"] = int(packets_recv.group(1))

        # Platform information
        if 'Platform: ' in scan_text:
            platform_match = re.search(r'Platform: (.+)', scan_text)
            if platform_match:
                metadata["platform"] = platform_match.group(1).strip()

        return metadata

    def _extract_targets(self, scan_text: str) -> List[str]:
        """Extract all target IPs/hostnames"""
        targets = []

        # Match "Nmap scan report for <target>"
        for match in re.finditer(r'Nmap scan report for ([^\s\n]+)', scan_text):
            target = match.group(1)
            if target not in targets:
                targets.append(target)

        return targets

    def _extract_hosts(self, scan_text: str) -> List[Dict[str, Any]]:
        """Extract detailed information for each host"""
        hosts = []

        # Split by "Nmap scan report for" to separate hosts
        host_sections = re.split(r'Nmap scan report for ', scan_text)[1:]

        for section in host_sections:
            host = self._parse_host_section(section)
            if host:
                hosts.append(host)

        return hosts

    def _parse_host_section(self, section: str) -> Optional[Dict[str, Any]]:
        """Parse a single host's scan results - COMPREHENSIVE extraction"""
        host = {
            "target": "",
            "status": "",
            "latency": "",
            "open_ports": [],
            "filtered_ports": [],
            "closed_ports_count": 0,
            "os_detection": {},
            "mac_address": "",
            "mac_vendor": "",
            "script_output": [],
            "traceroute": [],
            "os_guesses": [],
            "network_distance": "",
            "device_type": "",
            "tcp_sequence": "",
            "ip_id_sequence": "",
            "host_scripts": [],
            "warnings": [],
            "interesting_ports": []
        }

        lines = section.split('\n')
        if not lines:
            return None

        # First line is the target
        host["target"] = lines[0].strip()

        # Parse each line
        current_script = None
        for line in lines[1:]:
            # Host status and latency
            if line.startswith('Host is'):
                status_match = re.search(r'Host is (\w+)(?: \(([\d.]+)s latency\))?', line)
                if status_match:
                    host["status"] = status_match.group(1)
                    if status_match.group(2):
                        host["latency"] = status_match.group(2) + "s"

            # Closed ports count
            closed_match = re.search(r'Not shown: (\d+) (closed|filtered) (\w+) ports', line)
            if closed_match:
                count = int(closed_match.group(1))
                port_type = closed_match.group(2)
                if port_type == "closed":
                    host["closed_ports_count"] = count

            # Open/filtered ports
            port_match = re.match(r'(\d+)/(tcp|udp)\s+(open|filtered|closed)\s+(\S+)(?:\s+(.+))?', line)
            if port_match:
                port_info = {
                    "port": int(port_match.group(1)),
                    "protocol": port_match.group(2),
                    "state": port_match.group(3),
                    "service": port_match.group(4),
                    "version_info": port_match.group(5).strip() if port_match.group(5) else ""
                }

                if port_info["state"] == "open":
                    host["open_ports"].append(port_info)
                elif port_info["state"] == "filtered":
                    host["filtered_ports"].append(port_info)

            # MAC Address
            mac_match = re.search(r'MAC Address: ([0-9A-F:]+)(?: \((.+)\))?', line)
            if mac_match:
                host["mac_address"] = mac_match.group(1)
                if mac_match.group(2):
                    host["mac_vendor"] = mac_match.group(2)

            # Script output (e.g., | http-title:, | ssh-hostkey:)
            # Match both "| script: value" and "| script:" (multi-line)
            script_match = re.match(r'\|\s+([a-z0-9_-]+):\s*(.*)$', line)
            if script_match:
                script_name = script_match.group(1)
                script_value = script_match.group(2).strip()
                # Start a new script entry
                host["script_output"].append({
                    "script": script_name,
                    "output": script_value if script_value else ""
                })
                current_script = script_name
            elif re.match(r'\|', line) and current_script:
                # Continuation lines (| or |_)
                continuation = line.strip().lstrip('|_').strip()
                if continuation and host["script_output"]:
                    if host["script_output"][-1]["output"]:
                        host["script_output"][-1]["output"] += " " + continuation
                    else:
                        host["script_output"][-1]["output"] = continuation

            # OS Detection
            if 'Service Info: OS:' in line:
                os_match = re.search(r'OS: ([^;]+)', line)
                if os_match:
                    host["os_detection"]["os_family"] = os_match.group(1).strip()

            if 'CPE:' in line:
                cpe_match = re.search(r'CPE: (cpe:[^\s]+)', line)
                if cpe_match:
                    host["os_detection"]["cpe"] = cpe_match.group(1)

            # OS Guesses with confidence
            if 'Aggressive OS guesses:' in line or 'OS details:' in line:
                # Extract OS guess with confidence: "Linux 3.10 - 4.11 (95%)"
                guess_match = re.findall(r'([^,()]+)\((\d+)%\)', line)
                for os_name, confidence in guess_match:
                    host["os_guesses"].append({
                        "os": os_name.strip(),
                        "confidence": int(confidence)
                    })

            # Traceroute hops
            if line.startswith('TRACEROUTE') or (line.strip() and line[0].isdigit() and 'ms' in line and host.get("traceroute") is not None):
                # Traceroute line format: "1   0.50 ms  192.168.1.1"
                hop_match = re.match(r'^(\d+)\s+([\d.]+)\s*ms\s+(.+)', line.strip())
                if hop_match:
                    host["traceroute"].append({
                        "hop": int(hop_match.group(1)),
                        "rtt": hop_match.group(2) + "ms",
                        "ip": hop_match.group(3).strip()
                    })

            # Network Distance
            if 'Network Distance:' in line:
                distance_match = re.search(r'Network Distance: (\d+) hops?', line)
                if distance_match:
                    host["network_distance"] = distance_match.group(1) + " hops"

            # Device Type
            if 'Device type:' in line:
                device_match = re.search(r'Device type: (.+)', line)
                if device_match:
                    host["device_type"] = device_match.group(1).strip()

            # TCP Sequence Prediction
            if 'TCP Sequence Prediction:' in line:
                tcp_match = re.search(r'TCP Sequence Prediction: (.+)', line)
                if tcp_match:
                    host["tcp_sequence"] = tcp_match.group(1).strip()

            # IP ID Sequence Generation
            if 'IP ID Sequence Generation:' in line:
                ipid_match = re.search(r'IP ID Sequence Generation: (.+)', line)
                if ipid_match:
                    host["ip_id_sequence"] = ipid_match.group(1).strip()

            # Host script results (scripts that run on the host, not per-port)
            if line.startswith('Host script results:'):
                current_script = "host_scripts"

            # Warnings (filtered ports, timing, etc.)
            if 'Warning:' in line or 'Note:' in line:
                warning_match = re.search(r'(Warning|Note): (.+)', line)
                if warning_match:
                    host["warnings"].append({
                        "type": warning_match.group(1),
                        "message": warning_match.group(2).strip()
                    })

            # Interesting ports summary
            if 'interesting ports' in line.lower():
                interesting_match = re.search(r'(\d+) interesting ports?', line, re.IGNORECASE)
                if interesting_match:
                    host["interesting_ports"].append(line.strip())

        return host

    def _create_summary(self, facts: Dict[str, Any]) -> Dict[str, Any]:
        """Create summary statistics"""
        summary = {
            "total_hosts": len(facts["hosts"]),
            "hosts_up": 0,
            "total_open_ports": 0,
            "total_filtered_ports": 0,
            "unique_services": set(),
            "all_open_ports": []
        }

        for host in facts["hosts"]:
            if host["status"] == "up":
                summary["hosts_up"] += 1

            summary["total_open_ports"] += len(host["open_ports"])
            summary["total_filtered_ports"] += len(host["filtered_ports"])

            for port_info in host["open_ports"]:
                summary["unique_services"].add(port_info["service"])
                summary["all_open_ports"].append({
                    "host": host["target"],
                    "port": port_info["port"],
                    "service": port_info["service"]
                })

        summary["unique_services"] = list(summary["unique_services"])

        return summary

    def facts_to_text(self, facts: Dict[str, Any]) -> str:
        """
        Convert structured facts to simple Q&A format for LLM
        Ultra-simple format that LLMs can't misread
        """
        lines = []

        lines.append("FACTS EXTRACTED FROM SCAN:")
        lines.append("")

        # Target
        if facts["targets"]:
            lines.append(f"Q: What IP/hostname was scanned?")
            lines.append(f"A: {facts['targets'][0]}")
            lines.append("")

        # Scan metadata
        if facts["scan_metadata"]:
            meta = facts["scan_metadata"]
            if "nmap_version" in meta:
                lines.append(f"Q: What Nmap version was used?")
                lines.append(f"A: {meta['nmap_version']}")
                lines.append("")
            if "scan_duration_seconds" in meta:
                lines.append(f"Q: How long did the scan take?")
                lines.append(f"A: {meta['scan_duration_seconds']} seconds")
                lines.append("")
            if "scan_arguments" in meta:
                lines.append(f"Q: What scan flags/arguments were used?")
                lines.append(f"A: {meta['scan_arguments']}")
                lines.append("")
            if "timing_template" in meta:
                lines.append(f"Q: What timing template was used?")
                lines.append(f"A: {meta['timing_template']}")
                lines.append("")
            if "service_detection" in meta:
                lines.append(f"Q: Was service detection performed?")
                lines.append(f"A: Yes, service detection was {meta['service_detection']}")
                lines.append("")
            if "packets_sent" in meta:
                lines.append(f"Q: How many packets were sent/received?")
                lines.append(f"A: {meta['packets_sent']} sent, {meta.get('packets_received', 'unknown')} received")
                lines.append("")
            if "platform" in meta:
                lines.append(f"Q: What platform information was detected?")
                lines.append(f"A: {meta['platform']}")
                lines.append("")

        # Host info
        for host in facts["hosts"]:
            lines.append(f"Q: Was host {host['target']} up?")
            lines.append(f"A: {host['status']}")
            lines.append("")

            if host["latency"]:
                lines.append(f"Q: What was the latency?")
                lines.append(f"A: {host['latency']}")
                lines.append("")

            if host["open_ports"]:
                lines.append(f"Q: How many ports are open?")
                lines.append(f"A: {len(host['open_ports'])} ports")
                lines.append("")

                lines.append(f"Q: What are the open ports?")
                port_list = [f"{p['port']}/{p['protocol']}" for p in host["open_ports"]]
                lines.append(f"A: {', '.join(port_list)}")
                lines.append("")

                lines.append(f"Q: What services are running on the open ports?")
                for port in host["open_ports"]:
                    lines.append(f"A: Port {port['port']}/{port['protocol']}: {port['service']}")
                    if port['version_info']:
                        lines.append(f"   Version: {port['version_info']}")
                lines.append("")

            if host["closed_ports_count"] > 0:
                lines.append(f"Q: How many ports were closed?")
                lines.append(f"A: {host['closed_ports_count']} ports not shown")
                lines.append("")

            if host["filtered_ports"]:
                lines.append(f"Q: Are any ports filtered?")
                port_list = [f"{p['port']}/{p['protocol']}" for p in host["filtered_ports"]]
                lines.append(f"A: Yes - {', '.join(port_list)}")
                lines.append("")
            else:
                lines.append(f"Q: Are any ports filtered?")
                lines.append(f"A: No filtered ports detected")
                lines.append("")

            if host.get("os_detection", {}).get("os_family"):
                lines.append(f"Q: What OS was detected?")
                lines.append(f"A: {host['os_detection']['os_family']}")
                lines.append("")

            if host.get("os_guesses"):
                lines.append(f"Q: What are the OS guesses with confidence scores?")
                for guess in host["os_guesses"]:
                    lines.append(f"A: {guess['os']} ({guess['confidence']}% confidence)")
                lines.append("")

            if host.get("mac_vendor"):
                lines.append(f"Q: Is there evidence of virtualization or hardware vendor?")
                lines.append(f"A: Yes - MAC vendor: {host['mac_vendor']}")
                lines.append("")

            if host.get("script_output"):
                lines.append(f"Q: What script output was captured?")
                for script in host["script_output"]:
                    lines.append(f"A: {script['script']}: {script['output']}")
                lines.append("")

            if host.get("traceroute"):
                lines.append(f"Q: What does the traceroute show?")
                for hop in host["traceroute"]:
                    lines.append(f"A: Hop {hop['hop']}: {hop['ip']} ({hop['rtt']})")
                lines.append("")

            if host.get("network_distance"):
                lines.append(f"Q: What is the network distance to the target?")
                lines.append(f"A: {host['network_distance']}")
                lines.append("")

            if host.get("device_type"):
                lines.append(f"Q: What device type was detected?")
                lines.append(f"A: {host['device_type']}")
                lines.append("")

            if host.get("tcp_sequence"):
                lines.append(f"Q: What is the TCP sequence prediction?")
                lines.append(f"A: {host['tcp_sequence']}")
                lines.append("")

            if host.get("ip_id_sequence"):
                lines.append(f"Q: What is the IP ID sequence generation?")
                lines.append(f"A: {host['ip_id_sequence']}")
                lines.append("")

            if host.get("host_scripts"):
                lines.append(f"Q: Were any host-level scripts run?")
                for script in host["host_scripts"]:
                    lines.append(f"A: {script}")
                lines.append("")

            if host.get("warnings"):
                lines.append(f"Q: Were there any warnings or notes?")
                for warning in host["warnings"]:
                    lines.append(f"A: {warning['type']}: {warning['message']}")
                lines.append("")

            if host.get("interesting_ports"):
                lines.append(f"Q: Any interesting ports summary?")
                for summary in host["interesting_ports"]:
                    lines.append(f"A: {summary}")
                lines.append("")

        lines.append("---")
        lines.append("END OF FACTS - Answer ONLY using the Q&A pairs above")

        return "\n".join(lines)


# Example usage
if __name__ == "__main__":
    # Test with sample scan
    sample_scan = """# Nmap 7.98 scan initiated Tue Dec 30 2025 10:12:41 GMT
Nmap scan report for 192.168.56.101
Host is up (0.0013s latency).
Not shown: 996 closed tcp ports (reset)
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 8.9p1 Ubuntu 3ubuntu0.7 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http        Apache httpd 2.4.52 ((Ubuntu))
111/tcp  open  rpcbind     2-4 (RPC #100000)
631/tcp  open  ipp         CUPS 2.4
MAC Address: 08:00:27:AA:BB:CC (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Nmap done: 1 IP address (1 host up) scanned in 8.41 seconds"""

    extractor = NmapFactExtractor()
    facts = extractor.extract_facts(sample_scan)

    print("=== STRUCTURED FACTS (JSON) ===")
    print(json.dumps(facts, indent=2, default=str))
    print("\n")

    print("=== FACTS AS TEXT (FOR LLM) ===")
    print(extractor.facts_to_text(facts))
