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

        # Match "Nmap scan report for <target>" with optional "(IP)" or "(hostname)"
        # Handles both formats:
        #   "Nmap scan report for 10.0.5.10 (DC01.CORP.LOCAL)"  -> extracts 10.0.5.10
        #   "Nmap scan report for DC-INTERNAL-01.OMNI.LOCAL (10.50.1.10)" -> extracts DC-INTERNAL-01.OMNI.LOCAL AND 10.50.1.10
        for match in re.finditer(r'Nmap scan report for ([^\s\n]+)(?:\s+\(([^)]+)\))?', scan_text):
            target = match.group(1)
            if target not in targets:
                targets.append(target)
            # Also capture the value in parentheses (could be IP or hostname)
            alt = match.group(2)
            if alt and alt not in targets:
                targets.append(alt)

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
            "interesting_ports": [],
            "nfs_shares": [],
            "ftp_files": [],
            "smb_shares": [],
            "http_enum_findings": [],
            "discovered_credentials": [],
            "database_names": [],
            "finger_users": [],
            "exposed_files": []
        }

        lines = section.split('\n')
        if not lines:
            return None

        # First line is the target
        host["target"] = lines[0].strip()

        # Parse each line
        current_script = None
        for line in lines[1:]:
            line = line.strip()  # Remove leading/trailing whitespace for regex matching

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
            port_match = re.match(r'(\d+)/(tcp|udp)\s+(open|filtered|closed|open\|filtered)\s+(\S+)(?:\s+(.+))?', line)
            if port_match:
                port_info = {
                    "port": int(port_match.group(1)),
                    "protocol": port_match.group(2),
                    "state": port_match.group(3),
                    "service": port_match.group(4),
                    "version_info": port_match.group(5).strip() if port_match.group(5) else ""
                }

                if port_info["state"] in ("open", "open|filtered"):
                    host["open_ports"].append(port_info)
                elif port_info["state"] == "filtered":
                    host["filtered_ports"].append(port_info)

            # MAC Address
            mac_match = re.search(r'MAC Address: ([0-9A-Fa-f:]+)(?: \((.+)\))?', line)
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

        # === ADVANCED PATTERN EXTRACTION (Gemini's missing findings) ===
        section_text = '\n'.join(lines)

        # NFS Shares and File Listings - CRITICAL PATTERN
        self._extract_nfs_data(section_text, host)

        # FTP Directory Listings with Files
        self._extract_ftp_data(section_text, host)

        # SMB Shares with Files
        self._extract_smb_data(section_text, host)

        # HTTP-enum Findings (exposed dirs/files)
        self._extract_http_enum_data(section_text, host)

        # Discovered Credentials (brute force, default creds)
        self._extract_credentials(section_text, host)

        # Database Names (MySQL, Elasticsearch indices, etc.)
        self._extract_database_info(section_text, host)

        # Finger User Listings
        self._extract_finger_users(section_text, host)

        # Exposed Files (keys, configs, backups)
        self._extract_exposed_files(section_text, host)

        return host

    def _extract_nfs_data(self, text: str, host: Dict[str, Any]):
        """Extract NFS shares and file listings - THE CRITICAL PATTERN GEMINI CAUGHT"""
        # Pattern: nfs-showmount or nfs-ls output
        # Example: /exports * or /root 10.0.50.1
        nfs_showmount = re.findall(r'\|\s+(/[^\s]+)\s+([*\d.]+(?:/\d+)?)', text)
        for path, access in nfs_showmount:
            host["nfs_shares"].append({
                "path": path,
                "access_from": access,
                "type": "nfs_mount"
            })

        # Extract nfs-ls file listings - CATCHES id_rsa, shadow.bak, etc.
        # Pattern: -rw-r--r--  root  root  2048  id_rsa
        file_listings = re.findall(r'\|\s+([d-][rwx-]{9})\s+(\S+)\s+(\S+)\s+(\d+)\s+(.+)', text)
        for perms, owner, group, size, filename in file_listings:
            host["exposed_files"].append({
                "filename": filename.strip(),
                "permissions": perms,
                "owner": owner,
                "group": group,
                "size": int(size),
                "source": "nfs-ls"
            })

    def _extract_ftp_data(self, text: str, host: Dict[str, Any]):
        """Extract FTP anonymous access and directory listings"""
        # Anonymous FTP
        if 'ftp-anon:' in text.lower() or 'Anonymous FTP login allowed' in text:
            host["discovered_credentials"].append({
                "source": "FTP",
                "service": "FTP",
                "username": "anonymous",
                "password": "none_required",
                "access_level": "READ/WRITE" if 'drwxrwxrwx' in text else "READ"
            })

        # FTP directory listings
        # Pattern: drwxrwxrwx    2 0        0            4096 Jan 02 09:15 pub
        ftp_dirs = re.findall(r'\|\s*([d-][rwx-]{9})\s+\d+\s+\d+\s+\d+\s+\d+\s+\w+\s+\d+\s+[\d:]+\s+(.+?)(?:\[NSE:|$)', text)
        for perms, dirname in ftp_dirs:
            host["ftp_files"].append({
                "name": dirname.strip(),
                "permissions": perms,
                "type": "directory" if perms.startswith('d') else "file"
            })

    def _extract_smb_data(self, text: str, host: Dict[str, Any]):
        """Extract SMB shares and access levels"""
        # Pattern: \\10.0.50.5\backup$: or account_used: guest
        smb_shares = re.findall(r'\\\\\S+\\([^:]+):\s*\n\s*\|\s+.*access:\s*(\S+(?:\s+\S+)?)', text, re.MULTILINE)
        for share_name, access_type in smb_shares:
            host["smb_shares"].append({
                "share_name": share_name.strip(),
                "access": access_type.strip(),
                "authentication": "guest" if "guest" in text.lower() else "authenticated"
            })

        # SMB computer name and workgroup
        computer_name = re.search(r'NetBIOS computer name:\s*(\S+)', text)
        workgroup = re.search(r'Workgroup:\s*(\S+)', text)
        if computer_name:
            host["os_detection"]["netbios_name"] = computer_name.group(1)
        if workgroup:
            host["os_detection"]["workgroup"] = workgroup.group(1)

    def _extract_http_enum_data(self, text: str, host: Dict[str, Any]):
        """Extract http-enum findings (exposed directories and files)"""
        # Pattern: /admin/: Possible admin folder or /.git/HEAD: Git repository found
        http_findings = re.findall(r'\|\s+(/[^:]+):\s*(.+?)(?:\n|$)', text)
        for path, description in http_findings:
            if any(keyword in path.lower() for keyword in ['.git', 'admin', 'backup', 'config', 'phpmyadmin', 'server-status', '.env', 'phpinfo']):
                host["http_enum_findings"].append({
                    "path": path.strip(),
                    "description": description.strip(),
                    "risk": "HIGH" if any(x in path.lower() for x in ['.git', 'backup', 'config', '.env']) else "MEDIUM"
                })

    def _extract_credentials(self, text: str, host: Dict[str, Any]):
        """Extract discovered credentials from brute force and default credential checks"""
        # Brute force results
        # Pattern: admin:admin123 - Valid credentials
        brute_force_creds = re.findall(r'\|\s+([^:]+):([^\s]+)\s+-\s+Valid credentials', text)
        for username, password in brute_force_creds:
            host["discovered_credentials"].append({
                "source": "brute_force",
                "username": username.strip(),
                "password": password.strip(),
                "status": "valid"
            })

        # Default credentials
        # Pattern: [VULNERABLE] Tomcat Manager (admin:admin)
        default_creds = re.findall(r'\[VULNERABLE\]\s+([^(]+)\s+\(([^:]+):([^)]+)\)', text)
        for service, username, password in default_creds:
            host["discovered_credentials"].append({
                "source": "default_credentials",
                "service": service.strip(),
                "username": username.strip(),
                "password": password.strip(),
                "status": "default"
            })

        # Empty password / no auth required
        if 'empty password' in text.lower() or 'No auth required' in text.lower() or 'No password required' in text.lower():
            empty_pass_matches = re.findall(r'(\S+)\s+user\s+has\s+empty\s+password', text, re.IGNORECASE)
            for username in empty_pass_matches:
                host["discovered_credentials"].append({
                    "source": "empty_password",
                    "username": username.strip(),
                    "password": "",
                    "status": "CRITICAL"
                })

            # No password required pattern
            no_pass_matches = re.findall(r'(\S+)\s+from\s+\S+\s+-\s+No\s+password\s+required', text, re.IGNORECASE)
            for username in no_pass_matches:
                host["discovered_credentials"].append({
                    "source": "no_auth_required",
                    "username": username.strip(),
                    "password": "not_required",
                    "status": "CRITICAL"
                })

    def _extract_database_info(self, text: str, host: Dict[str, Any]):
        """Extract database names and indices"""
        # MySQL databases
        # Pattern: |   customer_data or |_  wordpress_prod
        if 'mysql-databases:' in text.lower() or 'mysql-enum' in text.lower():
            db_names = re.findall(r'\|\s+([a-zA-Z_][a-zA-Z0-9_]+)(?:\n|$)', text)
            for db_name in db_names:
                if db_name not in ['information_schema', 'mysql', 'performance_schema']:
                    host["database_names"].append({
                        "type": "MySQL",
                        "name": db_name.strip()
                    })

        # Elasticsearch indices
        # Pattern: elasticsearch-indices: logs-2024, customers, credentials_backup
        es_indices = re.findall(r'elasticsearch-indices:\s*\n((?:\|\s+\S+\s*\n?)+)', text, re.IGNORECASE)
        for index_block in es_indices:
            indices = re.findall(r'\|\s+(\S+)', index_block)
            for index_name in indices:
                host["database_names"].append({
                    "type": "Elasticsearch",
                    "name": index_name.strip()
                })

    def _extract_finger_users(self, text: str, host: Dict[str, Any]):
        """Extract user information from finger service"""
        # Pattern: | root      root       pts/0          Jan  6 08:15 (10.0.50.1)
        finger_users = re.findall(r'\|\s+(\S+)\s+([^\s]+(?:\s+[^\s]+)?)\s+(pts/\d+|\*)\s+([^\s]+)?\s+([A-Z][a-z]{2}\s+\d+\s+[\d:]+)(?:\s+\(([^)]+)\))?', text)
        for username, fullname, tty, idle, login_time, login_from in finger_users:
            host["finger_users"].append({
                "username": username.strip(),
                "full_name": fullname.strip(),
                "tty": tty.strip(),
                "idle_time": idle.strip() if idle else "active",
                "login_time": login_time.strip(),
                "login_from": login_from.strip() if login_from else "local"
            })

    def _extract_exposed_files(self, text: str, host: Dict[str, Any]):
        """Extract exposed sensitive files (SSH keys, password files, configs)"""
        # Pattern: -rw-r--r--  root  root  2048  id_rsa
        sensitive_patterns = [
            r'id_rsa', r'id_dsa', r'id_ecdsa', r'id_ed25519',  # SSH keys
            r'shadow\.bak', r'passwd\.bak', r'shadow$', r'passwd$',  # Password files
            r'\.pem$', r'\.key$', r'\.crt$',  # Certificate files
            r'config\.php', r'\.env', r'web\.config',  # Config files
            r'backup', r'\.sql', r'\.db', r'database'  # Backup files
        ]

        for pattern in sensitive_patterns:
            matches = re.finditer(pattern, text, re.IGNORECASE)
            for match in matches:
                # Try to extract full context around the match
                context_start = max(0, match.start() - 100)
                context_end = min(len(text), match.end() + 50)
                context = text[context_start:context_end]

                # Look for file permissions in context
                file_info = re.search(r'([d-][rwx-]{9})\s+(\S+)\s+(\S+)\s+(\d+)\s+(.+)', context)
                if file_info:
                    filename = file_info.group(5).strip()
                    if not any(existing['filename'] == filename for existing in host["exposed_files"]):
                        host["exposed_files"].append({
                            "filename": filename,
                            "permissions": file_info.group(1),
                            "owner": file_info.group(2),
                            "group": file_info.group(3),
                            "size": int(file_info.group(4)),
                            "source": "pattern_match",
                            "risk": "CRITICAL" if any(x in filename.lower() for x in ['id_rsa', 'shadow', '.env', '.pem']) else "HIGH"
                        })

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

        # Targets
        if facts["targets"]:
            lines.append(f"Q: What IPs/hostnames were scanned?")
            if len(facts["targets"]) == 1:
                lines.append(f"A: {facts['targets'][0]}")
            else:
                lines.append(f"A: {', '.join(facts['targets'])}")
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

            if host.get("os_detection", {}).get("netbios_name"):
                netbios = host['os_detection']['netbios_name']
                workgroup = host.get('os_detection', {}).get('workgroup', '')
                lines.append(f"Q: What is the hostname/computer name of this host?")
                lines.append(f"A: {netbios} (discovered via SMB/NetBIOS)")
                if workgroup:
                    lines.append(f"   Workgroup/Domain: {workgroup}")
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

            # === NEW CRITICAL FINDINGS (Gemini's patterns) ===
            if host.get("nfs_shares"):
                lines.append(f"Q: Are there any NFS shares exposed?")
                for share in host["nfs_shares"]:
                    lines.append(f"A: Yes - {share['path']} accessible from {share['access_from']}")
                lines.append("")

            if host.get("exposed_files"):
                lines.append(f"Q: Were any sensitive files discovered?")
                for file in host["exposed_files"]:
                    risk_label = f" [RISK: {file.get('risk', 'UNKNOWN')}]" if 'risk' in file else ""
                    lines.append(f"A: {file['filename']} ({file['permissions']}) owned by {file['owner']}:{file['group']}, size: {file['size']} bytes{risk_label}")
                lines.append("")

            if host.get("discovered_credentials"):
                lines.append(f"Q: Were any credentials discovered?")
                for cred in host["discovered_credentials"]:
                    if cred['source'] == 'brute_force':
                        lines.append(f"A: Brute force found: {cred['username']}:{cred['password']} (valid)")
                    elif cred['source'] == 'default_credentials':
                        lines.append(f"A: Default credentials: {cred.get('service', 'service')} - {cred['username']}:{cred['password']}")
                    elif cred['source'] == 'empty_password':
                        lines.append(f"A: CRITICAL - {cred['username']} has EMPTY PASSWORD")
                    elif cred['source'] == 'no_auth_required':
                        lines.append(f"A: CRITICAL - {cred['username']} requires NO AUTHENTICATION")
                    elif cred['source'] == 'FTP':
                        lines.append(f"A: Anonymous FTP access allowed ({cred.get('access_level', 'unknown')})")
                lines.append("")

            if host.get("smb_shares"):
                lines.append(f"Q: Are there any SMB shares accessible?")
                for share in host["smb_shares"]:
                    lines.append(f"A: Share '{share['share_name']}' with {share['access']} access ({share['authentication']})")
                lines.append("")

            if host.get("http_enum_findings"):
                lines.append(f"Q: Were any sensitive web directories/files found?")
                for finding in host["http_enum_findings"]:
                    lines.append(f"A: {finding['path']} - {finding['description']} [RISK: {finding['risk']}]")
                lines.append("")

            if host.get("database_names"):
                lines.append(f"Q: What database names or indices were found?")
                for db in host["database_names"]:
                    lines.append(f"A: {db['type']} database/index: {db['name']}")
                lines.append("")

            if host.get("finger_users"):
                lines.append(f"Q: What users were found via finger?")
                for user in host["finger_users"]:
                    lines.append(f"A: User {user['username']} ({user['full_name']}) logged in from {user['login_from']} at {user['login_time']}")
                lines.append("")

            if host.get("ftp_files"):
                lines.append(f"Q: What files/directories are in the FTP server?")
                for file in host["ftp_files"]:
                    lines.append(f"A: {file['name']} ({file['permissions']}) - {file['type']}")
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
