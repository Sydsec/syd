#!/usr/bin/env python3
"""
Deterministic Volatility 3 Fact Extractor (Stage A)
Parses Volatility 3 output into structured facts - 100% accurate, no AI
Mirrors Nmap/BloodHound fact extractor architecture
"""

import re
import json
from typing import Dict, List, Any, Optional


class VolatilityFactExtractor:
    """Extracts structured facts from Volatility 3 plugin output"""

    def extract_facts(self, vol_output: str) -> Dict[str, Any]:
        """
        Parse Volatility 3 output into structured facts
        Returns a dictionary of facts that can be queried by LLM
        """
        facts = {
            "plugin_type": self._detect_plugin_type(vol_output),
            "processes": [],
            "network_connections": [],
            "command_lines": [],
            "dll_list": [],
            "malfind_results": [],
            "registry_keys": [],
            "file_handles": [],
            "metadata": {},
            "all_pids": [],
            "all_process_names": [],
            "all_ips": [],
            "all_ports": []
        }

        # Parse ALL sections - output may contain multiple plugins
        # This handles cases where users paste multiple Volatility outputs together
        facts["processes"] = self._extract_processes_pslist(vol_output)
        facts["network_connections"] = self._extract_network_netscan(vol_output)
        facts["command_lines"] = self._extract_cmdline(vol_output)
        facts["dll_list"] = self._extract_dlllist(vol_output)
        facts["malfind_results"] = self._extract_malfind(vol_output)
        facts["file_handles"] = self._extract_filescan(vol_output)
        facts["registry_keys"] = self._extract_registry(vol_output)

        # Build aggregated lists for validation
        facts["all_pids"] = self._extract_all_pids(facts)
        facts["all_process_names"] = self._extract_all_process_names(facts)
        facts["all_ips"] = self._extract_all_ips(facts)
        facts["all_ports"] = self._extract_all_ports(facts)

        # Extract metadata
        facts["metadata"] = self._extract_metadata(vol_output)

        return facts

    def _detect_plugin_type(self, output: str) -> str:
        """Detect which Volatility plugin was used"""
        output_lower = output.lower()

        if "windows.pslist" in output_lower or "pslist" in output_lower[:200]:
            return "pslist"
        elif "windows.pstree" in output_lower or "pstree" in output_lower[:200]:
            return "pstree"
        elif "windows.netscan" in output_lower or "netscan" in output_lower[:200]:
            return "netscan"
        elif "windows.cmdline" in output_lower or "cmdline" in output_lower[:200]:
            return "cmdline"
        elif "windows.dlllist" in output_lower or "dlllist" in output_lower[:200]:
            return "dlllist"
        elif "windows.malfind" in output_lower or "malfind" in output_lower[:200]:
            return "malfind"
        elif "windows.filescan" in output_lower or "filescan" in output_lower[:200]:
            return "filescan"
        elif "windows.hivelist" in output_lower or "hivelist" in output_lower[:200]:
            return "hivelist"
        elif "windows.registry.printkey" in output_lower or "printkey" in output_lower[:200]:
            return "printkey"

        return "unknown"

    def _extract_processes_pslist(self, output: str) -> List[Dict[str, Any]]:
        """
        Extract process information from windows.pslist or windows.pstree output

        Typical format:
        PID     PPID    ImageFileName   Offset(V)       Threads Handles SessionId       Wow64   CreateTime      ExitTime
        4       0       System  0x8a0b4d90      123     890     N/A     False   2023-01-15 10:30:00.000000      N/A
        """
        processes = []

        # Split into lines
        lines = output.strip().split('\n')

        for line in lines:
            # Skip empty lines and headers
            if not line.strip() or 'PID' in line or '---' in line or 'ImageFileName' in line:
                continue

            # Try to parse process line (flexible whitespace)
            # Common patterns: PID PPID ImageFileName ...
            parts = line.split()

            if len(parts) >= 3:
                try:
                    # Attempt to extract PID, PPID, and process name
                    pid = parts[0]
                    ppid = parts[1] if len(parts) > 1 else "N/A"
                    image_name = parts[2] if len(parts) > 2 else "Unknown"

                    # Validate PID is numeric
                    if not pid.isdigit():
                        continue

                    process_info = {
                        "pid": int(pid),
                        "ppid": int(ppid) if ppid.isdigit() else None,
                        "name": image_name,
                        "raw_line": line.strip()
                    }

                    # Try to extract additional fields if present
                    if len(parts) >= 5:
                        process_info["threads"] = parts[4] if parts[4].isdigit() else None
                    if len(parts) >= 6:
                        process_info["handles"] = parts[5] if parts[5].isdigit() else None

                    # Extract CreateTime if present (typical format: "2023-01-15 10:30:00")
                    create_time_match = re.search(r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})', line)
                    if create_time_match:
                        process_info["create_time"] = create_time_match.group(1)

                    processes.append(process_info)

                except (ValueError, IndexError):
                    # Skip malformed lines
                    continue

        return processes

    def _extract_network_netscan(self, output: str) -> List[Dict[str, Any]]:
        """
        Extract network connections from windows.netscan output

        Typical formats:
        Format 1: Offset  Proto   LocalAddr       LocalPort       ForeignAddr     ForeignPort     State   PID     Owner
        Format 2: Proto LocalAddr      LPort ForeignAddr     FPort State        PID  Owner
        """
        connections = []

        lines = output.strip().split('\n')

        for line in lines:
            # Skip headers and empty lines
            if not line.strip() or 'Proto' in line or 'LocalAddr' in line or 'Offset' in line or '---' in line:
                continue

            # Extract IPs
            ip_pattern = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
            ips = re.findall(ip_pattern, line)

            # Extract ports - look for standalone port numbers (not part of IPs)
            # Split line into parts and find numeric values that are likely ports
            parts = line.split()
            ports = []
            for i, part in enumerate(parts):
                # Check if it's a number between 1-65535 and follows an IP or LocalPort/ForeignPort keyword
                if part.isdigit() and 1 <= int(part) <= 65535:
                    # Check context - should be near IP addresses or port keywords
                    if i > 0 and (parts[i-1] in ips or 'Port' in parts[i-1] or parts[i-1] in ['LPort', 'FPort']):
                        ports.append(int(part))

            # Extract PID - look for PID keyword or number followed by process name
            pid = None
            for i, part in enumerate(parts):
                # Look for pattern: number followed by .exe
                if part.isdigit() and i + 1 < len(parts) and '.exe' in parts[i+1].lower():
                    pid = int(part)
                    break

            # Extract process name (ends with .exe)
            process_match = re.search(r'\b([a-zA-Z0-9_\-]+\.exe)\b', line, re.IGNORECASE)
            process_name = process_match.group(1) if process_match else None

            # Extract protocol
            proto_match = re.search(r'\b(TCPv4|TCPv6|UDPv4|UDPv6|TCP|UDP)\b', line, re.IGNORECASE)
            protocol = proto_match.group(1) if proto_match else None

            # Extract state
            state_match = re.search(r'\b(ESTABLISHED|LISTENING|CLOSE_WAIT|TIME_WAIT|CLOSED)\b', line, re.IGNORECASE)
            state = state_match.group(1) if state_match else None

            if ips or pid:
                conn_info = {
                    "local_ip": ips[0] if len(ips) > 0 else None,
                    "local_port": ports[0] if len(ports) > 0 else None,
                    "remote_ip": ips[1] if len(ips) > 1 else None,
                    "remote_port": ports[1] if len(ports) > 1 else None,
                    "state": state,
                    "pid": pid,
                    "process": process_name,
                    "protocol": protocol,
                    "raw_line": line.strip()
                }
                connections.append(conn_info)

        return connections

    def _extract_cmdline(self, output: str) -> List[Dict[str, Any]]:
        """
        Extract command line arguments from windows.cmdline output

        Typical format:
        PID     Process Args
        1234    chrome.exe      "C:\\Program Files\\Google\\Chrome\\chrome.exe" --type=renderer
        """
        cmdlines = []

        lines = output.strip().split('\n')

        for line in lines:
            if not line.strip() or 'PID' in line or 'Process' in line or '---' in line:
                continue

            # Extract PID (first number)
            pid_match = re.match(r'^\s*(\d+)\s+', line)
            if pid_match:
                pid = int(pid_match.group(1))

                # Extract process name
                process_match = re.search(r'\b([a-zA-Z0-9_\-]+\.exe)\b', line, re.IGNORECASE)
                process_name = process_match.group(1) if process_match else "Unknown"

                # Extract command line (everything after PID and process name)
                cmdline = line[pid_match.end():].strip()

                cmdlines.append({
                    "pid": pid,
                    "process": process_name,
                    "cmdline": cmdline,
                    "raw_line": line.strip()
                })

        return cmdlines

    def _extract_dlllist(self, output: str) -> List[Dict[str, Any]]:
        """Extract DLL information from windows.dlllist output"""
        dlls = []
        current_pid = None
        current_process = None

        lines = output.strip().split('\n')

        for line in lines:
            if not line.strip():
                continue

            # Detect process header (PID: 1234 Process: chrome.exe)
            pid_match = re.search(r'PID:\s*(\d+)', line, re.IGNORECASE)
            if pid_match:
                current_pid = int(pid_match.group(1))

            process_match = re.search(r'Process:\s*([^\s]+)', line, re.IGNORECASE)
            if process_match:
                current_process = process_match.group(1)

            # Extract DLL paths (typically start with C:\ or other drive letters)
            dll_match = re.search(r'\b([A-Z]:\\[^\s]+\.dll)\b', line, re.IGNORECASE)
            if dll_match and current_pid:
                dll_path = dll_match.group(1)
                dll_name = dll_path.split('\\')[-1]

                dlls.append({
                    "pid": current_pid,
                    "process": current_process,
                    "dll_name": dll_name,
                    "dll_path": dll_path,
                    "raw_line": line.strip()
                })

        return dlls

    def _extract_malfind(self, output: str) -> List[Dict[str, Any]]:
        """
        Extract suspicious memory regions from windows.malfind output
        Indicates potential code injection
        """
        malfind_results = []
        current_pid = None
        current_process = None
        current_start_vpn = None
        current_end_vpn = None
        current_protection = None

        lines = output.strip().split('\n')

        for line in lines:
            if not line.strip():
                continue

            # Extract PID
            pid_match = re.search(r'PID:\s*(\d+)', line, re.IGNORECASE)
            if pid_match:
                current_pid = int(pid_match.group(1))

            # Extract process name
            process_match = re.search(r'Process:\s*([^\s]+)', line, re.IGNORECASE)
            if process_match:
                current_process = process_match.group(1)

            # Extract Start VPN address
            start_vpn_match = re.search(r'Start\s+VPN:\s*(0x[0-9a-fA-F]+)', line, re.IGNORECASE)
            if start_vpn_match:
                current_start_vpn = start_vpn_match.group(1)

            # Extract End VPN address
            end_vpn_match = re.search(r'End\s+VPN:\s*(0x[0-9a-fA-F]+)', line, re.IGNORECASE)
            if end_vpn_match:
                current_end_vpn = end_vpn_match.group(1)

            # Extract memory protection (PAGE_EXECUTE_READWRITE = suspicious)
            protection_match = re.search(r'Protection:\s*(PAGE_[A-Z_]+)', line, re.IGNORECASE)
            if protection_match:
                current_protection = protection_match.group(1)

                # When we find protection, we have a complete malfind entry
                if current_pid:
                    malfind_results.append({
                        "pid": current_pid,
                        "process": current_process,
                        "start_vpn": current_start_vpn,
                        "end_vpn": current_end_vpn,
                        "protection": current_protection,
                        "suspicious": "EXECUTE_READWRITE" in current_protection or "EXECUTE_WRITECOPY" in current_protection,
                        "raw_line": line.strip()
                    })

                    # Reset for next entry
                    current_start_vpn = None
                    current_end_vpn = None

        return malfind_results

    def _extract_filescan(self, output: str) -> List[Dict[str, Any]]:
        """Extract file handles from windows.filescan output"""
        files = []

        lines = output.strip().split('\n')

        for line in lines:
            if not line.strip() or 'Offset' in line or '---' in line:
                continue

            # Extract file paths
            file_match = re.search(r'\b([A-Z]:\\[^\s]+)\b', line, re.IGNORECASE)
            if file_match:
                file_path = file_match.group(1)

                files.append({
                    "file_path": file_path,
                    "raw_line": line.strip()
                })

        return files

    def _extract_registry(self, output: str) -> List[Dict[str, Any]]:
        """Extract registry keys from windows.registry.printkey or hivelist output"""
        keys = []

        lines = output.strip().split('\n')

        for line in lines:
            if not line.strip() or 'Offset' in line or '---' in line:
                continue

            # Extract registry paths (HKEY_LOCAL_MACHINE\..., etc.)
            key_match = re.search(r'(HKEY_[A-Z_]+\\[^\s]+|\\Registry\\[^\s]+)', line, re.IGNORECASE)
            if key_match:
                key_path = key_match.group(1)

                keys.append({
                    "key_path": key_path,
                    "raw_line": line.strip()
                })

        return keys

    def _extract_metadata(self, output: str) -> Dict[str, Any]:
        """Extract general metadata from Volatility output"""
        metadata = {}

        # Extract Volatility version
        version_match = re.search(r'Volatility\s+(\d+\.\d+\.\d+)', output, re.IGNORECASE)
        if version_match:
            metadata["volatility_version"] = version_match.group(1)

        # Extract plugin name
        plugin_match = re.search(r'windows\.([a-z]+)', output, re.IGNORECASE)
        if plugin_match:
            metadata["plugin"] = f"windows.{plugin_match.group(1)}"

        # Count total lines
        metadata["total_lines"] = len(output.split('\n'))

        return metadata

    def _extract_all_pids(self, facts: Dict[str, Any]) -> List[int]:
        """Extract all PIDs for validation"""
        pids = set()

        for proc in facts["processes"]:
            if proc.get("pid"):
                pids.add(proc["pid"])

        for conn in facts["network_connections"]:
            if conn.get("pid"):
                pids.add(conn["pid"])

        for cmd in facts["command_lines"]:
            if cmd.get("pid"):
                pids.add(cmd["pid"])

        for dll in facts["dll_list"]:
            if dll.get("pid"):
                pids.add(dll["pid"])

        for mal in facts["malfind_results"]:
            if mal.get("pid"):
                pids.add(mal["pid"])

        return sorted(list(pids))

    def _extract_all_process_names(self, facts: Dict[str, Any]) -> List[str]:
        """Extract all process names for validation"""
        names = set()

        for proc in facts["processes"]:
            if proc.get("name"):
                names.add(proc["name"].lower())

        for conn in facts["network_connections"]:
            if conn.get("process"):
                names.add(conn["process"].lower())

        for cmd in facts["command_lines"]:
            if cmd.get("process"):
                names.add(cmd["process"].lower())

        return sorted(list(names))

    def _extract_all_ips(self, facts: Dict[str, Any]) -> List[str]:
        """Extract all IP addresses for validation"""
        ips = set()

        for conn in facts["network_connections"]:
            if conn.get("local_ip"):
                ips.add(conn["local_ip"])
            if conn.get("remote_ip"):
                ips.add(conn["remote_ip"])

        return sorted(list(ips))

    def _extract_all_ports(self, facts: Dict[str, Any]) -> List[int]:
        """Extract all ports for validation"""
        ports = set()

        for conn in facts["network_connections"]:
            if conn.get("local_port"):
                ports.add(conn["local_port"])
            if conn.get("remote_port"):
                ports.add(conn["remote_port"])

        return sorted(list(ports))

    def facts_to_text(self, facts: Dict[str, Any]) -> str:
        """
        Convert structured facts to simple Q&A format for LLM
        Mirrors Nmap/BloodHound architecture
        """
        lines = []

        lines.append("FACTS EXTRACTED FROM MEMORY DUMP:")
        lines.append("")

        # Plugin type
        if facts.get("plugin_type"):
            lines.append(f"Q: What Volatility plugin output is this?")
            lines.append(f"A: {facts['plugin_type']}")
            lines.append("")

        # Metadata
        if facts.get("metadata"):
            meta = facts["metadata"]
            if meta.get("volatility_version"):
                lines.append(f"Q: What Volatility version was used?")
                lines.append(f"A: {meta['volatility_version']}")
                lines.append("")

        # Processes
        if facts.get("processes"):
            lines.append(f"Q: How many processes were found?")
            lines.append(f"A: {len(facts['processes'])} processes")
            lines.append("")

            lines.append(f"Q: What processes are running (PID, Name, PPID)?")
            for proc in facts["processes"][:50]:  # Limit to first 50
                ppid_str = f"PPID={proc['ppid']}" if proc.get('ppid') else "PPID=Unknown"
                lines.append(f"A: PID {proc['pid']}: {proc['name']} ({ppid_str})")
            if len(facts["processes"]) > 50:
                lines.append(f"A: ... and {len(facts['processes']) - 50} more processes")
            lines.append("")

        # Network connections
        if facts.get("network_connections"):
            lines.append(f"Q: How many network connections were found?")
            lines.append(f"A: {len(facts['network_connections'])} connections")
            lines.append("")

            lines.append(f"Q: What network connections exist?")
            for conn in facts["network_connections"][:30]:  # Limit to first 30
                local = f"{conn.get('local_ip', 'N/A')}:{conn.get('local_port', 'N/A')}"
                remote = f"{conn.get('remote_ip', 'N/A')}:{conn.get('remote_port', 'N/A')}"
                state = conn.get('state', 'N/A')
                pid = conn.get('pid', 'N/A')
                process = conn.get('process', 'N/A')
                lines.append(f"A: {local} -> {remote} [{state}] PID {pid} ({process})")
            if len(facts["network_connections"]) > 30:
                lines.append(f"A: ... and {len(facts['network_connections']) - 30} more connections")
            lines.append("")

        # Command lines
        if facts.get("command_lines"):
            lines.append(f"Q: What command lines were captured?")
            for cmd in facts["command_lines"][:20]:  # Limit to first 20
                lines.append(f"A: PID {cmd['pid']} ({cmd['process']}): {cmd['cmdline'][:200]}")
            if len(facts["command_lines"]) > 20:
                lines.append(f"A: ... and {len(facts['command_lines']) - 20} more command lines")
            lines.append("")

        # Malfind results (code injection indicators)
        if facts.get("malfind_results"):
            lines.append(f"Q: Were any suspicious memory regions found (potential code injection)?")
            lines.append(f"A: Yes, {len(facts['malfind_results'])} suspicious regions found")
            lines.append("")

            lines.append(f"Q: What are the specific memory addresses and protection flags?")
            for mal in facts["malfind_results"][:10]:
                start_vpn = mal.get('start_vpn', 'N/A')
                end_vpn = mal.get('end_vpn', 'N/A')
                lines.append(f"A: PID {mal['pid']} ({mal['process']}): Memory region {start_vpn} to {end_vpn}, Protection: {mal['protection']}")
            if len(facts["malfind_results"]) > 10:
                lines.append(f"A: ... and {len(facts['malfind_results']) - 10} more suspicious regions")
            lines.append("")

        # DLL list (if present)
        if facts.get("dll_list"):
            unique_dlls = set(dll['dll_name'] for dll in facts['dll_list'])
            lines.append(f"Q: How many unique DLLs were loaded?")
            lines.append(f"A: {len(unique_dlls)} unique DLLs across all processes")
            lines.append("")

            # Highlight DLLs from unusual locations (not System32, Windows, Program Files)
            unusual_dlls = [
                dll for dll in facts['dll_list']
                if dll.get('dll_path') and not any(
                    normal_path in dll['dll_path'].lower()
                    for normal_path in ['\\windows\\system32', '\\windows\\syswow64', '\\program files']
                )
            ]
            if unusual_dlls:
                lines.append(f"Q: Are there any DLLs loaded from unusual locations?")
                for dll in unusual_dlls[:10]:
                    lines.append(f"A: PID {dll['pid']} ({dll.get('process', 'Unknown')}): {dll['dll_path']}")
                if len(unusual_dlls) > 10:
                    lines.append(f"A: ... and {len(unusual_dlls) - 10} more unusual DLLs")
                lines.append("")

        # Summary of all PIDs
        if facts.get("all_pids"):
            lines.append(f"Q: What are ALL the PIDs in this analysis?")
            lines.append(f"A: {', '.join(map(str, facts['all_pids']))}")
            lines.append("")

        # Summary of all IPs
        if facts.get("all_ips"):
            lines.append(f"Q: What are ALL the IP addresses in this analysis?")
            lines.append(f"A: {', '.join(facts['all_ips'])}")
            lines.append("")

        lines.append("---")
        lines.append("END OF FACTS - Answer ONLY using the Q&A pairs above")
        lines.append("NEVER invent PIDs, process names, or IP addresses not listed above")

        return "\n".join(lines)

    def validate_answer(self, answer: str, facts: Dict[str, Any]) -> Dict[str, Any]:
        """
        Anti-hallucination validation layer
        Checks if AI answer mentions entities that don't exist in extracted facts
        """
        violations = []
        answer_lower = answer.lower()

        # Extract potential PIDs from answer - ONLY when explicitly labeled as PID
        potential_pids = re.findall(r'\bpid[:\s]+(\d+)\b', answer_lower, re.IGNORECASE)

        # Also check for patterns like "Process ID 1234" or "process 1234"
        potential_pids += re.findall(r'\bprocess(?:\s+id)?[:\s]+(\d+)\b', answer_lower, re.IGNORECASE)

        # Check if mentioned PIDs exist
        all_pids = facts.get('all_pids', [])
        seen_violations = set()  # Track to avoid duplicate violations

        for pid_str in potential_pids:
            try:
                pid = int(pid_str)
                # Only flag PIDs in typical process range (4-65535) and not already flagged
                if 4 <= pid <= 65535 and pid not in all_pids and pid not in seen_violations:
                    violations.append(f"Mentioned PID {pid} which doesn't exist in the memory dump")
                    seen_violations.add(pid)
            except ValueError:
                continue

        # Extract potential process names from answer (.exe files)
        potential_processes = re.findall(r'\b([a-zA-Z0-9_\-]+\.exe)\b', answer_lower)

        # Check if mentioned process names exist
        all_processes = [p.lower() for p in facts.get('all_process_names', [])]
        for proc in potential_processes:
            if proc.lower() not in all_processes:
                violations.append(f"Mentioned process '{proc}' which doesn't exist in the memory dump")

        # Extract potential IP addresses from answer
        potential_ips = re.findall(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', answer)

        # Check if mentioned IPs exist (excluding common ranges like 127.x.x.x, 0.0.0.0)
        all_ips = facts.get('all_ips', [])
        for ip in potential_ips:
            # Skip localhost and null IPs
            if ip.startswith('127.') or ip == '0.0.0.0' or ip.startswith('255.'):
                continue
            if ip not in all_ips:
                violations.append(f"Mentioned IP address {ip} which doesn't exist in the memory dump")

        # Determine if answer is valid
        is_valid = len(violations) == 0

        return {
            'valid': is_valid,
            'violations': violations,
            'reason': 'Answer mentions entities not in extracted facts' if not is_valid else 'Answer validated successfully'
        }


# Example usage and testing
if __name__ == "__main__":
    # Test with sample Volatility pslist output
    sample_pslist = """Volatility 3 Framework 2.5.0

windows.pslist

PID     PPID    ImageFileName   Offset(V)       Threads Handles SessionId       Wow64   CreateTime      ExitTime
4       0       System  0xfa8000c34d90  123     890     N/A     False   2023-01-15 10:30:00.000000      N/A
308     4       smss.exe        0xfa80018e4d90  2       30      N/A     False   2023-01-15 10:30:02.000000      N/A
412     404     csrss.exe       0xfa8001a52060  9       436     0       False   2023-01-15 10:30:05.000000      N/A
460     404     wininit.exe     0xfa8001a8f060  3       75      0       False   2023-01-15 10:30:05.000000      N/A
1234    808     chrome.exe      0xfa8002134d90  45      1024    1       False   2023-01-15 11:45:23.000000      N/A
5678    1234    chrome.exe      0xfa8002245d90  12      256     1       False   2023-01-15 11:45:25.000000      N/A
"""

    extractor = VolatilityFactExtractor()
    facts = extractor.extract_facts(sample_pslist)

    print("=== STRUCTURED FACTS (JSON) ===")
    print(json.dumps(facts, indent=2, default=str))
    print("\n")

    print("=== FACTS AS TEXT (FOR LLM) ===")
    print(extractor.facts_to_text(facts))
    print("\n")

    print("=== VALIDATION TEST ===")
    # Test with a hallucinated answer
    fake_answer = "Yes, PID 9999 (malware.exe) is connecting to 1.2.3.4 on port 8080"
    validation = extractor.validate_answer(fake_answer, facts)
    print(f"Valid: {validation['valid']}")
    print(f"Violations: {validation['violations']}")
