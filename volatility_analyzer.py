"""
Volatility 3 Output Parser with Intelligent Threat Detection
Parses output from common Volatility plugins and detects ransomware, malware, C2, and credential theft
"""

import re
from typing import Dict, List, Any, Tuple


# Comprehensive threat pattern dictionary - similar to Nmap's VULN_PATTERNS
THREAT_PATTERNS = {
    'RANSOMWARE_SHADOW_DELETE': {
        'patterns': [
            r'vssadmin.*delete.*shadows',
            r'vssadmin.*Delete.*Shadows',
            r'wmic.*shadowcopy.*delete',
            r'shadowcopy.*delete',
            r'bcdedit.*bootstatuspolicy.*ignoreallfailures',
            r'bcdedit.*recoveryenabled.*no',
            r'wbadmin.*delete.*catalog',
            r'Delete\s+Shadows\s*/All'
        ],
        'score': 10,
        'severity': 'CRITICAL',
        'category': 'Ransomware - Shadow Copy Deletion',
        'description': 'Ransomware attempting to delete backup shadow copies'
    },
    'RANSOMWARE_RECOVERY_DISABLE': {
        'patterns': [
            r'bcdedit.*set.*recoveryenabled.*no',
            r'bcdedit.*set.*bootstatuspolicy.*ignoreallfailures',
            r'reagentc.*disable',
            r'wbadmin.*delete.*systemstatebackup'
        ],
        'score': 10,
        'severity': 'CRITICAL',
        'category': 'Ransomware - Recovery Disabling',
        'description': 'Ransomware disabling Windows recovery features'
    },
    'RANSOMWARE_FILE_WIPE': {
        'patterns': [
            r'cipher\.exe.*\/w',
            r'sdelete',
            r'cipher.*delete',
            r'secure.*wipe'
        ],
        'score': 9,
        'severity': 'CRITICAL',
        'category': 'Ransomware - Secure File Wiping',
        'description': 'Ransomware wiping free space to prevent file recovery'
    },
    'MALWARE_DOUBLE_EXTENSION': {
        'patterns': [
            r'\.(pdf|doc|docx|xls|xlsx|jpg|png|txt|zip)\.(exe|scr|bat|cmd|ps1|vbs|js)',
            r'\.pdf\.exe',
            r'\.doc\.exe',
            r'invoice.*\.exe',
            r'receipt.*\.exe',
            r'document.*\.exe'
        ],
        'score': 10,
        'severity': 'CRITICAL',
        'category': 'Malware - Double Extension',
        'description': 'Malicious executable masquerading as document'
    },
    'MALWARE_TEMP_EXECUTION': {
        'patterns': [
            r'(temp|tmp|appdata|downloads|public).*\.exe',
            r'\\Temp\\.*\.exe',
            r'\\Downloads\\.*\.exe',
            r'\\AppData\\Local\\Temp',
            r'\\Public\\.*\.exe'
        ],
        'score': 7,
        'severity': 'HIGH',
        'category': 'Malware - Execution from Temp',
        'description': 'Executable running from temporary or suspicious location'
    },
    'MALWARE_SUSPICIOUS_NAMES': {
        'patterns': [
            r'\b(mimikatz|procdump|psexec|netcat|nc\.exe|pwdump|fgdump)\b',
            r'svch0st',  # Misspelled svchost
            r'csrss\s',  # csrss with space (fake)
            r'lsasss',   # lsass misspelled
            r'smss\s',   # smss with space
            r'winl0g0n'  # winlogon misspelled with zeros
        ],
        'score': 9,
        'severity': 'CRITICAL',
        'category': 'Malware - Suspicious Process Name',
        'description': 'Known malware tool or process impersonation detected'
    },
    'C2_SUSPICIOUS_CONNECTION': {
        'patterns': [
            r'(\.pdf|\.doc|\.xls|\.jpg|\.png)\.exe.*ESTABLISHED',
            r'powershell.*\d+\.\d+\.\d+\.\d+.*ESTABLISHED',
            r'cmd\.exe.*\d+\.\d+\.\d+\.\d+.*ESTABLISHED'
        ],
        'score': 9,
        'severity': 'CRITICAL',
        'category': 'C2 - Suspicious Process Network Activity',
        'description': 'Unusual process making network connections (likely C2)'
    },
    'C2_SUSPICIOUS_PORTS': {
        'patterns': [
            r':(4444|5555|6666|7777|8888|31337|1337)\s+(ESTABLISHED|LISTENING)',
            r'port.*4444',
            r'port.*31337'
        ],
        'score': 8,
        'severity': 'HIGH',
        'category': 'C2 - Known Malicious Ports',
        'description': 'Connection to commonly used C2 framework ports'
    },
    'CODE_INJECTION_RWX': {
        'patterns': [
            r'PAGE_EXECUTE_READWRITE',
            r'\bRWX\b',
            r'VadS.*EXECUTE_READWRITE'
        ],
        'score': 8,
        'severity': 'HIGH',
        'category': 'Code Injection - RWX Memory',
        'description': 'Process contains executable writable memory (code injection)'
    },
    'CODE_INJECTION_HOLLOW': {
        'patterns': [
            r'hollowing',
            r'process.*replaced',
            r'unmapped.*pe',
            r'rebased.*image'
        ],
        'score': 9,
        'severity': 'CRITICAL',
        'category': 'Code Injection - Process Hollowing',
        'description': 'Process hollowing detected (malware technique)'
    },
    'CREDENTIAL_THEFT_LSASS': {
        'patterns': [
            r'(procdump|mimikatz|pwdump).*lsass',
            r'lsass\.exe.*dump',
            r'access.*lsass\.exe',
            r'reading.*lsass'
        ],
        'score': 10,
        'severity': 'CRITICAL',
        'category': 'Credential Theft - LSASS Access',
        'description': 'Credential dumping tool accessing lsass.exe'
    },
    'CREDENTIAL_THEFT_HASHDUMP': {
        'patterns': [
            r'hashdump',
            r'lsadump',
            r'samdump',
            r'secretsdump',
            r'[a-f0-9]{32}:[a-f0-9]{32}'  # NT hash format
        ],
        'score': 9,
        'severity': 'CRITICAL',
        'category': 'Credential Theft - Hash Extraction',
        'description': 'Password hash dumping activity detected'
    },
    'PERSISTENCE_REGISTRY': {
        'patterns': [
            r'\\Run\\.*\.exe',
            r'\\RunOnce\\.*\.exe',
            r'CurrentVersion\\Run',
            r'HKLM\\.*\\Run\\',
            r'Startup.*\.exe'
        ],
        'score': 6,
        'severity': 'MEDIUM',
        'category': 'Persistence - Registry Run Keys',
        'description': 'Persistence mechanism via registry run keys'
    },
    'PERSISTENCE_SCHEDULED_TASK': {
        'patterns': [
            r'schtasks.*create',
            r'at.*\d\d:\d\d',
            r'scheduled.*task.*create',
            r'taskschd\.dll'
        ],
        'score': 6,
        'severity': 'MEDIUM',
        'category': 'Persistence - Scheduled Tasks',
        'description': 'Scheduled task creation for persistence'
    },
    'LATERAL_MOVEMENT': {
        'patterns': [
            r'psexec',
            r'wmic.*process.*call.*create',
            r'winrm',
            r'wmiprvse\.exe.*\d+\.\d+\.\d+\.\d+',
            r'net.*use.*\\\\',
            r'net.*share'
        ],
        'score': 8,
        'severity': 'HIGH',
        'category': 'Lateral Movement',
        'description': 'Tools or techniques used for lateral movement'
    },
    'ANTI_FORENSICS': {
        'patterns': [
            r'timestomp',
            r'modify.*timestamp',
            r'clear.*eventlog',
            r'wevtutil.*cl',
            r'del.*\s/f\s/q',
            r'powershell.*-ep\s+bypass'
        ],
        'score': 7,
        'severity': 'HIGH',
        'category': 'Anti-Forensics',
        'description': 'Anti-forensics techniques detected'
    }
}


def parse_volatility_output(output: str) -> Dict[str, Any]:
    """
    Parse Volatility 3 output and extract structured data

    Detects plugin type and routes to appropriate parser
    """
    output_lower = output.lower()

    # Detect plugin type from output - check for specific patterns and headers
    # Priority order: most specific first

    # Check for process list first (most common) - look for PID PPID ImageFileName pattern
    if ('pslist' in output_lower or 'pstree' in output_lower or 'psscan' in output_lower or
        ('imagefilename' in output_lower and 'ppid' in output_lower) or
        (re.search(r'pid\s+ppid\s+(imagefilename|image|process)', output_lower))):
        return parse_process_list(output)
    elif 'malfind' in output_lower or 'page_execute_readwrite' in output_lower:
        return parse_malfind(output)
    elif ('netscan' in output_lower or 'netstat' in output_lower or
          ('localaddr' in output_lower and 'remoteaddr' in output_lower) or
          ('local address' in output_lower and 'remote address' in output_lower)):
        return parse_network_connections(output)
    elif 'hashdump' in output_lower or 'lsadump' in output_lower or re.search(r':\d+:[a-f0-9]{32}:', output_lower):
        return parse_credentials(output)
    elif 'filescan' in output_lower or (r'\users\\'  in output_lower and 'offset' in output_lower):
        return parse_filescan(output)
    elif 'cmdline' in output_lower and 'command line' in output_lower:
        return parse_cmdline(output)
    elif 'dlllist' in output_lower or 'ldrmodules' in output_lower:
        return parse_dll_list(output)
    elif ('windows.handles' in output_lower or
          (re.search(r'handle\s+(value|type)', output_lower))):  # More specific for handles plugin
        return parse_handles(output)
    else:
        # Generic fallback parser
        return parse_generic(output)


def detect_threats(output: str) -> Tuple[List[Dict[str, Any]], int]:
    """
    Detect threats in Volatility output using pattern matching
    Returns: (threat_list, total_threat_score)

    Similar to Nmap's vulnerability detection
    """
    threats = []
    total_score = 0
    lines = output.split('\n')

    current_pid = None
    current_process = None

    for line in lines:
        # Extract PID and process name for context
        pid_match = re.match(r'(\d+)\s+(\d+)\s+(\S+)', line)
        if pid_match:
            current_pid = pid_match.group(1)
            current_process = pid_match.group(3)

        # Match against ALL threat patterns
        for threat_type, threat_config in THREAT_PATTERNS.items():
            for pattern in threat_config['patterns']:
                if re.search(pattern, line, re.IGNORECASE):
                    threats.append({
                        'type': threat_type,
                        'severity': threat_config['severity'],
                        'score': threat_config['score'],
                        'category': threat_config['category'],
                        'description': threat_config['description'],
                        'pid': current_pid,
                        'process': current_process,
                        'evidence': line.strip(),
                        'matched_pattern': pattern
                    })
                    total_score += threat_config['score']
                    break  # Only match once per line per threat type

    return threats, total_score


def parse_process_list(output: str) -> Dict[str, Any]:
    """Parse ps list/tree/scan output with enhanced threat detection"""
    processes = []
    suspicious_patterns = {
        'no_parent': [],
        'hidden': [],
        'malicious_names': [],
        'double_extension': [],
        'temp_execution': []
    }

    lines = output.split('\n')

    for line in lines:
        # Match typical pslist format: PID PPID ImageName Offset Threads Handles SessionId
        match = re.match(r'(\d+)\s+(\d+)\s+(\S+)\s+(0x[0-9a-f]+)\s+(\d+)\s+(\d+)\s+(\d+)', line, re.IGNORECASE)

        if match:
            pid = match.group(1)
            ppid = match.group(2)
            name = match.group(3)
            offset = match.group(4)
            threads = match.group(5)
            handles = match.group(6)
            session = match.group(7)

            process_entry = {
                'pid': pid,
                'ppid': ppid,
                'name': name,
                'offset': offset,
                'threads': threads,
                'handles': handles,
                'session': session,
                'details': line.strip()
            }

            processes.append(process_entry)

            # Enhanced threat detection
            if ppid == '0' and name.lower() not in ['system', 'idle']:
                suspicious_patterns['no_parent'].append({'pid': pid, 'name': name})

            # Check for double extensions
            if re.search(r'\.(pdf|doc|docx|xls|xlsx|jpg|png|txt)\.(exe|scr|bat)', name.lower()):
                suspicious_patterns['double_extension'].append({'pid': pid, 'name': name})

            # Check for known malware tools
            if any(sus in name.lower() for sus in ['mimikatz', 'procdump', 'psexec', 'netcat', 'nc.exe', 'pwdump']):
                suspicious_patterns['malicious_names'].append({'pid': pid, 'name': name})

    return {
        'plugin': 'pslist',
        'processes': processes,
        'total_count': len(processes),
        'suspicious': suspicious_patterns
    }


def parse_network_connections(output: str) -> Dict[str, Any]:
    """Parse netscan/netstat output with C2 detection"""
    connections = []
    suspicious_connections = []
    c2_indicators = []

    # Common C2 ports
    suspicious_ports = [4444, 5555, 6666, 7777, 8888, 31337, 1337]

    lines = output.split('\n')

    for line in lines:
        # Match various network connection formats
        # Format: Offset Proto LocalAddr LocalPort RemoteAddr RemotePort State PID Process
        match = re.search(r'(TCP|UDP|TCPv4|UDPv4)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+(ESTABLISHED|LISTENING|CLOSED)\s+(\d+)\s+(\S+)', line, re.IGNORECASE)

        if match:
            protocol = match.group(1)
            local_ip = match.group(2)
            local_port = match.group(3)
            remote_ip = match.group(4)
            remote_port = match.group(5)
            state = match.group(6)
            pid = match.group(7)
            process = match.group(8)

            conn_entry = {
                'protocol': protocol,
                'local_ip': local_ip,
                'local_port': local_port,
                'remote_ip': remote_ip,
                'remote_port': remote_port,
                'state': state,
                'pid': pid,
                'process': process,
                'details': line.strip()
            }

            connections.append(conn_entry)

            # Check for suspicious ports
            if int(remote_port) in suspicious_ports:
                suspicious_connections.append(conn_entry)

            # Check for suspicious processes making connections
            if re.search(r'\.(pdf|doc|xls|jpg|png)\.exe', process.lower()):
                c2_indicators.append({
                    'reason': 'Document-disguised executable making network connection',
                    'process': process,
                    'remote': f"{remote_ip}:{remote_port}",
                    'details': line.strip()
                })

            # Unusual processes making connections
            if process.lower() in ['cmd.exe', 'powershell.exe', 'wscript.exe'] and state == 'ESTABLISHED':
                c2_indicators.append({
                    'reason': 'Scripting process making network connection',
                    'process': process,
                    'remote': f"{remote_ip}:{remote_port}",
                    'details': line.strip()
                })

    return {
        'plugin': 'netscan',
        'connections': connections,
        'total_count': len(connections),
        'suspicious_connections': suspicious_connections,
        'c2_indicators': c2_indicators
    }


def parse_malfind(output: str) -> Dict[str, Any]:
    """Parse malfind output for code injection indicators"""
    findings = []
    injected_processes = []
    rwx_processes = []

    lines = output.split('\n')
    current_pid = None
    current_process = None

    for line in lines:
        # Match process info
        match = re.search(r'(\d+)\s+(\S+)', line)
        if match:
            current_pid = match.group(1)
            current_process = match.group(2)

        # Detect RWX memory (critical code injection indicator)
        if 'page_execute_readwrite' in line.lower() or 'rwx' in line.lower():
            if current_process:
                injected_processes.append(current_process)
                rwx_processes.append({
                    'pid': current_pid,
                    'process': current_process,
                    'details': line.strip()
                })
                findings.append({
                    'pid': current_pid,
                    'process': current_process,
                    'indicator': 'RWX Memory',
                    'severity': 'HIGH',
                    'details': line.strip()
                })

    return {
        'plugin': 'malfind',
        'findings': findings,
        'total_count': len(findings),
        'injected_processes': list(set(injected_processes)),
        'rwx_processes': rwx_processes
    }


def parse_filescan(output: str) -> Dict[str, Any]:
    """Parse filescan output"""
    files = []
    suspicious_files = []
    double_extension_files = []

    suspicious_extensions = ['.exe', '.dll', '.bat', '.ps1', '.vbs', '.js']
    suspicious_paths = ['temp', 'appdata', 'programdata', 'public', 'downloads']

    lines = output.split('\n')

    for line in lines:
        # Match file paths
        if '\\' in line or '/' in line:
            # Extract file path
            path_match = re.search(r'([A-Za-z]:\\[^\s]+|/[^\s]+)', line)
            if path_match:
                file_path = path_match.group(1)

                files.append({
                    'path': file_path,
                    'details': line.strip()
                })

                # Check for double extensions
                if re.search(r'\.(pdf|doc|docx|xls|xlsx|jpg|png|txt)\.(exe|scr|bat)', file_path.lower()):
                    double_extension_files.append(file_path)

                # Flag suspicious files
                lower_path = file_path.lower()
                if any(ext in lower_path for ext in suspicious_extensions):
                    if any(sus_path in lower_path for sus_path in suspicious_paths):
                        suspicious_files.append(file_path)

    return {
        'plugin': 'filescan',
        'files': files,
        'total_count': len(files),
        'suspicious_files': suspicious_files,
        'double_extension_files': double_extension_files
    }


def parse_dll_list(output: str) -> Dict[str, Any]:
    """Parse DLL list output"""
    dlls = []
    unsigned_dlls = []

    lines = output.split('\n')

    for line in lines:
        if '.dll' in line.lower():
            dlls.append({'details': line.strip()})

            # Flag unsigned or suspicious DLLs
            if 'unsigned' in line.lower() or 'unknown' in line.lower():
                unsigned_dlls.append(line.strip())

    return {
        'plugin': 'dlllist',
        'dlls': dlls,
        'total_count': len(dlls),
        'unsigned_dlls': unsigned_dlls
    }


def parse_credentials(output: str) -> Dict[str, Any]:
    """Parse hashdump/lsadump output"""
    credentials = []

    lines = output.split('\n')

    for line in lines:
        # Match hash format: username:rid:lm_hash:ntlm_hash
        if ':' in line and len(line.split(':')) >= 4:
            parts = line.split(':')
            if len(parts[2]) == 32 or len(parts[3]) == 32:  # Hash length
                credentials.append({
                    'username': parts[0],
                    'hash': line.strip()
                })

    return {
        'plugin': 'hashdump',
        'credentials': credentials,
        'total_count': len(credentials)
    }


def parse_cmdline(output: str) -> Dict[str, Any]:
    """Parse command line arguments with ransomware detection"""
    commands = []
    suspicious_commands = []
    ransomware_indicators = []

    suspicious_keywords = ['powershell', 'cmd.exe', 'wscript', 'cscript', 'rundll32', 'regsvr32']
    ransomware_keywords = ['vssadmin', 'bcdedit', 'cipher', 'wbadmin', 'shadow', 'delete']

    lines = output.split('\n')

    for line in lines:
        # Check for ransomware command patterns
        if any(keyword in line.lower() for keyword in ransomware_keywords):
            ransomware_indicators.append({
                'severity': 'CRITICAL',
                'command': line.strip()
            })

        # Check for suspicious commands
        if any(keyword in line.lower() for keyword in suspicious_keywords):
            commands.append({'details': line.strip()})
            suspicious_commands.append(line.strip())

    return {
        'plugin': 'cmdline',
        'commands': commands,
        'total_count': len(commands),
        'suspicious_commands': suspicious_commands,
        'ransomware_indicators': ransomware_indicators
    }


def parse_handles(output: str) -> Dict[str, Any]:
    """Parse handles output"""
    handles = []
    mutexes = []

    lines = output.split('\n')

    for line in lines:
        if 'mutex' in line.lower():
            mutexes.append({'details': line.strip()})

        handles.append({'details': line.strip()})

    return {
        'plugin': 'handles',
        'handles': handles,
        'total_count': len(handles),
        'mutexes': mutexes
    }


def parse_generic(output: str) -> Dict[str, Any]:
    """Generic parser for unknown plugins"""
    lines = output.split('\n')
    entries = [{'details': line.strip()} for line in lines if line.strip()]

    return {
        'plugin': 'generic',
        'processes': entries,  # Use 'processes' key for compatibility
        'total_count': len(entries)
    }


def generate_next_steps(parsed_data: Dict[str, Any], output: str) -> str:
    """
    Generate intelligent forensic next steps based on THREAT DETECTION
    Uses pattern-based threat analysis similar to Nmap vulnerability detection
    """
    plugin_type = parsed_data.get('plugin', 'unknown')

    # CRITICAL: Detect threats using pattern matching
    threats, total_threat_score = detect_threats(output)

    # Detect OS type from output
    is_linux = 'linux.' in output.lower() or 'elf64layer' in output.lower() or '.elf' in output.lower()
    is_windows = 'windows.' in output.lower() or not is_linux
    is_mac = 'mac.' in output.lower()

    # Check for empty banners output
    is_banners = 'banners.banners' in output.lower()
    banners_empty = is_banners and 'Offset    Banner' in output and output.count('\n') < 10

    next_steps = []
    next_steps.append("=" * 80)
    next_steps.append("VOLATILITY THREAT ANALYSIS")
    next_steps.append("=" * 80)
    next_steps.append("")

    # Special handling for empty banners
    if banners_empty:
        next_steps.append("[INFO] BANNERS SCAN COMPLETED - NO RESULTS FOUND")
        next_steps.append("=" * 80)
        next_steps.append("")
        next_steps.append("The banners plugin scanned the memory but found no kernel version strings.")
        next_steps.append("This is common with some memory dumps.")
        next_steps.append("")
        next_steps.append("RECOMMENDED NEXT STEPS:")
        next_steps.append("")
        next_steps.append("1. TRY BASH HISTORY (most useful for forensics):")
        next_steps.append("   python vol.py -f <dump> linux.bash.Bash")
        next_steps.append("   >> Shows commands executed by the user!")
        next_steps.append("")
        next_steps.append("2. TRY PROCESS LIST (slow but works without symbols):")
        next_steps.append("   python vol.py -f <dump> linux.psaux.PsAux")
        next_steps.append("   >> Scans memory for running processes")
        next_steps.append("")
        next_steps.append("3. MANUAL SYMBOL DOWNLOAD:")
        next_steps.append("   If you know the Linux version, download symbols from:")
        next_steps.append("   https://github.com/volatilityfoundation/volatility3")
        next_steps.append("")
        return "\n".join(next_steps)

    # Display threat score
    if total_threat_score > 0:
        threat_level = "CRITICAL" if total_threat_score >= 20 else "HIGH" if total_threat_score >= 10 else "MEDIUM"
        next_steps.append(f"THREAT SCORE: {total_threat_score} ({threat_level})")
        next_steps.append("")

    # Group threats by severity
    critical_threats = [t for t in threats if t['severity'] == 'CRITICAL']
    high_threats = [t for t in threats if t['severity'] == 'HIGH']
    medium_threats = [t for t in threats if t['severity'] == 'MEDIUM']

    # Display CRITICAL threats first
    if critical_threats:
        next_steps.append("[CRITICAL] CRITICAL THREATS DETECTED:")
        next_steps.append("=" * 80)

        # Group by category to avoid duplicates
        seen_categories = set()
        for threat in critical_threats:
            category = threat['category']
            if category not in seen_categories:
                seen_categories.add(category)
                next_steps.append(f"\n[{threat['severity']}] {category}")
                next_steps.append(f"Description: {threat['description']}")
                next_steps.append(f"Score: {threat['score']}/10")

                # Show evidence for this category
                next_steps.append("Evidence:")
                category_threats = [t for t in critical_threats if t['category'] == category]
                for t in category_threats[:3]:  # Limit to 3 pieces of evidence per category
                    if t.get('process'):
                        next_steps.append(f"   PID {t['pid']}: {t['process']}")
                    next_steps.append(f"   {t['evidence']}")
                next_steps.append("")

        next_steps.append("")

    # Display HIGH threats
    if high_threats:
        next_steps.append("[WARNING]  HIGH SEVERITY THREATS:")
        next_steps.append("=" * 80)

        seen_categories = set()
        for threat in high_threats:
            category = threat['category']
            if category not in seen_categories:
                seen_categories.add(category)
                next_steps.append(f"\n[{threat['severity']}] {category}")
                next_steps.append(f"Description: {threat['description']}")
                next_steps.append(f"Score: {threat['score']}/10")

                # Show evidence
                category_threats = [t for t in high_threats if t['category'] == category]
                for t in category_threats[:2]:
                    if t.get('process'):
                        next_steps.append(f"   PID {t['pid']}: {t['process']}")
                    next_steps.append(f"   {t['evidence']}")
                next_steps.append("")

        next_steps.append("")

    # Plugin-specific analysis
    next_steps.append("=" * 80)
    next_steps.append("FORENSIC ANALYSIS BY DATA TYPE")
    next_steps.append("=" * 80)
    next_steps.append("")

    if plugin_type == 'pslist':
        processes = parsed_data.get('processes', [])
        suspicious = parsed_data.get('suspicious', {})

        next_steps.append(f"Total Processes Found: {len(processes)}")
        next_steps.append("")

        # Check for double extension processes
        if suspicious.get('double_extension'):
            next_steps.append("[CRITICAL] MALWARE: Double-extension processes detected:")
            for proc in suspicious['double_extension']:
                next_steps.append(f"   PID {proc['pid']}: {proc['name']}")
            next_steps.append("")
            next_steps.append("   IMMEDIATE ACTION REQUIRED:")
            next_steps.append("   vol3 -f <dump> windows.malfind --pid <PID>")
            next_steps.append("   vol3 -f <dump> windows.netscan  # Check for C2 connections")
            next_steps.append("   vol3 -f <dump> windows.dlllist --pid <PID>")
            next_steps.append("   vol3 -f <dump> windows.memmap --pid <PID> --dump")
            next_steps.append("")

        if suspicious.get('malicious_names'):
            next_steps.append("[CRITICAL] CRITICAL: Known malware tools detected:")
            for proc in suspicious['malicious_names']:
                next_steps.append(f"   PID {proc['pid']}: {proc['name']}")
            next_steps.append("")

        if suspicious.get('no_parent'):
            next_steps.append("[WARNING]  WARNING: Processes with no parent (possible rootkit):")
            for proc in suspicious['no_parent']:
                next_steps.append(f"   PID {proc['pid']}: {proc['name']}")
            next_steps.append("")

    elif plugin_type == 'netscan':
        connections = parsed_data.get('connections', [])
        c2_indicators = parsed_data.get('c2_indicators', [])

        next_steps.append(f"Total Network Connections: {len(connections)}")
        next_steps.append("")

        if c2_indicators:
            next_steps.append("[CRITICAL] C2 ACTIVITY DETECTED:")
            for indicator in c2_indicators:
                next_steps.append(f"   Reason: {indicator['reason']}")
                next_steps.append(f"   Process: {indicator['process']}")
                next_steps.append(f"   Remote: {indicator['remote']}")
                next_steps.append(f"   Evidence: {indicator['details']}")
                next_steps.append("")

            next_steps.append("   IMMEDIATE ACTION:")
            next_steps.append("   1. Isolate the infected system from the network")
            next_steps.append("   2. Block the remote IP addresses at the firewall")
            next_steps.append("   3. Dump the malicious process: vol3 -f <dump> windows.memmap --pid <PID> --dump")
            next_steps.append("   4. Submit dumped executable to VirusTotal for analysis")
            next_steps.append("")

    elif plugin_type == 'malfind':
        rwx_processes = parsed_data.get('rwx_processes', [])

        if rwx_processes:
            next_steps.append("[CRITICAL] CODE INJECTION DETECTED:")
            for proc in rwx_processes:
                next_steps.append(f"   PID {proc['pid']}: {proc['process']}")
                next_steps.append(f"   {proc['details']}")
            next_steps.append("")

            next_steps.append("   RECOMMENDED ACTIONS:")
            next_steps.append("   vol3 -f <dump> windows.memmap --pid <PID> --dump")
            next_steps.append("   vol3 -f <dump> windows.pstree  # Check parent process")
            next_steps.append("   strings <dumped_memory> | grep -E '(http|C:\\\\|cmd|powershell)'")
            next_steps.append("   yara malware_rules.yar <dumped_memory>")
            next_steps.append("")

    elif plugin_type == 'cmdline':
        ransomware_indicators = parsed_data.get('ransomware_indicators', [])

        if ransomware_indicators:
            next_steps.append("[CRITICAL] RANSOMWARE COMMANDS DETECTED:")
            for indicator in ransomware_indicators:
                next_steps.append(f"   {indicator['command']}")
            next_steps.append("")

            next_steps.append("   IMMEDIATE INCIDENT RESPONSE:")
            next_steps.append("   1. DO NOT POWER OFF THE SYSTEM (preserve memory)")
            next_steps.append("   2. Isolate the system from the network immediately")
            next_steps.append("   3. Take a full memory dump and disk image")
            next_steps.append("   4. Check for encrypted files on disk")
            next_steps.append("   5. Identify the ransomware variant:")
            next_steps.append("      vol3 -f <dump> windows.filescan | grep -i ransom")
            next_steps.append("      vol3 -f <dump> windows.pslist  # Identify ransomware process")
            next_steps.append("")

    # INTELLIGENT RECOMMENDATIONS based on detected threats
    next_steps.append("=" * 80)
    next_steps.append("INTELLIGENT NEXT STEPS (THREAT-BASED)")
    next_steps.append("=" * 80)
    next_steps.append("")

    if any('RANSOMWARE' in t['category'] for t in threats):
        next_steps.append("[CRITICAL] RANSOMWARE INCIDENT DETECTED:")
        next_steps.append("   Priority Actions:")
        next_steps.append("   1. Isolate system from network NOW")
        next_steps.append("   2. Acquire full memory and disk forensics")
        next_steps.append("   3. Identify ransomware variant:")
        next_steps.append("      vol3 -f <dump> windows.filescan | grep -iE '(ransom|crypt|lock)'")
        next_steps.append("      vol3 -f <dump> windows.dumpfiles --pid <suspicious_PID>")
        next_steps.append("   4. Check for shadow copies (recovery may be possible):")
        next_steps.append("      Look for vssadmin commands in timeline")
        next_steps.append("   5. Submit sample to ID Ransomware: id-ransomware.malwarehunterteam.com")
        next_steps.append("")

    if any('C2' in t['category'] for t in threats):
        next_steps.append("[CRITICAL] COMMAND & CONTROL DETECTED:")
        next_steps.append("   Priority Actions:")
        next_steps.append("   1. Block all detected C2 IP addresses at firewall")
        next_steps.append("   2. Dump suspicious processes:")
        next_steps.append("      vol3 -f <dump> windows.memmap --pid <PID> --dump")
        next_steps.append("   3. Extract network artifacts:")
        next_steps.append("      vol3 -f <dump> windows.netscan > network_connections.txt")
        next_steps.append("   4. Check for persistence:")
        next_steps.append("      vol3 -f <dump> windows.registry.userassist")
        next_steps.append("      vol3 -f <dump> windows.svcscan")
        next_steps.append("")

    if any('CODE_INJECTION' in t['category'] for t in threats):
        next_steps.append("[CRITICAL] CODE INJECTION DETECTED:")
        next_steps.append("   Priority Actions:")
        next_steps.append("   1. Dump injected memory regions:")
        next_steps.append("      vol3 -f <dump> windows.memmap --pid <PID> --dump")
        next_steps.append("   2. Scan with YARA rules:")
        next_steps.append("      vol3 -f <dump> windows.yarascan --yara-rules malware.yar")
        next_steps.append("   3. Check for process hollowing:")
        next_steps.append("      vol3 -f <dump> windows.ldrmodules --pid <PID>")
        next_steps.append("   4. Extract shellcode and analyze")
        next_steps.append("")

    if any('CREDENTIAL' in t['category'] for t in threats):
        next_steps.append("[CRITICAL] CREDENTIAL THEFT DETECTED:")
        next_steps.append("   Priority Actions:")
        next_steps.append("   1. Force password reset for ALL users")
        next_steps.append("   2. Check for lateral movement:")
        next_steps.append("      vol3 -f <dump> windows.netscan")
        next_steps.append("      Look for connections to other systems")
        next_steps.append("   3. Extract and analyze credentials:")
        next_steps.append("      vol3 -f <dump> windows.hashdump")
        next_steps.append("      vol3 -f <dump> windows.lsadump")
        next_steps.append("   4. Review Active Directory logs for suspicious logons")
        next_steps.append("")

    # Standard forensic workflow - OS-specific
    next_steps.append("=" * 80)
    next_steps.append("STANDARD FORENSIC WORKFLOW")
    next_steps.append("=" * 80)

    if is_linux:
        next_steps.append("Linux Memory Forensics Commands:")
        next_steps.append("   1. Process list: python vol.py -f <dump> linux.psaux.PsAux")
        next_steps.append("   2. Bash history: python vol.py -f <dump> linux.bash.Bash")
        next_steps.append("   3. Open files: python vol.py -f <dump> linux.lsof.Lsof (needs symbols)")
        next_steps.append("   4. Network connections: python vol.py -f <dump> linux.netstat.Netstat (needs symbols)")
        next_steps.append("   5. Find kernel version: python vol.py -f <dump> banners.Banners")
        next_steps.append("")
        next_steps.append("NOTE: Many Linux plugins require kernel symbols!")
        next_steps.append("Download from: https://github.com/volatilityfoundation/volatility3")
    elif is_mac:
        next_steps.append("Mac Memory Forensics Commands:")
        next_steps.append("   1. Process list: python vol.py -f <dump> mac.pslist.PsList")
        next_steps.append("   2. Bash history: python vol.py -f <dump> mac.bash.Bash")
        next_steps.append("   3. Open files: python vol.py -f <dump> mac.lsof.Lsof")
        next_steps.append("   4. Network connections: python vol.py -f <dump> mac.netstat.Netstat")
    else:  # Windows
        next_steps.append("Windows Memory Forensics Commands:")
        next_steps.append("   1. Timeline analysis: python vol.py -f <dump> timeliner.Timeliner")
        next_steps.append("   2. Registry analysis: python vol.py -f <dump> windows.registry.hivelist")
        next_steps.append("   3. Service enumeration: python vol.py -f <dump> windows.svcscan")
        next_steps.append("   4. Driver analysis: python vol.py -f <dump> windows.driverscan")
        next_steps.append("   5. Mutex analysis: python vol.py -f <dump> windows.handles")

    next_steps.append("")

    return "\n".join(next_steps)


def analyze_volatility_output(output: str) -> Dict[str, Any]:
    """Legacy function for compatibility"""
    return parse_volatility_output(output)
