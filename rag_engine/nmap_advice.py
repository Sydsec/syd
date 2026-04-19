from dataclasses import dataclass
from typing import List, Optional, Tuple, Dict, Any
import re
from pathlib import Path

import sys as _sys

# Resolve base path: works both from source and from PyInstaller exe
_BASE = Path(_sys._MEIPASS) if getattr(_sys, 'frozen', False) else Path(__file__).resolve().parent.parent

# Try to import CVE query engine - gracefully handle if databases don't exist
try:
    _rag_dir = str(_BASE / "rag_engine")
    if _rag_dir not in _sys.path:
        _sys.path.insert(0, _rag_dir)
    from cve_query_engine import CVEQueryEngine
    CVE_DB_PATH = _BASE / "rag_engine" / "cve_database.db"
    EXPLOIT_DB_PATH = _BASE / "rag_engine" / "exploit_database.db"
    CVE_ENGINE_AVAILABLE = CVE_DB_PATH.exists() and EXPLOIT_DB_PATH.exists()
    if CVE_ENGINE_AVAILABLE:
        cve_engine = CVEQueryEngine(
            cve_db_path=str(CVE_DB_PATH),
            exploit_db_path=str(EXPLOIT_DB_PATH)
        )
    else:
        cve_engine = None
except Exception as e:
    CVE_ENGINE_AVAILABLE = False
    cve_engine = None

@dataclass
class ServiceFinding:
    port: int
    proto: str
    service: str
    vendor: Optional[str]
    product: Optional[str]
    version: Optional[str]
    cpe: Optional[str]
    state: str = "open"  # "open" or "open|filtered"
    host: Optional[str] = None  # IP or hostname of the host (for multi-host scans)

@dataclass
class NextStepRecommendation:
    priority: int  # 1=Critical, 2=High, 3=Medium, 4=Low
    tool: str
    command: str
    description: str
    reason: str
    category: str  # "enumeration", "vulnerability", "exploitation", "persistence"

def parse_nmap_text(text: str) -> List[ServiceFinding]:
    """Parse nmap output (XML or plaintext) into structured service findings"""
    items: List[ServiceFinding] = []

    # XML parsing - FIXED regex group reference
    if "<nmaprun" in text and "<ports>" in text:
        # Extract host blocks with their IP addresses
        for host_match in re.finditer(r'<host[^>]*>.*?</host>', text, flags=re.S):
            host_block = host_match.group(0)

            # Extract host IP from <address> tag
            ip_match = re.search(r'<address addr="([^"]+)" addrtype="ipv4"', host_block)
            host_ip = ip_match.group(1) if ip_match else None

            # If no IPv4, try hostname
            if not host_ip:
                hostname_match = re.search(r'<hostname name="([^"]+)"', host_block)
                host_ip = hostname_match.group(1) if hostname_match else None

            # Parse services within this host block
            for m in re.finditer(
                r'<port protocol="(?P<proto>tcp|udp)" portid="(?P<port>\d+)">.*?<service[^>]*name="(?P<n>[^\"]+)"(?P<attrs>[^>]*)>(?P<inner>.*?)</service>',
                host_block, flags=re.S|re.I):

                port = int(m.group("port"))
                proto = m.group("proto").lower()
                svc = (m.group("n") or "").lower()
                attrs = m.group("attrs") or ""
                inner = m.group("inner") or ""

                # Extract product, version, and extrainfo from attributes
                prod = re.search(r'product="([^"]+)"', attrs)
                ver = re.search(r'version="([^"]+)"', attrs)
                extrainfo = re.search(r'extrainfo="([^"]+)"', attrs)
                cpe = re.search(r"<cpe>([^<]+)</cpe>", inner)

                product_attr = prod.group(1).strip() if prod else None
                version_base = ver.group(1).strip() if ver else None
                version_extra = extrainfo.group(1).strip() if extrainfo else None

                # Combine version and extrainfo for backporting detection
                if version_base and version_extra:
                    version = f"{version_base} {version_extra}"
                else:
                    version = version_base

                cpe_text = cpe.group(1).strip() if cpe else None

                vendor, product = normalize_vendor_product(svc, product_attr, cpe_text)
                items.append(ServiceFinding(port, proto, svc, vendor, product, version, cpe_text, host=host_ip))

    # Plaintext parsing - only if XML parsing found nothing (avoid duplicates)
    if not items:
        # Split by "Nmap scan report for" to get each host section
        host_sections = re.split(r'Nmap scan report for ', text)

        for section in host_sections[1:]:  # Skip first empty section
            lines = section.split('\n')
            if not lines:
                continue

            # First line contains the host (IP or hostname, possibly with additional info in parens)
            # Examples: "192.168.1.20" or "WIN-SERVER01 (192.168.1.10)" or "10.0.5.10"
            host_line = lines[0].strip()
            host_match = re.match(r'^([^\s(]+)', host_line)
            current_host = host_match.group(1) if host_match else None

            # Parse services in this host section
            for line in lines[1:]:
                # Standard nmap output: PORT/PROTO STATE SERVICE VERSION
                m = re.match(r'(?P<p>\d+)/(?P<pr>\w+)\s+(?P<state>\S+)\s+(?P<svc>\S+)\s*(?P<banner>.*)$', line.strip(), flags=re.I)
                if not m:
                    continue

                port = int(m.group("p"))
                proto = m.group("pr").lower()
                port_state = m.group("state").lower()
                svc = m.group("svc").lower()
                banner = m.group("banner").strip()

                # Filter out nmap reason strings that aren't real banners
                if banner.lower() in ("no-response", "udp-response", "echo-reply",
                                       "syn-ack", "reset", "conn-refused"):
                    banner = ""

                vendor, product, version = banner_to_vpv(svc, banner)
                items.append(ServiceFinding(port, proto, svc, vendor, product, version, None, state=port_state, host=current_host))

    return dedupe(items)

def normalize_vendor_product(svc: str, product_attr: Optional[str], cpe: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    """Enhanced vendor/product normalization with more patterns"""
    
    # CPE parsing first (most reliable)
    # Format: cpe:/a:vendor:product:version
    # Split: ["cpe", "/a", "vendor", "product", "version"]
    if cpe and cpe.startswith("cpe:/a:"):
        parts = cpe.split(":")
        if len(parts) >= 4:
            return parts[2].lower(), parts[3].lower()  # vendor, product
    
    # Enhanced product attribute parsing
    p = (product_attr or "").lower()
    
    # Web servers
    if "apache" in p and ("httpd" in p or "http" in p):
        return "apache", "httpd"
    if "nginx" in p:
        return "nginx", "nginx"
    if "microsoft" in p and "iis" in p:
        return "microsoft", "iis"
    
    # SSH servers
    if "openssh" in p:
        return "openssh", "openssh"
    if "dropbear" in p:
        return "dropbear", "dropbear"
    
    # Database servers
    if "mysql" in p:
        return "mysql", "mysql"
    if "postgresql" in p or "postgres" in p:
        return "postgresql", "postgresql"
    if "microsoft" in p and "sql" in p:
        return "microsoft", "sql-server"
    
    # FTP servers
    if "vsftpd" in p:
        return "vsftpd", "vsftpd"
    if "proftpd" in p:
        return "proftpd", "proftpd"
    
    # SMB/NetBIOS
    if "samba" in p:
        return "samba", "samba"
    if "microsoft" in p and ("smb" in p or "netbios" in p):
        return "microsoft", "smb"
    
    return (None, None)

def banner_to_vpv(svc: str, banner: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Enhanced banner parsing for vendor/product/version
    Returns the FULL banner as version ONLY if it contains a numeric version.
    This preserves distro info for backporting detection (e.g. "8.2p1 Ubuntu 4ubuntu0.6")
    while preventing false CVE matches on banners like "Dovecot pop3d" (no version).
    """

    if not banner:
        return (None, None, None)

    banner_lower = banner.lower()

    # Only pass banner as version if it actually contains a numeric version
    # Otherwise downstream CVE matching will treat product names as version 0.0
    version_out = banner if re.search(r'\d', banner) else None

    # SSH banners
    if "openssh" in banner_lower:
        return "openssh", "openssh", version_out

    # Web server banners
    if "apache" in banner_lower and ("httpd" in banner_lower or "http" in banner_lower):
        return "apache", "httpd", version_out
    if "nginx" in banner_lower:
        return "nginx", "nginx", version_out
    if "microsoft-iis" in banner_lower:
        return "microsoft", "iis", version_out

    # Database banners
    if "mysql" in banner_lower:
        return "mysql", "mysql", version_out
    if "postgresql" in banner_lower:
        return "postgresql", "postgresql", version_out
    if "redis" in banner_lower:
        return "redis", "redis", version_out

    # FTP banners
    if "vsftpd" in banner_lower:
        return "vsftpd", "vsftpd", version_out
    if "proftpd" in banner_lower:
        return "proftpd", "proftpd", version_out

    # Windows Server (various formats)
    if "windows server" in banner_lower or "windows_server" in banner_lower:
        # Extract version: "Windows Server 2016", "Windows Server 2019", etc.
        if "2022" in banner_lower:
            return "microsoft", "windows_server_2022", version_out
        elif "2019" in banner_lower:
            return "microsoft", "windows_server_2019", version_out
        elif "2016" in banner_lower:
            return "microsoft", "windows_server_2016", version_out
        elif "2012" in banner_lower:
            return "microsoft", "windows_server_2012", version_out
        elif "2008" in banner_lower:
            return "microsoft", "windows_server_2008", version_out
        else:
            return "microsoft", "windows_server", version_out

    # Generic Microsoft Windows (only when explicit desktop versions are present)
    if "windows 10" in banner_lower or "windows 11" in banner_lower:
        return "microsoft", "windows_10", version_out

    # Telnet
    if "telnet" in banner_lower:
        return None, "telnetd", version_out

    # VNC
    if "vnc" in banner_lower:
        vnc_version = _extract_version(banner)
        return "vnc", "vnc", vnc_version

    # Mail servers
    if "postfix" in banner_lower:
        return "postfix", "postfix", version_out
    if "dovecot" in banner_lower:
        return "dovecot", "dovecot", version_out
    if "exim" in banner_lower:
        return "exim", "exim", version_out

    # Samba
    if "samba" in banner_lower:
        return "samba", "samba", version_out

    # Linux kernel - only match when "kernel" is explicitly mentioned
    if "linux kernel" in banner_lower:
        return "linux", "linux_kernel", version_out

    # If we have a banner but no known vendor/product and no numeric version,
    # preserve the banner as the product for display purposes.
    if banner and not version_out:
        return (None, banner, None)

    return (None, None, version_out)

def _extract_version(s: str) -> Optional[str]:
    """Extract version number from banner string"""
    # Look for version patterns: 1.2.3, 2.4, 10.1.1, etc.
    patterns = [
        r'\b(\d+\.\d+\.\d+(?:\.\d+)?)\b',  # 1.2.3.4 or 1.2.3
        r'\b(\d+\.\d+)\b',                 # 1.2
        r'version\s+(\d+\.\d+(?:\.\d+)?)', # "version 2.4.1"
        r'v(\d+\.\d+(?:\.\d+)?)',          # "v2.4"
    ]
    
    for pattern in patterns:
        m = re.search(pattern, s, re.IGNORECASE)
        if m:
            return m.group(1)
    
    return None

def dedupe(items: List[ServiceFinding]) -> List[ServiceFinding]:
    """Remove duplicate service findings"""
    seen = set()
    unique_items = []
    
    for item in items:
        # Create unique key based on essential attributes
        key = (item.port, item.proto, item.vendor or "", item.product or "", item.version or "")
        if key not in seen:
            seen.add(key)
            unique_items.append(item)
    
    return unique_items

class IntelligentDecisionTree:
    """AI-powered decision tree for next-step recommendations"""
    
    def __init__(self):
        self.recommendations = []
    
    def analyze_services(self, services: List[ServiceFinding], cve_count: int = 0) -> List[NextStepRecommendation]:
        """Generate intelligent, prioritized recommendations based on discovered services"""
        recommendations = []
        
        # Categorize services
        web_services = self._filter_web_services(services)
        ssh_services = self._filter_ssh_services(services) 
        smb_services = self._filter_smb_services(services)
        database_services = self._filter_database_services(services)
        vulnerable_services = self._identify_vulnerable_services(services)
        
        # HIGH PRIORITY: Vulnerable services first
        if vulnerable_services:
            recommendations.extend(self._generate_vulnerability_recommendations(vulnerable_services, cve_count))
        
        # MEDIUM-HIGH: Common attack vectors
        if web_services:
            recommendations.extend(self._generate_web_recommendations(web_services))
        
        if smb_services:
            recommendations.extend(self._generate_smb_recommendations(smb_services))
        
        if ssh_services:
            recommendations.extend(self._generate_ssh_recommendations(ssh_services))
        
        if database_services:
            recommendations.extend(self._generate_database_recommendations(database_services))
        
        # LOW PRIORITY: General enumeration
        if not any([web_services, ssh_services, smb_services, database_services]):
            recommendations.extend(self._generate_general_recommendations(services))
        
        # Sort by priority and return top recommendations
        recommendations.sort(key=lambda x: (x.priority, x.category))
        return recommendations[:10]  # Limit to top 10 recommendations
    
    def _filter_web_services(self, services: List[ServiceFinding]) -> List[ServiceFinding]:
        """Identify web services"""
        web_ports = {80, 443, 8080, 8443, 8000, 8008, 9080, 9443}
        web_services = []
        
        for s in services:
            if (s.port in web_ports or 
                'http' in s.service.lower() or
                (s.vendor and 'apache' in s.vendor.lower()) or
                (s.product and any(web in s.product.lower() for web in ['httpd', 'nginx', 'iis']))):
                web_services.append(s)
        
        return web_services
    
    def _filter_ssh_services(self, services: List[ServiceFinding]) -> List[ServiceFinding]:
        """Identify SSH services"""
        return [s for s in services if s.port == 22 or 'ssh' in s.service.lower()]
    
    def _filter_smb_services(self, services: List[ServiceFinding]) -> List[ServiceFinding]:
        """Identify SMB/NetBIOS services"""
        smb_ports = {139, 445}
        return [s for s in services if s.port in smb_ports or 'smb' in s.service.lower() or 'netbios' in s.service.lower()]
    
    def _filter_database_services(self, services: List[ServiceFinding]) -> List[ServiceFinding]:
        """Identify database services"""
        db_ports = {1433, 3306, 5432, 1521, 27017}
        db_services = []
        
        for s in services:
            if (s.port in db_ports or
                any(db in s.service.lower() for db in ['mysql', 'postgres', 'mssql', 'oracle', 'mongo'])):
                db_services.append(s)
        
        return db_services
    
    def _identify_vulnerable_services(self, services: List[ServiceFinding]) -> List[ServiceFinding]:
        """Identify services with known vulnerabilities based on version"""
        vulnerable = []
        
        for s in services:
            if self._has_known_vulnerabilities(s):
                vulnerable.append(s)
        
        return vulnerable
    
    def _has_known_vulnerabilities(self, service: ServiceFinding) -> bool:
        """Check if service version has known critical vulnerabilities"""
        if not service.version:
            return False
        
        # Known vulnerable versions (this could be expanded with CVE database)
        vulnerable_patterns = {
            ('apache', 'httpd'): ['2.4.49', '2.4.50'],  # Path traversal
            ('openssh', 'openssh'): ['7.4', '8.5'],      # Various CVEs
            ('microsoft', 'smb'): ['*'],                 # SMBv1 vulnerabilities
        }
        
        key = (service.vendor, service.product)
        if key in vulnerable_patterns:
            vulnerable_versions = vulnerable_patterns[key]
            return service.version in vulnerable_versions or '*' in vulnerable_versions
        
        return False
    
    def _generate_vulnerability_recommendations(self, vulnerable_services: List[ServiceFinding], cve_count: int) -> List[NextStepRecommendation]:
        """Generate recommendations for vulnerable services"""
        recommendations = []
        
        for service in vulnerable_services:
            # High priority vulnerability testing
            recommendations.append(NextStepRecommendation(
                priority=1,
                tool="Metasploit",
                command=f"search {service.vendor} {service.product} {service.version}",
                description=f"Search for exploits targeting {service.vendor} {service.product} {service.version}",
                reason=f"This version has known vulnerabilities (Port {service.port})",
                category="vulnerability"
            ))
            
            # Nmap vulnerability scripts
            recommendations.append(NextStepRecommendation(
                priority=1,
                tool="Nmap",
                command=f"nmap --script vuln -p {service.port} <target>",
                description=f"Run vulnerability detection scripts against port {service.port}",
                reason=f"Targeted vulnerability scanning for {service.service}",
                category="vulnerability"
            ))
        
        return recommendations
    
    def _generate_web_recommendations(self, web_services: List[ServiceFinding]) -> List[NextStepRecommendation]:
        """Generate web application testing recommendations"""
        recommendations = []
        
        if not web_services:
            return recommendations
        
        # Directory enumeration
        recommendations.append(NextStepRecommendation(
            priority=2,
            tool="Feroxbuster",
            command="feroxbuster -u http://<target> -w /usr/share/wordlists/dirb/common.txt",
            description="Enumerate web directories and files",
            reason="Web services often expose sensitive directories and files",
            category="enumeration"
        ))
        
        # Web vulnerability scanning
        recommendations.append(NextStepRecommendation(
            priority=2,
            tool="Nikto",
            command="nikto -h http://<target>",
            description="Comprehensive web vulnerability scan",
            reason="Nikto identifies common web application vulnerabilities",
            category="vulnerability"
        ))
        
        # HTTP enumeration
        recommendations.append(NextStepRecommendation(
            priority=3,
            tool="Nmap",
            command="nmap --script http-enum,http-title,http-methods <target>",
            description="Enumerate HTTP information and available methods",
            reason="Gather detailed information about web server configuration",
            category="enumeration"
        ))
        
        return recommendations
    
    def _generate_smb_recommendations(self, smb_services: List[ServiceFinding]) -> List[NextStepRecommendation]:
        """Generate SMB enumeration recommendations"""
        recommendations = []
        
        if not smb_services:
            return recommendations
        
        # SMB enumeration
        recommendations.append(NextStepRecommendation(
            priority=2,
            tool="Enum4linux",
            command="enum4linux -a <target>",
            description="Comprehensive SMB and NetBIOS enumeration",
            reason="SMB often exposes sensitive information and shares",
            category="enumeration"
        ))
        
        # SMB vulnerability check
        recommendations.append(NextStepRecommendation(
            priority=1,
            tool="Nmap",
            command="nmap --script smb-vuln-* <target>",
            description="Check for SMB vulnerabilities (EternalBlue, etc.)",
            reason="SMB has many critical vulnerabilities that should be tested",
            category="vulnerability"
        ))
        
        # SMB share enumeration
        recommendations.append(NextStepRecommendation(
            priority=2,
            tool="SMBClient",
            command="smbclient -L //<target>/ -N",
            description="List available SMB shares",
            reason="Identify accessible file shares",
            category="enumeration"
        ))
        
        return recommendations
    
    def _generate_ssh_recommendations(self, ssh_services: List[ServiceFinding]) -> List[NextStepRecommendation]:
        """Generate SSH testing recommendations"""
        recommendations = []
        
        if not ssh_services:
            return recommendations
        
        # SSH configuration analysis
        recommendations.append(NextStepRecommendation(
            priority=3,
            tool="Nmap",
            command="nmap --script ssh2-enum-algos,ssh-hostkey <target> -p 22",
            description="Analyze SSH configuration and supported algorithms",
            reason="Identify SSH misconfigurations and weak algorithms",
            category="enumeration"
        ))
        
        # Brute force (lower priority)
        recommendations.append(NextStepRecommendation(
            priority=4,
            tool="Hydra",
            command="hydra -L users.txt -P passwords.txt ssh://<target>",
            description="Attempt SSH credential brute force",
            reason="Test for weak SSH credentials (use with caution)",
            category="exploitation"
        ))
        
        return recommendations
    
    def _generate_database_recommendations(self, database_services: List[ServiceFinding]) -> List[NextStepRecommendation]:
        """Generate database testing recommendations"""
        recommendations = []
        
        for db_service in database_services:
            db_type = db_service.service.lower()
            
            # Database-specific enumeration
            recommendations.append(NextStepRecommendation(
                priority=2,
                tool="Nmap",
                command=f"nmap --script {db_type}-info,{db_type}-enum <target> -p {db_service.port}",
                description=f"Enumerate {db_type.upper()} database information",
                reason=f"Gather information about {db_type.upper()} configuration",
                category="enumeration"
            ))
            
            # Database brute force
            recommendations.append(NextStepRecommendation(
                priority=3,
                tool="Hydra",
                command=f"hydra -L users.txt -P passwords.txt {db_type}://<target>:{db_service.port}",
                description=f"Test {db_type.upper()} authentication",
                reason=f"Check for weak {db_type.upper()} credentials",
                category="exploitation"
            ))
        
        return recommendations
    
    def _generate_general_recommendations(self, services: List[ServiceFinding]) -> List[NextStepRecommendation]:
        """Generate general recommendations when no specific services detected"""
        recommendations = []
        
        # General service enumeration
        recommendations.append(NextStepRecommendation(
            priority=3,
            tool="Nmap",
            command="nmap -sV -sC --script default,discovery <target>",
            description="Detailed service version detection and default scripts",
            reason="Gather more detailed information about discovered services",
            category="enumeration"
        ))
        
        # UDP scan
        recommendations.append(NextStepRecommendation(
            priority=4,
            tool="Nmap",
            command="nmap -sU --top-ports 1000 <target>",
            description="Scan top UDP ports",
            reason="Many services run on UDP that TCP scans miss",
            category="enumeration"
        ))
        
        return recommendations

def plan_next_steps(services: List[ServiceFinding], cve_counts: int = 0) -> List[str]:
    """ENHANCED: More detailed and actionable next steps"""
    decision_tree = IntelligentDecisionTree()
    # Only consider confirmed open or open|filtered services for summary/risk/recommendations
    relevant_services = [
        s for s in services
        if getattr(s, "state", "open") in ("open", "open|filtered")
    ]
    confirmed_services = [s for s in relevant_services if getattr(s, "state", "open") == "open"]

    recommendations = decision_tree.analyze_services(relevant_services, cve_counts)
    
    steps = []
    
    if not relevant_services:
        steps.append(f"** COMPREHENSIVE SCAN ANALYSIS **")
        steps.append(f"   - Services Discovered: 0")
        steps.append(f"   - Critical Vulnerabilities: {cve_counts}")
        steps.append(f"   - Risk Level: LOW")
        steps.append("")
        steps.append("** EXPAND RECONNAISSANCE **")
        steps.append("   - Reason: Initial scan found no open services")
        steps.append("   - Next Actions:")
        steps.append("     * Full port scan: nmap -p- --min-rate 1000 <target>")
        steps.append("     * UDP discovery: nmap -sU --top-ports 1000 <target>")
        steps.append("     * Service detection: nmap -sV -sC <target>")
        steps.append("     * Host discovery: nmap -sn <network>/24")
        return steps

    # Detailed service categorization with attack surface analysis
    service_summary = {}
    attack_surface_score = 0
    high_risk_findings = []

    for s in relevant_services:
        category = _categorize_service(s)
        if category not in service_summary:
            service_summary[category] = []
        service_summary[category].append(s)

        # Calculate attack surface contribution
        if s.port in [21, 22, 23, 80, 443]:  # High-value targets
            attack_surface_score += 3
        elif s.port in [139, 445, 1433, 3306, 5432]:  # Critical services
            attack_surface_score += 5
        else:
            attack_surface_score += 1

        # Flag inherently dangerous services - only confirmed open, not open|filtered
        svc_lower = s.service.lower()
        if getattr(s, 'state', 'open') == 'open':
            if s.port == 23 or svc_lower == 'telnet':
                high_risk_findings.append(("Telnet", s.port, "cleartext protocol, credentials exposed in transit"))
            if s.port == 21 or svc_lower == 'ftp':  # Exact match - won't catch 'tftp'
                high_risk_findings.append(("FTP", s.port, "cleartext protocol, credentials exposed in transit"))
            if s.port == 161 or svc_lower in ('snmp', 'snmptrap'):
                high_risk_findings.append(("SNMP", s.port, "often uses default community strings"))
            if s.port in [139, 445] or svc_lower in ('netbios-ssn', 'microsoft-ds'):
                high_risk_findings.append(("SMB", s.port, "large attack surface, check for null sessions/EternalBlue"))
            if s.port in [3306, 5432, 1433] or svc_lower in ('mysql', 'postgresql', 'ms-sql-s'):
                high_risk_findings.append(("Database", s.port, "exposed to network, test authentication"))

    # Aggregate high-risk findings by service type (e.g., SMB → ports 139, 445)
    grouped_risks = {}
    for service_type, port, description in high_risk_findings:
        if service_type not in grouped_risks:
            grouped_risks[service_type] = {"ports": [], "description": description}
        grouped_risks[service_type]["ports"].append(str(port))

    # Risk level factors in BOTH CVE count AND attack surface
    # A network with telnet+FTP+SMB+exposed DB is not LOW risk even without known CVEs
    risk_score = cve_counts * 3 + attack_surface_score + len(grouped_risks) * 2
    if risk_score >= 25 or cve_counts >= 3:
        risk_level = "CRITICAL"
    elif risk_score >= 15 or cve_counts >= 1:
        risk_level = "HIGH"
    elif risk_score >= 8:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    # Enhanced summary with impact assessment
    steps.append(f"** COMPREHENSIVE SCAN ANALYSIS **")
    steps.append(f"   - Services Discovered: {len(relevant_services)}")
    steps.append(f"   - Critical Vulnerabilities: {cve_counts}")
    steps.append(f"   - Attack Surface Score: {attack_surface_score}")
    steps.append(f"   - Risk Level: {risk_level}")
    steps.append("")

    # Show high-risk findings prominently
    if grouped_risks:
        steps.append("** HIGH-RISK FINDINGS **")
        for service_type, info in grouped_risks.items():
            ports_str = ", ".join(sorted(set(info["ports"])))
            steps.append(f"   [!] {service_type} (port {ports_str}) - {info['description']}")
        steps.append("")

    steps.append("** ATTACK SURFACE ANALYSIS **")
    steps.append(f"   - Surface Complexity: {'HIGH' if attack_surface_score > 15 else 'MEDIUM' if attack_surface_score > 8 else 'LOW'}")
    steps.append("")

    steps.append("** DISCOVERED SERVICES BY CATEGORY **")
    for category, service_list in service_summary.items():
        risk_level = "[HIGH]" if any(s.port in [139, 445, 1433, 3306] for s in service_list) else "[MEDIUM]" if any(s.port in [21, 22, 23, 80, 443] for s in service_list) else "[LOW]"
        steps.append(f"   - {category}: {len(service_list)} service(s) {risk_level}")
        for s in service_list[:3]:  # Show top 3 per category
            detail = s.service
            if s.version:
                detail += f" {s.version}"
            elif s.product:
                detail += f" {s.product}"
            if s.vendor:
                detail += f" ({s.vendor})"
            steps.append(f"     - {s.port}/{s.proto}: {detail}")
        if len(service_list) > 3:
            steps.append(f"     - ... and {len(service_list) - 3} more")
    steps.append("")

    # CVE/EXPLOIT LOOKUP INTEGRATION (Dynamic Database Queries)
    if CVE_ENGINE_AVAILABLE and cve_engine:
        # Vendor name normalization to match CVE database
        VENDOR_MAPPINGS = {
            'openssh': 'openbsd',       # OpenSSH is maintained by OpenBSD
            'windows server': 'microsoft',  # Windows Server → Microsoft
            'redis key-value store': 'redis',  # Redis service
            'linux': 'linux',           # Linux kernel
        }

        # Product name normalization to CPE format
        # Format: (vendor, product) -> mapped_product
        PRODUCT_MAPPINGS = {
            # Apache variants
            ('apache', 'httpd'): 'http_server',
            ('apache', 'http_server'): 'http_server',

            # OpenSSH (already mapped by banner_to_vpv)
            ('openbsd', 'openssh'): 'openssh',

            # Web servers
            ('nginx', 'nginx'): 'nginx',

            # Databases
            ('mysql', 'mysql'): 'mysql',
            ('postgresql', 'postgresql'): 'postgresql',
            ('redis', 'redis'): 'redis',

            # Microsoft Windows Server (already extracted by banner_to_vpv)
            ('microsoft', 'windows_server_2022'): 'windows_server_2022',
            ('microsoft', 'windows_server_2019'): 'windows_server_2019',
            ('microsoft', 'windows_server_2016'): 'windows_server_2016',
            ('microsoft', 'windows_server_2012'): 'windows_server_2012',
            ('microsoft', 'windows_server_2008'): 'windows_server_2008',
            ('microsoft', 'windows_server'): 'windows_server',
            ('microsoft', 'windows_10'): 'windows_10',
            ('microsoft', 'iis'): 'iis',

            # Linux kernel
            ('linux', 'linux_kernel'): 'linux_kernel',
        }

        cve_findings = []

        for s in relevant_services:
            if s.vendor and s.product and s.version:
                # Query CVE database with strict matching
                try:
                    # Extract base version from banner string
                    # Banner format: "OpenSSH 7.2p2 Ubuntu 4ubuntu2.8" or "Apache httpd 2.4.18 ((Ubuntu))"
                    # We need to find the version number (e.g., "7.2p2", "2.4.18")

                    import re
                    version_match = re.search(r'\b(\d+[\d.a-z]+(?:p\d+)?)\b', s.version)
                    if version_match:
                        base_version = version_match.group(1)
                        # Everything after the base version is extra_info
                        version_start_pos = version_match.end()
                        extra_info = s.version[version_start_pos:].strip()
                    else:
                        # Fallback: split on first space
                        version_parts = s.version.split() if s.version else [""]
                        base_version = version_parts[0]
                        extra_info = " ".join(version_parts[1:]) if len(version_parts) > 1 else ""

                    # Normalize vendor and product names to CPE format
                    vendor = s.vendor.lower()
                    product = s.product.lower()

                    # Map vendor if needed
                    mapped_vendor = VENDOR_MAPPINGS.get(vendor, vendor)

                    # Try mapped product name first
                    mapped_product = PRODUCT_MAPPINGS.get((mapped_vendor, product), product)

                    # Query CVE engine with mapped vendor/product names
                    cve_results = cve_engine.query_cves_for_service(
                        mapped_vendor,
                        mapped_product,
                        base_version,
                        extra_info
                    )

                    # If no results with mapped names, try original
                    if not cve_results and (mapped_vendor != vendor or mapped_product != product):
                        cve_results = cve_engine.query_cves_for_service(
                            vendor,
                            product,
                            base_version,
                            extra_info
                        )

                    if cve_results:
                        cve_findings.append((s, cve_results))
                except Exception as e:
                    # Skip services that fail to query
                    continue

        if cve_findings:
            # Update summary line with actual CVE count (not score)
            cve_total = sum(len(cve_results) for _, cve_results in cve_findings)
            for i, line in enumerate(steps):
                if line.startswith("   - Critical Vulnerabilities:"):
                    steps[i] = f"   - Critical Vulnerabilities: {cve_total}"
                    break

            steps.append("=" * 80)
            steps.append("[!!!] CRITICAL VULNERABILITIES DETECTED (CVE Database)")
            steps.append("=" * 80)
            steps.append("")

            for service, cve_results in cve_findings:
                version_str = f" {service.version}" if service.version else ""
                host_str = f" on {service.host}" if service.host else ""
                steps.append(f"Service: {service.product}{version_str}{host_str} port {service.port}/{service.proto}")
                steps.append(f"Vendor: {service.vendor}")
                steps.append("")

                for cve in cve_results:
                    # Format CVE output
                    exploit_indicator = " [HAS EXPLOIT]" if cve.has_exploit else ""
                    distro_indicator = f" [WARNING: {cve.distro_name} may be patched]" if cve.is_distro_version else ""

                    steps.append(f"  {cve.cve_id} - CVSS {cve.cvss_score} ({cve.severity}){exploit_indicator}{distro_indicator}")
                    steps.append(f"    Confidence: {cve.confidence}%")

                    # Show description (truncated)
                    if cve.description:
                        desc = cve.description[:200] + "..." if len(cve.description) > 200 else cve.description
                        steps.append(f"    {desc}")

                    # Show backport warning if applicable
                    if cve.backport_warning:
                        steps.append(f"    [!] {cve.backport_warning}")

                    # Show exploit info if available
                    if cve.has_exploit and cve.exploit_count > 0:
                        exploits = cve_engine.get_exploits_for_cve(cve.cve_id)
                        if exploits:
                            for exploit in exploits[:2]:  # Show top 2 exploits
                                steps.append(f"    [EXPLOIT] EDB-{exploit['edb_id']}: {exploit['title'][:80]}")
                                if exploit.get('is_remote'):
                                    steps.append(f"              Type: REMOTE")

                    steps.append("")

                steps.append("")

            steps.append("=" * 80)
            steps.append("Anti-Hallucination Safeguards Active:")
            steps.append("  - Max 5 CVEs per service (highest CVSS)")
            steps.append("  - Min confidence: 80%")
            steps.append("  - Min CVSS: 7.0")
            steps.append("  - Version range validation enabled")
            steps.append("  - Distro backporting detection enabled")
            steps.append("=" * 80)
            steps.append("")
    elif not CVE_ENGINE_AVAILABLE:
        steps.append("[INFO] CVE database not available. Run 'python build_all_databases.py' to enable dynamic CVE lookup.")
        steps.append("")

    # Add the existing recommendations code but with enhanced formatting
    if recommendations:
        steps.append("** INTELLIGENT NEXT STEPS **")
        steps.append("")
        
        # Group by priority
        priority_groups = {}
        for rec in recommendations:
            if rec.priority not in priority_groups:
                priority_groups[rec.priority] = []
            priority_groups[rec.priority].append(rec)
        
        priority_labels = {
            1: "[CRITICAL]",
            2: "[HIGH]",
            3: "[MEDIUM]",
            4: "[LOW]"
        }
        
        for priority in sorted(priority_groups.keys()):
            group = priority_groups[priority]
            steps.append(f"**{priority_labels.get(priority, 'UNKNOWN PRIORITY')}:**")
            
            for i, rec in enumerate(group, 1):
                steps.append(f"{i}. **{rec.tool}**: {rec.description}")
                steps.append(f"   ```")
                steps.append(f"   {rec.command}")
                steps.append(f"   ```")
                steps.append(f"   *Why: {rec.reason}*")
                steps.append("")
        
        # ENHANCED: Ready-to-execute command examples
        steps.append("** READY-TO-EXECUTE COMMANDS **")
        steps.append("")

        # Generate specific commands based on discovered services
        target_placeholder = "<target>"

        # Web services (confirmed open only) - prioritize common web ports
        web_services = [s for s in confirmed_services if s.port in [80, 443, 8080, 8443, 8000, 8008, 9080, 9443] or 'http' in s.service.lower()]
        if web_services:
            steps.append("Web Services Detected:")
            seen_web = set()
            unique_web = []
            preferred_ports = {80, 443, 8080, 8443, 8000, 8008, 9080, 9443}
            web_services_sorted = sorted(
                web_services,
                key=lambda s: (0 if s.port in preferred_ports else 1, s.port)
            )
            for ws in web_services_sorted:
                key = (ws.port, ws.proto)
                if key in seen_web:
                    continue
                seen_web.add(key)
                unique_web.append(ws)

            for ws in unique_web[:2]:  # Top 2 unique web endpoints
                protocol = "https" if ws.port == 443 else "http"
                port_suffix = f":{ws.port}" if ws.port not in [80, 443] else ""
                steps.append(f"```bash")
                steps.append(f"# Target: {protocol}://{target_placeholder}{port_suffix}")
                steps.append(f"feroxbuster -u {protocol}://{target_placeholder}{port_suffix} -w /usr/share/wordlists/dirb/common.txt")
                steps.append(f"nikto -h {protocol}://{target_placeholder}{port_suffix}")
                steps.append(f"nmap --script http-enum,http-title,http-methods -p {ws.port} {target_placeholder}")
                steps.append(f"```")
                steps.append("")
        
        # SMB services (confirmed open only)
        smb_services = [s for s in confirmed_services if s.port in [139, 445]]
        if smb_services:
            steps.append("SMB Services Detected:")
            steps.append(f"```bash")
            steps.append(f"# SMB Enumeration")
            steps.append(f"enum4linux -a {target_placeholder}")
            steps.append(f"nmap --script smb-enum-shares,smb-vuln-*,smb-protocols {target_placeholder}")
            steps.append(f"smbclient -L //{target_placeholder}/ -N")
            steps.append(f"crackmapexec smb {target_placeholder}")
            steps.append(f"```")
            steps.append("")
        
        # SSH services (confirmed open only)
        ssh_services = [s for s in confirmed_services if s.port == 22 or 'ssh' in s.service.lower()]
        if ssh_services:
            steps.append("SSH Services Detected:")
            steps.append(f"```bash")
            steps.append(f"# SSH Analysis")
            steps.append(f"nmap --script ssh2-enum-algos,ssh-hostkey,ssh-auth-methods -p 22 {target_placeholder}")
            steps.append(f"ssh-audit {target_placeholder}")
            steps.append(f"# Credential testing (use with caution)")
            steps.append(f"hydra -L users.txt -P passwords.txt ssh://{target_placeholder}")
            steps.append(f"```")
            steps.append("")
    
    return steps

def _categorize_service(service: ServiceFinding) -> str:
    """Categorize service for summary display"""
    service_lower = service.service.lower()
    
    if service.port in [80, 443, 8080, 8443] or 'http' in service_lower:
        return "Web Services"
    elif service.port == 22 or 'ssh' in service_lower:
        return "Remote Access"
    elif service.port in [139, 445] or 'smb' in service_lower:
        return "File Sharing"
    elif service.port in [1433, 3306, 5432, 1521] or any(db in service_lower for db in ['mysql', 'postgres', 'mssql', 'oracle']):
        return "Databases"
    elif service.port in [21, 22] or 'ftp' in service_lower:
        return "File Transfer"
    elif service.port in [25, 110, 143, 993, 995] or any(mail in service_lower for mail in ['smtp', 'pop', 'imap']):
        return "Email Services"
    elif service.port == 53 or 'dns' in service_lower:
        return "DNS Services"
    else:
        return "Other Services"
