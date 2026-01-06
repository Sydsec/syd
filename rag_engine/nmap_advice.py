from dataclasses import dataclass
from typing import List, Optional, Tuple, Dict, Any
import re

@dataclass
class ServiceFinding:
    port: int
    proto: str
    service: str
    vendor: Optional[str]
    product: Optional[str]
    version: Optional[str]
    cpe: Optional[str]

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
        for m in re.finditer(
            r'<port protocol="(?P<proto>tcp|udp)" portid="(?P<port>\d+)">.*?<service[^>]*name="(?P<n>[^\"]+)"(?P<attrs>[^>]*)>(?P<inner>.*?)</service>',
            text, flags=re.S|re.I):
            
            port = int(m.group("port"))
            proto = m.group("proto").lower()
            svc = (m.group("n") or "").lower()  # FIXED: was m.group("name")
            attrs = m.group("attrs") or ""
            inner = m.group("inner") or ""
            
            # Extract product and version from attributes
            prod = re.search(r'product="([^"]+)"', attrs)
            ver = re.search(r'version="([^"]+)"', attrs)
            cpe = re.search(r"<cpe>([^<]+)</cpe>", inner)
            
            product_attr = prod.group(1).strip() if prod else None
            version = ver.group(1).strip() if ver else None
            cpe_text = cpe.group(1).strip() if cpe else None
            
            vendor, product = normalize_vendor_product(svc, product_attr, cpe_text)
            items.append(ServiceFinding(port, proto, svc, vendor, product, version, cpe_text))
    
    # Plaintext parsing - ENHANCED patterns
    for line in text.splitlines():
        # Standard nmap output: PORT/PROTO STATE SERVICE VERSION
        m = re.match(r'(?P<p>\d+)/(?P<pr>\w+)\s+\w+\s+(?P<svc>\S+)\s*(?P<banner>.*)$', line.strip(), flags=re.I)
        if not m:
            continue
            
        port = int(m.group("p"))
        proto = m.group("pr").lower()
        svc = m.group("svc").lower()
        banner = m.group("banner").strip()
        
        vendor, product, version = banner_to_vpv(svc, banner)
        items.append(ServiceFinding(port, proto, svc, vendor, product, version, None))
    
    return dedupe(items)

def normalize_vendor_product(svc: str, product_attr: Optional[str], cpe: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    """Enhanced vendor/product normalization with more patterns"""
    
    # CPE parsing first (most reliable)
    if cpe and cpe.startswith("cpe:/a:"):
        parts = cpe.split(":")
        if len(parts) >= 5:
            return parts[3].lower(), parts[4].lower()
    
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
    """Enhanced banner parsing for vendor/product/version"""
    
    banner_lower = banner.lower()
    
    # SSH banners
    if "openssh" in banner_lower:
        return "openssh", "openssh", _extract_version(banner)
    
    # Web server banners
    if "apache" in banner_lower and ("httpd" in banner_lower or "http" in banner_lower):
        return "apache", "httpd", _extract_version(banner)
    if "nginx" in banner_lower:
        return "nginx", "nginx", _extract_version(banner)
    if "microsoft-iis" in banner_lower:
        return "microsoft", "iis", _extract_version(banner)
    
    # Database banners
    if "mysql" in banner_lower:
        return "mysql", "mysql", _extract_version(banner)
    if "postgresql" in banner_lower:
        return "postgresql", "postgresql", _extract_version(banner)
    
    # FTP banners
    if "vsftpd" in banner_lower:
        return "vsftpd", "vsftpd", _extract_version(banner)
    if "proftpd" in banner_lower:
        return "proftpd", "proftpd", _extract_version(banner)
    
    return (None, None, _extract_version(banner))

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
    recommendations = decision_tree.analyze_services(services, cve_counts)
    
    steps = []
    
    # Enhanced summary with impact assessment
    steps.append(f"** COMPREHENSIVE SCAN ANALYSIS **")
    steps.append(f"   - Services Discovered: {len(services)}")
    steps.append(f"   - Critical Vulnerabilities: {cve_counts}")
    steps.append(f"   - Risk Level: {'HIGH' if cve_counts >= 3 else 'MEDIUM' if cve_counts >= 1 else 'LOW'}")
    steps.append("")

    if not services:
        steps.append("** EXPAND RECONNAISSANCE **")
        steps.append("   - Reason: Initial scan found no open services")
        steps.append("   - Next Actions:")
        steps.append("     * Full port scan: nmap -p- --min-rate 1000 <target>")
        steps.append("     * UDP discovery: nmap -sU --top-ports 1000 <target>")
        steps.append("     * Service detection: nmap -sV -sC <target>")
        steps.append("     * Host discovery: nmap -sn <network>/24")
        return steps
    
    # ENHANCED: Detailed service categorization with attack surface analysis
    service_summary = {}
    attack_surface_score = 0
    
    for s in services:
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
    
    steps.append("** ATTACK SURFACE ANALYSIS **")
    steps.append(f"   - Surface Complexity: {'HIGH' if attack_surface_score > 15 else 'MEDIUM' if attack_surface_score > 8 else 'LOW'}")
    steps.append("")

    steps.append("** DISCOVERED SERVICES BY CATEGORY **")
    for category, service_list in service_summary.items():
        risk_level = "[HIGH]" if any(s.port in [139, 445, 1433, 3306] for s in service_list) else "[MEDIUM]" if any(s.port in [21, 22, 23, 80, 443] for s in service_list) else "[LOW]"
        steps.append(f"   - {category}: {len(service_list)} service(s) {risk_level}")
        for s in service_list[:3]:  # Show top 3 per category
            version_info = f" {s.version}" if s.version else ""
            vendor_info = f" ({s.vendor})" if s.vendor else ""
            steps.append(f"     - {s.port}/{s.proto}: {s.service}{version_info}{vendor_info}")
        if len(service_list) > 3:
            steps.append(f"     - ... and {len(service_list) - 3} more")
    steps.append("")

    # CVE/EXPLOIT LOOKUP INTEGRATION (Offensive Context)
    try:
        import sys
        from pathlib import Path
        # Add parent directory to path for imports
        sys.path.insert(0, str(Path(__file__).parent.parent))
        from cve_exploit_lookup import lookup_service_exploits

        cve_findings = []
        for s in services:
            if s.version:
                # Try different service name formats
                service_names = [s.service, s.product] if s.product else [s.service]
                for svc_name in service_names:
                    if svc_name:
                        cves, formatted = lookup_service_exploits(svc_name, s.version)
                        if cves:
                            cve_findings.append((s, formatted))
                            break

        if cve_findings:
            steps.append("=" * 80)
            steps.append("## [!!!] KNOWN VULNERABILITIES & EXPLOITS DETECTED")
            steps.append("=" * 80 + "\n")
            for service, cve_output in cve_findings:
                steps.append(cve_output)
                steps.append("")
            steps.append("=" * 80 + "\n")
    except Exception as e:
        # Silently fail if CVE lookup not available
        pass

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

        # Web services
        web_services = [s for s in services if s.port in [80, 443, 8080, 8443] or 'http' in s.service.lower()]
        if web_services:
            steps.append("Web Services Detected:")
            for ws in web_services[:2]:  # Top 2 web services
                protocol = "https" if ws.port == 443 else "http"
                port_suffix = f":{ws.port}" if ws.port not in [80, 443] else ""
                steps.append(f"```bash")
                steps.append(f"# Target: {protocol}://{target_placeholder}{port_suffix}")
                steps.append(f"feroxbuster -u {protocol}://{target_placeholder}{port_suffix} -w /usr/share/wordlists/dirb/common.txt")
                steps.append(f"nikto -h {protocol}://{target_placeholder}{port_suffix}")
                steps.append(f"nmap --script http-enum,http-title,http-methods -p {ws.port} {target_placeholder}")
                steps.append(f"```")
                steps.append("")
        
        # SMB services
        smb_services = [s for s in services if s.port in [139, 445]]
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
        
        # SSH services
        ssh_services = [s for s in services if s.port == 22 or 'ssh' in s.service.lower()]
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
