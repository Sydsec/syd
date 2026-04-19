#!/usr/bin/env python3
"""
CVE Query Engine - ANTI-HALLUCINATION safeguards
CRITICAL: This module prevents Syd from pulling irrelevant CVEs

Safeguards:
1. EXACT version matching with range validation
2. Confidence scoring (only >= 80%)
3. Hard limits (max 5 CVEs per query)
4. CVSS threshold (only >= 7.0)
5. Exploit prioritization
6. Deduplication
"""

import sqlite3
import re
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass

@dataclass
class CVEResult:
    """CVE query result with confidence scoring"""
    cve_id: str
    description: str
    cvss_score: float
    severity: str
    confidence: int  # 0-100
    has_exploit: bool
    exploit_count: int
    exploitability_score: float
    published_date: str
    is_distro_version: bool = False
    distro_name: str = ""
    backport_warning: str = ""

    def __str__(self):
        exploit_str = f" [EXPLOIT: {self.exploit_count}]" if self.has_exploit else ""
        conf_str = f" [Confidence: {self.confidence}%]"
        distro_str = f" [WARNING: {self.distro_name} - May be backport-patched]" if self.is_distro_version else ""
        return f"{self.cve_id} (CVSS {self.cvss_score}) {self.severity}{exploit_str}{conf_str}{distro_str}"

class CVEQueryEngine:
    """
    Query CVE and ExploitDB databases with STRICT matching
    """

    def __init__(self, cve_db_path: str = "rag_engine/cve_database.db",
                 exploit_db_path: str = "rag_engine/exploit_database.db"):
        self.cve_db_path = Path(cve_db_path)
        self.exploit_db_path = Path(exploit_db_path)

        # Anti-hallucination thresholds
        self.MIN_CONFIDENCE = 80  # Only show results with >= 80% confidence
        self.MIN_CVSS = 7.0  # Only show CVSS >= 7.0
        self.MAX_RESULTS = 5  # Hard limit per query

        # Check database existence
        if not self.cve_db_path.exists():
            raise FileNotFoundError(f"CVE database not found: {self.cve_db_path}")

        self.has_exploit_db = self.exploit_db_path.exists()

    def normalize_version(self, version: str) -> Optional[str]:
        """Normalize version string for comparison"""
        if not version or version == '*' or version == '-':
            return None

        version = version.lower().strip()
        version = re.sub(r'^v\.?', '', version)  # Remove 'v' or 'v.'

        # CRITICAL: Reject "versions" with no digits (e.g. "dovecot", "pop3d", "smtpd")
        # These are product/daemon names, not versions - comparing them causes false positives
        if not re.search(r'\d', version):
            return None

        return version

    def detect_distro_patching(self, version_string: str) -> Tuple[bool, str, int]:
        """
        Detect if version string indicates distro-managed package with backporting

        Returns: (is_distro_version, distro_name, confidence_penalty)

        Examples:
          "7.2p2 Ubuntu 4ubuntu2.8" → (True, "Ubuntu", -20)
          "2.4.18 ((Ubuntu))" → (True, "Ubuntu", -20)
          "5.5.62-0ubuntu0.14.04.1" → (True, "Ubuntu", -20)
          "7.4p1 Debian 10+deb9u7" → (True, "Debian", -20)
          "2.4.6-93.el7.centos" → (True, "RHEL/CentOS", -20)
          "2.4.41" → (False, "", 0)
        """
        if not version_string:
            return (False, "", 0)

        version_lower = version_string.lower()

        # Distro detection patterns
        distro_patterns = [
            (r'ubuntu|0ubuntu', "Ubuntu", -20),
            (r'debian|\+deb|~deb', "Debian", -20),
            (r'el\d+|centos|rhel|\.el\d+', "RHEL/CentOS", -20),
            (r'fc\d+|fedora', "Fedora", -20),
            (r'suse|sles|opensuse', "SUSE", -20),
            (r'gentoo', "Gentoo", -15),  # Gentoo patches aggressively
            (r'arch', "Arch", -10),  # Arch usually closer to upstream
        ]

        for pattern, distro_name, penalty in distro_patterns:
            if re.search(pattern, version_lower):
                return (True, distro_name, penalty)

        return (False, "", 0)

    def compare_versions(self, v1: str, v2: str) -> int:
        """Compare two version strings (-1, 0, 1)"""
        def version_parts(v):
            parts = []
            for part in v.split('.'):
                try:
                    parts.append(int(re.sub(r'[^0-9]', '', part)))
                except ValueError:
                    parts.append(0)
            return parts

        try:
            p1 = version_parts(v1)
            p2 = version_parts(v2)

            max_len = max(len(p1), len(p2))
            p1 += [0] * (max_len - len(p1))
            p2 += [0] * (max_len - len(p2))

            for a, b in zip(p1, p2):
                if a < b:
                    return -1
                elif a > b:
                    return 1
            return 0
        except:
            return 0

    def is_version_vulnerable(self, target_version: str, cpe_entry: Dict, product: str = "") -> Tuple[bool, int]:
        """
        Check if target version is vulnerable based on CPE entry
        Returns: (is_vulnerable, confidence_score)

        CRITICAL: This prevents false positives
        """
        target = self.normalize_version(target_version)
        is_windows = 'windows' in product.lower() if product else False

        # Special case: Windows products can match with lower confidence even without exact version
        if not target and is_windows:
            # For Windows, if there's any CPE entry, assume it could be vulnerable
            # Return with 80% confidence (minimum threshold) since we can't verify exact version
            # Windows uses version codes (1607, 1709) but Nmap provides build numbers (14393)
            return (True, 80)

        if not target:
            return (False, 0)

        cpe_version = self.normalize_version(cpe_entry.get('version'))
        version_start = self.normalize_version(cpe_entry.get('version_start'))
        version_end = self.normalize_version(cpe_entry.get('version_end'))
        start_including = cpe_entry.get('version_start_including', True)
        end_including = cpe_entry.get('version_end_including', True)

        # Case 1: Exact version match
        if cpe_version and cpe_version == target:
            return (True, 100)

        # Case 2: Version range match
        if version_start or version_end:
            in_range = True
            confidence = 90  # Slightly lower confidence for range matches

            # Check start bound
            if version_start:
                cmp = self.compare_versions(target, version_start)
                if start_including:
                    if cmp < 0:  # target < start
                        in_range = False
                else:
                    if cmp <= 0:  # target <= start
                        in_range = False

            # Check end bound
            if version_end and in_range:
                cmp = self.compare_versions(target, version_end)
                if end_including:
                    if cmp > 0:  # target > end
                        in_range = False
                else:
                    if cmp >= 0:  # target >= end
                        in_range = False

            if in_range:
                return (True, confidence)

        # Case 3: Wildcard match (lowest confidence)
        if cpe_version == '*' and not version_start and not version_end:
            # Only return True if product matches exactly
            return (True, 60)  # Low confidence, may not pass threshold

        # Case 4: Windows special case - only match if we have version range data
        # Previously returned (True, 80) for ALL Windows CVEs regardless of version,
        # which caused massive false positives. Now requires at least partial version evidence.
        if is_windows and target and (version_start or version_end):
            return (True, 65)  # Lower confidence - version range exists but didn't match exactly

        return (False, 0)

    def query_cves_for_service(self, vendor: str, product: str, version: str,
                                version_extra_info: str = "") -> List[CVEResult]:
        """
        Query CVEs for a specific service version
        ANTI-HALLUCINATION: Strict matching, confidence scoring, distro backport detection

        Args:
            vendor: e.g., "apache"
            product: e.g., "http_server"
            version: e.g., "2.4.18"
            version_extra_info: e.g., "Ubuntu 4ubuntu2.8" (for distro detection)

        Returns:
            List of CVEResult objects (max 5, confidence >= 80%)
        """
        if not vendor or not product:
            return []

        vendor = vendor.lower().strip()
        product = product.lower().strip()

        # CRITICAL: Detect distro patching BEFORE normalizing
        # This prevents false positives on backported packages
        full_version_string = f"{version} {version_extra_info}".strip()
        is_distro, distro_name, confidence_penalty = self.detect_distro_patching(full_version_string)

        version = self.normalize_version(version)

        # Special case: Windows products often use version codes (1607, 1709) in CVE database
        # but Nmap provides build numbers (14393). Allow fuzzy matching for Windows.
        is_windows_product = 'windows' in product.lower()

        if not version and not is_windows_product:
            return []  # CRITICAL: Don't return results without version (except Windows)

        conn = sqlite3.connect(self.cve_db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Query: Find CVEs matching vendor/product
        cursor.execute("""
            SELECT DISTINCT
                c.cve_id, c.description, c.cvss_v3_score, c.cvss_v3_severity,
                c.exploitability_score, c.published_date,
                cp.version, cp.version_start, cp.version_end,
                cp.version_start_including, cp.version_end_including
            FROM cves c
            INNER JOIN cve_cpe cp ON c.cve_id = cp.cve_id
            WHERE cp.vendor = ? AND cp.product = ?
              AND c.cvss_v3_score >= ?
            ORDER BY c.cvss_v3_score DESC
        """, (vendor, product, self.MIN_CVSS))

        results = []
        seen_cves = set()

        for row in cursor.fetchall():
            cve_id = row['cve_id']

            # Deduplication
            if cve_id in seen_cves:
                continue

            # Check if version is vulnerable
            cpe_entry = {
                'version': row['version'],
                'version_start': row['version_start'],
                'version_end': row['version_end'],
                'version_start_including': row['version_start_including'],
                'version_end_including': row['version_end_including']
            }

            is_vuln, confidence = self.is_version_vulnerable(version, cpe_entry, product)

            # CRITICAL: Apply distro confidence penalty
            # This handles Ubuntu/Debian/RHEL backporting
            if is_distro:
                confidence = max(0, confidence + confidence_penalty)  # Apply penalty (negative number)

            # CRITICAL: Only include if confident match
            if not is_vuln or confidence < self.MIN_CONFIDENCE:
                continue

            # Check for exploits
            has_exploit, exploit_count = self._check_exploits(cve_id)

            # Boost confidence if exploit exists
            if has_exploit:
                confidence = min(100, confidence + 10)

            # Create backport warning
            backport_warning = ""
            if is_distro:
                backport_warning = (f"{distro_name} detected. This version MAY have security patches "
                                   f"backported by the distribution. Verify with package manager "
                                   f"(apt-cache policy, yum info, etc.)")

            results.append(CVEResult(
                cve_id=cve_id,
                description=row['description'][:200],  # Truncate long descriptions
                cvss_score=row['cvss_v3_score'],
                severity=row['cvss_v3_severity'],
                confidence=confidence,
                has_exploit=has_exploit,
                exploit_count=exploit_count,
                exploitability_score=row['exploitability_score'],
                published_date=row['published_date'],
                is_distro_version=is_distro,
                distro_name=distro_name,
                backport_warning=backport_warning
            ))

            seen_cves.add(cve_id)

            # CRITICAL: Hard limit to prevent noise
            if len(results) >= self.MAX_RESULTS:
                break

        conn.close()

        # Sort by priority: CVSS score, then exploit availability, then confidence
        results.sort(key=lambda r: (r.cvss_score, r.exploit_count, r.confidence), reverse=True)

        return results

    def _check_exploits(self, cve_id: str) -> Tuple[bool, int]:
        """Check if CVE has exploits in ExploitDB"""
        if not self.has_exploit_db:
            return (False, 0)

        try:
            conn = sqlite3.connect(self.exploit_db_path)
            cursor = conn.cursor()

            cursor.execute("""
                SELECT COUNT(*) as count
                FROM exploit_cve
                WHERE cve_id = ?
            """, (cve_id,))

            result = cursor.fetchone()
            count = result[0] if result else 0

            conn.close()

            return (count > 0, count)

        except Exception:
            return (False, 0)

    def get_exploits_for_cve(self, cve_id: str) -> List[Dict]:
        """Get ExploitDB entries for a CVE"""
        if not self.has_exploit_db:
            return []

        try:
            conn = sqlite3.connect(self.exploit_db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute("""
                SELECT e.edb_id, e.title, e.type, e.platform, e.verified, e.is_remote
                FROM exploits e
                INNER JOIN exploit_cve ec ON e.edb_id = ec.edb_id
                WHERE ec.cve_id = ?
                  AND e.confidence_score >= 70
                ORDER BY e.verified DESC, e.is_remote DESC
                LIMIT 5
            """, (cve_id,))

            exploits = []
            for row in cursor.fetchall():
                exploits.append({
                    'edb_id': row['edb_id'],
                    'title': row['title'],
                    'type': row['type'],
                    'platform': row['platform'],
                    'verified': row['verified'],
                    'is_remote': row['is_remote'],
                    'url': f"https://www.exploit-db.com/exploits/{row['edb_id']}"
                })

            conn.close()
            return exploits

        except Exception:
            return []

    def test_query(self, vendor: str, product: str, version: str, extra_info: str = ""):
        """Test query with detailed output"""
        full_ver = f"{version} {extra_info}".strip()
        print(f"\n[TEST QUERY] {vendor} {product} {full_ver}")
        print("=" * 60)

        results = self.query_cves_for_service(vendor, product, version, extra_info)

        if not results:
            print("[INFO] No CVEs found (strict matching, confidence >= 80%)")
            return

        print(f"[FOUND] {len(results)} CVEs:")
        print()

        for result in results:
            print(f"  {result}")

            # Show backport warning if applicable
            if result.backport_warning:
                print(f"    [!] {result.backport_warning}")

            # Show exploits if available
            exploits = self.get_exploits_for_cve(result.cve_id)
            if exploits:
                for exploit in exploits[:2]:  # Show max 2
                    verified_str = "[VERIFIED]" if exploit['verified'] else ""
                    remote_str = "[REMOTE]" if exploit['is_remote'] else ""
                    print(f"    └─ EDB-{exploit['edb_id']}: {exploit['title'][:60]}... {verified_str} {remote_str}")

            print()

if __name__ == "__main__":
    # Test queries
    engine = CVEQueryEngine()

    print("\n" + "="*80)
    print("DISTRO BACKPORTING TEST - Critical for False Positive Prevention")
    print("="*80)

    # Test 1: Upstream version (NO distro string) - Should show high confidence
    print("\n>>> TEST 1: Upstream OpenSSH 7.2p2 (vanilla)")
    engine.test_query("openbsd", "openssh", "7.2p2")

    # Test 2: Ubuntu version (WITH distro string) - Should show LOWER confidence + warning
    print("\n>>> TEST 2: OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (PATCHED)")
    engine.test_query("openbsd", "openssh", "7.2p2", "Ubuntu 4ubuntu2.8")

    # Test 3: Debian version - Should also show lower confidence
    print("\n>>> TEST 3: OpenSSH 7.4p1 Debian 10+deb9u7 (PATCHED)")
    engine.test_query("openbsd", "openssh", "7.4p1", "Debian 10+deb9u7")

    print("\n" + "="*80)
    print("STANDARD TESTS - Healthcare Scan Services")
    print("="*80)

    # Test 4: Apache HTTP Server 2.4.18 (healthcare scan)
    engine.test_query("apache", "http_server", "2.4.18")

    # Test 5: MySQL 5.5.62 (should have authentication bypass)
    engine.test_query("oracle", "mysql", "5.5.62")

    print("\n[✓] Test queries complete")
    print("\n" + "="*80)
    print("EXPECTED BEHAVIOR:")
    print("  - Upstream versions: Confidence 90-100%")
    print("  - Distro versions: Confidence drops to 70-80% + warning")
    print("  - Results below 80% confidence are FILTERED OUT")
    print("  - Distro versions with exploits may still show (exploit boost)")
    print("="*80)
