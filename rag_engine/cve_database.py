from pathlib import Path
from typing import List, Dict, Any

class CVE:
    def __init__(self, cve_id: str, description: str, cvss_score: float, severity: str):
        self.cve_id = cve_id
        self.description = description
        self.cvss_score = cvss_score
        self.severity = severity

class OfflineCVEDatabase:
    """
    Placeholder for OfflineCVEDatabase.
    In a real implementation, this would manage a local CVE database.
    """
    def __init__(self, db_path: Path):
        self.db_path = db_path
        print(f"[OfflineCVEDatabase] Initialized placeholder with db_path: {db_path}")

    def has_data(self) -> bool:
        """Placeholder: always return True for demo purposes."""
        return True

    def build_database_from_json_feeds(self):
        """Placeholder: simulate building the database."""
        print("[OfflineCVEDatabase] Simulating database build from JSON feeds.")

    def search_cves_for_service(self, vendor: str, product: str, version: str, min_cvss: float = 0.0, limit: int = 5) -> List[CVE]:
        """Placeholder: Simulate CVE search for a service."""
        print(f"[OfflineCVEDatabase] Simulating CVE search for {vendor} {product} {version}")
        # Return some dummy CVEs for testing purposes
        return [
            CVE(cve_id="CVE-2023-0001", description=f"Dummy vuln for {product} {version}", cvss_score=7.5, severity="HIGH"),
            CVE(cve_id="CVE-2023-0002", description=f"Another dummy vuln for {product} {version}", cvss_score=6.0, severity="MEDIUM")
        ]

    def search_cves_by_keywords(self, keywords: List[str], min_cvss: float = 0.0, limit: int = 5) -> List[CVE]:
        """Placeholder: Simulate CVE search by keywords."""
        print(f"[OfflineCVEDatabase] Simulating CVE search by keywords: {', '.join(keywords)}")
        return [
            CVE(cve_id="CVE-2023-0003", description=f"Keyword-based dummy vuln for {keywords[0]}", cvss_score=8.0, severity="CRITICAL")
        ]

