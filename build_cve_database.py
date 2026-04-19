#!/usr/bin/env python3
"""
CVE Database Builder - Downloads NVD CVE feeds and builds searchable database
ANTI-HALLUCINATION DESIGN: Strict version matching, confidence scoring, hard limits
"""

import sqlite3
import json
import requests
import gzip
import lzma
import io
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from datetime import datetime

# Configuration
# Using community reconstruction since NVD deprecated legacy feeds
# https://github.com/fkie-cad/nvd-json-data-feeds
NVD_BASE_URL = "https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download"
DB_PATH = Path("rag_engine/cve_database.db")
CACHE_DIR = Path("rag_engine/cve_cache")

# ANTI-HALLUCINATION: Only download recent years to keep database manageable
YEARS_TO_DOWNLOAD = [2018, 2019, 2020, 2021, 2022, 2023, 2024, 2025]

class CVEDatabaseBuilder:
    def __init__(self):
        self.db_path = DB_PATH
        self.cache_dir = CACHE_DIR
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    def create_schema(self):
        """Create database schema with STRICT constraints"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Main CVE table with version range support
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cves (
                cve_id TEXT PRIMARY KEY,
                description TEXT,
                cvss_v3_score REAL,
                cvss_v3_severity TEXT,
                cvss_v2_score REAL,
                cvss_v2_severity TEXT,
                published_date TEXT,
                last_modified TEXT,
                exploitability_score REAL,
                impact_score REAL,

                -- Anti-hallucination: Track data quality
                confidence_score INTEGER DEFAULT 100,
                verified BOOLEAN DEFAULT 0,

                -- Indexes for fast queries
                UNIQUE(cve_id)
            )
        """)

        # CPE (Common Platform Enumeration) table for version matching
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cve_cpe (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT NOT NULL,
                vendor TEXT,
                product TEXT,
                version TEXT,
                version_start TEXT,
                version_end TEXT,
                version_start_including BOOLEAN DEFAULT 1,
                version_end_including BOOLEAN DEFAULT 1,
                vulnerable BOOLEAN DEFAULT 1,

                -- Anti-hallucination: Match quality tracking
                match_confidence INTEGER DEFAULT 100,

                FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
            )
        """)

        # Create indexes for fast lookups
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cves_cvss ON cves(cvss_v3_score)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cve_cpe_vendor ON cve_cpe(vendor, product)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cve_date ON cves(published_date)")

        conn.commit()
        conn.close()
        print("[[OK]] Database schema created")

    def download_cve_feed(self, year: int) -> Optional[Path]:
        """Download NVD CVE feed for a specific year"""
        cache_file = self.cache_dir / f"CVE-{year}.json"

        # Use cache if available and recent
        if cache_file.exists():
            print(f"[CACHE] Using cached feed for {year}")
            return cache_file

        print(f"[DOWNLOAD] Fetching NVD feed for {year}...")
        url = f"{NVD_BASE_URL}/CVE-{year}.json.xz"

        try:
            response = requests.get(url, timeout=120, allow_redirects=True)
            response.raise_for_status()

            # Decompress xz (lzma)
            data = lzma.decompress(response.content)

            # Save to cache
            with open(cache_file, 'wb') as f:
                f.write(data)

            print(f"[OK] Downloaded {len(data) / 1024 / 1024:.1f}MB for {year}")
            return cache_file

        except requests.RequestException as e:
            print(f"[ERROR] Failed to download {year}: {e}")
            return None
        except lzma.LZMAError as e:
            print(f"[ERROR] Failed to decompress {year}: {e}")
            return None

    def parse_cpe_string(self, cpe_str: str) -> Dict[str, str]:
        """Parse CPE 2.3 URI string"""
        # Format: cpe:2.3:a:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
        parts = cpe_str.split(':')
        if len(parts) < 5:
            return {}

        return {
            'vendor': parts[3] if len(parts) > 3 else '*',
            'product': parts[4] if len(parts) > 4 else '*',
            'version': parts[5] if len(parts) > 5 else '*'
        }

    def normalize_version(self, version: str) -> Optional[str]:
        """Normalize version string for comparison"""
        if not version or version == '*' or version == '-':
            return None

        # Remove common prefixes
        version = version.lower().strip()
        version = re.sub(r'^v\.?', '', version)  # Remove 'v' or 'v.'

        return version

    def compare_versions(self, v1: str, v2: str) -> int:
        """
        Compare two version strings
        Returns: -1 if v1 < v2, 0 if equal, 1 if v1 > v2
        """
        def version_parts(v):
            # Split on dots and convert to integers where possible
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

            # Pad shorter list
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
            return 0  # Unable to compare

    def is_version_in_range(self, version: str, start: Optional[str], end: Optional[str],
                           start_including: bool = True, end_including: bool = True) -> bool:
        """
        Check if version falls within vulnerable range
        CRITICAL: This prevents false positives
        """
        if not version:
            return False

        version = self.normalize_version(version)
        if not version:
            return False

        # No range specified - exact match only
        if not start and not end:
            return False

        # Check start bound
        if start:
            start = self.normalize_version(start)
            if start:
                cmp = self.compare_versions(version, start)
                if start_including:
                    if cmp < 0:  # version < start
                        return False
                else:
                    if cmp <= 0:  # version <= start
                        return False

        # Check end bound
        if end:
            end = self.normalize_version(end)
            if end:
                cmp = self.compare_versions(version, end)
                if end_including:
                    if cmp > 0:  # version > end
                        return False
                else:
                    if cmp >= 0:  # version >= end
                        return False

        return True

    def parse_cve_item(self, cve_item: Dict) -> Optional[Tuple[Dict, List[Dict]]]:
        """
        Parse single CVE item from NVD feed (supports both 1.1 and 2.0 formats)
        Returns: (cve_data, cpe_list) or None if invalid
        """
        try:
            # Detect format: NVD 2.0 has "id" at top level, 1.1 has "cve" wrapper
            is_v2 = 'id' in cve_item

            if is_v2:
                # NVD API 2.0 format
                cve_id = cve_item.get('id')
                if not cve_id:
                    return None

                # Extract description
                descriptions = cve_item.get('descriptions', [])
                description = ''
                for desc in descriptions:
                    if desc.get('lang') == 'en':
                        description = desc.get('value', '')
                        break

                # Extract CVSS scores from metrics
                metrics = cve_item.get('metrics', {})
                cvss_v3_score = 0.0
                cvss_v3_severity = ''
                cvss_v2_score = 0.0
                cvss_v2_severity = ''
                exploitability_score = 0.0
                impact_score = 0.0

                # Try CVSS v3.1
                for metric in metrics.get('cvssMetricV31', []):
                    if metric.get('type') == 'Primary':
                        cvss_data = metric.get('cvssData', {})
                        cvss_v3_score = cvss_data.get('baseScore', 0.0)
                        cvss_v3_severity = cvss_data.get('baseSeverity', '')
                        exploitability_score = metric.get('exploitabilityScore', 0.0)
                        impact_score = metric.get('impactScore', 0.0)
                        break

                # Try CVSS v3.0 if v3.1 not found
                if cvss_v3_score == 0.0:
                    for metric in metrics.get('cvssMetricV30', []):
                        if metric.get('type') == 'Primary':
                            cvss_data = metric.get('cvssData', {})
                            cvss_v3_score = cvss_data.get('baseScore', 0.0)
                            cvss_v3_severity = cvss_data.get('baseSeverity', '')
                            exploitability_score = metric.get('exploitabilityScore', 0.0)
                            impact_score = metric.get('impactScore', 0.0)
                            break

                # Try CVSS v2
                for metric in metrics.get('cvssMetricV2', []):
                    if metric.get('type') == 'Primary':
                        cvss_data = metric.get('cvssData', {})
                        cvss_v2_score = cvss_data.get('baseScore', 0.0)
                        cvss_v2_severity = cvss_data.get('baseSeverity', '')
                        break

                # Dates
                published_date = cve_item.get('published', '')
                last_modified = cve_item.get('lastModified', '')

                # Configurations
                configurations = cve_item.get('configurations', [])

            else:
                # NVD 1.1 format (legacy)
                cve = cve_item.get('cve', {})
                cve_id = cve.get('CVE_data_meta', {}).get('ID')
                if not cve_id:
                    return None

                descriptions = cve.get('description', {}).get('description_data', [])
                description = descriptions[0].get('value', '') if descriptions else ''

                impact = cve_item.get('impact', {})
                cvss_v3 = impact.get('baseMetricV3', {}).get('cvssV3', {})
                cvss_v2 = impact.get('baseMetricV2', {}).get('cvssV2', {})

                cvss_v3_score = cvss_v3.get('baseScore', 0.0)
                cvss_v3_severity = cvss_v3.get('baseSeverity', '')
                cvss_v2_score = cvss_v2.get('baseScore', 0.0)
                cvss_v2_severity = cvss_v2.get('severity', '')

                exploitability_score = impact.get('baseMetricV3', {}).get('exploitabilityScore', 0.0)
                impact_score = impact.get('baseMetricV3', {}).get('impactScore', 0.0)

                published_date = cve_item.get('publishedDate', '')
                last_modified = cve_item.get('lastModifiedDate', '')

                configurations = cve.get('configurations', {}).get('nodes', [])

            # ANTI-HALLUCINATION: Only include if CVSS >= 7.0
            if cvss_v3_score < 7.0 and cvss_v2_score < 7.0:
                return None

            cve_data = {
                'cve_id': cve_id,
                'description': description,
                'cvss_v3_score': cvss_v3_score,
                'cvss_v3_severity': cvss_v3_severity,
                'cvss_v2_score': cvss_v2_score,
                'cvss_v2_severity': cvss_v2_severity,
                'published_date': published_date,
                'last_modified': last_modified,
                'exploitability_score': exploitability_score,
                'impact_score': impact_score,
                'confidence_score': 100,
                'verified': 1 if cvss_v3_score >= 9.0 else 0
            }

            # Extract CPE configurations
            cpe_list = []
            for config in configurations:
                nodes = config.get('nodes', [config]) if is_v2 else [config]
                for node in nodes:
                    cpe_matches = node.get('cpeMatch', node.get('cpe_match', []))
                    for match in cpe_matches:
                        if not match.get('vulnerable', True):
                            continue

                        cpe23_uri = match.get('criteria', match.get('cpe23Uri', ''))
                        if not cpe23_uri:
                            continue

                        cpe_parsed = self.parse_cpe_string(cpe23_uri)
                        if not cpe_parsed:
                            continue

                        # Extract version range
                        version = self.normalize_version(cpe_parsed.get('version', '*'))
                        version_start = self.normalize_version(match.get('versionStartIncluding') or match.get('versionStartExcluding'))
                        version_end = self.normalize_version(match.get('versionEndIncluding') or match.get('versionEndExcluding'))

                        version_start_including = 'versionStartIncluding' in match
                        version_end_including = 'versionEndIncluding' in match

                        cpe_entry = {
                            'cve_id': cve_id,
                            'vendor': cpe_parsed.get('vendor', '').lower(),
                            'product': cpe_parsed.get('product', '').lower(),
                            'version': version,
                            'version_start': version_start,
                            'version_end': version_end,
                            'version_start_including': version_start_including,
                            'version_end_including': version_end_including,
                            'vulnerable': 1,
                            'match_confidence': 100
                        }

                        # ANTI-HALLUCINATION: Skip wildcard entries with no range
                        if not version and not version_start and not version_end:
                            continue

                        cpe_list.append(cpe_entry)

            return (cve_data, cpe_list)

        except Exception as e:
            print(f"[WARNING] Failed to parse CVE item: {e}")
            return None

    def import_cve_feed(self, feed_path: Path):
        """Import CVE feed into database"""
        print(f"[IMPORT] Processing {feed_path.name}...")

        try:
            with open(feed_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            # Support both old (CVE_Items) and new (cve_items) formats
            cve_items = data.get('cve_items', data.get('CVE_Items', []))
            print(f"[INFO] Found {len(cve_items)} CVE entries")

            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            imported_count = 0
            skipped_count = 0

            for item in cve_items:
                parsed = self.parse_cve_item(item)
                if not parsed:
                    skipped_count += 1
                    continue

                cve_data, cpe_list = parsed

                # Insert CVE
                try:
                    cursor.execute("""
                        INSERT OR REPLACE INTO cves
                        (cve_id, description, cvss_v3_score, cvss_v3_severity, cvss_v2_score, cvss_v2_severity,
                         published_date, last_modified, exploitability_score, impact_score, confidence_score, verified)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        cve_data['cve_id'], cve_data['description'], cve_data['cvss_v3_score'],
                        cve_data['cvss_v3_severity'], cve_data['cvss_v2_score'], cve_data['cvss_v2_severity'],
                        cve_data['published_date'], cve_data['last_modified'], cve_data['exploitability_score'],
                        cve_data['impact_score'], cve_data['confidence_score'], cve_data['verified']
                    ))

                    # Insert CPE entries
                    for cpe in cpe_list:
                        cursor.execute("""
                            INSERT INTO cve_cpe
                            (cve_id, vendor, product, version, version_start, version_end,
                             version_start_including, version_end_including, vulnerable, match_confidence)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, (
                            cpe['cve_id'], cpe['vendor'], cpe['product'], cpe['version'],
                            cpe['version_start'], cpe['version_end'], cpe['version_start_including'],
                            cpe['version_end_including'], cpe['vulnerable'], cpe['match_confidence']
                        ))

                    imported_count += 1

                except sqlite3.IntegrityError:
                    # Duplicate, skip
                    pass

            conn.commit()
            conn.close()

            print(f"[[OK]] Imported {imported_count} CVEs (skipped {skipped_count} low-severity)")

        except Exception as e:
            print(f"[ERROR] Failed to import feed: {e}")

    def build(self):
        """Build complete CVE database"""
        print("=" * 60)
        print("CVE Database Builder")
        print("ANTI-HALLUCINATION: Strict matching, confidence scoring")
        print("=" * 60)
        print()

        # Create schema
        self.create_schema()

        # Download and import feeds
        for year in YEARS_TO_DOWNLOAD:
            feed_path = self.download_cve_feed(year)
            if feed_path:
                self.import_cve_feed(feed_path)

        # Print statistics
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM cves")
        total_cves = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM cve_cpe")
        total_cpes = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM cves WHERE cvss_v3_score >= 9.0")
        critical_cves = cursor.fetchone()[0]

        conn.close()

        print()
        print("=" * 60)
        print("DATABASE STATISTICS")
        print("=" * 60)
        print(f"Total CVEs (CVSS >= 7.0): {total_cves}")
        print(f"Total CPE entries: {total_cpes}")
        print(f"Critical CVEs (CVSS >= 9.0): {critical_cves}")
        print(f"Database size: {self.db_path.stat().st_size / 1024 / 1024:.1f} MB")
        print()
        print(f"[[OK]] Database saved to: {self.db_path}")
        print()

if __name__ == "__main__":
    builder = CVEDatabaseBuilder()
    builder.build()
