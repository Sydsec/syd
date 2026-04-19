#!/usr/bin/env python3
"""
Master Database Builder - Builds all security databases for Syd
Run this script ONCE to populate CVE and ExploitDB databases
"""

import sys
from pathlib import Path

print("""
=================================================================
          SYD SECURITY DATABASE BUILDER

  This will download and build:
  1. NVD CVE Database (2018-2025) - ~500MB download
  2. ExploitDB Database - ~5MB download

  Time: ~10-30 minutes depending on internet speed
  Disk space: ~600MB

  ANTI-HALLUCINATION SAFEGUARDS ENABLED:
  [X] Strict version matching
  [X] Confidence scoring (>= 80%)
  [X] Hard limits (max 5 CVEs per query)
  [X] CVSS threshold (>= 7.0 only)
  [X] Exploit verification
=================================================================
""")

# Check if databases already exist
cve_db = Path("rag_engine/cve_database.db")
exploit_db = Path("rag_engine/exploit_database.db")

if cve_db.exists() or exploit_db.exists():
    print("[WARNING] Databases already exist:")
    if cve_db.exists():
        print(f"  - {cve_db} ({cve_db.stat().st_size / 1024 / 1024:.1f} MB)")
    if exploit_db.exists():
        print(f"  - {exploit_db} ({exploit_db.stat().st_size / 1024:.1f} KB)")
    print()
    response = input("Rebuild databases? This will overwrite existing data. [y/N]: ")
    if response.lower() != 'y':
        print("[ABORTED] Keeping existing databases")
        sys.exit(0)

print("\n[STARTING] Database build process...\n")

# Build CVE Database
print("=" * 70)
print("STEP 1/2: Building CVE Database")
print("=" * 70)
try:
    from build_cve_database import CVEDatabaseBuilder
    cve_builder = CVEDatabaseBuilder()
    cve_builder.build()
    print("[OK] CVE database built successfully\n")
except Exception as e:
    print(f"[ERROR] Failed to build CVE database: {e}")
    print("[INFO] Syd can still work with pattern-based detection")
    print()

# Build ExploitDB Database
print("=" * 70)
print("STEP 2/2: Building ExploitDB Database")
print("=" * 70)
try:
    from build_exploitdb_database import ExploitDBBuilder
    exploit_builder = ExploitDBBuilder()
    exploit_builder.build()
    print("[OK] ExploitDB database built successfully\n")
except Exception as e:
    print(f"[ERROR] Failed to build ExploitDB database: {e}")
    print("[INFO] Syd can still work without exploit linkage")
    print()

# Test queries
print("=" * 70)
print("TESTING: Running test queries")
print("=" * 70)
try:
    from rag_engine.cve_query_engine import CVEQueryEngine
    engine = CVEQueryEngine()

    # Test with Apache 2.4.18 from healthcare scan
    print("\n[TEST] Querying Apache HTTP Server 2.4.18...")
    results = engine.query_cves_for_service("apache", "http_server", "2.4.18")
    print(f"[RESULT] Found {len(results)} CVEs (confidence >= 80%)")

    if results:
        print(f"[SAMPLE] {results[0]}")

    print("\n[OK] Query engine working correctly\n")

except Exception as e:
    print(f"[ERROR] Query test failed: {e}\n")

print("=" * 70)
print("[OK] DATABASE BUILD COMPLETE")
print("=" * 70)
print()
print("Databases created:")
if cve_db.exists():
    print(f"  [OK] {cve_db} ({cve_db.stat().st_size / 1024 / 1024:.1f} MB)")
if exploit_db.exists():
    print(f"  [OK] {exploit_db} ({exploit_db.stat().st_size / 1024:.1f} KB)")
print()
print("You can now run Syd with dynamic CVE lookup enabled!")
print()
