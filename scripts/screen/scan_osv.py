"""Scan an OSV ecosystem export (zip, read in place, never extracted) for malware reports
that name specific versions of a package rather than every version.

Output (TSV on stdout): id, source, published, ecosystem, package, n_versions, versions, all_versions_range
  source = MAL (ossf/malicious-packages) or GHSA-CWE-506 (GitHub malware advisory)
"""

import json
import sys
import zipfile

path = sys.argv[1]
with zipfile.ZipFile(path) as z:
    for info in z.infolist():
        if not info.filename.endswith(".json"):
            continue
        rec = json.loads(z.read(info))
        rid = rec.get("id", "")
        cwes = (rec.get("database_specific") or {}).get("cwe_ids") or []
        if rid.startswith("MAL-"):
            source = "MAL"
        elif rid.startswith("GHSA-") and "CWE-506" in cwes:
            source = "GHSA-CWE-506"
        else:
            continue
        for aff in rec.get("affected", []):
            pkg = aff.get("package", {})
            versions = aff.get("versions") or []
            all_range = any(
                ev.get("introduced") == "0" and not any("fixed" in e or "last_affected" in e for e in r.get("events", []))
                for r in aff.get("ranges", []) for ev in r.get("events", [])
            )
            print("\t".join([rid, source, rec.get("published", ""), pkg.get("ecosystem", ""), pkg.get("name", ""),
                             str(len(versions)), ",".join(versions[:50]), str(all_range)]))
