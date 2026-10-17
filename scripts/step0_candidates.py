"""Step 0: build the candidate list of compromised established packages for one ecosystem.

Inputs
  scratch/osv/<eco>-all.zip     OSV export (read in place, never extracted)
  data/screen/<eco>_class.tsv  advisory-text classification (scripts/screen/advisory_text.py)
Tiers
  A: the advisory text explicitly describes an unauthorised release (compromise, account
     takeover, stolen credentials, phishing, worm campaign). See scripts/screen/advisory_text.py for the rule.
  B: listed by name on the command line: confirmed malicious release of an established
     package, but the advisories do not state how it was published.
Malicious versions = union of versions listed by malware advisories for the package:
  MAL-* (ossf/malicious-packages), GHSA-* with CWE-506, and PYSEC ids given in PYSEC_MALWARE.
Advisory date = earliest `published` among those advisories.

Usage: python3 scripts/step0_candidates.py pypi data/candidates.csv litellm ctx
       (appends rows for that ecosystem to data/candidates.csv, replacing earlier rows for it)
"""

import csv
import json
import os
import sys
import zipfile
from collections import defaultdict

# PyPA advisories (no MAL/GHSA malware record lists versions for these packages)
PYSEC_MALWARE = {"PYSEC-2024-154", "PYSEC-2022-199"}  # ultralytics, ctx

eco, out, tier_b = sys.argv[1], sys.argv[2], set(sys.argv[3:])
cls = {}
for line in open(f"data/screen/{eco}_class.tsv", encoding="utf-8"):
    name, label, _ = line.rstrip("\n").split("\t", 2)
    cls[name] = label
wanted = {n for n, l in cls.items() if l == "COMPROMISED"} | tier_b

versions, ids, dates = defaultdict(set), defaultdict(set), defaultdict(list)
osv_eco = {"pypi": "PyPI", "npm": "npm"}[eco]
with zipfile.ZipFile(f"scratch/osv/{eco}-all.zip") as z:
    for info in z.infolist():
        rec = json.loads(z.read(info))
        rid = rec.get("id", "")
        cwes = (rec.get("database_specific") or {}).get("cwe_ids") or []
        if not (rid.startswith("MAL-") or (rid.startswith("GHSA-") and "CWE-506" in cwes) or rid in PYSEC_MALWARE):
            continue
        for aff in rec.get("affected", []):
            pkg = aff.get("package", {})
            if pkg.get("ecosystem") != osv_eco or pkg.get("name") not in wanted:
                continue
            n = pkg["name"]
            ids[n].add(rid)
            dates[n].append(rec.get("published", ""))
            versions[n] |= set(aff.get("versions") or [])

rows = []
for n in sorted(wanted):
    rows.append({"ecosystem": eco, "package": n, "tier": "B" if n in tier_b else "A",
                 "malicious_versions": ";".join(sorted(versions[n])),
                 "advisory_date": min(d for d in dates[n] if d) if dates[n] else "",
                 "advisory_ids": ";".join(sorted(ids[n]))})

existing = []
if os.path.exists(out):
    existing = [r for r in csv.DictReader(open(out, encoding="utf-8")) if r["ecosystem"] != eco]
fields = ["ecosystem", "package", "tier", "malicious_versions", "advisory_date", "advisory_ids"]
with open(out, "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=fields, lineterminator="\n")
    w.writeheader()
    w.writerows(existing + rows)
print(f"{eco}: {len(rows)} candidates (tier A {sum(r['tier'] == 'A' for r in rows)}, tier B {sum(r['tier'] == 'B' for r in rows)}); "
      f"without listed versions: {[r['package'] for r in rows if not r['malicious_versions']]}")
