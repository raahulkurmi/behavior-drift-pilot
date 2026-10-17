"""Step 0: list every established package that did not end up as a usable candidate, with the reason.

Inputs:  data/screen/<eco>_class.tsv, data/candidates.csv, data/availability.csv
Output:  data/excluded.csv

Stages (in order; a package is listed at the first stage it fails):
  classification  established, but no malware advisory explicitly describes an unauthorised
                  release (UNCLEAR). Tier B packages are kept as candidates and not listed here.
  established     candidate fails the established re-check on registry metadata
  record          UNAVAILABLE: no record for any malicious version, or none for that version's prev1
"""

import csv
from collections import defaultdict


def main():
    cands = {(r["ecosystem"], r["package"]): r for r in csv.DictReader(open("data/candidates.csv", encoding="utf-8"))}
    av = defaultdict(list)
    for r in csv.DictReader(open("data/availability.csv", encoding="utf-8")):
        av[(r["ecosystem"], r["package"])].append(r)
    rows = []
    for eco in ("npm", "pypi"):
        for line in open(f"data/screen/{eco}_class.tsv", encoding="utf-8"):
            name, label, _ = line.rstrip("\n").split("\t", 2)
            if label == "UNCLEAR" and (eco, name) not in cands:
                rows.append({"ecosystem": eco, "package": name, "tier": "", "stage": "classification",
                             "reason": "UNCLEAR: no malware advisory explicitly describes an unauthorised release"})
    for k, c in cands.items():
        rs = av[k]
        if not rs or all(r["established_recheck"] != "YES" for r in rs):
            why = rs[0]["established_recheck"] if rs else "no availability row"
            rows.append({"ecosystem": k[0], "package": k[1], "tier": c["tier"], "stage": "established",
                         "reason": f"not established on re-check ({why}); previous versions cannot be determined"})
        elif not any(r["record_malicious"] == "YES" for r in rs):
            rows.append({"ecosystem": k[0], "package": k[1], "tier": c["tier"], "stage": "record",
                         "reason": f"UNAVAILABLE: no record for any malicious version "
                                   f"({len(rs)} malicious versions; {rs[0]['total_records_for_package']} records for other versions)"})
        elif not any(r["minimal_pair"] == "YES" for r in rs):
            rows.append({"ecosystem": k[0], "package": k[1], "tier": c["tier"], "stage": "record",
                         "reason": "UNAVAILABLE: malicious version recorded, but no record for its prev1"})
    with open("data/excluded.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["ecosystem", "package", "tier", "stage", "reason"], lineterminator="\n")
        w.writeheader()
        w.writerows(rows)
    for eco in ("npm", "pypi"):
        for st in ("classification", "established", "record"):
            n = [r for r in rows if r["ecosystem"] == eco and r["stage"] == st]
            print(eco, st, len(n), [r["package"] for r in n] if len(n) <= 25 else "")


if __name__ == "__main__":
    main()
