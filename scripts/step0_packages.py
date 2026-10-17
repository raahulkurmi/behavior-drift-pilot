"""Step 0: the package list for the metadata fetches = candidates + baseline packages.

Usage: python3 scripts/step0_packages.py   (writes data/packages.csv)
"""

import csv

rows = []
for src in ("data/candidates.csv", "data/baseline_packages.csv"):
    for r in csv.DictReader(open(src, encoding="utf-8")):
        k = (r["ecosystem"], r["package"])
        if k not in rows:
            rows.append(k)
with open("data/packages.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f, lineterminator="\n")
    w.writerow(["ecosystem", "package"])
    w.writerows(rows)
print(f"{len(rows)} packages -> data/packages.csv")
