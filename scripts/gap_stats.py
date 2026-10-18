"""Analysis-time gap of the compromised pairs (malicious record minus comparison record), from
metadata only: data/comparison.csv (eligible set) and data/sample.csv (pre-registered sample).

Output: results/gap_stats.csv, and the same table on stdout.
Usage: python3 scripts/gap_stats.py
"""

import csv
import statistics
from collections import Counter

STRATA = ("<90", "90-365", ">365")


def describe(label, rows):
    gaps = [float(r["analysis_gap_days"]) for r in rows]
    c = Counter(r["gap_stratum"] for r in rows)
    return {"set": label, "pairs": len(rows), "median_gap_days": f"{statistics.median(gaps):.1f}",
            **{f"stratum_{s}": c[s] for s in STRATA}}


def main():
    eligible = [r for r in csv.DictReader(open("data/comparison.csv", encoding="utf-8")) if r["eligible_primary"] == "YES"]
    sample = list(csv.DictReader(open("data/sample.csv", encoding="utf-8")))
    rows = [describe("eligible (data/comparison.csv, eligible_primary = YES)", eligible),
            describe("sample (data/sample.csv)", sample)]
    with open("results/gap_stats.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]), lineterminator="\n")
        w.writeheader()
        w.writerows(rows)
    for r in rows:
        print(r)


if __name__ == "__main__":
    main()
