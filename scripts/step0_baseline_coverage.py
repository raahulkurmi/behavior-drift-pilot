"""Step 0: is a benign baseline feasible?  Record EXISTENCE (and timeCreated) for consecutive releases of
popular packages with no malware report (chosen by rule: scripts/step0_baseline_select.py).

Inputs:  data/baseline_packages.csv, data/registry_versions.csv, data/record_index.csv
Output:  data/baseline_coverage.csv, data/baseline_records.csv (per release), summary on stdout

For each package: clean (non-pre-release) releases published on/after WINDOW_START, in
version order; how many have a record; how many consecutive pairs have records for both.
"""

import csv
from collections import defaultdict
from datetime import datetime, timezone

from step0_availability import key_npm, key_pypi, pre_npm, pre_pypi, ts

WINDOW_START = datetime(2022, 1, 1, tzinfo=timezone.utc)
NEAR_DAYS = 7


def main():
    pkgs = list(csv.DictReader(open("data/baseline_packages.csv", encoding="utf-8")))
    reg = defaultdict(dict)
    for r in csv.DictReader(open("data/registry_versions.csv", encoding="utf-8")):
        if r["version"]:
            reg[(r["ecosystem"], r["package"])][r["version"]] = r["published"]
    idx = defaultdict(dict)
    for r in csv.DictReader(open("data/record_index.csv", encoding="utf-8")):
        idx[(r["ecosystem"], r["package"])][r["version"]] = r["time_created"]

    rows, recs = [], []
    for p in pkgs:
        eco, pkg = p["ecosystem"], p["package"]
        key, pre = (key_npm, pre_npm) if eco == "npm" else (key_pypi, pre_pypi)
        vs = sorted((v for v, t in reg[(eco, pkg)].items()
                     if not pre(v) and key(v) is not None and ts(t) and ts(t) >= WINDOW_START), key=key)
        have = [v in idx[(eco, pkg)] for v in vs]
        pairs = sum(1 for a, b in zip(have, have[1:]) if a and b)
        near = 0
        for v in vs:
            tc = idx[(eco, pkg)].get(v, "")
            lag = (ts(tc) - ts(reg[(eco, pkg)][v])).total_seconds() / 86400 if tc else None
            near += lag is not None and lag <= NEAR_DAYS
            recs.append({"ecosystem": eco, "package": pkg, "version": v, "published": reg[(eco, pkg)][v],
                         "time_created": tc or "UNAVAILABLE", "lag_days": f"{lag:.1f}" if lag is not None else ""})
        rows.append({"ecosystem": eco, "package": pkg, "releases_since_2022": len(vs), "with_record": sum(have),
                     "record_within_7d_of_release": near,
                     "consecutive_pairs": max(len(vs) - 1, 0), "consecutive_pairs_both_recorded": pairs,
                     "total_records_any_version": len(idx[(eco, pkg)])})
    with open("data/baseline_coverage.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]), lineterminator="\n")
        w.writeheader()
        w.writerows(rows)
    with open("data/baseline_records.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(recs[0]), lineterminator="\n")
        w.writeheader()
        w.writerows(recs)
    for eco in ("npm", "pypi"):
        rs = [r for r in rows if r["ecosystem"] == eco]
        rel, rec = sum(r["releases_since_2022"] for r in rs), sum(r["with_record"] for r in rs)
        cp, cpb = sum(r["consecutive_pairs"] for r in rs), sum(r["consecutive_pairs_both_recorded"] for r in rs)
        nr = sum(r["record_within_7d_of_release"] for r in rs)
        print(f"{eco}: {len(rs)} packages; releases since 2022 with a record: {rec}/{rel} "
              f"({nr} created within {NEAR_DAYS} d of release); consecutive pairs with both recorded: {cpb}/{cp}; "
              f"packages with >= 1 such pair: {sum(r['consecutive_pairs_both_recorded'] > 0 for r in rs)}")


if __name__ == "__main__":
    main()
