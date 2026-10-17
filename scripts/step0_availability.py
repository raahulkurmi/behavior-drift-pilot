"""Step 0: per malicious version, does a package-analysis record exist for it and for the
three clean versions immediately before it?  Existence only; no record content is read.

Inputs:  data/candidates.csv, data/registry_versions.csv, data/record_index.csv
Output:  data/availability.csv (one row per malicious version), summary on stdout

"Previous versions" (defined before looking at availability):
  the clean versions immediately below the malicious version in version order, where
  clean = not listed as malicious for this package, not a pre-release, and published
  in the registry before the malicious version (or, if the malicious version's publish
  time is unknown, before the advisory date). prev1 is the nearest, then prev2, prev3.
Version order: npm semver (numeric major.minor.patch); PyPI PEP 440 (packaging.version).
"""

import csv
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta

from packaging.version import InvalidVersion, Version


def ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00")) if s and s != "REGISTRY_404" else None


def key_npm(v):
    m = re.match(r"^v?(\d+)\.(\d+)\.(\d+)(-[^+]*)?(\+.*)?$", v)
    return (int(m[1]), int(m[2]), int(m[3])) if m else None


def pre_npm(v):
    return "-" in v.split("+")[0]


def key_pypi(v):
    try:
        return Version(v)
    except InvalidVersion:
        return None


def pre_pypi(v):
    k = key_pypi(v)
    return k is None or k.is_prerelease or k.is_devrelease


def main():
    cands = list(csv.DictReader(open("data/candidates.csv", encoding="utf-8")))
    reg = defaultdict(dict)
    for r in csv.DictReader(open("data/registry_versions.csv", encoding="utf-8")):
        if r["version"]:
            reg[(r["ecosystem"], r["package"])][r["version"]] = r["published"]
    idx = defaultdict(dict)
    for r in csv.DictReader(open("data/record_index.csv", encoding="utf-8")):
        idx[(r["ecosystem"], r["package"])][r["version"]] = r["time_created"]

    rows = []
    for c in cands:
        eco, pkg = c["ecosystem"], c["package"]
        mal = [v for v in c["malicious_versions"].split(";") if v]
        key, pre = (key_npm, pre_npm) if eco == "npm" else (key_pypi, pre_pypi)
        versions = reg[(eco, pkg)]
        recs = idx[(eco, pkg)]
        adv_date = ts(c["advisory_date"])
        # Re-check "established" from registry metadata (not trusting the scratch screen):
        # >= 3 clean versions published before the earliest malicious publish time (or the
        # advisory date if no malicious version is in the registry metadata), earliest >= 180 days before.
        mal_times = [ts(versions[v]) for v in mal if ts(versions.get(v, ""))]
        first_mal = min(mal_times) if mal_times else adv_date
        clean_before = sorted(ts(t) for v, t in versions.items()
                              if v not in mal and not pre(v) and ts(t) and first_mal and ts(t) < first_mal)
        established = len(clean_before) >= 3 and first_mal - clean_before[0] >= timedelta(days=180)
        if not versions:
            established_label = "REGISTRY_404"
        else:
            established_label = "YES" if established else "NO"
        for m in mal:
            km = key(m)
            cutoff = ts(versions.get(m, "")) or adv_date
            prev = sorted(
                (v for v in versions if v not in mal and not pre(v) and key(v) is not None and km is not None
                 and key(v) < km and ts(versions[v]) is not None and cutoff is not None and ts(versions[v]) < cutoff),
                key=key, reverse=True)[:3]
            prev += [""] * (3 - len(prev))

            def ex(v):
                return "" if not v else ("YES" if v in recs else "NO")

            row = {
                "ecosystem": eco, "package": pkg, "tier": c["tier"], "established_recheck": established_label,
                "clean_before": len(clean_before), "advisory_ids": c["advisory_ids"], "malicious_version": m,
                "malicious_published": versions.get(m, "") or "NOT_IN_REGISTRY_METADATA",
                "record_malicious": ex(m), "record_malicious_time_created": recs.get(m, ""),
                "prev1": prev[0], "record_prev1": ex(prev[0]),
                "prev2": prev[1], "record_prev2": ex(prev[1]),
                "prev3": prev[2], "record_prev3": ex(prev[2]),
                "total_records_for_package": len(recs),
            }
            if not versions:  # registry metadata unavailable: previous versions cannot be determined
                for k in ("record_prev1", "record_prev2", "record_prev3"):
                    row[k] = "UNKNOWN"
            row["full_set"] = "YES" if all(row[k] == "YES" for k in ("record_malicious", "record_prev1", "record_prev2", "record_prev3")) else "NO"
            row["minimal_pair"] = "YES" if row["record_malicious"] == "YES" and row["record_prev1"] == "YES" else "NO"
            rows.append(row)

    with open("data/availability.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]), lineterminator="\n")
        w.writeheader()
        w.writerows(rows)

    for eco in sorted({r["ecosystem"] for r in rows}):
        for tier in ("A", "B"):
            rs = [r for r in rows if r["ecosystem"] == eco and r["tier"] == tier]
            if not rs:
                continue
            pk = sorted({r["package"] for r in rs})
            est = sorted({r["package"] for r in rs if r["established_recheck"] == "YES"})
            sel = [r for r in rs if r["established_recheck"] == "YES"]
            mal_rec = sorted({r["package"] for r in sel if r["record_malicious"] == "YES"})
            pair = sorted({r["package"] for r in sel if r["minimal_pair"] == "YES"})
            full = sorted({r["package"] for r in sel if r["full_set"] == "YES"})
            print(f"[{eco} tier {tier}] candidates: {len(pk)}; established (re-check): {len(est)}; "
                  f"malicious versions: {len(rs)}")
            def show(xs):
                return xs if len(xs) <= 40 else f"(list in data/availability.csv)"

            print(f"  not established on re-check: {len(set(pk) - set(est))} {show(sorted(set(pk) - set(est)))}")
            print(f"  established with a record for >=1 malicious version: {len(mal_rec)} {show(mal_rec)}")
            print(f"  ... and for its prev1 (minimal pair): {len(pair)} {show(pair)}")
            print(f"  ... and for prev1, prev2, prev3 (full set): {len(full)} {show(full)}")
            # Independence proxy: advisory publication day of each full-set package
            day = {c["package"]: c["advisory_date"][:10] for c in cands if c["ecosystem"] == eco}
            days = defaultdict(int)
            for p_ in full:
                days[day[p_]] += 1
            top = sorted(days.items(), key=lambda kv: -kv[1])[:5]
            print(f"  full-set packages by advisory day: {len(days)} distinct days; largest: {top}")


if __name__ == "__main__":
    sys.exit(main())
