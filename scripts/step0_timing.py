"""Step 0: when were the records created, relative to the release they describe?

Inputs:  data/availability.csv, data/clusters.csv, data/registry_versions.csv, data/record_index.csv
Output:  data/timing.csv (one row per malicious version with a minimal pair), summary on stdout

Only object timeCreated (bucket metadata) and registry publish times are used.
timeCreated is the creation time of the object's CURRENT generation, so a version that was
analysed again later shows the later time.
  lag_days = record timeCreated - registry publish time of that version
  NEAR     = lag <= NEAR_DAYS (analysed close to its own release)
  LATE     = lag >  NEAR_DAYS (analysed much later, i.e. re-analysis or backfill)
  with_mal = record created within NEAR_DAYS of the malicious version's record
"""

import csv
from collections import Counter, defaultdict
from datetime import timedelta

from step0_availability import ts

NEAR_DAYS = 7


def main():
    reg = defaultdict(dict)
    for r in csv.DictReader(open("data/registry_versions.csv", encoding="utf-8")):
        if r["version"]:
            reg[(r["ecosystem"], r["package"])][r["version"]] = r["published"]
    idx = defaultdict(dict)
    for r in csv.DictReader(open("data/record_index.csv", encoding="utf-8")):
        idx[(r["ecosystem"], r["package"])][r["version"]] = r["time_created"]
    camp = {(r["ecosystem"], r["package"]): r["campaign"] or r["date_group"] for r in csv.DictReader(open("data/clusters.csv", encoding="utf-8"))}

    rows = []
    for a in csv.DictReader(open("data/availability.csv", encoding="utf-8")):
        if a["established_recheck"] != "YES" or a["minimal_pair"] != "YES":
            continue
        k = (a["ecosystem"], a["package"])
        mal_tc = ts(idx[k][a["malicious_version"]])
        row = {"ecosystem": a["ecosystem"], "package": a["package"], "tier": a["tier"], "campaign": camp.get(k, ""),
               "malicious_version": a["malicious_version"], "malicious_published": a["malicious_published"],
               "malicious_time_created": idx[k][a["malicious_version"]]}
        for slot in ("prev1", "prev2", "prev3"):
            v = a[slot]
            tc = idx[k].get(v, "") if v else ""
            pub = reg[k].get(v, "") if v else ""
            if tc and ts(pub):
                lag = (ts(tc) - ts(pub)).total_seconds() / 86400
                timing = "NEAR" if lag <= NEAR_DAYS else "LATE"
                with_mal = "YES" if abs(ts(tc) - mal_tc) <= timedelta(days=NEAR_DAYS) else "NO"
            else:
                lag, timing, with_mal = "", ("UNAVAILABLE" if v else ""), ""
            row.update({f"{slot}": v, f"{slot}_published": pub, f"{slot}_time_created": tc,
                        f"{slot}_lag_days": f"{lag:.1f}" if lag != "" else "", f"{slot}_timing": timing,
                        f"{slot}_created_near_malicious_record": with_mal})
        if ts(a["malicious_published"] if a["malicious_published"] != "NOT_IN_REGISTRY_METADATA" else ""):
            row["malicious_lag_days"] = f"{(mal_tc - ts(a['malicious_published'])).total_seconds() / 86400:.1f}"
        else:
            row["malicious_lag_days"] = ""
        rows.append(row)

    if not rows:
        print("no minimal pairs")
        return
    with open("data/timing.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]), lineterminator="\n")
        w.writeheader()
        w.writerows(rows)
    for eco in ("pypi", "npm"):
        rs = [r for r in rows if r["ecosystem"] == eco]
        if not rs:
            continue
        c = Counter(r[f"{s}_timing"] for r in rs for s in ("prev1", "prev2", "prev3") if r[f"{s}_timing"])
        nm = Counter(r[f"{s}_created_near_malicious_record"] for r in rs for s in ("prev1", "prev2", "prev3")
                     if r[f"{s}_created_near_malicious_record"])
        print(f"{eco}: {len(rs)} malicious versions with a minimal pair ({len({r['package'] for r in rs})} packages); "
              f"previous-version records {dict(c)}; created within {NEAR_DAYS} d of the malicious record: {dict(nm)}")


if __name__ == "__main__":
    main()
