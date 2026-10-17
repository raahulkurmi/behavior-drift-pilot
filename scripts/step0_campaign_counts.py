"""Step 0: per-campaign counts of usable candidates (for choosing a per-campaign cap or a
seeded sample in the pre-registration; no sample is drawn here).

Inputs:  data/availability.csv, data/clusters.csv
Output:  data/campaign_counts.csv, summary on stdout

Package-level flags (established packages only, from the re-check in step0_availability.py):
  mal_record   >= 1 malicious version has a record
  minimal_pair >= 1 malicious version has a record and so does its prev1
  full_set     >= 1 malicious version has records for itself and prev1..prev3
Incident = named campaign wave, else the unnamed date group (see step0_clusters.py).
Three independence levels are counted: incident (wave / date group); family (all waves of one
named worm family together); linked group (connected components of incidents that share a
worm family OR a named actor; e.g. a TeamPCP-attributed Shai-Hulud wave links the Shai-Hulud
family with other TeamPCP incidents). The linked-group count is the most conservative.
"""

import csv
from collections import defaultdict


def main():
    clus = {(r["ecosystem"], r["package"]): r for r in csv.DictReader(open("data/clusters.csv", encoding="utf-8"))}
    pk = defaultdict(lambda: {"est": False, "mal": False, "pair": False, "full": False})
    for a in csv.DictReader(open("data/availability.csv", encoding="utf-8")):
        k = (a["ecosystem"], a["package"])
        p = pk[k]
        if a["established_recheck"] == "YES":
            p["est"] = True
            p["mal"] |= a["record_malicious"] == "YES"
            p["pair"] |= a["minimal_pair"] == "YES"
            p["full"] |= a["full_set"] == "YES"
    agg = defaultdict(lambda: defaultdict(int))
    for k, c in clus.items():
        inc = c["campaign"] or c["date_group"]
        g = agg[(inc, c["family"] or "(unnamed)", c["actor"] or "", c["tier"], k[0])]
        g["candidates"] += 1
        p = pk[k]
        g["established"] += p["est"]
        g["mal_record"] += p["mal"]
        g["minimal_pair"] += p["pair"]
        g["full_set"] += p["full"]
    rows = [{"incident": i, "family": f, "actor": a, "tier": t, "ecosystem": e, **{x: g[x] for x in
             ("candidates", "established", "mal_record", "minimal_pair", "full_set")}}
            for (i, f, a, t, e), g in agg.items()]
    rows.sort(key=lambda r: (r["ecosystem"], -r["minimal_pair"], -r["candidates"], r["incident"]))
    with open("data/campaign_counts.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]), lineterminator="\n")
        w.writeheader()
        w.writerows(rows)
    print("\t".join(rows[0]))
    for r in rows:
        print("\t".join(str(r[x]) for x in r))
    # linked groups: union-find over incidents sharing a family or an actor (computed over all rows)
    parent = {r["incident"]: r["incident"] for r in rows}  # incidents span both ecosystems

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    by_key = defaultdict(list)
    for r in rows:
        if r["family"] != "(unnamed)":
            by_key["family:" + r["family"]].append(r["incident"])
        for a in filter(None, r["actor"].split(";")):
            by_key["actor:" + a].append(r["incident"])
    for members in by_key.values():
        for m in members[1:]:
            parent[find(m)] = find(members[0])
    group = {i: find(i) for i in parent}
    comps = defaultdict(set)
    for i, g in group.items():
        comps[g].add(i)
    for g, ms in comps.items():
        if len(ms) > 1:
            print("linked group:", sorted(ms))
    for tier in ("A", "B"):
        rs = [r for r in rows if r["tier"] == tier]
        for flag in ("mal_record", "minimal_pair", "full_set"):
            inc = [r for r in rs if r[flag]]
            for eco in ("npm", "pypi"):
                ie = [r for r in inc if r["ecosystem"] == eco]
                print(f"  tier {tier} {flag} {eco}: {sum(r[flag] for r in ie)} packages, "
                      f"{len({r['incident'] for r in ie})} incidents, {len({group[r['incident']] for r in ie})} linked groups")
            fam = {r["family"] if r["family"] != "(unnamed)" else r["incident"] for r in inc}
            print(f"tier {tier} {flag}: {sum(r[flag] for r in rs)} packages; {len({r['incident'] for r in inc})} incidents, "
                  f"{len(fam)} after merging worm families, {len({group[r['incident']] for r in inc})} linked groups")


if __name__ == "__main__":
    main()
