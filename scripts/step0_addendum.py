"""Step 0 addendum: comparison release, analysis-time gaps, prev1 proximity (metadata only).

Inputs:  data/candidates.csv, data/clusters.csv, data/availability.csv, data/timing.csv,
         data/registry_versions.csv, data/record_index.csv, data/baseline_packages.csv
Outputs: data/comparison.csv        one row per candidate (rule b)
         data/benign_within.csv     within-package benign pairs of the candidates (rule d)
         data/benign_baseline_pairs.csv  top-download consecutive pairs with both records (rule d)
         summary on stdout
Only registry publish times and record object timeCreated are used; no record content is read.

Rules
  clean release      not listed as malicious for the package, not a pre-release, valid version,
                     publish time known (same definitions as step0_availability.py)
  incident date      earliest `published` of any malware advisory of any package in the incident
                     (incident = campaign wave, else unnamed date group; data/clusters.csv)
  earliest malicious the package's malicious version with the earliest known time, where the time
                     is the registry publish time, else (deleted release) the record timeCreated;
                     if no malicious version has either, the lowest version
  comparison (C0)    the latest (by publish time) clean release published at least MIN_DAYS days
                     before the incident date
  C1, C2             C1 = latest clean release published at least MIN_DAYS days before C0;
                     C2 likewise before C1. Within-package benign pairs: C1->C0 and C2->C1
  analysis-time gap  days between the two records' timeCreated (newer release minus older release;
                     for the malicious comparison: malicious record minus C0 record)
  gap stratum        <90 d, 90-365 d, >365 d (on the absolute gap; negative gaps are counted)
  baseline pairs     consecutive clean releases since 2022-01-01 (version order) of the
                     top-download baseline packages, both with a record
"""

import csv
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from step0_availability import key_npm, key_pypi, pre_npm, pre_pypi, ts

MIN_DAYS = 14
WINDOW_START = datetime(2022, 1, 1, tzinfo=timezone.utc)


def stratum(g):
    if g == "":
        return ""
    a = abs(g)
    return "<90" if a < 90 else ("90-365" if a <= 365 else ">365")


def days(a, b):
    return (a - b).total_seconds() / 86400


def fmt(x):
    return f"{x:.1f}" if x != "" else ""


def main():
    reg = defaultdict(dict)
    for r in csv.DictReader(open("data/registry_versions.csv", encoding="utf-8")):
        if r["version"]:
            reg[(r["ecosystem"], r["package"])][r["version"]] = r["published"]
    idx = defaultdict(dict)
    for r in csv.DictReader(open("data/record_index.csv", encoding="utf-8")):
        idx[(r["ecosystem"], r["package"])][r["version"]] = r["time_created"]
    clus = {(r["ecosystem"], r["package"]): r for r in csv.DictReader(open("data/clusters.csv", encoding="utf-8"))}
    est = {}
    for r in csv.DictReader(open("data/availability.csv", encoding="utf-8")):
        est[(r["ecosystem"], r["package"])] = r["established_recheck"]
    inc_of = {k: c["campaign"] or c["date_group"] for k, c in clus.items()}
    inc_date = {}
    for k, c in clus.items():
        t = ts(c["first_advisory"])
        i = inc_of[k]
        inc_date[i] = min(inc_date.get(i, t), t)

    # (a) prev1 published within 7 days before the malicious version (minimal-pair rows, as for npm)
    prox = defaultdict(Counter)
    for r in csv.DictReader(open("data/timing.csv", encoding="utf-8")):
        e = r["ecosystem"]
        p1 = ts(r["prev1_published"])
        mp = ts(r["malicious_published"]) if r["malicious_published"] != "NOT_IN_REGISTRY_METADATA" else None
        prox[e]["rows"] += 1
        if mp:
            prox[e]["publish_known"] += 1
            prox[e]["within7_publish"] += days(mp, p1) <= 7
        else:  # proxy: malicious record timeCreated (records are created within hours of upload)
            prox[e]["within7_record_proxy"] += days(ts(r["malicious_time_created"]), p1) <= 7
            prox[e]["proxy_used"] += 1

    comp_rows, within_rows = [], []
    for c in csv.DictReader(open("data/candidates.csv", encoding="utf-8")):
        eco, pkg = c["ecosystem"], c["package"]
        k = (eco, pkg)
        key, pre = (key_npm, pre_npm) if eco == "npm" else (key_pypi, pre_pypi)
        mal = [v for v in c["malicious_versions"].split(";") if v]
        vers, recs = reg[k], idx[k]
        clean = sorted(((ts(t), v) for v, t in vers.items()
                        if v not in mal and not pre(v) and key(v) is not None and ts(t)),
                       key=lambda x: (x[0], key(x[1])))

        def latest_before(cut):
            xs = [x for x in clean if x[0] <= cut]
            return xs[-1] if xs else None

        times = []
        for v in mal:
            t = ts(vers.get(v, "")) or ts(recs.get(v, ""))
            basis = "publish" if ts(vers.get(v, "")) else ("record" if v in recs else "")
            if t:
                times.append((t, v, basis))
        if times:
            t_mal, m, basis = min(times)
        else:
            ks = sorted((v for v in mal if key(v) is not None), key=key)
            t_mal, m, basis = None, (ks[0] if ks else mal[0]), "version_order"
        inc = inc_of[k]
        cut = inc_date[inc] - timedelta(days=MIN_DAYS)
        c0 = latest_before(cut) if vers else None
        c1 = latest_before(c0[0] - timedelta(days=MIN_DAYS)) if c0 else None
        c2 = latest_before(c1[0] - timedelta(days=MIN_DAYS)) if c1 else None
        mal_tc = recs.get(m, "")
        c0_tc = recs.get(c0[1], "") if c0 else ""
        gap = days(ts(mal_tc), ts(c0_tc)) if mal_tc and c0_tc else ""
        flags = []
        if not vers:
            flags.append("REGISTRY_404")
        if c0 and t_mal and c0[0] >= t_mal:
            flags.append("C0_PUBLISHED_AFTER_EARLIEST_MALICIOUS")
        if c0 and key(c0[1]) is not None and key(m) is not None and key(c0[1]) > key(m):
            flags.append("C0_VERSION_ABOVE_MALICIOUS")
        any_mal_rec = any(v in recs for v in mal)
        eligible = (c["tier"] == "A" and est.get(k) == "YES" and bool(mal_tc) and bool(c0_tc)
                    and "C0_PUBLISHED_AFTER_EARLIEST_MALICIOUS" not in flags)
        comp_rows.append({
            "ecosystem": eco, "package": pkg, "tier": c["tier"], "incident": inc,
            "family": clus[k]["family"], "actor": clus[k]["actor"], "established": est.get(k, ""),
            "incident_date": inc_date[inc].isoformat(), "cutoff": cut.isoformat(),
            "earliest_malicious": m, "earliest_malicious_basis": basis,
            "earliest_malicious_time": t_mal.isoformat() if t_mal else "",
            "record_earliest_malicious": "YES" if mal_tc else "NO",
            "record_other_malicious_only": "YES" if (not mal_tc and any_mal_rec) else "",
            "comparison": c0[1] if c0 else "UNAVAILABLE", "comparison_published": c0[0].isoformat() if c0 else "",
            "record_comparison": ("YES" if c0_tc else "NO") if c0 else "",
            "analysis_gap_days": fmt(gap), "gap_stratum": stratum(gap),
            "flags": ";".join(flags), "eligible_primary": "YES" if eligible else "NO",
        })
        for older, newer, label in ((c1, c0, "C1->C0"), (c2, c1, "C2->C1")):
            if not (older and newer):
                continue
            to, tn = recs.get(older[1], ""), recs.get(newer[1], "")
            g = days(ts(tn), ts(to)) if to and tn else ""
            within_rows.append({
                "ecosystem": eco, "package": pkg, "tier": c["tier"], "incident": inc, "pair": label,
                "older": older[1], "older_published": older[0].isoformat(), "newer": newer[1],
                "newer_published": newer[0].isoformat(), "both_recorded": "YES" if to and tn else "NO",
                "analysis_gap_days": fmt(g), "gap_stratum": stratum(g),
                "candidate_eligible_primary": "YES" if eligible else "NO"})

    base_rows = []
    for b in csv.DictReader(open("data/baseline_packages.csv", encoding="utf-8")):
        eco, pkg = b["ecosystem"], b["package"]
        k = (eco, pkg)
        key, pre = (key_npm, pre_npm) if eco == "npm" else (key_pypi, pre_pypi)
        vs = sorted((v for v, t in reg[k].items()
                     if not pre(v) and key(v) is not None and ts(t) and ts(t) >= WINDOW_START), key=key)
        for a, n in zip(vs, vs[1:]):
            ta, tn = idx[k].get(a, ""), idx[k].get(n, "")
            if not (ta and tn):
                continue
            g = days(ts(tn), ts(ta))
            base_rows.append({"ecosystem": eco, "package": pkg, "older": a, "newer": n,
                              "release_spacing_days": fmt(days(ts(reg[k][n]), ts(reg[k][a]))),
                              "analysis_gap_days": fmt(g), "gap_stratum": stratum(g)})

    for path, rows in (("data/comparison.csv", comp_rows), ("data/benign_within.csv", within_rows),
                       ("data/benign_baseline_pairs.csv", base_rows)):
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0]), lineterminator="\n")
            w.writeheader()
            w.writerows(rows)

    print("(a) prev1 within 7 d:", {e: dict(c) for e, c in prox.items()})
    for eco in ("npm", "pypi"):
        rs = [r for r in comp_rows if r["ecosystem"] == eco]
        print(f"(b) {eco}: candidates {len(rs)}; comparison found {sum(r['comparison'] != 'UNAVAILABLE' for r in rs)}; "
              f"comparison recorded {sum(r['record_comparison'] == 'YES' for r in rs)}; "
              f"earliest malicious recorded {sum(r['record_earliest_malicious'] == 'YES' for r in rs)} "
              f"(+{sum(r['record_other_malicious_only'] == 'YES' for r in rs)} with only a later malicious version recorded); "
              f"flags {dict(Counter(f for r in rs for f in r['flags'].split(';') if f))}; "
              f"eligible (tier A) {sum(r['eligible_primary'] == 'YES' for r in rs)}; "
              f"gap strata of eligible {dict(Counter(r['gap_stratum'] for r in rs if r['eligible_primary'] == 'YES'))}")
    el = [r for r in comp_rows if r["eligible_primary"] == "YES"]
    per = Counter(r["incident"] for r in el)
    print(f"(b) eligible by incident ({len(per)} incidents; sample size at <=10 each = "
          f"{sum(min(10, n) for n in per.values())}):", dict(per.most_common()))
    tb = [r for r in comp_rows if r["tier"] == "B"]
    print("(b) tier B:", [(r["package"], r["comparison"], r["record_comparison"], r["record_earliest_malicious"],
                           r["analysis_gap_days"], r["flags"]) for r in tb])
    for scope, rs in (("all candidates", within_rows),
                      ("eligible candidates", [r for r in within_rows if r["candidate_eligible_primary"] == "YES"])):
        rec = [r for r in rs if r["both_recorded"] == "YES"]
        print(f"(d) within-package pairs, {scope}: {len(rs)} pairs, both recorded {len(rec)} "
              f"({len({(r['ecosystem'], r['package']) for r in rec})} packages, "
              f"{len({r['incident'] for r in rec})} incidents); strata {dict(Counter(r['gap_stratum'] for r in rec))}; "
              f"negative gaps {sum(float(r['analysis_gap_days']) < 0 for r in rec)}")
    for eco in ("npm", "pypi"):
        rs = [r for r in base_rows if r["ecosystem"] == eco]
        sp = [r for r in rs if float(r["release_spacing_days"]) >= MIN_DAYS]
        print(f"(d) baseline {eco}: {len(rs)} recorded consecutive pairs ({len({r['package'] for r in rs})} packages); "
              f"strata {dict(Counter(r['gap_stratum'] for r in rs))}; of those with release spacing >= {MIN_DAYS} d: "
              f"{len(sp)} ({len({r['package'] for r in sp})} packages), strata {dict(Counter(r['gap_stratum'] for r in sp))}")


if __name__ == "__main__":
    main()
