"""Compute the pre-registered results (docs/PREREGISTRATION.md sections 6 and 7, as amended).

1. Re-fetch every pinned record by name from the public bucket, verify md5Hash against
   data/record_pins.csv, and stop on any mismatch (section 8). Record contents stay in memory.
2. Reduce each record's install phase to item sets (scripts/normalise.py).
3. Compute M1, M1p, M2, M3 (pooled, per ecosystem, per gap stratum, per category), the family
   and linked-group sensitivity, the post-2024 sensitivity and the masked credential entries,
   then evaluate H1-H5.
Outputs are aggregate only: results/*.csv and results/RESULTS.md. No per-package or per-incident
behaviour, and no item, domain, path or command, is written anywhere.
Usage: python3 scripts/results.py
"""

import csv
import json
import math
import os
import random
import re
import sys
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import normalise as nz  # noqa: E402
from fetch_records import content, md5b64  # noqa: E402

SEED = 20261017
B = 10_000
STRATA = ("<90", "90-365", ">365")
POST = datetime(2024, 1, 1, tzinfo=timezone.utc)
MIN_INC, MIN_PAIRS = 5, 10
OUT = "results"


def ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def stratum(days):
    a = abs(days)
    return "<90" if a < 90 else ("90-365" if a <= 365 else ">365")


def norm_name(s):
    return re.sub(r"[-_.]+", "-", s).lower()


# ------------------------------------------------------------------ statistics

def wilson(k, n, z=1.959964):
    if n == 0:
        return (math.nan, math.nan)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def pct(xs, q):
    xs = sorted(xs)
    i = (len(xs) - 1) * q
    lo, hi = math.floor(i), math.ceil(i)
    return xs[lo] + (xs[hi] - xs[lo]) * (i - lo)


def cluster_share(clusters):
    """clusters: list of lists of 0/1. Pooled share."""
    k = sum(sum(c) for c in clusters)
    n = sum(len(c) for c in clusters)
    return k / n if n else math.nan


def cluster_boot(clusters, stat=cluster_share):
    """Percentile 95% interval, B resamples of clusters, random.Random(SEED)."""
    if not clusters:
        return (math.nan, math.nan), []
    rng = random.Random(SEED)
    m = len(clusters)
    vals = []
    for _ in range(B):
        s = [clusters[rng.randrange(m)] for _ in range(m)]
        v = stat(s)
        if not math.isnan(v):
            vals.append(v)
    return (pct(vals, 0.025), pct(vals, 0.975)), vals


def diff_boot(a_clusters, b_clusters):
    """Interval for share(a) - share(b), a and b resampled independently, random.Random(SEED)."""
    rng = random.Random(SEED)
    vals = []
    ma, mb = len(a_clusters), len(b_clusters)
    for _ in range(B):
        sa = [a_clusters[rng.randrange(ma)] for _ in range(ma)]
        sb = [b_clusters[rng.randrange(mb)] for _ in range(mb)]
        x, y = cluster_share(sa), cluster_share(sb)
        if not (math.isnan(x) or math.isnan(y)):
            vals.append(x - y)
    return (pct(vals, 0.025), pct(vals, 0.975))


def strat_diff_boot(clusters_hi, clusters_lo, all_keys):
    """Interval for share(>365) - share(<90) when both come from one set of package clusters:
    resample packages once per iteration (keys), recompute both strata."""
    rng = random.Random(SEED)
    vals = []
    m = len(all_keys)
    for _ in range(B):
        s = [all_keys[rng.randrange(m)] for _ in range(m)]
        hi = [clusters_hi[k] for k in s if k in clusters_hi]
        lo = [clusters_lo[k] for k in s if k in clusters_lo]
        x, y = cluster_share(hi), cluster_share(lo)
        if not (math.isnan(x) or math.isnan(y)):
            vals.append(x - y)
    return (pct(vals, 0.025), pct(vals, 0.975))


# ------------------------------------------------------------------ data

def load_records():
    pins = list(csv.DictReader(open("data/record_pins.csv", encoding="utf-8")))

    def one(p):
        data = content(p["object_name"])  # by name: the current object
        if md5b64(data) != p["md5Hash"]:
            raise SystemExit(f"STOP: md5Hash mismatch for a pinned record ({p['object_name']})")
        return p["object_name"], json.loads(data)

    with ThreadPoolExecutor(8) as ex:
        recs = dict(ex.map(one, pins))
    return {p["object_name"]: p for p in pins}, recs


def main():
    pins, recs = load_records()
    psl = nz.load_psl()
    idx = {}
    for r in csv.DictReader(open("data/record_index.csv", encoding="utf-8")):
        idx[(r["ecosystem"], r["package"], r["version"])] = r["object_name"]

    reduced = {}
    for name, rec in recs.items():
        pk = rec.get("Package", {})
        eco, pkg, ver = name.split("/", 1)[0], name.split("/", 1)[1].rsplit("/", 1)[0], name.rsplit("/", 1)[1][:-5]
        if (pk.get("Ecosystem", "").lower() != eco or norm_name(pk.get("Name", "")) != norm_name(pkg)
                or pk.get("Version") != ver):
            sys.exit(f"STOP: record identity does not match its object name ({name})")
        reduced[name] = {"evaluable": nz.evaluable(rec), "status": (nz.install_phase(rec) or {}).get("Status", "NO_INSTALL_PHASE"),
                         "items": nz.items(rec, psl) if nz.evaluable(rec) else None}
    del recs

    def pair(eco, pkg, older, newer):
        o, n_ = idx[(eco, pkg, older)], idx[(eco, pkg, newer)]
        gap = (ts(pins[n_]["timeCreated"]) - ts(pins[o]["timeCreated"])).total_seconds() / 86400
        ok = reduced[o]["evaluable"] and reduced[n_]["evaluable"]
        new = nz.new_items(reduced[o]["items"], reduced[n_]["items"]) if ok else None
        post = ts(pins[o]["timeCreated"]) >= POST and ts(pins[n_]["timeCreated"]) >= POST
        return {"eco": eco, "pkg": pkg, "older_obj": o, "newer_obj": n_, "gap": gap, "stratum": stratum(gap),
                "evaluable": ok, "post2024": post,
                "new": {c: bool(new[c]) for c in nz.CATEGORIES} if ok else None,
                "any": any(new.values()) if ok else None}

    sample = list(csv.DictReader(open("data/sample.csv", encoding="utf-8")))
    comp = []
    for r in sample:
        p = pair(r["ecosystem"], r["package"], r["comparison"], r["earliest_malicious"])
        p.update(incident=r["incident"], family=r["family"] or r["incident"], actor=r["actor"])
        comp.append(p)
    within = [pair(r["ecosystem"], r["package"], r["older"], r["newer"])
              for r in csv.DictReader(open("data/sample_within_pairs.csv", encoding="utf-8"))]
    base = [pair(r["ecosystem"], r["package"], r["older"], r["newer"])
            for r in csv.DictReader(open("data/sample_baseline_pairs.csv", encoding="utf-8"))]

    # linked groups: union-find over sampled incidents sharing a family or an actor
    parent = {p["incident"]: p["incident"] for p in comp}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    keyed = defaultdict(set)
    for p in comp:
        keyed["f:" + p["family"]].add(p["incident"])
        for a in filter(None, p["actor"].split(";")):
            keyed["a:" + a].add(p["incident"])
    for ms in keyed.values():
        ms = sorted(ms)
        for m in ms[1:]:
            parent[find(m)] = find(ms[0])
    for p in comp:
        p["linked"] = find(p["incident"])

    os.makedirs(OUT, exist_ok=True)
    rows = []  # results/metrics.csv

    def m1(pairs, unit="incident", cat=None):
        groups = defaultdict(list)
        for p in pairs:
            if p["evaluable"]:
                groups[p[unit]].append(p["new"][cat] if cat else p["any"])
        pos = sum(1 for v in groups.values() if sum(v) > len(v) / 2)
        n = len(groups)
        lo, hi = wilson(pos, n)
        return {"k": pos, "n": n, "share": pos / n if n else math.nan, "lo": lo, "hi": hi,
                "evaluable": n >= MIN_INC}

    def share_by(pairs, cluster_key, cat=None):
        cl = defaultdict(list)
        for p in pairs:
            if p["evaluable"]:
                cl[p[cluster_key]].append(int(p["new"][cat] if cat else p["any"]))
        clusters = list(cl.values())
        k = sum(sum(c) for c in clusters)
        n = sum(len(c) for c in clusters)
        (lo, hi), _ = cluster_boot(clusters)
        pw = sum(sum(c) / len(c) for c in clusters) / len(clusters) if clusters else math.nan
        return {"k": k, "n": n, "share": k / n if n else math.nan, "lo": lo, "hi": hi,
                "evaluable": n >= MIN_PAIRS, "clusters": len(clusters), "package_weighted": pw}

    def add(metric, ecosystem, strat, category, subset, res):
        rows.append({"metric": metric, "ecosystem": ecosystem, "stratum": strat, "category": category,
                     "subset": subset, "positive": res["k"], "denominator": res["n"],
                     "share": f"{res['share']:.4f}" if not math.isnan(res["share"]) else "",
                     "ci_low": f"{res['lo']:.4f}" if not math.isnan(res["lo"]) else "",
                     "ci_high": f"{res['hi']:.4f}" if not math.isnan(res["hi"]) else "",
                     "clusters": res.get("clusters", res["n"]),
                     "package_weighted": f"{res['package_weighted']:.4f}" if "package_weighted" in res and not math.isnan(res["package_weighted"]) else "",
                     "evaluable_cell": "YES" if res["evaluable"] else "NO (counts only)"})

    for c in comp:
        c["pkgkey"] = (c["eco"], c["pkg"])
    for p in within + base:
        p["pkgkey"] = (p["eco"], p["pkg"])

    results = {}
    for subset, flt in (("primary", lambda p: True), ("post2024", lambda p: p["post2024"])):
        for eco in ("pooled", "npm", "pypi"):
            ef = (lambda p: True) if eco == "pooled" else (lambda p, e=eco: p["eco"] == e)
            for strat in ("all",) + STRATA:
                sf = (lambda p: True) if strat == "all" else (lambda p, s=strat: p["stratum"] == s)
                cp = [p for p in comp if flt(p) and ef(p) and sf(p)]
                wp = [p for p in within if flt(p) and ef(p) and sf(p)]
                bp = [p for p in base if flt(p) and ef(p) and sf(p)]
                for cat in (None,) + nz.CATEGORIES:
                    cn = cat or "any"
                    if subset == "primary" or cat is None:
                        r1 = m1(cp, "incident", cat)
                        add("M1", eco, strat, cn, subset, r1)
                        results[("M1", eco, strat, cn, subset)] = r1
                        r1p = share_by(cp, "incident", cat)
                        add("M1p", eco, strat, cn, subset, r1p)
                        results[("M1p", eco, strat, cn, subset)] = r1p
                        r2 = share_by(wp, "pkgkey", cat)
                        add("M2", eco, strat, cn, subset, r2)
                        results[("M2", eco, strat, cn, subset)] = r2
                    if subset == "primary":
                        r3 = share_by(bp, "pkgkey", cat)
                        add("M3", eco, strat, cn, subset, r3)
                        results[("M3", eco, strat, cn, subset)] = r3
                if subset == "primary" and strat == "all":
                    for unit in ("family", "linked"):
                        r = m1(cp, unit)
                        add(f"M1_{unit}", eco, strat, "any", subset, r)
                        results[(f"M1_{unit}", eco, strat, "any", subset)] = r

    with open(f"{OUT}/metrics.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]), lineterminator="\n")
        w.writeheader()
        w.writerows(rows)

    # evaluability / status counts (aggregate)
    cov = []
    for name, ps in (("compromised", comp), ("within", within), ("baseline", base)):
        for eco in ("npm", "pypi"):
            q = [p for p in ps if p["eco"] == eco]
            st = Counter()
            for p in q:
                for o in (p["older_obj"], p["newer_obj"]):
                    st[reduced[o]["status"]] += 1
            cov.append({"pairs": name, "ecosystem": eco, "sampled": len(q), "evaluable": sum(p["evaluable"] for p in q),
                        "post2024_evaluable": sum(p["evaluable"] and p["post2024"] for p in q),
                        "record_status_counts": ";".join(f"{k}={v}" for k, v in sorted(st.items())),
                        "strata_evaluable": ";".join(f"{s}={sum(1 for p in q if p['evaluable'] and p['stratum'] == s)}" for s in STRATA)})
    with open(f"{OUT}/coverage.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(cov[0]), lineterminator="\n")
        w.writeheader()
        w.writerows(cov)

    # masked credential entries: share of unique evaluable older records containing each entry
    masked = []
    for eco in ("npm", "pypi"):
        olds = {p["older_obj"] for p in comp + within + base if p["eco"] == eco and p["evaluable"]}
        cnt = Counter(e for o in olds for e in reduced[o]["items"]["credential"])
        for e, _ in nz.CREDENTIAL_LIST:
            share = cnt[e] / len(olds) if olds else 0
            masked.append({"ecosystem": eco, "entry": e, "older_records": len(olds), "present": cnt[e],
                           "share": f"{share:.4f}", "masked_by_harness": "YES" if share >= 0.95 else "NO"})
    with open(f"{OUT}/credential_masking.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(masked[0]), lineterminator="\n")
        w.writeheader()
        w.writerows(masked)

    # ------------------------------------------------------------- predictions
    def R(*k):
        return results[k]

    def verdict(holds, clearly, evaluable):
        if not evaluable:
            return "not evaluable"
        return "holds clearly" if holds and clearly else ("holds" if holds else "fails")

    preds = []
    h1 = R("M1", "pooled", "all", "any", "primary")
    preds.append(("H1", "M1 >= 0.80", f"M1 = {h1['k']}/{h1['n']} = {h1['share']:.3f} [{h1['lo']:.3f}, {h1['hi']:.3f}]",
                  verdict(h1["share"] >= 0.80, h1["lo"] >= 0.80, h1["evaluable"])))

    h2a, h2b = R("M2", "pooled", "all", "any", "primary"), R("M2", "pooled", "<90", "any", "primary")
    preds.append(("H2", "M2 <= 0.30 pooled and M2 <= 0.20 in <90 d",
                  f"M2 = {h2a['k']}/{h2a['n']} = {h2a['share']:.3f} [{h2a['lo']:.3f}, {h2a['hi']:.3f}]; "
                  f"<90 d: {h2b['k']}/{h2b['n']} = {h2b['share']:.3f} [{h2b['lo']:.3f}, {h2b['hi']:.3f}]",
                  verdict(h2a["share"] <= 0.30 and h2b["share"] <= 0.20, h2a["hi"] <= 0.30 and h2b["hi"] <= 0.20,
                          h2a["evaluable"] and h2b["evaluable"])))

    hi2, lo2 = R("M2", "pooled", ">365", "any", "primary"), R("M2", "pooled", "<90", "any", "primary")
    if hi2["n"] >= MIN_PAIRS:
        src, pool = "M2", [p for p in within if p["evaluable"]]
    else:
        src, pool = "M2 and M3 pooled (M2 has fewer than 10 pairs in >365 d)", [p for p in within + base if p["evaluable"]]
    by_hi, by_lo = defaultdict(list), defaultdict(list)
    for p in pool:
        if p["stratum"] == ">365":
            by_hi[p["pkgkey"]].append(int(p["any"]))
        if p["stratum"] == "<90":
            by_lo[p["pkgkey"]].append(int(p["any"]))
    nh, nl = sum(map(len, by_hi.values())), sum(map(len, by_lo.values()))
    sh, sl = cluster_share(list(by_hi.values())), cluster_share(list(by_lo.values()))
    ev3 = nh >= MIN_PAIRS and nl >= MIN_PAIRS
    if ev3:
        lo3, hi3 = strat_diff_boot(dict(by_hi), dict(by_lo), sorted({p["pkgkey"] for p in pool}))
    else:
        lo3 = hi3 = math.nan
    d3 = sh - sl
    preds.append(("H3", "benign rate >365 d minus <90 d >= 0.15",
                  f"on {src}: >365 d {sum(map(sum, by_hi.values()))}/{nh} = {sh:.3f}, <90 d {sum(map(sum, by_lo.values()))}/{nl} = {sl:.3f}, "
                  f"difference {d3:+.3f} [{lo3:+.3f}, {hi3:+.3f}]",
                  verdict(d3 >= 0.15, lo3 >= 0.15, ev3)))

    a4 = [v for v in _clusters(comp, "incident", "<90")]
    b4 = [v for v in _clusters(within, "pkgkey", "<90")]
    s4a, s4b = cluster_share(a4), cluster_share(b4)
    ev4 = sum(map(len, a4)) >= MIN_PAIRS and sum(map(len, b4)) >= MIN_PAIRS
    lo4, hi4 = diff_boot(a4, b4) if ev4 else (math.nan, math.nan)
    preds.append(("H4", "in <90 d, M1p - M2 >= 0.50",
                  f"M1p {sum(map(sum, a4))}/{sum(map(len, a4))} = {s4a:.3f}, M2 {sum(map(sum, b4))}/{sum(map(len, b4))} = {s4b:.3f}, "
                  f"difference {s4a - s4b:+.3f} [{lo4:+.3f}, {hi4:+.3f}]",
                  verdict(s4a - s4b >= 0.50, lo4 >= 0.50, ev4)))

    c2, c3 = R("M2", "pooled", "all", "credential", "primary"), R("M3", "pooled", "all", "credential", "primary")
    n2 = R("M2", "pooled", "all", "network", "primary")
    preds.append(("H5", "new credential read <= 0.05 (M2 and M3); new network destination <= 0.15 (M2)",
                  f"credential M2 {c2['k']}/{c2['n']} = {c2['share']:.3f} [{c2['lo']:.3f}, {c2['hi']:.3f}], "
                  f"M3 {c3['k']}/{c3['n']} = {c3['share']:.3f} [{c3['lo']:.3f}, {c3['hi']:.3f}]; "
                  f"network M2 {n2['k']}/{n2['n']} = {n2['share']:.3f} [{n2['lo']:.3f}, {n2['hi']:.3f}]",
                  verdict(c2["share"] <= 0.05 and c3["share"] <= 0.05 and n2["share"] <= 0.15,
                          c2["hi"] <= 0.05 and c3["hi"] <= 0.05 and n2["hi"] <= 0.15,
                          c2["evaluable"] and c3["evaluable"] and n2["evaluable"])))

    with open(f"{OUT}/predictions.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(["prediction", "threshold", "estimate", "outcome"])
        w.writerows(preds)

    m1p, mp = R("M1", "pooled", "all", "any", "primary"), R("M1p", "pooled", "all", "any", "primary")
    summary = {"incidents_evaluable": m1p["n"], "incidents_positive": m1p["k"],
               "packages_evaluable": mp["n"], "packages_positive": mp["k"],
               "benign_within_pairs_evaluable": h2a["n"], "benign_within_pairs_positive": h2a["k"],
               "benign_within_share": f"{h2a['share']:.4f}",
               "benign_baseline_pairs_evaluable": R("M3", "pooled", "all", "any", "primary")["n"],
               "benign_baseline_share": f"{R('M3', 'pooled', 'all', 'any', 'primary')['share']:.4f}"}
    with open(f"{OUT}/summary.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(summary), lineterminator="\n")
        w.writeheader()
        w.writerow(summary)

    write_md(rows, cov, masked, preds, summary, src)
    for p in preds:
        print(" | ".join(p))
    print(summary)


def _clusters(pairs, key, strat):
    cl = defaultdict(list)
    for p in pairs:
        if p["evaluable"] and p["stratum"] == strat:
            cl[p[key]].append(int(p["any"]))
    return list(cl.values())


def write_md(rows, cov, masked, preds, summary, h3src):
    def f(x):
        return x if x != "" else "-"

    def table(metric, subset="primary", category="any"):
        out = ["| ecosystem | stratum | positive / denominator | share | 95% CI | clusters | evaluable cell |",
               "|---|---|---|---|---|---|---|"]
        for r in rows:
            if r["metric"] == metric and r["subset"] == subset and r["category"] == category:
                out.append(f"| {r['ecosystem']} | {r['stratum']} | {r['positive']} / {r['denominator']} | {f(r['share'])} | "
                           f"{f(r['ci_low'])} - {f(r['ci_high'])} | {r['clusters']} | {r['evaluable_cell']} |")
        return "\n".join(out)

    def cats(metric):
        out = ["| category | positive / denominator | share | 95% CI |", "|---|---|---|---|"]
        for r in rows:
            if r["metric"] == metric and r["subset"] == "primary" and r["ecosystem"] == "pooled" and r["stratum"] == "all":
                out.append(f"| {r['category']} | {r['positive']} / {r['denominator']} | {f(r['share'])} | {f(r['ci_low'])} - {f(r['ci_high'])} |")
        return "\n".join(out)

    L = ["# Results", "",
         "Generated by `scripts/results.py` from the records pinned in `data/record_pins.csv` (each re-fetched "
         "by name and md5-verified). Pre-registration: `docs/PREREGISTRATION.md` (cfa9957, amended 4fd0d2a and "
         "830e3b4). Aggregate numbers only.", "",
         "Gap = analysis-time gap between the two records of a pair. M1 intervals are Wilson 95%; M1p, M2 and "
         "M3 intervals are cluster-bootstrap percentile 95% (10,000 resamples, `random.Random(20261017)`; "
         "clusters: incidents for M1p, packages for M2/M3). A cell with fewer than 5 incidents (M1) or fewer "
         "than 10 pairs is counts only.", "",
         "## Predictions", "", "| prediction | threshold | estimate | outcome |", "|---|---|---|---|"]
    L += [f"| {a} | {b} | {c} | **{d}** |" for a, b, c, d in preds]
    L += ["", f"H3 was evaluated on: {h3src}.", "",
          "## Coverage (sampled pairs, evaluable = both records have a completed install phase)", "",
          "| pairs | ecosystem | sampled | evaluable | evaluable, both records >= 2024-01-01 | record status counts | evaluable by stratum |",
          "|---|---|---|---|---|---|---|"]
    L += [f"| {c['pairs']} | {c['ecosystem']} | {c['sampled']} | {c['evaluable']} | {c['post2024_evaluable']} | "
          f"{c['record_status_counts']} | {c['strata_evaluable']} |" for c in cov]
    for metric, title in (("M1", "M1: incidents with a majority of sampled packages showing a new capability"),
                          ("M1p", "M1p: sampled compromised pairs showing a new capability"),
                          ("M2", "M2: within-package benign pairs showing a new capability"),
                          ("M3", "M3: top-download benign pairs (gap-matched) showing a new capability")):
        L += ["", f"## {title}", "", table(metric), "", "By category (pooled, all strata):", "", cats(metric)]
    L += ["", "## Sensitivity: unit of independence (M1, all strata)", "",
          "| unit | ecosystem | positive / units | share | Wilson 95% CI |", "|---|---|---|---|---|"]
    for r in rows:
        if r["metric"] in ("M1", "M1_family", "M1_linked") and r["subset"] == "primary" and r["stratum"] == "all" and r["category"] == "any":
            unit = {"M1": "incident", "M1_family": "family", "M1_linked": "linked group"}[r["metric"]]
            L.append(f"| {unit} | {r['ecosystem']} | {r['positive']} / {r['denominator']} | {f(r['share'])} | {f(r['ci_low'])} - {f(r['ci_high'])} |")
    L += ["", "## Sensitivity: both records created on or after 2024-01-01 (no prediction evaluated)", "",
          "| metric | ecosystem | stratum | positive / denominator | share | 95% CI |", "|---|---|---|---|---|---|"]
    for r in rows:
        if r["subset"] == "post2024" and r["category"] == "any" and r["ecosystem"] == "pooled":
            L.append(f"| {r['metric']} | {r['ecosystem']} | {r['stratum']} | {r['positive']} / {r['denominator']} | {f(r['share'])} | {f(r['ci_low'])} - {f(r['ci_high'])} |")
    L += ["", "## Credential entries masked by the harness (>= 95% of evaluable older records)", "",
          "| ecosystem | entry | older records | present | share | masked |", "|---|---|---|---|---|---|"]
    L += [f"| {m['ecosystem']} | `{m['entry']}` | {m['older_records']} | {m['present']} | {m['share']} | {m['masked_by_harness']} |"
          for m in masked if int(m["present"]) > 0]
    L += ["", "Entries not listed were present in no evaluable older record.", "",
          "## Summary numbers", "", "| quantity | value |", "|---|---|"]
    L += [f"| {k} | {v} |" for k, v in summary.items()]
    open(f"{OUT}/RESULTS.md", "w", encoding="utf-8").write("\n".join(L) + "\n")


if __name__ == "__main__":
    main()
