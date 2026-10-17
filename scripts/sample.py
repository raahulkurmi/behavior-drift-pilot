"""Draw the pre-registered sample (docs/PREREGISTRATION.md sections 3 and 4). Metadata only.

Outputs
  data/sample.csv                compromised side: <= 10 eligible packages per incident (section 3)
  data/sample_within_pairs.csv   within-package benign pairs (C1->C0, C2->C1) of the sampled
                                 packages with both releases recorded (section 4)
  data/sample_baseline_pairs.csv top-download pairs, <= 5 per package, gap-matched (section 4)
Usage: python3 scripts/sample.py
"""

import csv
import random
from collections import Counter

# --- section 3, verbatim -------------------------------------------------------------------
SEED = 20261017
import csv, random
rows = [r for r in csv.DictReader(open("data/comparison.csv")) if r["eligible_primary"] == "YES"]
by_inc = {}
for r in rows:
    by_inc.setdefault(r["incident"], []).append((r["ecosystem"], r["package"]))
sample = {}
for inc, pk in sorted(by_inc.items()):
    pk = sorted(pk)
    rng = random.Random(f"{SEED}:{inc}")          # one generator per incident, order-independent
    sample[inc] = pk if len(pk) <= 10 else sorted(rng.sample(pk, 10))
# --------------------------------------------------------------------------------------------

STRATA = ("<90", "90-365", ">365")
SLOTS = 5
MIN_SPACING_DAYS = 14


def largest_remainder(shares, total):
    raw = {s: shares[s] * total for s in STRATA}
    alloc = {s: int(raw[s]) for s in STRATA}
    rest = total - sum(alloc.values())
    for s in sorted(STRATA, key=lambda s: (-(raw[s] - alloc[s]), STRATA.index(s)))[:rest]:
        alloc[s] += 1
    return alloc


def main():
    comp = {(r["ecosystem"], r["package"]): r for r in rows}
    out = []
    for inc, pk in sample.items():
        for eco, pkg in pk:
            r = comp[(eco, pkg)]
            out.append({k: r[k] for k in ("incident", "family", "actor", "ecosystem", "package", "earliest_malicious",
                                          "comparison", "analysis_gap_days", "gap_stratum")})
    with open("data/sample.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(out[0]), lineterminator="\n")
        w.writeheader()
        w.writerows(out)

    chosen = {(r["ecosystem"], r["package"]) for r in out}
    within = [r for r in csv.DictReader(open("data/benign_within.csv", encoding="utf-8"))
              if (r["ecosystem"], r["package"]) in chosen and r["both_recorded"] == "YES"]
    with open("data/sample_within_pairs.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(within[0]), lineterminator="\n")
        w.writeheader()
        w.writerows(within)

    # gap-matched top-download draw: target shares = strata shares of the sampled compromised pairs
    n = Counter(r["gap_stratum"] for r in out)
    shares = {s: n[s] / len(out) for s in STRATA}
    alloc = largest_remainder(shares, SLOTS)
    pairs = {}
    for r in csv.DictReader(open("data/benign_baseline_pairs.csv", encoding="utf-8")):
        if float(r["release_spacing_days"]) >= MIN_SPACING_DAYS:
            pairs.setdefault((r["ecosystem"], r["package"], r["gap_stratum"]), []).append(r)
    base = []
    pkgs = sorted({(e, p) for e, p, _ in pairs})
    for eco, pkg in pkgs:
        for s in STRATA:
            cand = sorted(pairs.get((eco, pkg, s), []), key=lambda r: (r["older"], r["newer"]))
            k = min(alloc[s], len(cand))
            if k == 0:
                continue
            rng = random.Random(f"{SEED}:{eco}:{pkg}:{s}")
            base += sorted(rng.sample(cand, k), key=lambda r: (r["older"], r["newer"]))
    with open("data/sample_baseline_pairs.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(base[0]), lineterminator="\n")
        w.writeheader()
        w.writerows(base)

    print(f"compromised sample: {len(out)} packages, {len(sample)} incidents; strata {dict(n)}")
    print(f"target shares {shares}; slots per package {alloc}")
    print(f"within-package pairs (both recorded): {len(within)} from {len({(r['ecosystem'], r['package']) for r in within})} "
          f"packages; strata {dict(Counter(r['gap_stratum'] for r in within))}")
    print(f"baseline pairs: {len(base)} from {len({(r['ecosystem'], r['package']) for r in base})} packages; "
          f"strata {dict(Counter(r['gap_stratum'] for r in base))}; by ecosystem {dict(Counter(r['ecosystem'] for r in base))}")


if __name__ == "__main__":
    main()
