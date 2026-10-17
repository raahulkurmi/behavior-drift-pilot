"""Step 0: group candidate packages into incidents / campaigns from advisory METADATA only.

Inputs:  data/candidates.csv, scratch/osv/<eco>-all.zip (read in place)
Output:  data/clusters.csv (one row per candidate), summary on stdout

Per candidate, every malware advisory naming it (same filter as step0_candidates.py) is read
for: id, `published`, and campaign names in its summary/details (CAMPAIGNS, matched in the
order listed, so the more specific wave name wins). Only the campaign label is kept; no other
advisory text is stored.
  campaign  = label of the package's EARLIEST malware advisory that names a campaign
              (all labels seen are kept in `all_campaigns`)
  A bare "Shai-Hulud" mention counts as the first wave only in an advisory published in
  FIRST_WAVE (Sept-Oct 2025); later bare mentions get "Shai-Hulud (wave unspecified)".
  actor     = threat-actor / phishing-campaign name stated in ANY of the package's advisories
              (ACTORS); the strictest grouping, since one actor can run several waves
  unnamed packages: grouped by single linkage on earliest advisory date (gap <= GAP_DAYS,
  across both ecosystems) into `date_group`. Bulk imports give many unrelated advisories the same
  `published` time, so a date group is an UPPER bound on merging, a singleton a LOWER bound.
"""

import csv
import json
import re
import zipfile
from collections import Counter, defaultdict
from datetime import datetime, timedelta

PYSEC_MALWARE = {"PYSEC-2024-154", "PYSEC-2022-199"}
GAP_DAYS = 2
CAMPAIGNS = [  # (label, family, pattern)
    ("Sha1-Hulud: The Second Coming", "Shai-Hulud", r"second coming"),
    ("Shai-Hulud: Here We Go Again", "Shai-Hulud", r"here we go again"),
    ("Mini Shai-Hulud is back", "Shai-Hulud", r"mini shai[- ]hulud\W{0,3} is back"),
    ("Hades", "Shai-Hulud", r"\bhades\b"),
    ("Mini Shai-Hulud", "Shai-Hulud", r"mini shai[- ]hulud"),
    ("s1ngularity", "s1ngularity", r"s1ngularity"),
    ("CanisterWorm", "CanisterWorm", r"canisterworm"),
    ("IronWorm", "IronWorm", r"ironworm"),
    ("Miasma", "Miasma", r"\bmiasma\b"),
    ("Shai-Hulud (first wave)", "Shai-Hulud", r"shai[- ]hulud|sha1[- ]hulud"),
]
ACTORS = [("TeamPCP", re.compile(r"\bteam\s?pcp\b", re.I)),
          ("Qix / npmjs.help phishing", re.compile(r"\bqix\b|npmjs\.help", re.I))]
FIRST_WAVE = ("2025-09-01", "2025-11-01")
CRX = [(l, f, re.compile(p, re.I)) for l, f, p in CAMPAIGNS]
FAMILY = {l: f for l, f, _ in CAMPAIGNS}
FAMILY["Shai-Hulud (wave unspecified)"] = "Shai-Hulud"


def ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def main():
    cands = list(csv.DictReader(open("data/candidates.csv", encoding="utf-8")))
    want = defaultdict(set)
    for c in cands:
        want[c["ecosystem"]].add(c["package"])
    adv = defaultdict(list)  # (eco, pkg) -> [(published, id, label)]
    for eco, osv in (("npm", "npm"), ("pypi", "PyPI")):
        with zipfile.ZipFile(f"scratch/osv/{eco}-all.zip") as z:
            for info in z.infolist():
                rec = json.loads(z.read(info))
                rid = rec.get("id", "")
                cwes = (rec.get("database_specific") or {}).get("cwe_ids") or []
                if not (rid.startswith("MAL-") or (rid.startswith("GHSA-") and "CWE-506" in cwes) or rid in PYSEC_MALWARE):
                    continue
                names = {a.get("package", {}).get("name") for a in rec.get("affected", [])
                         if a.get("package", {}).get("ecosystem") == osv} & want[eco]
                if not names:
                    continue
                text = (rec.get("summary") or "") + " " + (rec.get("details") or "")
                label = next((l for l, _, rx in CRX if rx.search(text)), "")
                if label == "Shai-Hulud (first wave)" and not FIRST_WAVE[0] <= rec.get("published", "") < FIRST_WAVE[1]:
                    label = "Shai-Hulud (wave unspecified)"
                actor = next((a for a, rx in ACTORS if rx.search(text)), "")
                for n in names:
                    adv[(eco, n)].append((rec.get("published", ""), rid, label, actor))

    rows = []
    for c in cands:
        eco, pkg = c["ecosystem"], c["package"]
        a = sorted(adv[(eco, pkg)])
        named = [x for x in a if x[2]]
        rows.append({"ecosystem": eco, "package": pkg, "tier": c["tier"],
                     "first_advisory": a[0][0] if a else "", "first_advisory_id": a[0][1] if a else "",
                     "campaign": named[0][2] if named else "", "family": FAMILY.get(named[0][2], "") if named else "",
                     "all_campaigns": ";".join(sorted({x[2] for x in named})),
                     "actor": ";".join(sorted({x[3] for x in a if x[3]})),
                     "advisory_ids": ";".join(x[1] for x in a)})
    # date groups for packages without a campaign name (both ecosystems together)
    un = sorted((r for r in rows if not r["campaign"]), key=lambda r: r["first_advisory"])
    gid, last = None, None
    for r in un:
        t = ts(r["first_advisory"])
        if last is None or t - last > timedelta(days=GAP_DAYS):
            gid = f"unnamed-{t.date().isoformat()}"
        r["date_group"], last = gid, t
    for r in rows:
        r.setdefault("date_group", "")
    with open("data/clusters.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]), lineterminator="\n")
        w.writeheader()
        w.writerows(rows)

    for eco in ("npm", "pypi"):
        rs = [r for r in rows if r["ecosystem"] == eco]
        print(f"== {eco}: {len(rs)} candidates")
        for lab, n in Counter(r["campaign"] or "(no campaign name)" for r in rs).most_common():
            ds = sorted(r["first_advisory"][:10] for r in rs if (r["campaign"] or "(no campaign name)") == lab)
            print(f"  {n:5d}  {lab}  [{ds[0]} .. {ds[-1]}]")
        multi = [r["package"] for r in rs if ";" in r["all_campaigns"]]
        print(f"  packages named in >1 campaign: {len(multi)}")
        groups = Counter(r["date_group"] for r in rs if r["date_group"])
        print(f"  unnamed: {sum(groups.values())} packages in {len(groups)} date groups (gap <= {GAP_DAYS} d)")
    groups = Counter(r["date_group"] for r in rows if r["date_group"])
    print(f"both ecosystems: {len(rows)} candidates; named waves {len({r['campaign'] for r in rows if r['campaign']})}, "
          f"families {len({r['family'] for r in rows if r['family']})}; unnamed {sum(groups.values())} packages, "
          f"{len(groups)} date groups")


if __name__ == "__main__":
    main()
