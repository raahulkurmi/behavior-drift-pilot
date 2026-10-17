"""Step 0: choose the benign-baseline packages by a fixed rule (no hand-picking).

Ranking sources (public download rankings, saved as plain name lists):
  npm:  wooorm/npm-high-impact lib/top.js (packages ordered by downloads), pinned commit
  PyPI: hugovk top-pypi-packages, top-pypi-packages.min.json (30-day downloads)
Rule, applied in ranking order until N packages are selected per ecosystem:
  1. skip the package if any OSV malware advisory names it (MAL-*, GHSA-* with CWE-506,
     or a PYSEC id in PYSEC_MALWARE), so packages that were ever compromised are excluded;
  2. skip it if registry metadata lists fewer than MIN_RELEASES clean (non-pre-release)
     releases published on/after WINDOW_START (no consecutive pair to compare).
Registry metadata only; no package archive is requested.

Usage: python3 scripts/step0_baseline_select.py <npm top.js> <pypi top json>
Output: data/baseline_ranking.csv (top RANK_LIMIT names per ecosystem, with the decision)
        data/baseline_packages.csv (selected packages)
"""

import csv
import json
import re
import sys
import zipfile
from datetime import datetime, timezone

from step0_availability import key_npm, key_pypi, pre_npm, pre_pypi, ts
from step0_registry_versions import npm_times, pypi_times

N = 20
RANK_LIMIT = 100
MIN_RELEASES = 2
WINDOW_START = datetime(2022, 1, 1, tzinfo=timezone.utc)
PYSEC_MALWARE = {"PYSEC-2024-154", "PYSEC-2022-199"}


def malware_names(zpath, osv_eco):
    names = set()
    with zipfile.ZipFile(zpath) as z:
        for info in z.infolist():
            rec = json.loads(z.read(info))
            rid = rec.get("id", "")
            cwes = (rec.get("database_specific") or {}).get("cwe_ids") or []
            if rid.startswith("MAL-") or (rid.startswith("GHSA-") and "CWE-506" in cwes) or rid in PYSEC_MALWARE:
                for aff in rec.get("affected", []):
                    p = aff.get("package", {})
                    if p.get("ecosystem") == osv_eco:
                        names.add(p.get("name", "").lower())
    return names


def main():
    npm_rank = re.findall(r"^\s*'([^']+)',?$", open(sys.argv[1], encoding="utf-8").read(), re.M)[:RANK_LIMIT]
    pypi_rank = [r["project"] for r in json.load(open(sys.argv[2], encoding="utf-8"))["rows"]][:RANK_LIMIT]
    ranking, selected = [], []
    for eco, names, osv_eco in (("npm", npm_rank, "npm"), ("pypi", pypi_rank, "PyPI")):
        bad = malware_names(f"scratch/osv/{eco}-all.zip", osv_eco)
        key, pre, times = (key_npm, pre_npm, npm_times) if eco == "npm" else (key_pypi, pre_pypi, pypi_times)
        n_sel = 0
        for rank, name in enumerate(names, 1):
            if n_sel >= N:
                decision = "NOT_REACHED"
            elif name.lower() in bad:
                decision = "EXCLUDED_MALWARE_ADVISORY"
            else:
                t = times(name) or {}
                recent = [v for v, p in t.items() if not pre(v) and key(v) is not None and ts(p) and ts(p) >= WINDOW_START]
                if len(recent) < MIN_RELEASES:
                    decision = f"EXCLUDED_FEWER_THAN_{MIN_RELEASES}_RELEASES_SINCE_2022"
                else:
                    decision = "SELECTED"
                    n_sel += 1
                    selected.append({"ecosystem": eco, "package": name, "rank": rank})
            ranking.append({"ecosystem": eco, "rank": rank, "package": name, "decision": decision})
    with open("data/baseline_ranking.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["ecosystem", "rank", "package", "decision"], lineterminator="\n")
        w.writeheader()
        w.writerows(ranking)
    with open("data/baseline_packages.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["ecosystem", "package", "rank"], lineterminator="\n")
        w.writeheader()
        w.writerows(selected)
    for eco in ("npm", "pypi"):
        rs = [r for r in ranking if r["ecosystem"] == eco]
        print(eco, {d: sum(r["decision"] == d for r in rs) for d in sorted({r["decision"] for r in rs})})
        print("  selected:", [s["package"] for s in selected if s["ecosystem"] == eco])
        print("  malware-excluded:", [r["package"] for r in rs if r["decision"] == "EXCLUDED_MALWARE_ADVISORY"])


if __name__ == "__main__":
    main()
