"""Second pass for packages whose reported-malicious versions are absent from registry
time metadata (deleted releases): same criterion, cutoff = earliest advisory publish date.
Usage: python3 scripts/screen/rescreen_removed.py npm|pypi <mal.tsv> <screen.tsv> <out.tsv>
Resumable: packages already present in <out.tsv> are skipped and new rows are appended.
"""

import os
import sys
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

eco, maltsv, screen, out = sys.argv[1:5]
sys.argv = [sys.argv[0], eco, maltsv, "/dev/null"]
import screen_registry_lib as sr  # reads the faked argv above

pub = defaultdict(list)
for line in open(maltsv, encoding="utf-8"):
    f = line.rstrip("\n").split("\t")
    if int(f[5]) > 0 and f[7] == "False":
        pub[f[4]].append(f[2])
names = [l.split("\t")[0] for l in open(screen, encoding="utf-8") if "\tMAL_VERSIONS_NOT_IN_REGISTRY_TIME\t" in l]


def go(name):
    t = sr.times_npm(name) if eco == "npm" else sr.times_pypi(name)
    if t in (None, "ERROR"):
        return (name, "ERROR", "", "", "")
    pre = sr.npm_pre if eco == "npm" else sr.pypi_pre
    cutoff = min(sr.parse_t(p) for p in pub[name])
    malv = sr.mal[name]
    clean = sorted((sr.parse_t(ts), v) for v, ts in t.items() if v not in malv and not pre(v) and sr.parse_t(ts) < cutoff)
    ok = len(clean) >= 3 and cutoff - clean[0][0] >= timedelta(days=180)
    return (name, "ESTABLISHED" if ok else "NOT_ESTABLISHED", "advisory:" + cutoff.isoformat(), str(len(clean)),
            ",".join(sorted(malv)) + "\t" + ";".join(sorted(sr.ids[name])))


done = set()
if os.path.exists(out):
    done = {l.split("\t")[0] for l in open(out, encoding="utf-8") if l.strip()}
names = [n for n in names if n not in done]
with ThreadPoolExecutor(16) as ex, open(out, "a", encoding="utf-8") as fo:
    for row in ex.map(go, names):
        fo.write("\t".join(row) + "\n")
print(len(names), "rescreened")
