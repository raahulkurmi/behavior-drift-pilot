"""First-pass screen (see screen_registry_lib.py for the criterion and the metadata fetchers).
Usage: python3 scripts/screen/screen_registry.py npm|pypi <mal.tsv> <out.tsv>
"""

import sys
from concurrent.futures import ThreadPoolExecutor

from screen_registry_lib import ids, mal, out, screen

names = sorted(mal)
with ThreadPoolExecutor(16) as ex, open(out, "w", encoding="utf-8") as f:
    f.write("package\tstatus\tfirst_malicious_publish\tclean_before\tmalicious_versions\tfirst_clean_publish\tids\n")
    for i, row in enumerate(ex.map(screen, names)):
        f.write("\t".join(row) + "\t" + ";".join(sorted(ids[row[0]])) + "\n")
        if i % 1000 == 0:
            print(i, file=sys.stderr, flush=True)
