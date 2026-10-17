"""Step 0: list which OpenSSF package-analysis dynamic-analysis records EXIST for given packages.

Uses the public, anonymously listable GCS bucket `ossf-malware-analysis-results`
(objects named <ecosystem>/<package>/<version>.json; see docs/STEP0_DATA_AVAILABILITY.md).
Only object NAMES and creation timestamps are requested (`fields=items(name,timeCreated)`).
No object content is downloaded, so no behaviour data is read.

Usage: python3 scripts/step0_record_index.py data/packages.csv data/record_index.csv
  packages.csv columns: ecosystem,package   (ecosystem: npm | pypi)
"""

import csv
import json
import sys
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

BUCKET = "ossf-malware-analysis-results"
API = f"https://storage.googleapis.com/storage/v1/b/{BUCKET}/o"


def list_prefix(prefix):
    out, token = [], None
    while True:
        q = {"prefix": prefix, "fields": "items(name,timeCreated),nextPageToken", "maxResults": "1000"}
        if token:
            q["pageToken"] = token
        url = API + "?" + urllib.parse.urlencode(q)
        for attempt in range(4):
            try:
                with urllib.request.urlopen(url, timeout=60) as r:
                    page = json.load(r)
                break
            except Exception:
                if attempt == 3:
                    raise
                time.sleep(2 * (attempt + 1))
        out += page.get("items", [])
        token = page.get("nextPageToken")
        if not token:
            return out


def main():
    src, dst = sys.argv[1], sys.argv[2]
    with open(src, newline="", encoding="utf-8") as f:
        pkgs = [(r["ecosystem"], r["package"]) for r in csv.DictReader(f)]
    with open(dst, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(["ecosystem", "package", "version", "object_name", "time_created"])
        def index(ep):
            eco, pkg = ep
            rows = []
            # PyPI names may be stored in another spelling; try the PEP 503-style variants too.
            variants = [pkg]
            if eco == "pypi":
                for v in (pkg.lower(), pkg.lower().replace("_", "-"), pkg.lower().replace("-", "_")):
                    if v not in variants:
                        variants.append(v)
            for variant in variants:
                prefix = f"{eco}/{variant}/"
                for it in list_prefix(prefix):
                    name = it["name"]
                    rest = name[len(prefix):]
                    if "/" in rest or not rest.endswith(".json"):
                        continue  # a deeper path belongs to another package (e.g. scoped names)
                    rows.append([eco, pkg, rest[: -len(".json")], name, it["timeCreated"]])
            return rows

        with ThreadPoolExecutor(8) as ex:
            for rows in ex.map(index, pkgs):
                w.writerows(rows)
    print(f"indexed {len(pkgs)} packages -> {dst}")


if __name__ == "__main__":
    main()
