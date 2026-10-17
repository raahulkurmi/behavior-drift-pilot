"""Step 0: fetch version lists and publish times from registry METADATA (no tarballs/wheels).

npm: https://registry.npmjs.org/<package>  (`time` map)
PyPI: https://pypi.org/pypi/<package>/json (earliest upload_time_iso_8601 per release)
Download URLs present in that metadata are never requested.

Usage: python3 scripts/step0_registry_versions.py data/packages.csv data/registry_versions.csv
"""

import csv
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

UA = {"User-Agent": "behavior-drift-pilot step0 metadata check"}


def get(url):
    for attempt in range(5):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=120) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            if attempt == 4:
                raise
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError):
            if attempt == 4:
                raise
        time.sleep(2 * (attempt + 1))


def npm_times(pkg):
    enc = "@" + urllib.parse.quote(pkg[1:], safe="") if pkg.startswith("@") else urllib.parse.quote(pkg, safe="")
    doc = get(f"https://registry.npmjs.org/{enc}")
    if doc is None:
        return None
    return {v: t for v, t in doc.get("time", {}).items() if v not in ("created", "modified", "unpublished")}


def pypi_times(pkg):
    doc = get(f"https://pypi.org/pypi/{urllib.parse.quote(pkg)}/json")
    if doc is None:
        return None
    out = {}
    for v, files in doc.get("releases", {}).items():
        ts = [f["upload_time_iso_8601"] for f in files if f.get("upload_time_iso_8601")]
        out[v] = min(ts) if ts else ""  # "" = release listed with no files (e.g. removed)
    return out


def main():
    src, dst = sys.argv[1], sys.argv[2]
    with open(src, newline="", encoding="utf-8") as f:
        pkgs = [(r["ecosystem"], r["package"]) for r in csv.DictReader(f)]
    with open(dst, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(["ecosystem", "package", "version", "published"])
        def fetch(ep):
            eco, pkg = ep
            try:
                return npm_times(pkg) if eco == "npm" else pypi_times(pkg)
            except Exception:
                return "ERROR"

        with ThreadPoolExecutor(8) as ex:
            results = list(ex.map(fetch, pkgs))
        for (eco, pkg), t in zip(pkgs, results):
            if t is None or t == "ERROR":
                w.writerow([eco, pkg, "", "REGISTRY_404" if t is None else "ERROR"])
                continue
            for v, ts in sorted(t.items()):
                w.writerow([eco, pkg, v, ts])
    print(f"wrote registry versions for {len(pkgs)} packages -> {dst}")


if __name__ == "__main__":
    main()
