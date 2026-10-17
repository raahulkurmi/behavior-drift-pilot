"""Screen packages with version-specific malware reports for 'established' history.

Registry METADATA only (npm registry documents, PyPI JSON API). Tarball and
wheel URLs present in the metadata are never requested.

Imported by screen_registry.py and rescreen_removed.py (reads eco, mal.tsv, out from sys.argv).
<mal.tsv> is the output of scan_osv.py.
Criterion: >= 3 clean (not reported malicious, not pre-release) versions published
before the earliest reported-malicious version, the earliest of them >= 180 days earlier.
"""

import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta

eco, tsv, out = sys.argv[1], sys.argv[2], sys.argv[3]
mal = defaultdict(set)
ids = defaultdict(set)
for line in open(tsv, encoding="utf-8"):
    rid, src, pub, _e, name, n, versions, all_range = line.rstrip("\n").split("\t")
    if int(n) > 0 and all_range == "False":
        mal[name] |= set(versions.split(","))
        ids[name].add(rid)

UA = {"User-Agent": "behavior-drift-pilot step0 metadata screen (contact: repository owner)"}


def get(url, accept=None):
    h = dict(UA)
    if accept:
        h["Accept"] = accept
    for attempt in range(4):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=h), timeout=60) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            if e.code == 429:
                time.sleep(5 * (attempt + 1))
                continue
            raise
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError):
            time.sleep(2 * (attempt + 1))
    return "ERROR"


def parse_t(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def npm_pre(v):
    return "-" in v


def pypi_pre(v):
    return re.search(r"(a|b|rc|dev|alpha|beta|pre|preview)\d*", v, re.I) is not None


def times_npm(name):
    enc = urllib.parse.quote(name, safe="@")
    if name.startswith("@"):
        enc = "@" + urllib.parse.quote(name[1:], safe="")
    abbrev = get(f"https://registry.npmjs.org/{enc}", "application/vnd.npm.install-v1+json")
    if abbrev in (None, "ERROR"):
        return abbrev
    if len(abbrev.get("versions", {})) < 3:
        return {}
    doc = get(f"https://registry.npmjs.org/{enc}")
    if doc in (None, "ERROR"):
        return doc
    return {v: t for v, t in doc.get("time", {}).items() if v not in ("created", "modified", "unpublished")}


def times_pypi(name):
    doc = get(f"https://pypi.org/pypi/{urllib.parse.quote(name)}/json")
    if doc in (None, "ERROR"):
        return doc
    out = {}
    for v, files in doc.get("releases", {}).items():
        ts = [f["upload_time_iso_8601"] for f in files if f.get("upload_time_iso_8601")]
        if ts:
            out[v] = min(ts)
    return out


def screen(name):
    t = times_npm(name) if eco == "npm" else times_pypi(name)
    if t in (None, "ERROR"):
        return (name, "REGISTRY_404" if t is None else "ERROR", "", "", "", "")
    pre = npm_pre if eco == "npm" else pypi_pre
    malv = mal[name]
    mal_times = [parse_t(t[v]) for v in malv if v in t]
    if not mal_times:
        return (name, "MAL_VERSIONS_NOT_IN_REGISTRY_TIME", "", "", ",".join(sorted(malv)), "")
    first_mal = min(mal_times)
    clean = sorted((parse_t(ts), v) for v, ts in t.items() if v not in malv and not pre(v) and parse_t(ts) < first_mal)
    ok = len(clean) >= 3 and first_mal - clean[0][0] >= timedelta(days=180)
    return (name, "ESTABLISHED" if ok else "NOT_ESTABLISHED", first_mal.isoformat(), str(len(clean)),
            ",".join(sorted(malv)), clean[0][0].isoformat() if clean else "")


