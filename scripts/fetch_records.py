"""Fetch the analysis records needed by the sample (anonymous, public bucket) and pin them.

Inputs:  data/sample.csv, data/sample_within_pairs.csv, data/sample_baseline_pairs.csv,
         data/record_index.csv (version -> object name)
Outputs: scratch/records/<object name>   record contents (git-ignored, never committed)
         data/record_pins.csv            object name, generation, md5Hash, timeCreated
Only the bucket's JSON API on storage.googleapis.com is requested. Nothing inside a record is
ever requested, and no package archive is touched.
Usage: python3 scripts/fetch_records.py
"""

import base64
import csv
import hashlib
import json
import os
import sys
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

BUCKET = "ossf-malware-analysis-results"
API = f"https://storage.googleapis.com/storage/v1/b/{BUCKET}/o/"
OUT = "scratch/records"


def get(url):
    for attempt in range(5):
        try:
            with urllib.request.urlopen(url, timeout=120) as r:
                return r.read()
        except Exception:
            if attempt == 4:
                raise
            time.sleep(2 * (attempt + 1))


def meta(name):
    q = urllib.parse.quote(name, safe="")
    return json.loads(get(API + q + "?fields=name,generation,md5Hash,timeCreated,size"))


def content(name, generation=None):
    q = urllib.parse.quote(name, safe="")
    url = API + q + "?alt=media" + (f"&generation={generation}" if generation else "")
    return get(url)


def md5b64(data):
    return base64.b64encode(hashlib.md5(data).digest()).decode()


def needed():
    idx = {}
    for r in csv.DictReader(open("data/record_index.csv", encoding="utf-8")):
        idx[(r["ecosystem"], r["package"], r["version"])] = r["object_name"]
    want = []
    for r in csv.DictReader(open("data/sample.csv", encoding="utf-8")):
        want += [(r["ecosystem"], r["package"], r["earliest_malicious"]), (r["ecosystem"], r["package"], r["comparison"])]
    for f in ("data/sample_within_pairs.csv", "data/sample_baseline_pairs.csv"):
        for r in csv.DictReader(open(f, encoding="utf-8")):
            want += [(r["ecosystem"], r["package"], r["older"]), (r["ecosystem"], r["package"], r["newer"])]
    out = []
    for k in want:
        if k not in idx:
            sys.exit(f"no object name for {k}")
        if idx[k] not in out:
            out.append(idx[k])
    return out


def fetch(name):
    m = meta(name)
    data = content(name, m["generation"])
    if md5b64(data) != m["md5Hash"]:
        raise SystemExit(f"md5 mismatch on download: {name}")
    path = os.path.join(OUT, name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)
    return {"object_name": name, "generation": m["generation"], "md5Hash": m["md5Hash"],
            "timeCreated": m["timeCreated"], "size": m["size"]}


def main():
    names = needed()
    with ThreadPoolExecutor(8) as ex:
        pins = list(ex.map(fetch, names))
    with open("data/record_pins.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(pins[0]), lineterminator="\n")
        w.writeheader()
        w.writerows(pins)
    print(f"fetched and pinned {len(pins)} records, {sum(int(p['size']) for p in pins) / 1e6:.1f} MB")


if __name__ == "__main__":
    main()
