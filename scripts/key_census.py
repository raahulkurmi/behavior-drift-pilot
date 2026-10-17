"""Compare the key names of the fetched records with the documented schema (section 2).

Prints key paths and counts only, never values. Array elements are summarised as "[]".
Usage: python3 scripts/key_census.py
"""

import csv
import json
import os
from collections import Counter

SCHEMA = {
    "Package", "Package.Ecosystem", "Package.Name", "Package.Version", "CreatedTimestamp", "Analysis",
    "Analysis.<phase>", "Analysis.<phase>.Status", "Analysis.<phase>.Stdout", "Analysis.<phase>.Stderr",
    "Analysis.<phase>.Files", "Analysis.<phase>.Files[].Path", "Analysis.<phase>.Files[].Read",
    "Analysis.<phase>.Files[].Write", "Analysis.<phase>.Files[].Delete",
    "Analysis.<phase>.Sockets", "Analysis.<phase>.Sockets[].Address", "Analysis.<phase>.Sockets[].Port",
    "Analysis.<phase>.Sockets[].Hostnames", "Analysis.<phase>.Commands", "Analysis.<phase>.Commands[].Command",
    "Analysis.<phase>.Commands[].Environment", "Analysis.<phase>.DNS", "Analysis.<phase>.DNS[].Class",
    "Analysis.<phase>.DNS[].Queries", "Analysis.<phase>.DNS[].Queries[].Hostname",
    "Analysis.<phase>.DNS[].Queries[].Types",
}


def paths(obj, prefix, out, depth=0):
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = k
            if prefix == "Analysis":
                out["phase_names"].add(k)
                key = "<phase>"
            p = f"{prefix}.{key}" if prefix else key
            out["paths"][p] += 1
            if depth < 6 and not (prefix.endswith("Commands[]") and k == "Environment"):
                paths(v, p, out, depth + 1)
    elif isinstance(obj, list):
        for v in obj:
            if isinstance(v, (dict, list)):
                paths(v, prefix + "[]", out, depth + 1)


def main():
    pins = list(csv.DictReader(open("data/record_pins.csv", encoding="utf-8")))
    out = {"paths": Counter(), "phase_names": set()}
    seen = Counter()
    for p in pins:
        rec = json.load(open(os.path.join("scratch/records", p["object_name"]), encoding="utf-8"))
        local = {"paths": Counter(), "phase_names": set()}
        paths(rec, "", local)
        for k in local["paths"]:
            seen[k] += 1
        out["phase_names"] |= local["phase_names"]
    print(f"records: {len(pins)}; phase keys under Analysis: {sorted(out['phase_names'])}")
    for k in sorted(seen):
        print(f"{'  ' if k in SCHEMA else '+ '}{k}  (in {seen[k]} records)")
    missing = sorted(SCHEMA - set(seen))
    print("schema paths never seen:", missing)
    print("paths not in schema:", sorted(set(seen) - SCHEMA))


if __name__ == "__main__":
    main()
