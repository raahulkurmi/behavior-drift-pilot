"""Classify packages as COMPROMISED (advisory text explicitly says the release was published
without authorisation) or UNCLEAR. Prints only the matched phrase with ~80 chars of context,
so behaviour descriptions in the advisories are not reproduced.
Usage: python3 scripts/screen/advisory_text.py <osv zip> <pkg list file> > <eco>_class.tsv
"""

import json
import re
import sys
import zipfile
from collections import defaultdict

KW = re.compile(
    r"(\bcompromise of\b|compromised (npm |pypi )?(account|maintainer|token|credential|package|version|release)s?"
    r"|(maintainer|account|package|project)( was| has been)? compromised"
    r"|stolen (credentials|tokens?|npm token|pypi token)|account takeover|account was taken over|hijacked"
    r"|phishing (attack|campaign|email)|shai-hulud|s1ngularity|self-propagating worm"
    r"|without (the )?(maintainer'?s? )?(authori[sz]ation|consent|knowledge)|unauthori[sz]ed (release|version|publish))",
    re.I)
MALWARE_HEAD = re.compile(r"malicious|malware|compromis", re.I)
want = {l.strip() for l in open(sys.argv[2]) if l.strip()}
evidence = defaultdict(list)
with zipfile.ZipFile(sys.argv[1]) as z:
    for info in z.infolist():
        rec = json.loads(z.read(info))
        rid = rec.get("id", "")
        if not rid.startswith(("MAL-", "GHSA-", "PYSEC-")):
            continue
        # Only malware advisories count (not vulnerability advisories that merely mention a phrase):
        # MAL-*, a GHSA tagged CWE-506/CWE-912, or a GHSA/PYSEC whose summary or opening
        # details say the release is malicious / malware / compromised.
        cwes = set((rec.get("database_specific") or {}).get("cwe_ids") or [])
        head = ((rec.get("summary") or "") + " " + (rec.get("details") or "")[:300])
        if not (rid.startswith("MAL-") or cwes & {"CWE-506", "CWE-912"} or MALWARE_HEAD.search(head)):
            continue
        names = {a.get("package", {}).get("name") for a in rec.get("affected", [])} & want
        if not names:
            continue
        text = " ".join(((rec.get("summary") or "") + " " + (rec.get("details") or "")).split())
        m = KW.search(text)
        for n in names:
            if m:
                s = max(0, m.start() - 80)
                evidence[n].append(f"{rid}: ...{text[s:m.end() + 40]}...")
            else:
                evidence.setdefault(n, [])
for n in sorted(want):
    ev = evidence.get(n)
    print(f"{n}\t{'COMPROMISED' if ev else 'UNCLEAR'}\t{ev[0] if ev else ''}")
