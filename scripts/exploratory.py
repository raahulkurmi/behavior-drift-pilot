"""EXPLORATORY analyses (not pre-registered), written to results/EXPLORATORY.md.

1. Per-incident H1 table (incident, family and linked-group units).
2. Missingness: error_analysis records by side (malicious, C0, C1, C2, baseline) and ecosystem;
   compromised side by incident; bounds on M1 if every unevaluable compromised pair were
   positive / negative.
3. Deviation reruns: written F3 order, literal P3 (no P4 after shell unwrapping), incidents
   without an evaluable package counted as negative, one shared random generator.

Records: data/record_pins.csv. Each record is read from scratch/records/ if present, otherwise
fetched by name; either way its md5Hash must equal the pin (stop on mismatch). Nothing found inside
a record is ever requested. Small-cell suppression as in scripts/results.py: any cell counting
fewer than 5 units, and anything derived from it, is written as "<5". Variant result tables go to
scratch/exploratory/ (git-ignored); only this summary is committed.
Usage: python3 scripts/exploratory.py
"""

import contextlib
import csv
import io
import json
import os
import random as _random
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import normalise as nz  # noqa: E402
import results as R  # noqa: E402
from fetch_records import content, md5b64  # noqa: E402

SUP, small = R.SUP, R.small
OUT_MD = "results/EXPLORATORY.md"
VAR_DIR = "scratch/exploratory"


def sc(n):
    return R.sup_count(n)


# ------------------------------------------------------------------ records
def load():
    pins = {p["object_name"]: p for p in csv.DictReader(open("data/record_pins.csv", encoding="utf-8"))}
    raw = {}
    for name, p in pins.items():
        path = os.path.join("scratch/records", name)
        data = open(path, "rb").read() if os.path.exists(path) else content(name)
        if md5b64(data) != p["md5Hash"]:
            data = content(name)
            if md5b64(data) != p["md5Hash"]:
                raise SystemExit(f"STOP: md5Hash mismatch for a pinned record ({name})")
        raw[name] = json.loads(data)
    return pins, raw


PINS, RAW = load()
R.load_records = lambda: (PINS, dict(RAW))
ORIG_NZ = {k: getattr(nz, k) for k in ("f3", "process_item")}
ORIG_RANDOM = R.random


def restore():
    for k, v in ORIG_NZ.items():
        setattr(nz, k, v)
    R.random = ORIG_RANDOM


def ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def build():
    psl = nz.load_psl()
    idx = {(r["ecosystem"], r["package"], r["version"]): r["object_name"]
           for r in csv.DictReader(open("data/record_index.csv", encoding="utf-8"))}
    red = {}
    for name, rec in RAW.items():
        ev = nz.evaluable(rec)
        red[name] = {"ev": ev, "status": (nz.install_phase(rec) or {}).get("Status", "NO_INSTALL_PHASE"),
                     "items": nz.items(rec, psl) if ev else None}

    def pair(eco, pkg, o_v, n_v):
        o, n_ = idx[(eco, pkg, o_v)], idx[(eco, pkg, n_v)]
        ok = red[o]["ev"] and red[n_]["ev"]
        new = nz.new_items(red[o]["items"], red[n_]["items"]) if ok else None
        gap = (ts(PINS[n_]["timeCreated"]) - ts(PINS[o]["timeCreated"])).total_seconds() / 86400
        return {"eco": eco, "pkg": pkg, "o": o, "n": n_, "ok": ok, "any": any(new.values()) if ok else None,
                "stratum": R.stratum(gap)}

    comp = []
    for r in csv.DictReader(open("data/sample.csv", encoding="utf-8")):
        p = pair(r["ecosystem"], r["package"], r["comparison"], r["earliest_malicious"])
        p.update(incident=r["incident"], family=r["family"] or r["incident"], actor=r["actor"])
        comp.append(p)
    within = []
    for r in csv.DictReader(open("data/sample_within_pairs.csv", encoding="utf-8")):
        p = pair(r["ecosystem"], r["package"], r["older"], r["newer"])
        p["label"] = r["pair"]
        within.append(p)
    base = [pair(r["ecosystem"], r["package"], r["older"], r["newer"])
            for r in csv.DictReader(open("data/sample_baseline_pairs.csv", encoding="utf-8"))]
    # linked groups: same union-find as scripts/results.py
    parent = {p["incident"]: p["incident"] for p in comp}

    def find(x):
        while parent[x] != x:
            x = parent[x]
        return x
    keyed = defaultdict(set)
    for p in comp:
        keyed["f:" + p["family"]].add(p["incident"])
        for a in filter(None, p["actor"].split(";")):
            keyed["a:" + a].add(p["incident"])
    for ms in keyed.values():
        ms = sorted(ms)
        for m in ms[1:]:
            parent[find(m)] = find(ms[0])
    members = defaultdict(set)
    for p in comp:
        members[find(p["incident"])].add(p["incident"])
    for p in comp:
        g = members[find(p["incident"])]
        p["linked"] = sorted(g)[0] if len(g) == 1 else f"{len(g)} linked incidents incl. {sorted(g)[0]}"
    return comp, within, base, red


def majority(vals):
    return sum(vals) > len(vals) / 2 if vals else None


def outcome(m):
    return "not evaluable" if m is None else ("positive" if m else "negative")


# ------------------------------------------------------------------ sections
def h1_tables(comp, L):
    L += ["## 1. Per-unit H1 table", "",
          "Majority rule as pre-registered: a unit is positive if more than half of its evaluable sampled "
          "packages show a new capability. Per-ecosystem cells use only that ecosystem's packages of the unit. "
          "Cells counting fewer than 5 packages, and the outcome derived from them, are `<5`.", ""]
    for unit, title in (("incident", "incident"), ("family", "family"), ("linked", "linked group")):
        L += [f"### Unit: {title}", "",
              "| unit | ecosystems | sampled | evaluable | positive | outcome (pooled) | npm evaluable / positive / outcome | pypi evaluable / positive / outcome |",
              "|---|---|---|---|---|---|---|---|"]
        tot = Counter()
        for u in sorted({p[unit] for p in comp}):
            ps = [p for p in comp if p[unit] == u]
            ev = [p for p in ps if p["ok"]]
            m = majority([p["any"] for p in ev])
            if m is not None:
                tot["n"] += 1
                tot["k"] += m
            cells = []
            for eco in ("npm", "pypi"):
                e = [p for p in ev if p["eco"] == eco]
                if not any(p["eco"] == eco for p in ps):
                    cells.append("-")
                    continue
                me = majority([p["any"] for p in e])
                if me is not None:
                    tot[eco + "n"] += 1
                    tot[eco + "k"] += me
                cells.append(SUP if small(len(e)) else f"{len(e)} / {sum(p['any'] for p in e)} / {outcome(me)}")
            hide = small(len(ev))
            L.append(f"| {u} | {','.join(sorted({p['eco'] for p in ps}))} | {sc(len(ps))} | {sc(len(ev))} | "
                     f"{SUP if hide else sum(p['any'] for p in ev)} | {SUP if hide else outcome(m)} | {cells[0]} | {cells[1]} |")
        # Only totals that results/RESULTS.md already shows unsuppressed are printed; per-ecosystem
        # family / linked-group totals would let suppressed rows be recovered by subtraction.
        parts = [f"pooled {tot['k']}/{tot['n']}"]
        if unit == "incident":
            parts += [f"npm {tot['npmk']}/{tot['npmn']}", f"pypi {tot['pypik']}/{tot['pypin']}"]
        L += ["", "Totals (computed from the unsuppressed values; equal to results/RESULTS.md): " + ", ".join(parts) + ".", ""]


def missingness(comp, within, base, red, L):
    L += ["## 2. Missingness (exploratory)", "",
          "Install-phase status of the records, by role. A record can hold several roles (a C0 is also the newer "
          "side of a within-package pair); each record is counted once per role.", "",
          "| role | ecosystem | records | completed | error_analysis | other |", "|---|---|---|---|---|---|"]
    roles = defaultdict(set)
    for p in comp:
        roles[p["n"]].add("malicious")
        roles[p["o"]].add("C0")
    for p in within:
        o_role, n_role = {"C1->C0": ("C1", "C0"), "C2->C1": ("C2", "C1")}[p["label"]]
        roles[p["o"]].add(o_role)
        roles[p["n"]].add(n_role)
    for p in base:
        roles[p["o"]].add("baseline")
        roles[p["n"]].add("baseline")
    for role in ("malicious", "C0", "C1", "C2", "baseline"):
        for eco in ("npm", "pypi"):
            names = [n for n, rs in roles.items() if role in rs and n.startswith(eco + "/")]
            st = Counter(red[n]["status"] for n in names)
            other = sum(v for k, v in st.items() if k not in ("completed", "error_analysis"))
            L.append(f"| {role} | {eco} | {sc(len(names))} | {sc(st['completed'])} | {sc(st['error_analysis'])} | {sc(other)} |")
    L += ["", "Compromised side by incident (sampled packages):", "",
          "| incident | ecosystem | sampled | malicious record error_analysis | C0 record error_analysis | pair not evaluable |",
          "|---|---|---|---|---|---|"]
    for inc, eco in sorted({(p["incident"], p["eco"]) for p in comp}):
        ps = [p for p in comp if p["incident"] == inc and p["eco"] == eco]
        L.append(f"| {inc} | {eco} | {sc(len(ps))} | {sc(sum(red[p['n']]['status'] == 'error_analysis' for p in ps))} | "
                 f"{sc(sum(red[p['o']]['status'] == 'error_analysis' for p in ps))} | {sc(sum(not p['ok'] for p in ps))} |")
    L += ["", "Bounds: each incident's outcome if every unevaluable compromised pair were positive, or negative "
              "(units = the incident's sampled packages):", "",
          "| incident | sampled | unevaluable | observed | if all positive | if all negative | can flip |",
          "|---|---|---|---|---|---|---|"]
    lo = hi = 0
    for inc in sorted({p["incident"] for p in comp}):
        ps = [p for p in comp if p["incident"] == inc]
        ev = [p["any"] for p in ps if p["ok"]]
        u = sum(not p["ok"] for p in ps)
        obs, up, dn = majority(ev), majority(ev + [True] * u), majority(ev + [False] * u)
        hi += bool(up)
        lo += bool(dn)
        flip = "yes" if (obs is None or up != obs or dn != obs) else "no"
        if small(len(ps)):
            L.append(f"| {inc} | {SUP} | {SUP} | {SUP} | {SUP} | {SUP} | {SUP} |")
        else:
            L.append(f"| {inc} | {len(ps)} | {sc(u)} | {outcome(obs)} | {outcome(up)} | {outcome(dn)} | {flip} |")
    n_inc = len({p["incident"] for p in comp})
    flips = sum(1 for inc in {p["incident"] for p in comp}
                if (lambda ev, u: majority(ev) is None or majority(ev + [True] * u) != majority(ev) or majority(ev + [False] * u) != majority(ev))(
                    [p["any"] for p in comp if p["incident"] == inc and p["ok"]],
                    sum(not p["ok"] for p in comp if p["incident"] == inc)))
    L += ["", f"Incidents whose outcome could flip: {flips} of {n_inc}. Pooled M1 over all {n_inc} incidents: lower bound "
              f"{lo}/{n_inc} (every unevaluable pair negative), upper bound {hi}/{n_inc} (every unevaluable pair positive). "
              f"H1 (M1 >= 0.80) needs at least {-(-8 * n_inc // 10)}/{n_inc}, so it fails at both bounds.", ""]
    return lo, hi, n_inc


def variants(comp, L):
    L += ["## 3. Deviation reruns (written versions)", "",
          "Each variant reruns `scripts/results.py` end to end with one rule changed; outcomes are evaluated "
          "exactly as in the primary analysis.", ""]

    def f3_written(s):  # written order: digit runs first, then long tokens (which can then never match)
        s = nz._DIGITS.sub("N", s)
        return nz._LONG.sub(lambda m: "X" if re.search(r"[A-Za-z]", m[0]) and re.search(r"[0-9]", m[0]) else m[0], s)

    orig_proc = ORIG_NZ["process_item"]

    def p3_literal(argv):  # P3 item = P1(first word); P4 not applied after unwrapping
        argv = [str(a) for a in (argv or [])]
        if argv and nz.p1(argv[0]) in nz.SHELLS and len(argv) >= 3 and argv[1] == "-c":
            w = nz._words(argv[2])
            return nz.p1(w[0]) if w else None
        return orig_proc(argv)

    class Shared:  # one generator shared by every interval, seeded once with SEED
        rng = None

        def Random(self, seed):
            if Shared.rng is None:
                Shared.rng = _random.Random(seed)
            return Shared.rng

    psl = nz.load_psl()
    ev_recs = [r for r in RAW.values() if nz.evaluable(r)]
    base_items = [nz.items(r, psl) for r in ev_recs]

    def changed_records():
        return sum(1 for r, b in zip(ev_recs, base_items) if nz.items(r, psl) != b)

    plan = [("as committed", lambda: None, False),
            ("F3 written order (digits first)", lambda: setattr(nz, "f3", f3_written), True),
            ("P3 literal (no P4 after shell unwrap)", lambda: setattr(nz, "process_item", p3_literal), True),
            ("one shared random generator", lambda: setattr(R, "random", Shared()), False)]
    rows = []
    for tag, apply, items_rule in plan:
        restore()
        Shared.rng = None
        apply()
        nrec = changed_records() if items_rule else None
        out = os.path.join(VAR_DIR, re.sub(r"\W+", "_", tag).strip("_"))
        os.makedirs(out, exist_ok=True)
        R.OUT = out
        with contextlib.redirect_stdout(io.StringIO()):
            R.main()
        preds = list(csv.DictReader(open(os.path.join(out, "predictions.csv"), encoding="utf-8")))
        summ = next(csv.DictReader(open(os.path.join(out, "summary.csv"), encoding="utf-8")))
        metrics = open(os.path.join(out, "metrics.csv"), encoding="utf-8").read().splitlines()
        rows.append((tag, nrec, preds, summ, metrics))
    restore()
    R.OUT = "results"
    base_metrics = rows[0][4]
    L += ["| variant | records with changed item sets | metrics.csv rows changed | packages pos/eval | incidents pos/eval | M2 | M3 | H1 | H2 | H3 | H4 | H5 |",
          "|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for tag, nrec, preds, s, metrics in rows:
        o = {p["prediction"]: p["outcome"] for p in preds}
        ch = sum(1 for a, b in zip(base_metrics, metrics) if a != b)
        L.append(f"| {tag} | {'-' if nrec is None else sc(nrec)} | {ch} | {s['packages_positive']}/{s['packages_evaluable']} | "
                 f"{s['incidents_positive']}/{s['incidents_evaluable']} | {s['benign_within_share']} | {s['benign_baseline_share']} | "
                 + " | ".join(o[h] for h in ("H1", "H2", "H3", "H4", "H5")) + " |")
    L += ["", "Estimates that differ from the committed run:", ""]
    base_est = {p["prediction"]: p["estimate"] for p in rows[0][2]}
    for tag, _, preds, _, _ in rows[1:]:
        d = [f"{p['prediction']}: {p['estimate']}" for p in preds if p["estimate"] != base_est[p["prediction"]]]
        L.append(f"- **{tag}:** " + ("none." if not d else "; ".join(d)))

    # incidents without an evaluable package counted as negative (instead of omitted)
    groups = defaultdict(list)
    for p in comp:
        groups[p["incident"]].append(p["any"] if p["ok"] else None)
    k = sum(1 for v in groups.values() if majority([x for x in v if x is not None]))
    n = len(groups)
    lo_, hi_ = R.wilson(k, n)
    L += ["", f"- **Incidents without an evaluable package counted as negative:** M1 = {k}/{n} = {k / n:.3f} "
              f"[{lo_:.3f}, {hi_:.3f}] (Wilson); H1 {'holds' if k / n >= 0.8 else 'fails'}.", ""]


def main():
    restore()
    comp, within, base, red = build()
    L = ["# Exploratory results (NOT pre-registered)", "",
         "**These analyses were not pre-registered.** They were added after the results, during the audit of "
         "ded0640, to explain the H1 outcome and to check the interpretations listed in docs/DEVIATIONS.md. No "
         "prediction is evaluated here, and nothing here changes the pre-registered outcomes in "
         "results/RESULTS.md.", "",
         "Generated by `scripts/exploratory.py` from the records pinned in data/record_pins.csv (md5-verified). "
         "Any cell counting fewer than 5 units, and anything derived from it, is shown as `<5`.", ""]
    h1_tables(comp, L)
    missingness(comp, within, base, red, L)
    variants(comp, L)
    open(OUT_MD, "w", encoding="utf-8").write("\n".join(L) + "\n")
    print(f"wrote {OUT_MD}")


if __name__ == "__main__":
    main()
