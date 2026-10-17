# Step 0: data availability

Snapshot date: 2026-10-17. This step checks whether the records needed for the study **exist**.
It does not read, open or summarise any behaviour field of any analysis record, and no package
archive (tarball, wheel, sdist) was downloaded, installed, executed or unpacked.

Research question (context only, not started): when an established package is compromised, does the
malicious release show install-time behaviour (network destinations, file writes, credential-file
reads, process spawns) that its own earlier releases did not, and how often do benign consecutive
releases show the same kind of change?

## Verdict

**FEASIBLE: 343 packages, 15 independent incidents** (tier A, at least a minimal pair: a record for
a malicious version and for the clean release immediately before it). 64 of those packages also have
a full set (records for prev1, prev2 and prev3), across 13 incidents.

Read this together with the clustering caveat. The 15 incidents are named campaign waves plus
unnamed date groups. If all waves of one worm family are merged, there are 9 groups. If incidents
linked by a named actor are also merged (TeamPCP links several Shai-Hulud waves, CanisterWorm and
telnyx), there are 7 groups, and one group holds 328 of the 343 packages. Package-level counts are
large, but incident-level independence is limited, and the pre-registration must handle this
explicitly (see "npm scale").

Tier B (reported separately): litellm has a full set; ua-parser-js has no record for any version
involved (UNAVAILABLE); ctx cannot be checked.

The benign baseline is feasible in both ecosystems (PyPI: 2,515 consecutive release pairs with
both records; npm: 126).

## Sources

| source | what was used | link |
|---|---|---|
| OSV bulk export | malware advisories (MAL-*, GHSA-* with CWE-506, PYSEC ids listed in the scripts): ids, `published`, `affected` versions, summary/details text for classification and campaign names | https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip, https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip (snapshot: newest `modified` 2026-10-17T02:56Z npm, 2026-10-16T20:15Z PyPI; 230,382 and 26,370 records) |
| ossf/malicious-packages | origin of the MAL-* records in OSV | https://github.com/ossf/malicious-packages |
| npm registry metadata | `time` map of the package document (version -> publish time) | https://registry.npmjs.org/&lt;package&gt; |
| PyPI JSON API | earliest `upload_time_iso_8601` per release | https://pypi.org/pypi/&lt;package&gt;/json |
| OpenSSF package-analysis results bucket | object **names** and **timeCreated** only (`fields=items(name,timeCreated)`), anonymous public listing, no cloud account | https://storage.googleapis.com/storage/v1/b/ossf-malware-analysis-results/o?prefix=&lt;ecosystem&gt;/&lt;package&gt;/ |
| package-analysis schema docs | field names only | https://github.com/ossf/package-analysis/blob/c5c45008da694036d701ba76fe9567fc8a5b9675/docs/data_schema.md, `function/loader/dynamic-analysis-schema.json` at the same commit |
| npm download ranking (baseline) | ordered package names | https://github.com/wooorm/npm-high-impact/blob/6ca165357f4cf1e127f38065455fc1c7680f8b16/lib/top.js |
| PyPI download ranking (baseline) | ordered project names, 30-day downloads, `last_update` 2026-10-01 12:40:51 | https://hugovk.dev/top-pypi-packages/top-pypi-packages.min.json |

Download URLs that appear inside registry metadata were never requested.

## Rules

Fixed before the record-existence results were looked at.

- **Malware advisory**: an OSV record that is MAL-*, a GHSA-* tagged CWE-506, or one of the PYSEC
  ids in `PYSEC_MALWARE` (PYSEC-2024-154 ultralytics, PYSEC-2022-199 ctx; no MAL/GHSA record lists
  versions for these two, so they enter the candidate list only through these ids).
- **Malicious versions**: the union of the versions listed by the package's malware advisories.
  Advisories that cover all versions (introduced 0, never fixed) are not version-specific and are
  skipped.
- **Established**: at least 3 clean releases (not reported malicious, not pre-release) published
  before the first malicious release, the earliest of them at least 180 days earlier. If no
  malicious version is in registry time metadata (a deleted release), the cutoff is the earliest
  advisory `published` date (second pass). The rule is checked again in
  `step0_availability.py` from freshly fetched metadata.
- **Compromised (tier A)**: the text of at least one malware advisory explicitly describes an
  unauthorised release: compromise of an account, token or credentials, account takeover,
  hijacking, phishing, a named worm campaign, or a release made without authorisation. Advisories
  are counted only if they are malware advisories (MAL-*, GHSA tagged CWE-506/CWE-912, or a
  GHSA/PYSEC whose summary or opening details say malicious, malware or compromised). The regex is
  in `scripts/screen/advisory_text.py`. Everything else is UNCLEAR.
- **Tier B**: confirmed malicious release of an established package where the advisories do not
  say how it was published. These are named on the command line: ua-parser-js (npm), litellm and
  ctx (PyPI). Reported separately.
- **prev1..prev3**: the clean releases immediately below the malicious version in version order
  (npm: numeric semver; PyPI: PEP 440). Each must be published before the malicious version, or
  before the advisory date if the malicious publish time is unknown. prev1 is the nearest.
- **Minimal pair**: a record exists for the malicious version and for its prev1.
  **Full set**: records exist for the malicious version and for prev1, prev2 and prev3.
- **Record exists**: an object `<ecosystem>/<package>/<version>.json` is listed in the bucket.
  PyPI names are also tried lower-cased and with `_`/`-` swapped. Otherwise it is UNAVAILABLE.
  Nothing is generated and no sandbox is built.

## Commands

Run from the repository root. `scratch/` is git-ignored and holds the large downloaded inputs.

```sh
# 1. OSV exports (read in place, never extracted)
curl -sSo scratch/osv/npm-all.zip  https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip
curl -sSo scratch/osv/pypi-all.zip https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip

# 2. version-specific malware reports, then the established screen (registry metadata only)
for e in npm pypi; do
  python3 scripts/screen/scan_osv.py scratch/osv/$e-all.zip > scratch/tools/${e}_mal.tsv
  python3 scripts/screen/screen_registry.py $e scratch/tools/${e}_mal.tsv data/screen/${e}_screen.tsv
  python3 scripts/screen/rescreen_removed.py $e scratch/tools/${e}_mal.tsv data/screen/${e}_screen.tsv data/screen/${e}_rescreen.tsv
  awk -F'\t' '$2=="ESTABLISHED"{print $1}' data/screen/${e}_screen.tsv data/screen/${e}_rescreen.tsv > data/screen/${e}_est.txt
done
printf 'ctx\nultralytics\n' >> data/screen/pypi_est.txt   # PYSEC-only packages, see Rules

# 3. advisory-text classification, candidate list (tier B named explicitly)
for e in npm pypi; do
  python3 scripts/screen/advisory_text.py scratch/osv/$e-all.zip data/screen/${e}_est.txt > data/screen/${e}_class.tsv
done
python3 scripts/step0_candidates.py pypi data/candidates.csv litellm ctx
python3 scripts/step0_candidates.py npm  data/candidates.csv ua-parser-js

# 4. baseline packages by rule
curl -sSo scratch/rankings/npm-high-impact-top.js \
  https://raw.githubusercontent.com/wooorm/npm-high-impact/6ca165357f4cf1e127f38065455fc1c7680f8b16/lib/top.js
curl -sSLo scratch/rankings/top-pypi-packages.min.json https://hugovk.dev/top-pypi-packages/top-pypi-packages.min.json
PYTHONPATH=scripts python3 scripts/step0_baseline_select.py scratch/rankings/npm-high-impact-top.js scratch/rankings/top-pypi-packages.min.json

# 5. registry versions and record index for candidates + baseline
python3 scripts/step0_packages.py
python3 scripts/step0_registry_versions.py data/packages.csv data/registry_versions.csv
python3 scripts/step0_record_index.py      data/packages.csv data/record_index.csv

# 6. availability, clustering, timing, counts, baseline coverage, exclusions
PYTHONPATH=scripts python3 scripts/step0_availability.py
python3 scripts/step0_clusters.py
PYTHONPATH=scripts python3 scripts/step0_timing.py
python3 scripts/step0_campaign_counts.py
PYTHONPATH=scripts python3 scripts/step0_baseline_coverage.py
python3 scripts/step0_excluded.py
```

Notes on reproduction:
- The npm first-pass screen ran with a copy of `screen_registry.py` that did not retry on
  `OSError`. The committed version retries, which changes nothing about the criterion.
- The npm second pass was interrupted once by a connection reset and resumed; it is resumable by
  design. It completed with 10,947 of 10,947 packages and no ERROR rows.
- Re-running `advisory_text.py` on this snapshot reproduces `data/screen/{npm,pypi}_class.tsv`
  exactly, and re-running `step0_candidates.py` reproduces `data/candidates.csv` byte for byte.

## Funnel

| step | npm | PyPI |
|---|---|---|
| packages with version-specific malware reports | 14,843 | 5,437 |
| registry 404 (removed) | 1,433 | 5,317 |
| not established, first pass | 769 | 49 |
| malicious versions absent from registry time, second pass | 10,947 (18 ESTABLISHED) | 56 (32 ESTABLISHED) |
| established (both passes, + PYSEC-only for PyPI) | 1,712 | 49 |
| COMPROMISED (tier A) | 1,448 | 30 |
| UNCLEAR | 264 (incl. ua-parser-js, tier B) | 19 (incl. litellm, ctx, tier B) |
| candidates (A + B) | 1,449 | 32 |
| established on re-check | 1,449 | 31 (ctx: registry 404) |
| record for >= 1 malicious version, tier A | 925 | 23 |
| minimal pair, tier A | 321 | 22 |
| full set, tier A | 43 | 21 |

The 18 packages added by the npm second pass (admin-panel, bootstrapper, react, shell, ...) are all
UNCLEAR, so none became a candidate.

## Candidate table

Per package, the row shown is the malicious version with the most complete record set. Per-version
rows for all 1,481 candidates are in `data/availability.csv`.

### PyPI (all candidates)

| package | tier | incident | malicious versions | with record | best case (record for mal / prev1 / prev2 / prev3) | status |
|---|---|---|---|---|---|---|
| cmd2func | A | Mini Shai-Hulud | 2 | 0 | 0.2.2: NO / YES / YES / YES | UNAVAILABLE |
| coolbox | A | Mini Shai-Hulud | 2 | 1 | 0.4.2: YES / YES / YES / NO | MINIMAL PAIR |
| ctx | B | unnamed-2022-05-24 | 11 | 4 | 0.2: YES / UNKNOWN / UNKNOWN / UNKNOWN | NOT CHECKABLE |
| dreamgen | A | Mini Shai-Hulud | 1 | 1 | 1.8.1: YES / YES / YES / YES | FULL SET |
| durabletask | A | unnamed-2026-05-19 | 3 | 3 | 1.4.1: YES / YES / YES / YES | FULL SET |
| dydx-v4-client | A | unnamed-2026-02-06 | 2 | 2 | 1.1.5.post1: YES / YES / YES / YES | FULL SET |
| dynamo-release | A | Mini Shai-Hulud | 1 | 1 | 1.5.4: YES / YES / YES / YES | FULL SET |
| embiggen | A | Hades | 1 | 1 | 0.11.97: YES / YES / YES / YES | FULL SET |
| ensmallen | A | Mini Shai-Hulud | 1 | 1 | 0.8.101: YES / YES / YES / YES | FULL SET |
| executor-engine | A | Mini Shai-Hulud | 2 | 2 | 0.3.4: YES / YES / YES / YES | FULL SET |
| executor-http | A | Mini Shai-Hulud | 2 | 2 | 0.1.3: YES / YES / YES / YES | FULL SET |
| funcdesc | A | Mini Shai-Hulud | 2 | 2 | 0.2.2: YES / YES / YES / YES | FULL SET |
| gpsea | A | Hades | 1 | 1 | 0.9.14: YES / YES / YES / YES | FULL SET |
| guardrails-ai | A | Mini Shai-Hulud is back | 1 | 1 | 0.10.1: YES / YES / YES / YES | FULL SET |
| lightning | A | unnamed-2026-04-29 | 2 | 0 | 2.6.2: NO / YES / YES / YES | UNAVAILABLE |
| litellm | B | unnamed-2026-03-24 | 2 | 2 | 1.82.7: YES / YES / YES / YES | FULL SET |
| magique | A | Mini Shai-Hulud | 2 | 2 | 0.6.8: YES / YES / YES / YES | FULL SET |
| magique-ai | A | Mini Shai-Hulud | 2 | 2 | 0.4.4: YES / YES / YES / YES | FULL SET |
| mem8 | A | Mini Shai-Hulud | 1 | 1 | 6.0.1: YES / YES / YES / YES | FULL SET |
| memoryos | A | unnamed-2026-09-23 | 1 | 0 | 2.0.34: NO / NO / NO / YES | UNAVAILABLE |
| mistralai | A | Mini Shai-Hulud is back | 1 | 1 | 2.4.6: YES / YES / YES / YES | FULL SET |
| mrmustard | A | unnamed-2026-07-24 | 1 | 1 | 0.7.4: YES / NO / NO / YES | UNAVAILABLE |
| num2words | A | unnamed-2025-07-31 | 2 | 2 | 0.5.15: YES / YES / YES / YES | FULL SET |
| okite | A | Mini Shai-Hulud | 2 | 2 | 0.0.7: YES / YES / YES / YES | FULL SET |
| pantheon-agents | A | Mini Shai-Hulud | 2 | 1 | 0.6.2: YES / YES / YES / YES | FULL SET |
| pantheon-toolsets | A | Mini Shai-Hulud | 2 | 2 | 0.5.5: YES / YES / YES / YES | FULL SET |
| phenopacket-store-toolkit | A | Hades | 1 | 0 | 0.1.7: NO / YES / YES / YES | UNAVAILABLE |
| pyphetools | A | Hades | 1 | 1 | 0.9.120: YES / YES / YES / YES | FULL SET |
| pytorch-lightning | A | unnamed-2026-05-07 | 2 | 0 | 2.6.2: NO / YES / YES / YES | UNAVAILABLE |
| spateo-release | A | Mini Shai-Hulud | 1 | 0 | 1.1.2: NO / NO / NO / NO | UNAVAILABLE |
| telnyx | A | unnamed-2026-03-27 | 2 | 2 | 4.87.1: YES / YES / YES / YES | FULL SET |
| ultralytics | A | unnamed-2024-12-10 | 6 | 0 | 8.3.41: NO / NO / YES / NO | UNAVAILABLE |

### npm (by incident)

The npm candidates are summarised per incident in "npm scale" below; per-package rows are in
`data/availability.csv` and `data/clusters.csv`. Tier B: ua-parser-js (0.7.29, 0.8.0, 1.0.0;
advisory 2021-10-22) has 19 records, none for a malicious version or for prev1 0.7.28. The
releases predate the bucket, whose earliest timeCreated is 2022-02-01. Status: UNAVAILABLE.

### Explicit notes

- **ultralytics** (PyPI, tier A): no record exists for **any** malicious version (8.3.41-8.3.46),
  although the package has 219 records for other versions. UNAVAILABLE.
- **ctx** (PyPI, tier B) **cannot be checked**: the project has been removed from PyPI (JSON API
  404), so its release history, and therefore prev1..prev3, cannot be determined. The bucket holds
  4 ctx records (0.2, 0.2.2.1, 0.2.3, 0.2.6), all for reported-malicious versions, so even
  ignoring the registry there is no clean comparison record.

## Excluded and UNCLEAR

All in `data/excluded.csv` (one row per package, first failing stage, reason).

| stage | npm | PyPI | reason |
|---|---|---|---|
| classification | 263 | 17 | UNCLEAR: no malware advisory explicitly describes an unauthorised release |
| established re-check | 0 | 1 (ctx) | registry 404; previous versions cannot be determined |
| record | 1,128 | 8 | UNAVAILABLE: no record for any malicious version (npm 523 + ua-parser-js; PyPI 7), or the malicious version is recorded but its prev1 is not (npm 604; PyPI 1, mrmustard) |

PyPI UNCLEAR (tier B names excluded): always-updates, apilogicserver, cdktn-provider-azurerm,
elementary-data, fastapi, guan, massive, morin, notebook-intelligence, noteparse,
nvidia-nat-semantic-kernel, qontract-reconcile, saas-common-lib-473815, semantic-router,
strawberry-graphql, txdpy, xinference.

PyPI record-stage exclusions: cmd2func, lightning, memoryos, phenopacket-store-toolkit,
pytorch-lightning, spateo-release, ultralytics (no record for any malicious version); mrmustard
(malicious version recorded, prev1 not).

## Campaign clustering

From advisory metadata only (`scripts/step0_clusters.py`, output `data/clusters.csv`): for each
candidate, every malware advisory naming it is read for its id, its `published` time, and a campaign
name in its summary/details. Only the label is stored. Labels are matched most specific first:
"Sha1-Hulud: The Second Coming", "Shai-Hulud: Here We Go Again", "Mini Shai-Hulud is back",
"Hades", "Mini Shai-Hulud", s1ngularity, CanisterWorm, IronWorm, Miasma, then a bare "Shai-Hulud".
A bare mention counts as the first wave only in advisories published Sept-Oct 2025; one later
mention (@ctrl/plex) is "wave unspecified". A package's incident is the label of its earliest
advisory that names one. One package carries two labels (pantheon-agents: Hades and Mini
Shai-Hulud; assigned to Mini Shai-Hulud).

An actor is any threat-actor or phishing name stated in a package's malware advisories: TeamPCP
(named for CanisterWorm, Hades, "Mini Shai-Hulud is back" and telnyx) and the Qix / npmjs.help
phishing (11 of the 2025-09-08 packages).

Packages with no campaign name are grouped by single linkage on earliest advisory date (gap at most
2 days, both ecosystems together) into `unnamed-<date>` groups. Bulk imports give unrelated
advisories identical `published` times, so a date group may merge unrelated incidents (it is an
upper bound on merging), and treating each unnamed package separately is the lower bound.

Three independence levels:
1. **incident**: a wave or a date group;
2. **family**: all waves of one worm family merged (Shai-Hulud: first wave, Second Coming, Mini,
   Mini is back, Here We Go Again, Hades, wave unspecified);
3. **linked group**: connected components of incidents sharing a family or a named actor. This is
   the most conservative level. It produces one large group: all Shai-Hulud waves + CanisterWorm +
   unnamed-2026-03-27 (telnyx), linked through TeamPCP.

| | packages | incidents | families | linked groups |
|---|---|---|---|---|
| tier A, record for a malicious version | 948 | 21 | 15 | 13 |
| tier A, minimal pair | 343 (npm 321, PyPI 22) | 15 | 9 | 7 |
| tier A, full set | 64 (npm 43, PyPI 21) | 13 | 8 | 6 |
| tier B, minimal pair / full set | 1 (litellm) | 1 | 1 | 1 |

Of the 343 tier-A minimal-pair packages, 328 fall in the large linked group. The other 15 are
Miasma (8), unnamed-2026-05-19 (3: durabletask and 2 npm packages), s1ngularity (1),
unnamed-2025-07-31 (num2words), unnamed-2026-02-06 (dydx-v4-client) and unnamed-2026-02-19 (cline).

## npm scale (per-campaign counts for the pre-registration)

`data/campaign_counts.csv`. No cap or sample is chosen here.

| incident | family | actor | candidates | record for malicious | minimal pair | full set |
|---|---|---|---|---|---|---|
| Sha1-Hulud: The Second Coming | Shai-Hulud | | 449 | 271 | 79 | 12 |
| Mini Shai-Hulud is back | Shai-Hulud | TeamPCP | 322 | 221 | 78 | 12 |
| Shai-Hulud: Here We Go Again | Shai-Hulud | | 352 | 263 | 76 | 8 |
| Shai-Hulud (first wave) | Shai-Hulud | | 135 | 85 | 38 | 4 |
| Mini Shai-Hulud | Shai-Hulud | | 30 | 30 | 22 | 0 |
| CanisterWorm | CanisterWorm | TeamPCP | 40 | 29 | 15 | 5 |
| Miasma | Miasma | | 44 | 15 | 8 | 1 |
| unnamed-2026-05-19 | | | 4 | 2 | 2 | 0 |
| s1ngularity | s1ngularity | | 6 | 2 | 1 | 0 |
| Shai-Hulud (wave unspecified) | Shai-Hulud | | 1 | 1 | 1 | 0 |
| unnamed-2026-02-19 | | | 1 | 1 | 1 | 1 |
| IronWorm | IronWorm | | 30 | 1 | 0 | 0 |
| unnamed-2025-09-08 (11 with the Qix / npmjs.help actor) | | | 25 | 0 | 0 | 0 |
| unnamed-2026-04-29 | | | 4 | 1 | 0 | 0 |
| unnamed-2018-07-12 | | | 2 | 1 | 0 | 0 |
| unnamed-2022-03-16, -2026-07-11, -2026-09-23 | | | 3 | 2 | 0 | 0 |
| unnamed-2021-10-22 (ua-parser-js, tier B) | | | 1 | 0 | 0 | 0 |

PyPI, for comparison: Mini Shai-Hulud 13 minimal pairs (12 full), Hades 3 (3), Mini Shai-Hulud is
back 2 (2), and five single-package unnamed incidents with a full set (num2words, dydx-v4-client,
telnyx, durabletask, litellm tier B).

Four Shai-Hulud waves give 271 of the 321 npm minimal pairs. A per-campaign cap or a seeded
sample stratified by incident would keep any one wave from dominating.

Observation for the pre-registration (timing metadata only): for 170 of the 580 npm malicious
versions with a minimal pair (72 packages), prev1 was published at most 7 days before the malicious
version. For "Mini Shai-Hulud" npm this holds for all 36. Such a prev1 may be a release made during
the incident that the advisories do not list. A minimum gap between prev1 and the first malicious
release would exclude these.

## Record timing

`data/timing.csv` has one row per malicious version with a minimal pair (npm 580, PyPI 36), with the
timeCreated of the malicious record and of prev1..prev3, the registry publish time of each, and the
lag. `timeCreated` is the creation time of the object's **current** generation, so a version that
was re-analysed later would show the later time.

**Result: previous-version records were created close to their own release, not re-analysed after
the incident.**

- PyPI: all 107 existing prev records were created within 0.1 days of their release (1 UNAVAILABLE).
  Malicious records were created within hours of the malicious upload; publish times for 35 of the 36
  malicious versions are no longer in PyPI metadata (deleted releases), so their lag is computed
  only where known.
- npm: 1,019 prev records NEAR (at most 7 days after release), 23 LATE, 698 UNAVAILABLE. All 23
  LATE records were created 2022-02-09..11, the first days of the bucket, for releases from
  2016-2021. That is the initial backfill, not re-analysis prompted by an incident. Every
  malicious record was created within 0.1 days of the malicious publish time.
- Prev records created within 7 days of the malicious record (npm 200, PyPI 15) are cases where
  the prev release itself was published shortly before the malicious one (see the observation
  above). They are NEAR their own release too.

### PyPI (every malicious version with a minimal pair)

prev columns: version (record timeCreated date, lag in days from that version's publish time).

| package | malicious version | record created | prev1 | prev2 | prev3 |
|---|---|---|---|---|---|
| coolbox | 0.4.2 | 2026-06-05T23:56 | 0.4.0 (2025-11-11, 0.0) | 0.3.9 (2025-02-28, 0.0) | 0.3.8 UNAVAILABLE |
| dreamgen | 1.8.1 | 2026-06-08T00:07 | 1.8.0 (2026-06-01, 0.1) | 1.7.0 (2026-06-01, 0.1) | 1.6.0 (2026-05-31, 0.0) |
| durabletask | 1.4.1 | 2026-05-19T16:33 | 1.4.0 (2026-04-08, 0.0) | 1.3.0 (2026-01-12, 0.0) | 1.2.0 (2026-01-07, 0.0) |
| durabletask | 1.4.2 | 2026-05-19T16:51 | 1.4.0 (2026-04-08, 0.0) | 1.3.0 (2026-01-12, 0.0) | 1.2.0 (2026-01-07, 0.0) |
| durabletask | 1.4.3 | 2026-05-19T16:55 | 1.4.0 (2026-04-08, 0.0) | 1.3.0 (2026-01-12, 0.0) | 1.2.0 (2026-01-07, 0.0) |
| dydx-v4-client | 1.1.5.post1 | 2026-01-15T12:23 | 1.1.5 (2025-08-19, 0.0) | 1.1.4 (2025-01-22, 0.0) | 1.1.3 (2024-12-10, 0.0) |
| dydx-v4-client | 1.1.6 | 2026-02-12T20:57 | 1.1.5 (2025-08-19, 0.0) | 1.1.4 (2025-01-22, 0.0) | 1.1.3 (2024-12-10, 0.0) |
| dynamo-release | 1.5.4 | 2026-06-06T01:00 | 1.5.3 (2026-03-17, 0.0) | 1.5.2 (2026-02-20, 0.0) | 1.5.1 (2026-02-07, 0.0) |
| embiggen | 0.11.97 | 2026-06-08T03:20 | 0.11.96 (2026-01-08, 0.0) | 0.11.95 (2023-12-05, 0.0) | 0.11.94 (2023-12-05, 0.0) |
| ensmallen | 0.8.101 | 2026-06-08T03:32 | 0.8.100 (2025-09-29, 0.0) | 0.8.99 (2025-09-28, 0.0) | 0.8.98 (2024-05-31, 0.0) |
| executor-engine | 0.3.4 | 2026-06-05T23:20 | 0.3.3 (2025-07-24, 0.0) | 0.3.2 (2025-03-21, 0.0) | 0.3.1 (2025-01-29, 0.0) |
| executor-engine | 0.3.5 | 2026-06-05T23:53 | 0.3.3 (2025-07-24, 0.0) | 0.3.2 (2025-03-21, 0.0) | 0.3.1 (2025-01-29, 0.0) |
| executor-http | 0.1.3 | 2026-06-05T23:21 | 0.1.2 (2024-09-18, 0.0) | 0.1.1 (2023-04-18, 0.0) | 0.1.0 (2023-04-18, 0.0) |
| executor-http | 0.1.4 | 2026-06-05T23:41 | 0.1.2 (2024-09-18, 0.0) | 0.1.1 (2023-04-18, 0.0) | 0.1.0 (2023-04-18, 0.0) |
| funcdesc | 0.2.2 | 2026-06-05T23:40 | 0.2.1 (2025-09-11, 0.0) | 0.2.0 (2025-09-11, 0.0) | 0.1.9 (2025-02-24, 0.0) |
| funcdesc | 0.2.3 | 2026-06-06T00:05 | 0.2.1 (2025-09-11, 0.0) | 0.2.0 (2025-09-11, 0.0) | 0.1.9 (2025-02-24, 0.0) |
| gpsea | 0.9.14 | 2026-06-08T03:23 | 0.9.13 (2026-01-21, 0.0) | 0.9.12 (2025-12-12, 0.0) | 0.9.11 (2025-08-04, 0.0) |
| guardrails-ai | 0.10.1 | 2026-05-12T01:24 | 0.10.0 (2026-04-03, 0.0) | 0.9.3 (2026-03-24, 0.0) | 0.9.2 (2026-03-16, 0.0) |
| litellm (B) | 1.82.7 | 2026-03-24T10:47 | 1.82.6 (2026-03-22, 0.0) | 1.82.5 (2026-03-21, 0.0) | 1.82.4 (2026-03-18, 0.0) |
| litellm (B) | 1.82.8 | 2026-03-24T11:15 | 1.82.6 (2026-03-22, 0.0) | 1.82.5 (2026-03-21, 0.0) | 1.82.4 (2026-03-18, 0.0) |
| magique | 0.6.8 | 2026-06-05T23:54 | 0.6.7 (2025-08-02, 0.0) | 0.6.6 (2025-07-27, 0.0) | 0.6.5 (2025-07-27, 0.0) |
| magique | 0.6.9 | 2026-06-05T23:41 | 0.6.7 (2025-08-02, 0.0) | 0.6.6 (2025-07-27, 0.0) | 0.6.5 (2025-07-27, 0.0) |
| magique-ai | 0.4.4 | 2026-06-05T23:42 | 0.4.3 (2025-07-27, 0.0) | 0.4.2 (2025-07-27, 0.0) | 0.4.0 (2025-07-27, 0.0) |
| magique-ai | 0.4.5 | 2026-06-05T23:44 | 0.4.3 (2025-07-27, 0.0) | 0.4.2 (2025-07-27, 0.0) | 0.4.0 (2025-07-27, 0.0) |
| mem8 | 6.0.1 | 2026-06-07T23:31 | 6.0.0 (2025-10-15, 0.0) | 5.1.0 (2025-10-14, 0.0) | 5.0.0 (2025-10-14, 0.0) |
| mistralai | 2.4.6 | 2026-05-12T00:21 | 2.4.5 (2026-05-07, 0.0) | 2.4.4 (2026-04-30, 0.0) | 2.4.3 (2026-04-27, 0.0) |
| num2words | 0.5.15 | 2025-07-28T14:06 | 0.5.14 (2024-12-17, 0.0) | 0.5.13 (2023-10-18, 0.0) | 0.5.12 (2022-08-19, 0.0) |
| num2words | 0.5.16 | 2025-07-28T17:00 | 0.5.14 (2024-12-17, 0.0) | 0.5.13 (2023-10-18, 0.0) | 0.5.12 (2022-08-19, 0.0) |
| okite | 0.0.7 | 2026-06-05T23:30 | 0.0.6 (2022-09-21, 0.0) | 0.0.3 (2022-09-21, 0.0) | 0.0.2 (2022-09-20, 0.0) |
| okite | 0.0.8 | 2026-06-05T23:40 | 0.0.6 (2022-09-21, 0.0) | 0.0.3 (2022-09-21, 0.0) | 0.0.2 (2022-09-20, 0.0) |
| pantheon-agents | 0.6.2 | 2026-06-05T23:53 | 0.6.0 (2026-05-24, 0.0) | 0.5.3 (2026-04-22, 0.0) | 0.5.2 (2026-04-14, 0.0) |
| pantheon-toolsets | 0.5.5 | 2026-06-05T23:51 | 0.5.4 (2025-08-25, 0.0) | 0.5.3 (2025-08-22, 0.0) | 0.5.2 (2025-08-15, 0.0) |
| pantheon-toolsets | 0.5.6 | 2026-06-06T00:07 | 0.5.4 (2025-08-25, 0.0) | 0.5.3 (2025-08-22, 0.0) | 0.5.2 (2025-08-15, 0.0) |
| pyphetools | 0.9.120 | 2026-06-08T03:43 | 0.9.119 (2025-11-03, 0.0) | 0.9.118 (2025-08-01, 0.0) | 0.9.117 (2025-01-19, 0.0) |
| telnyx | 4.87.1 | 2026-03-27T03:56 | 4.87.0 (2026-03-26, 0.0) | 4.86.1 (2026-03-25, 0.0) | 4.86.0 (2026-03-24, 0.0) |
| telnyx | 4.87.2 | 2026-03-27T04:26 | 4.87.0 (2026-03-26, 0.0) | 4.86.1 (2026-03-25, 0.0) | 4.86.0 (2026-03-24, 0.0) |

### npm (summary by incident; per-version rows in data/timing.csv)

| incident | malicious versions with minimal pair | packages | prev records NEAR / LATE / UNAVAILABLE | prev records created within 7 d of the malicious record | malicious records created |
|---|---|---|---|---|---|
| Shai-Hulud: Here We Go Again | 184 | 76 | 308 / 12 / 232 | 38 | 2026-08-04 |
| Mini Shai-Hulud is back | 125 | 78 | 239 / 0 / 136 | 10 | 2026-05-11 .. 2026-05-19 |
| Shai-Hulud (first wave) | 108 | 38 | 202 / 0 / 122 | 92 | 2025-09-14 .. 2025-09-16 |
| Sha1-Hulud: The Second Coming | 85 | 79 | 131 / 11 / 113 | 16 | 2025-11-24 |
| Mini Shai-Hulud | 36 | 22 | 48 / 0 / 60 | 38 | 2026-06-01 |
| CanisterWorm | 27 | 15 | 64 / 0 / 17 | 0 | 2026-03-20 .. 2026-03-21 |
| Miasma | 8 | 8 | 14 / 0 / 10 | 3 | 2026-06-04 .. 2026-06-24 |
| unnamed-2026-05-19 | 4 | 2 | 6 / 0 / 6 | 0 | 2026-05-19 .. 2026-05-20 |
| Shai-Hulud (wave unspecified) | 1 | 1 | 2 / 0 / 1 | 0 | 2026-05-18 |
| unnamed-2026-02-19 | 1 | 1 | 3 / 0 / 0 | 3 | 2026-02-17 |
| s1ngularity | 1 | 1 | 2 / 0 / 1 | 0 | 2025-08-27 |

### Sandbox / analysis version field

From the official docs and schema at commit c5c4500 (`docs/data_schema.md`,
`function/loader/dynamic-analysis-schema.json`, `pkg/api/analysisrun/result.go`), checked by
field name only: the dynamic-analysis record has `Package` (`Ecosystem`, `Name`, `Version`),
`CreatedTimestamp` and `Analysis`. **No field records the sandbox image or analyzer version.**
`Package.Version` is the version of the analysed package and `CreatedTimestamp` is when the
analysis ran. The static-analysis schema has `schema_version`, which versions the data format, not
the sandbox. Sandbox drift between the old and new records can therefore only be approximated from
`CreatedTimestamp` / object `timeCreated`.

## Benign baseline

**Selection rule** (`scripts/step0_baseline_select.py`, not hand-picked). The previous hand-written
list was replaced. Go through each ecosystem's public download ranking in order (npm:
npm-high-impact `lib/top.js` at the pinned commit; PyPI: top-pypi-packages 30-day) and take the
first 20 packages that:
1. are not named by any OSV malware advisory (MAL-*, GHSA CWE-506, listed PYSEC), and
2. have at least 2 clean releases published since 2022-01-01 in registry metadata.

The decision for each of the first 100 ranked names is in `data/baseline_ranking.csv`. Rule 1
excluded 9 npm packages (debug, ansi-styles, strip-ansi, ansi-regex, supports-color, chalk,
wrap-ansi, color-name, color-convert), all from the September 2025 compromise. It excluded no PyPI
package. Rule 2 excluded 4 npm and 1 PyPI package.

- npm: semver, minimatch, brace-expansion, commander, lru-cache, string-width, tslib, picomatch,
  emoji-regex, glob, type-fest, eslint-visitor-keys, ajv, minipass, source-map, balanced-match,
  readable-stream, which, find-up, locate-path.
- PyPI: boto3, packaging, typing-extensions, idna, urllib3, certifi, requests, charset-normalizer,
  cryptography, setuptools, cffi, pygments, pyyaml, python-dateutil, pluggy, botocore, pydantic,
  pycparser, click, pydantic-core.

**Existence and timing** (`data/baseline_coverage.csv`, per release in `data/baseline_records.csv`):

| | releases since 2022 | with a record | record created within 7 d of release | consecutive pairs | pairs with both records | packages with >= 1 such pair |
|---|---|---|---|---|---|---|
| npm | 654 | 279 (43%) | 279 | 634 | 126 | 17 of 20 |
| PyPI | 3,047 | 2,707 (89%) | 2,707 | 3,027 | 2,515 | 20 of 20 |

Every baseline record was created within 7 days of its release, so the benign pairs have the same
"analysed at release time" timing as the compromised-package previous versions. boto3 and botocore
supply 1,930 of the 2,515 PyPI pairs, and minimatch, type-fest and lru-cache supply 73 of the 126 npm
pairs, so the baseline needs a per-package cap as well. The npm baseline is smaller than the npm
candidate set (126 pairs against 321 minimal pairs), which matters if the comparison is made
within one ecosystem.

## Files

| file | content |
|---|---|
| `data/screen/` | screen, second-pass and classification outputs (names, dates, ids, matched phrase) |
| `data/candidates.csv` | candidates with tier, malicious versions, advisory ids/date |
| `data/packages.csv` | candidates + baseline packages |
| `data/registry_versions.csv` | version -> publish time from registry metadata |
| `data/record_index.csv` | bucket object names and timeCreated (no content) |
| `data/availability.csv` | per malicious version: prev1..prev3 and record existence |
| `data/clusters.csv` | incident, family, actor, date group per candidate |
| `data/campaign_counts.csv` | per-incident counts |
| `data/timing.csv` | per minimal-pair malicious version: timeCreated and lags |
| `data/excluded.csv` | excluded / UNCLEAR / UNAVAILABLE with reason |
| `data/baseline_ranking.csv`, `data/baseline_packages.csv` | baseline selection |
| `data/baseline_coverage.csv`, `data/baseline_records.csv` | baseline record existence and timing |

## Addendum: comparison release and analysis-time gaps

Added after the Step 0 commit (e34db7e). This section still uses metadata only: registry publish
times and record object `timeCreated`. No record content was read. Script:
`scripts/step0_addendum.py`. Outputs: `data/comparison.csv`, `data/benign_within.csv`,
`data/benign_baseline_pairs.csv`.

```sh
# npm baseline extended to 60 (same rule); only the 40 new packages are fetched and appended,
# so the Step 0 rows of registry_versions.csv / record_index.csv are unchanged
PYTHONPATH=scripts python3 scripts/step0_baseline_select.py scratch/rankings/npm-high-impact-top.js scratch/rankings/top-pypi-packages.min.json
cp data/packages.csv scratch/packages_step0.csv && python3 scripts/step0_packages.py
(echo "ecosystem,package"; comm -13 <(tail -n +2 scratch/packages_step0.csv | sort) <(tail -n +2 data/packages.csv | sort)) > scratch/packages_addendum.csv
python3 scripts/step0_registry_versions.py scratch/packages_addendum.csv scratch/registry_versions_addendum.csv
python3 scripts/step0_record_index.py      scratch/packages_addendum.csv scratch/record_index_addendum.csv
tail -n +2 scratch/registry_versions_addendum.csv >> data/registry_versions.csv
tail -n +2 scratch/record_index_addendum.csv      >> data/record_index.csv
PYTHONPATH=scripts python3 scripts/step0_baseline_coverage.py
PYTHONPATH=scripts python3 scripts/step0_addendum.py
```

### a) prev1 published within 7 days before the malicious version, PyPI

Same population and method as for npm: every malicious version with a minimal pair
(`data/timing.csv`, 36 PyPI rows), comparing malicious publish time minus prev1 publish time
against 7 days.

| | rows | malicious publish time known | prev1 within 7 d (publish time) | prev1 within 7 d (proxy) |
|---|---|---|---|---|
| npm | 580 | 580 | 170 | - |
| PyPI | 36 | 1 | 0 of 1 | 6 of 35 |

PyPI no longer lists publish times for deleted malicious releases. For the other 35 rows the
proxy is the malicious record's timeCreated. Records are created within hours of upload: every
npm malicious record, and the one PyPI record with a known publish time, was created within 0.1 d.
So PyPI has 6 of 36, against 170 of 580 for npm.

### b) Comparison release (one per candidate)

Rule: the **comparison release C0** is the latest clean release (by publish time) published at
least 14 days before the **incident's** earliest advisory date. That date is the earliest malware
advisory of any package in the same incident from `data/clusters.csv`, across both ecosystems. Clean means
not listed as malicious, not a pre-release, a valid version, and a known publish time. The
malicious side is the package's **earliest malicious version**: earliest registry publish time,
or record timeCreated where the release was deleted. The analysis-time gap is the malicious
record's timeCreated minus C0's record timeCreated, in days.

- **Eligible** = tier A, established, a record for the earliest malicious version, a record for C0,
  and C0 published before the earliest malicious version. The last condition is my addition, not
  part of the rule as given. It drops 2 packages (@asyncapi/studio, art-template) whose C0 came
  out after the malicious release but more than 14 days before the incident's advisory. Please
  confirm or remove it.
- 27 npm candidates (1 of them eligible) have a C0 whose version is higher than the malicious
  version (another release line), flagged `C0_VERSION_ABOVE_MALICIOUS`. The rule as given allows
  this. They remain eligible.

| | npm | PyPI |
|---|---|---|
| candidates | 1,449 | 32 |
| C0 found | 1,449 | 31 (ctx: registry 404) |
| C0 has a record | 456 | 27 |
| earliest malicious version has a record | 502 | 25 |
| ... only a later malicious version has a record | 423 | 0 |
| **eligible (tier A)** | **150** | **22** |

The earliest-version rule and the 14-day rule together cut the Step 0 minimal-pair set (343
packages, 15 incidents) to **172 packages in 13 incidents**. That is 7 families, or 5 linked
groups (the Shai-Hulud family, CanisterWorm and telnyx are linked through TeamPCP). The largest
single loss is 423 npm packages where the worm's first malicious release has no record but a
later one does. Capped at 10 per incident, the sample would hold **66 packages**.

| incident | family | candidates | earliest malicious recorded | C0 recorded | eligible | sampled (<=10) | gap <90 / 90-365 / >365 d | within-package pairs, both recorded (<90 / 90-365 / >365) |
|---|---|---|---|---|---|---|---|---|
| Mini Shai-Hulud is back | Shai-Hulud | 324 | 169 | 106 | 61 | 10 | 20 / 15 / 26 | 31 (24 / 5 / 2) |
| Sha1-Hulud: The Second Coming | Shai-Hulud | 449 | 202 | 134 | 53 | 10 | 5 / 11 / 37 | 22 (16 / 6 / 0) |
| Mini Shai-Hulud | Shai-Hulud | 45 | 39 | 19 | 18 | 10 | 5 / 11 / 2 | 25 (16 / 7 / 2) |
| Shai-Hulud (first wave) | Shai-Hulud | 135 | 48 | 49 | 14 | 10 | 6 / 6 / 2 | 10 (8 / 1 / 1) |
| CanisterWorm | CanisterWorm | 40 | 23 | 21 | 10 | 10 | 9 / 1 / 0 | 9 (7 / 2 / 0) |
| Shai-Hulud: Here We Go Again | Shai-Hulud | 352 | 18 | 97 | 6 | 6 | 4 / 0 / 2 | 5 (3 / 2 / 0) |
| Hades | Shai-Hulud | 4 | 3 | 4 | 3 | 3 | 0 / 3 / 0 | 6 (2 / 3 / 1) |
| Miasma | Miasma | 44 | 12 | 20 | 2 | 2 | 0 / 1 / 1 | 1 (0 / 0 / 1) |
| unnamed-2026-05-19 | - | 5 | 2 | 3 | 1 | 1 | 1 / 0 / 0 | 2 (2 / 0 / 0) |
| unnamed-2026-02-06 (dydx-v4-client) | - | 1 | 1 | 1 | 1 | 1 | 0 / 1 / 0 | 2 (1 / 1 / 0) |
| unnamed-2025-07-31 (num2words) | - | 1 | 1 | 1 | 1 | 1 | 0 / 1 / 0 | 2 (0 / 0 / 2) |
| unnamed-2026-03-27 (telnyx) | - | 1 | 1 | 1 | 1 | 1 | 1 / 0 / 0 | 2 (2 / 0 / 0) |
| Shai-Hulud (wave unspecified) | Shai-Hulud | 1 | 1 | 1 | 1 | 1 | 1 / 0 / 0 | 0 |

Tier-A incidents with no eligible package: IronWorm, s1ngularity, unnamed-2025-09-08 (the Qix
phishing), unnamed-2026-02-19 (cline), unnamed-2024-12-10 (ultralytics), and seven other unnamed
groups.

Tier B: **litellm**: C0 = 1.82.1, both recorded, gap 14.1 d. **ua-parser-js**: C0 = 0.7.28, no
records. **ctx**: no C0 (registry 404).

**The analysis-time gap is long on the compromised side.** For the 172 eligible packages the
median gap is 223 days: 52 are under 90 d, 50 are 90-365 d, and 70 are over 365 d. The 14-day
rule pushes the comparison release back, and many compromised packages had not released for
months. The benign pairs below are mostly under 90 d, so a comparison that is not stratified by
gap would confound package compromise with sandbox drift.

### c) npm baseline extended to 60 packages

Same rule (`scripts/step0_baseline_select.py`, `N = {"npm": 60, "pypi": 20}`, ranking window
widened to 200 names; the 60th selected package is at rank 86). The first 20 npm selections and
all 20 PyPI selections are unchanged. Rule 1 still excludes the same 9 npm packages, and rule 2
now excludes 17. `data/baseline_packages.csv`, `data/baseline_ranking.csv`,
`data/baseline_coverage.csv` and `data/baseline_records.csv` now hold the extended version. The
Step 0 numbers above are for the first 20.

The 40 added npm packages: p-limit, uuid, undici-types, ignore, iconv-lite, signal-exit, esbuild,
is-fullwidth-code-point, js-yaml, entities, globals, postcss, isexe, argparse, ws, mime-db,
resolve, agent-base, @esbuild/linux-x64, yargs-parser, mime-types, acorn, cross-spawn, react-is,
picocolors, fs-extra, hasown, nanoid, yargs, pretty-format, json5, https-proxy-agent,
path-to-regexp, punycode, js-tokens, cliui, @babel/types, chokidar, strip-json-comments,
webidl-conversions.

| npm baseline | 20 packages (Step 0) | 60 packages |
|---|---|---|
| releases since 2022 | 654 | 1,748 |
| with a record | 279 (43%) | 704 (40%) |
| record created within 7 d of release | 279 | 703 |
| consecutive pairs with both records | 126 / 634 | 301 / 1,688 |
| packages with >= 1 such pair | 17 | 45 |

### d) Analysis-time gap of benign pairs

**Within-package benign pairs** (the candidates' own clean history, built the same way as C0). C1 is
the latest clean release published at least 14 days before C0, and C2 the same for C1. The pairs
are C1->C0 and C2->C1. The gap is the newer record's timeCreated minus the older one's.

| | pairs | both recorded | packages | incidents | gap <90 / 90-365 / >365 d |
|---|---|---|---|---|---|
| all candidates | 2,562 | 300 | 223 | 18 | 222 / 66 / 12 |
| eligible candidates only | 303 | 117 | 75 | 12 | 81 / 27 / 9 |

**Top-download baseline pairs** (consecutive clean releases since 2022, both recorded):

| | recorded pairs | packages | gap <90 / 90-365 / >365 d | of which release spacing >= 14 d | packages | gap <90 / 90-365 / >365 d |
|---|---|---|---|---|---|---|
| npm (60 packages) | 301 | 45 | 255 / 38 / 8 | 133 | 40 | 88 / 38 / 7 |
| PyPI (20 packages) | 2,515 | 20 | 2,435 / 68 / 12 | 266 | 17 | 190 / 67 / 9 |

No benign pair has a negative gap: the newer release's record is always the later one.

**What this means for the design.** The >365 d stratum holds 70 eligible compromised comparisons
but only 9 within-package benign pairs from eligible candidates, plus 7 (npm) and 9 (PyPI)
top-download pairs with 14-day spacing. Benign evidence about drift over a gap of more than a year
will be thin in every source.

| file (addendum) | content |
|---|---|
| `data/comparison.csv` | per candidate: incident date, earliest malicious version, C0, record existence, gap, flags, eligibility |
| `data/benign_within.csv` | per candidate: C1->C0 and C2->C1 pairs, record existence, gap |
| `data/benign_baseline_pairs.csv` | top-download consecutive pairs with both records: release spacing and gap |
