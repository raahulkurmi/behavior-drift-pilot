# Pre-registration: install-time behaviour drift in compromised releases

Status: draft for review, written before any behaviour field of any analysis record has been read.
Data availability and every count below come from Step 0 and the Step 0 addendum
(`docs/STEP0_DATA_AVAILABILITY.md`, commits e34db7e and 1650537), which used metadata only.

## 1. Question

When an established package is compromised, does the malicious release show install-time
behaviour that the package's own earlier release did not, and how often do benign release pairs
show the same kind of change? The informative quantity is the **benign rate**: how often a new
capability appears without a compromise, overall and as a function of the time between the two
analyses.

## 2. Data

- Records: OpenSSF package-analysis dynamic-analysis results, public bucket
  `ossf-malware-analysis-results`, objects `<ecosystem>/<package>/<version>.json`, read anonymously.
  No cloud account is used, no package archive is downloaded or run, and no record is generated.
  A missing record is UNAVAILABLE.
- Phase: only `Analysis["install"]`. The `import` and `execute` phases are not used.
- Field names come from `docs/data_schema.md` and `function/loader/dynamic-analysis-schema.json`
  of ossf/package-analysis at commit c5c45008da694036d701ba76fe9567fc8a5b9675. If the stored
  records use different key names, a key-name mapping is written down in section 11 before any
  comparison is computed, based on key names only.

## 3. Units and sample

**Candidates eligible for the primary analysis**: rows of `data/comparison.csv` with
`eligible_primary = YES`. That means 172 packages (npm 150, PyPI 22) in 13 incidents, all of them:
- tier A;
- established;
- with a record for the earliest malicious version and for the comparison release;
- with the comparison release published before the earliest malicious version.

Tier B (litellm, the only tier-B package with records) is reported separately and descriptively.

- **Primary unit: incident.** An incident is a named campaign wave, else an unnamed date group
  (`data/clusters.csv`).
- **Sensitivity units:**
  - family: all waves of one worm family together, 7 groups among the eligible packages;
  - linked group: incidents sharing a family or a named actor, 5 groups.
- **One malicious version per package**: the earliest malicious version, defined in the addendum
  as the earliest registry publish time, or record timeCreated for a deleted release.
- **Sample**: at most 10 packages per incident, drawn at random with a fixed seed.

```python
SEED = 20261017
import csv, random
rows = [r for r in csv.DictReader(open("data/comparison.csv")) if r["eligible_primary"] == "YES"]
by_inc = {}
for r in rows:
    by_inc.setdefault(r["incident"], []).append((r["ecosystem"], r["package"]))
sample = {}
for inc, pk in sorted(by_inc.items()):
    pk = sorted(pk)
    rng = random.Random(f"{SEED}:{inc}")          # one generator per incident, order-independent
    sample[inc] = pk if len(pk) <= 10 else sorted(rng.sample(pk, 10))
```

Expected sample: 66 packages. Incidents capped at 10: Mini Shai-Hulud is back, Sha1-Hulud: The
Second Coming, Mini Shai-Hulud, Shai-Hulud (first wave), CanisterWorm. Shai-Hulud: Here We Go
Again contributes 6, and the other seven incidents contribute 1-3 packages each. The sample is drawn by `scripts/sample.py` (the code above) and committed before any
record is read.

## 4. Comparisons

- **Compromised pair**: comparison release C0 (older) -> earliest malicious version (newer).
  C0 is the latest clean release published at least 14 days before the incident's earliest
  advisory date (Step 0 addendum, rule b).
- **Primary benign comparator: within-package pairs** of the sampled packages. C1 is the latest
  clean release published at least 14 days before C0, and C2 the same for C1. The pairs are
  C1 -> C0 and C2 -> C1 (the "prev2->prev1, prev3->prev2" pairs, every step at least 14 days
  apart), and only pairs where both releases have a record are used. `data/benign_within.csv`
  lists them. Across all 172 eligible packages, 117 such pairs exist; the sampled subset is fixed
  by the seed.
- **Secondary benign comparator: top-download baseline** (`data/baseline_packages.csv`: npm 60,
  PyPI 20, chosen by rule). The pairs are consecutive clean releases since 2022 with both records
  and release spacing of at least 14 days (`data/benign_baseline_pairs.csv`), at most 5 per
  package, gap-matched:
  1. Target shares = the share of sampled compromised pairs in each gap stratum (<90 d,
     90-365 d, >365 d).
  2. For each package, its 5 slots are split across strata by those shares (largest-remainder
     rounding).
  3. Within each stratum, pairs are drawn with `random.Random(f"{SEED}:{ecosystem}:{package}:{stratum}")`.
  4. A slot whose stratum has no pairs in that package stays empty; it is not refilled from
     another stratum.
- **Analysis-time gap** of a pair = the newer record's timeCreated minus the older record's
  timeCreated, in days. Strata: <90 d, 90-365 d, >365 d (on the absolute value).
- **Evaluable pair**: both records exist, both contain `Analysis["install"]`, and both have
  `Status == "completed"`. Other pairs are counted and reported as not evaluable. A package whose
  compromised pair is not evaluable stays in its incident's denominator only as "not evaluable".
  The majority rule in section 6 uses evaluable packages only.

## 5. Behaviour categories and normalisation

All four categories come from `Analysis["install"]` and use only these fields: `Files[].Path`,
`Files[].Read`, `Files[].Write`, `Sockets[].Address`, `Sockets[].Hostnames`,
`DNS[].Queries[].Hostname` and `Commands[].Command`. `Stdout`, `Stderr`, `Environment`,
`Files[].Delete`, `Sockets[].Port` and `DNS[].Class` are not used. Each record is reduced to one
set of items per category. The rules are applied in the order given.

### 5.1 Network destinations

Sources: `Sockets[]` and `DNS[].Queries[].Hostname`.

- **N1. Hostnames.** Lowercase each hostname, strip a trailing dot, and map it to its
  **registrable domain** (eTLD+1) using the Public Suffix List, ICANN and private sections, at the
  commit of github.com/publicsuffix/list current on the day analysis starts. That commit is
  recorded in section 11. A hostname that is itself a public suffix, or cannot be parsed, is kept
  as is.
- **N2. Sockets with a hostname.** For each socket with a non-empty `Hostnames`, the items are the
  registrable domains of its hostnames. The address is then ignored.
- **N3. Sockets without a hostname.** Classify `Address`:
  - loopback (127.0.0.0/8, ::1), private (10/8, 172.16/12, 192.168/16, 100.64/10, fc00::/7),
    link-local (169.254/16, fe80::/10), unspecified (0.0.0.0, ::) and multicast: **dropped**,
    except 169.254.169.254 and fd00:ec2::254, which become the item `cloud-metadata`;
  - any other valid IP becomes the single item `ip-literal` (one item regardless of the address);
  - a value that is not an IP address is dropped.
- **N4. Self-traffic dropped.** Items equal to these registrable domains are removed:
  - npm registry: `npmjs.org`, `npmjs.com`, `yarnpkg.com`;
  - PyPI: `pypi.org`, `pythonhosted.org`;
  - sandbox: loopback, private and link-local traffic (already dropped in N3, which covers the
    sandbox's own DNS resolver and gateway).
- **N5.** Ports are ignored. A destination is a registrable domain, never an IP address, except
  for the two tokens above.

### 5.2 File writes

Source: `Files[]` with `Write == true`.

- **F1. Path normalisation.** Collapse repeated `/`, resolve `.` and `..` lexically, and replace a
  leading `/root/` or `/home/<name>/` with `~/`.
- **F2. Dropped paths** (after F1):
  - **temporary:** anything under `/tmp/`, `/var/tmp/`, `/dev/`, `/proc/`, `/sys/`, `/run/`;
  - **cache:** anything under `~/.npm/`, `~/.cache/`, `~/.node-gyp/`, `~/.yarn/`,
    `~/.bun/install/cache/`, any path containing `/__pycache__/`, any path ending in `.pyc`;
  - **package-install directories:** any path containing `/node_modules/`, `/site-packages/` or
    `/dist-packages/`, anything under `/app/.pyenv/` (the sandbox's pip virtualenv) or
    `/usr/local/lib/node_modules/`, and the files `/app/package.json` and
    `/app/package-lock.json` written by the harness (`npm init --force`, `npm install` in `/app`).
- **F3. Generalisation.** Replace every run of digits with `N`. Replace every path segment, or
  part of one, that is a run of at least 16 characters from `[A-Za-z0-9_-]` containing both
  letters and digits with `X`. The resulting path is the item.

### 5.3 Credential-file reads

Source: `Files[]` with `Read == true`, path after F1. The item is the **list entry matched**, not
the full path. Fixed list (glob, `*` = one segment, `**` = any depth):

| entry | entry |
|---|---|
| `~/.npmrc` | `~/.config/gcloud/**` |
| `~/.pypirc` | `~/.azure/**` |
| `~/.netrc` | `~/.kube/config` |
| `~/.git-credentials` | `~/.docker/config.json` |
| `~/.gitconfig` | `~/.config/gh/hosts.yml` |
| `~/.ssh/*` | `~/.bash_history`, `~/.zsh_history` |
| `~/.aws/credentials`, `~/.aws/config` | `/etc/shadow` |
| `/proc/*/environ` | any path whose last segment is `.env` or starts with `.env.` |

### 5.4 Process spawns

Source: `Commands[].Command` (the argv passed to execve).

- **P1.** The executable is the last path segment of `argv[0]`, lowercased, with a trailing
  version suffix removed when it follows a letter (regex `(?<=[a-z])[0-9][0-9.]*$`; so
  `python3.11` becomes `python` and `node20` becomes `node`).
- **P2.** If the executable is `env`, skip `env` and any following `NAME=value` arguments, and
  apply P1 to the next argument.
- **P3.** If the executable is `sh`, `bash`, `dash` or `zsh` and `argv[1] == "-c"`, the item is
  P1 applied to the first word of `argv[2]` (split with `shlex.split`, or on whitespace if that
  fails). The shell itself is not an item. This unwrapping is applied once.
- **P4.** Otherwise the item is the executable from P1. The sandbox harness
  (`/usr/local/bin/analyze-*`, `npm init`, `npm install`, `pip install`) runs in both records of a
  pair and cancels by construction; nothing else is dropped.

### 5.5 New capability

For a pair (older record O, newer record N) and a category c, the **new items** are items(N, c)
minus items(O, c), after normalisation. The pair shows a **new capability in c** if that set is
non-empty, and a **new capability** if this holds for at least one of the four categories.

## 6. Metrics

- **M1. Compromised, primary.** A sampled package is positive if its compromised pair shows a new
  capability. An incident is positive if more than half of its evaluable sampled packages are
  positive (a tie is not positive). M1 is the share of incidents that are positive, with a Wilson
  95% interval. It is also reported per category, and with families and linked groups as the
  unit: there, the majority is taken over the sampled packages of all incidents in the group.
- **M2. Benign, primary.** M2 is the share of evaluable within-package pairs of the sampled
  packages that show a new capability. The 95% interval comes from a cluster bootstrap over
  packages: 10,000 resamples, `random.Random(SEED)`. A package-weighted share (each package's own
  share, averaged) is reported as a sensitivity. M2 is also reported per category.
- **M3. Benign, secondary.** The same as M2, on the gap-matched top-download pairs.
- **Stratification.** M1, M2 and M3 are each reported per gap stratum (<90 d, 90-365 d, >365 d).
  For M1 within a stratum, an incident is evaluated on its sampled packages whose compromised pair
  falls in that stratum, and incidents with none are omitted from that stratum. Each metric is
  also reported per ecosystem and pooled.
- A cell with fewer than 5 incidents (M1) or fewer than 10 pairs (M2/M3) is reported as counts
  only and marked "not evaluable" for the predictions.

## 7. Predictions

A prediction **holds** if the point estimate meets the threshold, and **holds clearly** if the
whole 95% interval also meets it. Otherwise it fails, unless it is not evaluable.

- **H1 (compromised side; expected, not the informative test).** M1 >= 0.80 overall.
  Install-hook worms (Shai-Hulud waves, CanisterWorm) add install-time behaviour by design, so H1
  is expected to hold. A pass shows that the method detects such payloads; it says nothing about
  specificity.
- **H2 (benign rate).** M2 <= 0.30 pooled over strata, and M2 <= 0.20 in the <90 d stratum.
- **H3 (gap stratification).** The benign rate in the >365 d stratum is at least 15 percentage
  points higher than in the <90 d stratum: drift in the sandbox and the base image adds new items
  without any compromise. It is evaluated on M2. If M2 has fewer than 10 pairs in the >365 d
  stratum, it is evaluated on M2 and M3 pooled, and this is said in the report.
- **H4 (contrast within the shortest gap).** In the <90 d stratum, M1 - M2 >= 0.50.
- **H5 (category specificity, benign).** A new credential-file read appears in <= 5% of benign
  pairs (M2 and M3 each), and a new network destination in <= 15% of benign pairs (M2).

No other hypothesis is tested. Any further analysis is labelled exploratory.

## 8. Procedure and order

1. Commit `scripts/sample.py` and the drawn sample (names stay in the private repository).
2. Commit the normalisation code (section 5) and unit tests built from hand-written synthetic
   records, before any real record is read.
3. Download the needed records anonymously, then compute M1-M3 and evaluate H1-H5 in one run. The
   per-pair item sets stay private.
4. Any deviation from this document is written in section 11 with its date and reason before the
   affected numbers are reported.

## 9. Public outputs

Only aggregate behaviour results are published: shares, intervals, and counts per category,
stratum and ecosystem. Package names appear only as citations of public advisories (advisory id,
with the package named as in that advisory). No per-package behaviour, item list, domain, path or
command is published.

## 10. Limitations

- **Clustered sample.** 13 incidents, 7 families and 5 linked groups. One linked group (the
  Shai-Hulud family plus TeamPCP incidents) holds most eligible packages, and several incidents
  contribute a single package. Incident-level shares rest on few units, and their intervals are
  wide.
- **No sandbox-version field.** The schema records `CreatedTimestamp` but no sandbox-image or
  analyzer version. Drift is approximated by the analysis-time gap only. The compromised pairs have
  long gaps (median 223 d among eligible packages) and the benign pairs mostly short ones, which is
  why every comparison is stratified.
- **Sandbox evasion.** A payload that detects the sandbox and does nothing looks like no new
  capability.
- **CI-only or time-triggered payloads.** Code that runs only under CI variables, on a schedule or
  after a delay may not run during the analysed install.
- **Import and runtime-only behaviour.** Only the install phase is compared. A payload that runs
  on import or at runtime is invisible here by design.
- **Normalisation choices.** Dropping registry domains hides exfiltration or self-publishing
  through the registry. Dropping install directories hides writes inside them. Generalising paths
  can merge distinct files. All of these push toward fewer new capabilities on both sides.
- **Record selection.** Records exist only for releases the pipeline saw: about 40% of npm
  baseline releases and 89% of PyPI releases. The earliest-malicious-version rule excludes 423 npm
  packages whose first malicious release has no record.
- **Advisory-defined labels.** Malicious versions, incidents and actors come from advisory text.
  A malicious release missing from the advisories could be taken as clean.

## 11. Deviations and recorded parameters

- (open) Eligibility includes "C0 published before the earliest malicious version"; this was added
  in the Step 0 addendum and is pending review.
- Public Suffix List commit: to be recorded on the day analysis starts.
