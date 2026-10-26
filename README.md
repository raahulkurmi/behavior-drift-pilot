# behavior-drift-pilot

## TL;DR

- **Question.** Does a compromised release of an established npm or PyPI package behave differently at install time from its own earlier release, and how often do harmless releases change the same way?
- **What was done.** Published OpenSSF package-analysis sandbox records were read, and each compromised release was compared with an earlier clean release and with two benign baselines. No package was installed or run.
- **Headline.** The main prediction failed: 7 of 12 evaluable incidents met the majority rule, against a threshold of 80%. At package level, 37 of 44 compromised releases showed a new install-time capability, against 12.5% (7 of 56) of benign pairs from the same packages. The pooled benign rate rose from 0.139 under 90 days between analyses to 0.444 over a year, about 3x; with no sandbox version in the records, this is the pilot's proxy for sandbox drift ([results/RESULTS.md](results/RESULTS.md)).
- **What it does not show.** It builds no detector. The sample is 13 clustered incidents, 22 of 66 sampled pairs could not be evaluated, and only install-time behaviour is seen ([docs/LIMITATIONS.md](docs/LIMITATIONS.md)).
- **Pre-registration.** [docs/PREREGISTRATION.md](docs/PREREGISTRATION.md), commit `cfa9957`, pushed to GitHub at 2026-10-17 14:24:52 UTC ([timeline below](#pre-registration-and-timeline)).

This pilot asks whether a compromised release of an established npm or PyPI package behaves
differently at install time from the package's own earlier release, and how often harmless
releases change in the same way. **The main pre-registered prediction failed:** only 7 of 12
evaluable incidents (58%) met the majority rule, against a threshold of 80%. At the package level,
37 of 44 compromised releases showed a new install-time capability, against 12.5% of benign
release pairs from the same packages.

## Question and why it matters

A release can come from the expected place and still behave in a new way. Provenance checks
(signatures, attestations, trusted publishing) confirm where a release came from, not what it
does. In December 2024, compromised releases of the `ultralytics` package reached PyPI through
the project's own release pipeline
([PyPI's public analysis](https://blog.pypi.org/posts/2024-12-11-ultralytics-attack-analysis/)).
A behaviour check is only useful if harmless releases rarely trigger it, so this pilot measures
the benign rate as carefully as the compromised one.

## What was done

1. **Find compromised releases.** Malware reports come from the [OSV](https://osv.dev/) export,
   which includes [ossf/malicious-packages](https://github.com/ossf/malicious-packages) and GitHub
   malware advisories. Release dates come from npm and PyPI registry metadata.
2. **Keep established packages that were taken over.** A package counts as established if it had
   at least 3 clean releases before the first malicious one, the earliest at least 180 days
   earlier. It counts as taken over if an advisory explicitly describes an unauthorised release
   (for example a stolen account or a worm).
3. **Find the analysis records.** The
   [OpenSSF package-analysis](https://github.com/ossf/package-analysis) project installs packages
   in a sandbox and publishes what it observed. This pilot only reads those published records.
4. **Compare each malicious release with an earlier clean release.** That release is the latest
   clean one published at least 14 days before the incident's first advisory. The sample has at
   most 10 packages per incident, drawn with a fixed seed (20261017).
5. **Build two benign baselines:**
   - *within-package:* earlier consecutive clean releases of the same packages;
   - *top-download:* consecutive releases of the most-downloaded npm and PyPI packages with no
     malware report (rankings:
     [npm-high-impact](https://github.com/wooorm/npm-high-impact),
     [top-pypi-packages](https://hugovk.github.io/top-pypi-packages/)), matched on the time
     between analyses.
6. **Look at four kinds of install-time behaviour,** each normalised by fixed rules:
   - network destinations (registrable domains);
   - file writes (outside temporary, cache and install directories);
   - attempted reads of a fixed list of credential files;
   - process spawns.

   A *new capability* is an item present in the newer record and absent in the older one.
7. **Split by the time between the two analyses** (under 90 days, 90-365 days, over a year). The
   sandbox itself changes over time, so a long gap can produce changes on its own.

The sample has 66 compromised pairs from 13 incidents, drawn from 172 eligible packages
(`results/gap_stats.csv`, `results/EXPLORATORY.md`).

## Safety

No package archive (tarball, wheel or sdist) was downloaded, installed, executed or unpacked.
Only published analysis records, advisories and registry metadata were read. No URL, domain or IP
address found inside a record was ever requested.

## Pre-registration and timeline

The design, normalisation rules, metrics and numeric predictions were written in
[docs/PREREGISTRATION.md](docs/PREREGISTRATION.md) and pushed before any analysis record was read.
GitHub records when each commit was pushed (the repository's
[activity log](https://github.com/raahulkurmi/behavior-drift-pilot/activity)). Those push times
are evidence from outside this repository that the pre-registration and its amendments existed
before the record pins and the results. They show when commits reached GitHub, not what was done
locally in between; the latter rests on the commit history and the author's account.

| step | commit | pushed (GitHub /activity, UTC) |
|---|---|---|
| Step 0: data availability | `e34db7e84fe14ea0a8aa74b07ff9b9a705827fda` | 2026-10-17 13:40:05 |
| Step 0 addendum | `16505376ba622aa7ada6acfb042fb7655770f53c` | 2026-10-17 14:22:52 |
| Pre-registration | `cfa9957212295a0d15b439bcc52200fb5eeaa5c0` | 2026-10-17 14:24:52 |
| Pre-registration amendment | `4fd0d2a99f124a7813adab4c0a16be1477b473a5` | 2026-10-17 15:56:25 |
| Pre-registration amendment 2 | `830e3b47c367efcc2b7bacf210ff2c8b41b7cc46` | 2026-10-17 16:09:03 |
| Sample | `f78d0bb822dcd48d1abe743b02b988e1af0bb2a2` | 2026-10-17 16:09:44 |
| Normalisation and tests | `af5d43a9666b97cfbfbc6b593d88e83e5a32f706` | 2026-10-17 16:12:08 |
| Raw data pins (first records fetched) | `22e150f3c80b1048b6cf603d936e397d65e6cd40` | 2026-10-17 16:15:12 |
| Results | `5a7cae768c275e1bbb4240c1ee3730bbadf17f6a` | 2026-10-17 16:20:18 |
| Docs | `ded06407011454947eb48b341f7ca7f11d0a9830` | 2026-10-17 16:38:52 |
| Audit fixes | `c1c08e41323b3650b1ad938d71e1950153284d18` | 2026-10-18 13:07:35 |

## Results

Copied from [results/RESULTS.md](results/RESULTS.md). M1 counts incidents in which more than half
of the sampled packages show a new capability. M1p counts compromised pairs. M2 counts
within-package benign pairs, and M3 top-download benign pairs. Values in brackets are 95%
intervals. "Holds clearly" would mean the whole interval meets the threshold; no prediction did.

| prediction | threshold | result | outcome |
|---|---|---|---|
| H1 | M1 >= 0.80 | M1 = 7/12 = 0.583 [0.320, 0.807] | **fails** |
| H2 | M2 <= 0.30 pooled and M2 <= 0.20 in <90 d | M2 = 7/56 = 0.125 [0.037, 0.228]; <90 d: 4/39 = 0.103 [0.000, 0.225] | **holds** |
| H3 | benign rate >365 d minus <90 d >= 0.15 | on M2 and M3 pooled: >365 d 8/18 = 0.444, <90 d 15/108 = 0.139, difference +0.306 [+0.080, +0.532] | **holds** |
| H4 | in <90 d, M1p - M2 >= 0.50 | M1p 19/22 = 0.864, M2 4/39 = 0.103, difference +0.761 [+0.470, +0.923] | **holds** |
| H5 | new credential read <= 0.05 (M2 and M3); new network destination <= 0.15 (M2) | credential M2 1/56 = 0.018 [0.000, 0.057], M3 5/145 = 0.034 [0.008, 0.065]; network M2 1/56 = 0.018 [0.000, 0.056] | **holds** |

**What held and what failed.** Harmless releases of the same packages rarely showed new
install-time behaviour: 12.5% of pairs, and 20.0% for the top-download packages. When the two
analyses were close in time, compromised releases stood far apart from benign ones (H4). The
incident-level prediction failed, because in several incidents half or fewer of the evaluable
packages were positive.
Some incidents also could not be evaluated, and with all unevaluable pairs counted either way the
incident share stays between 5/13 and 9/13, below the threshold
([results/EXPLORATORY.md](results/EXPLORATORY.md)). The benign rate rose from 0.139 to 0.444 when
the analyses were more than a year apart. A behaviour-change signal is therefore only meaningful
when both analyses are recent.

## Limitations

Details in [docs/LIMITATIONS.md](docs/LIMITATIONS.md).

- **Clustered sample:** 13 incidents, most of them waves of one worm family; the 12 evaluable
  incidents form 5 linked groups.
- **Unevaluable pairs:** only 44 of the 66 sampled compromised pairs could be evaluated; the rest
  have a record whose analysis ended in an error.
- **Harness masking:** the package managers read `~/.npmrc` (npm) and `~/.netrc` (PyPI) during
  every install (`results/credential_masking.csv`), so a payload reading those files cannot show
  up as new.
- **Install phase only:** behaviour that starts on import, at runtime, in CI only or after a delay
  is not seen.
- **No sandbox-version field:** the records do not say which sandbox version produced them, so
  sandbox drift is approximated by the time between analyses.

## Deviations and exploratory results

- [docs/DEVIATIONS.md](docs/DEVIATIONS.md) lists every decision the pre-registration did not
  settle, and how each was handled.
- [results/EXPLORATORY.md](results/EXPLORATORY.md) holds analyses added after the results and
  **not pre-registered**: per-incident tables, missingness bounds and reruns under alternative
  readings of the rules.

From commit `c1c08e4` on, every results cell that counts fewer than 5 units is shown as `<5`.
Earlier commits (`5a7cae7`, `ded0640`) contain those cells unsuppressed, and history has not been
rewritten.

## Related work

This pilot builds no detector. Under a pre-registered design it measures how often benign
releases show the same kind of install-time change, and how that rate depends on the time
between analyses. All its data comes from records that were already published.

- **Garrett et al., 2019** ([ICSE-NIER](https://doi.org/10.1109/ICSE-NIER.2019.00012)) flag
  suspicious npm updates by comparing an update's features with the package's earlier versions.
- **Amalfi** (Sejfia & Schäfer, [ICSE 2022](https://doi.org/10.1145/3510003.3510104)) detects
  malicious npm packages with machine-learning classifiers, reproducibility checks and clone
  detection.
- **Froh, Gobbi & Kinder** ([SCORED 2023](https://doi.org/10.1145/3605770.3625211)) use
  differential static analysis between versions to detect malicious updates.
- **RogueOne** ([ICSE 2024](https://doi.org/10.1145/3597503.3639199)) detects rogue npm updates
  with differential data-flow analysis across trust domains.
- **DySec** ([IEEE TIFS](https://doi.org/10.1109/TIFS.2026.3654388)) detects malicious PyPI
  packages with machine learning on dynamic-analysis traces.
- **Socket** ([socket.dev](https://socket.dev), [GitHub](https://github.com/SocketDev)) is a
  commercial service that reports package capabilities and changes between versions.
- **OpenSSF package-analysis** ([GitHub](https://github.com/ossf/package-analysis)) runs packages
  in a sandbox and publishes the records this pilot reads.

## Repository layout

| path | content |
|---|---|
| [docs/](docs/) | [Step 0 data availability](docs/STEP0_DATA_AVAILABILITY.md), [pre-registration](docs/PREREGISTRATION.md), [deviations](docs/DEVIATIONS.md), [limitations](docs/LIMITATIONS.md), [summary](docs/SUMMARY.md) |
| [results/](results/) | aggregate results ([RESULTS.md](results/RESULTS.md), `*.csv`) and [EXPLORATORY.md](results/EXPLORATORY.md) |
| [scripts/](scripts/) | Step 0 metadata scripts (`step0_*.py`), [sample.py](scripts/sample.py), [normalise.py](scripts/normalise.py), [fetch_records.py](scripts/fetch_records.py), [results.py](scripts/results.py), [gap_stats.py](scripts/gap_stats.py), [exploratory.py](scripts/exploratory.py) |
| [scripts/screen/](scripts/screen/) | first-pass screening of OSV reports and registry history |
| [tests/](tests/) | unit tests of the normalisation rules on hand-written synthetic records |
| [data/](data/) | metadata: candidates, clusters, sample, comparison releases, record pins ([record_pins.csv](data/record_pins.csv)) |
| [requirements.txt](requirements.txt) | pinned third-party dependency |
| [LICENSE](LICENSE) | MIT licence for the code |

## Reproduce

Tested with Python 3.13.9 only. The Step 0 scripts need `packaging`; everything else uses only
the standard library. Run from the repository root; `scratch/` is git-ignored and holds downloads
and record contents.

```sh
python3 -m pip install -r requirements.txt          # packaging==24.2
mkdir -p scratch/psl && curl -sSfo scratch/psl/public_suffix_list.dat \
  https://raw.githubusercontent.com/publicsuffix/list/2dbfce14c57bcea83fef2be3bdcb560667d7ef93/public_suffix_list.dat
python3 -m unittest discover -s tests               # normalisation rules (synthetic records)
python3 scripts/sample.py                           # redraws the pre-registered sample (seed 20261017)
python3 scripts/results.py                          # re-fetches pinned records, writes results/
python3 scripts/gap_stats.py                        # results/gap_stats.csv
python3 scripts/exploratory.py                      # results/EXPLORATORY.md (not pre-registered)
```

- **How verification works.** `scripts/results.py` fetches each record named in
  `data/record_pins.csv` from the public `ossf-malware-analysis-results` bucket. It compares the
  download's MD5 with the pinned `md5Hash`, and stops if any record differs, for example because
  the object was rewritten in the bucket. The Public Suffix List file is checked against a pinned
  SHA-256.
- **Exploratory script.** `scripts/exploratory.py` uses the copies in `scratch/records/` when
  they are present and match their pins, and fetches the rest.
- **Run time.** In earlier runs, `results.py` took between about 2 and 15 minutes, almost all of
  it network time. `exploratory.py` took about 1 minute with the records cached.
- **Fresh data.** `scripts/fetch_records.py` re-pins the records and overwrites
  `data/record_pins.csv`, so use it only to start from new data. The Step 0 commands are in
  [docs/STEP0_DATA_AVAILABILITY.md](docs/STEP0_DATA_AVAILABILITY.md).

## How this fits

This pilot is one of several studying one question: when a security check passes, what has it
actually established? The question started from a threshold-signing project,
[threshold-signing-k8s](https://github.com/raahulkurmi/threshold-signing-k8s). Here the check
that passes is provenance: a compromised release can come from the project's own pipeline and
still pass it, so the pilot asks whether a change in install-time behaviour adds information.
In these records it did, but only when both analyses were recent.

## Citation and contact

Author: Rahul Kurmi ([github.com/raahulkurmi](https://github.com/raahulkurmi)). Please cite
the commit you used.

```bibtex
@misc{kurmi2026behaviordrift,
  author       = {Rahul Kurmi},
  title        = {behavior-drift-pilot: a pre-registered pilot on install-time behaviour changes
                  in compromised npm and PyPI releases},
  year         = {2026},
  howpublished = {\url{https://github.com/raahulkurmi/behavior-drift-pilot}}
}
```

## License

The code is under the MIT License ([LICENSE](LICENSE)). Third-party data keeps its original terms:
OSV and ossf/malicious-packages records, OpenSSF package-analysis records, npm and PyPI registry
metadata, the download rankings, and the Public Suffix List.
