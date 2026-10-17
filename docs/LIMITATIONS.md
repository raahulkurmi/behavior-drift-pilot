# Limitations

The limitations listed in the pre-registration (section 10) all apply. This file restates them
with what the run showed.

## Sample and independence

- **Few, clustered units.**
  - The sample has 13 incidents, of which 12 are evaluable. At the stricter units there are 6
    families and 5 linked groups. One linked group, the Shai-Hulud worm family plus the TeamPCP
    campaigns, holds most of the sampled packages.
  - The incident-level result is sensitive to the unit. With incidents as the unit it is 7 of 12;
    with families, 3 of 6; with linked groups, 2 of 5.
  - Incident-level intervals are wide; for M1 the 95% interval is 32-81%.
- **Evaluability.** 22 of 66 sampled compromised pairs were not evaluable, because a record's
  install phase ended in `error_analysis`. On the benign side this affected 13 of 69
  within-package pairs and 1 of 146 baseline pairs. Unevaluable records are not missing at random:
  the rate is higher for PyPI.
- **Small strata.** Only 4 within-package benign pairs fall in the >365 d stratum, so H3 was
  evaluated on within-package and baseline pairs pooled (18 pairs in that stratum).

## What the records can see

- **Install phase only.** Payloads that run on import, at runtime, under CI variables, after a
  delay or on a schedule are invisible. The low incident rate for PyPI (2 of 6 incidents) is
  consistent with Python payloads that run on import rather than at install. The run cannot
  confirm this, because the import phase was not analysed.
- **Sandbox evasion.** A payload that detects the sandbox and does nothing looks like no change.
- **No sandbox-version field.** Drift is approximated by the time between the two analyses. The
  benign rate rose from 14% (<90 d) to 44% (>365 d) in the pooled benign pairs, so drift is real
  and of the same order as some compromised-side effects. The compromised pairs have long gaps
  (median 223 days among eligible packages). Comparisons are therefore stratified, and only the
  <90 d stratum gives a contrast with little drift.
- **Bait changes.** The SSH-key and AWS-variable baits were added to the sandbox in late 2023. The
  post-2024 sensitivity analysis (both records created on or after 2024-01-01) gives similar
  numbers: M1p 34/41, M2 5/51.

## Normalisation

- **What a new capability is made of.** In every positive compromised pair, a new process spawn
  was among the changes. The result therefore depends largely on the process rules (P1-P5),
  including the decision to name `node`/`python` items by script basename or inline-code flag.
- **Dropped self-traffic and paths.** Registry domains are dropped, which hides exfiltration or
  self-publishing through the registry. Writes under `/tmp/`, caches and install directories are
  dropped, which hides payloads staged there.
- **Credential masking.** `~/.npmrc` (npm) and `~/.netrc` (PyPI) appear in 100% of older records,
  because the package managers read them on every install. A payload read of those two files
  cannot appear as new, which makes the credential part of H5 easier to pass.
- **Failed opens count as reads.** The analysis records a `Read` for every open or stat attempt,
  including ones that fail. The credential category measures attempted access, not successful
  reads.

## Labels and selection

- **Advisory-defined labels.** Malicious versions, incidents and actors come from advisory text. A
  malicious release missing from the advisories could have been used as a clean comparison.
- **Record selection.** Records exist only for releases the analysis pipeline processed. The
  earliest-malicious-version rule excluded 423 npm packages whose first malicious release has no
  record.
- **Benign comparators.** The within-package pairs come from the same compromised packages, before
  the incident. The top-download pairs come from very popular packages whose release practice
  differs. Their rates differ: 12.5% within-package against 20.0% top-download.
