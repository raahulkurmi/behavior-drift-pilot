# Deviations and interpretations

Decisions taken during analysis that the pre-registration (`docs/PREREGISTRATION.md`, cfa9957,
amended 4fd0d2a and 830e3b4) does not settle. Amendments to the pre-registration itself are
logged in its section 11. Every item below was decided while writing the code, before any
record was fetched, unless it is marked otherwise.

## Normalisation (`scripts/normalise.py`)

1. **F3, rule order.** The long-token rule (a run of at least 16 `[A-Za-z0-9_-]` characters with
   both letters and digits becomes `X`) is applied before the digit rule (digit runs become `N`).
   In the written order, the digit rule would remove every digit first and the token rule could
   never fire.
2. **N1, IP literals given as hostnames.** A `Hostnames` or DNS query value that parses as an IP
   address is classified with N3 (dropped, `cloud-metadata` or `ip-literal`), so that no
   destination item is ever a raw address (N5).
3. **N1, "cannot be parsed".** A hostname is unparsable if, after lowercasing and stripping a
   trailing dot, it does not consist of dot-separated labels of `[a-z0-9_-]`. Such a value is kept
   as is. An empty hostname is dropped.
4. **F1.** `/root` alone becomes `~`. `/rootfs/...` is not a home directory.
5. **F2, "anything under".** This means the path starts with the listed prefix including the
   trailing `/`; the directory itself is not dropped.
6. **P2 and P3 edge cases.** `env` with only `NAME=value` arguments gives the item `env`. A shell
   `-c` string with no words gives no item. After shell unwrapping, P4/P5 apply to the unwrapped
   command; P2 is not applied again.
7. **P4.** A path argument ending in `/` uses its last non-empty segment.
8. **Public Suffix List.** The pinned file is not committed. It is fetched from the pinned commit
   into `scratch/psl/`, and its SHA-256
   (`13879fec7cb7f6c67991de0810874f511d67eca2d99af53e40db2a833b207cdc`) is checked on load. Rules
   are matched after IDNA encoding, and exception rules take precedence.

## Data handling

9. **Downloads.** The first download (`scripts/fetch_records.py`) requested each object at its
   pinned `generation` and verified `md5Hash`. The results run re-fetches by name (the current
   generation), as section 8 specifies, and stops on any md5 mismatch. None occurred.
10. **Identity check (added).** The results script stops if a record's
    `Package.Ecosystem/Name/Version` does not match its object name. PyPI names are compared after
    PEP 503 normalisation. None mismatched.
11. **Key names.** All 458 records use exactly the documented key paths
    (`scripts/key_census.py`), so no key-name mapping was needed. `Files[].Delete` is absent from
    some records; it is not used.
12. **Gaps** are computed from the pinned object `timeCreated`. All 458 pinned values equal the
    Step 0 index values.

## Metrics (`scripts/results.py`)

13. **Incidents without evaluable packages.** An incident none of whose sampled packages is
    evaluable is omitted from M1 denominators. This happened to 1 of 13 incidents, leaving 12.
14. **Bootstrap generator.** Each interval uses a fresh `random.Random(20261017)`, so every
    interval is reproducible on its own. Intervals are percentile intervals (2.5%, 97.5%).
15. **H3 interval.** H3 ran on the pooled M2 + M3 pairs, because M2 had fewer than 10 pairs in the
    >365 d stratum: 4 evaluable pairs, against 6 in the sampled list, since some records are not
    evaluable. The difference interval resamples packages, the clusters of both strata, once per
    iteration.
16. **H4 interval.** Incidents (M1p) and packages (M2) are resampled independently in each
    iteration, and the interval is that of the difference.
17. **"Holds clearly" for compound predictions** (H2, H5) requires every component's interval to
    meet its threshold.
18. **Masking.** The 95% share is computed over unique evaluable older records per ecosystem; a
    record that is the older side of several pairs counts once.
19. **Package-weighted shares** are reported for M3 as well as M2.
20. **Within-package pairs.** These are all C1->C0 and C2->C1 pairs of the 66 sampled packages
    where both releases have a record (69 pairs; 56 evaluable). No cap was applied, because the
    pre-registration specifies none for M2.

## Outputs

21. **Small cells.** Committed tables give counts per ecosystem x stratum x category, as
    pre-registered, including cells with very small denominators. Combined with `data/sample.csv`,
    which lists the sampled packages and their gap strata, a very small cell could narrow down
    the behaviour of an individual package. Before any public release, cells with a denominator
    below 5 should be suppressed, or `data/sample.csv` withheld. This repository is private.
