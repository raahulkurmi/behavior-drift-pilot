# behavior-drift-pilot

When an established npm or PyPI package is compromised, does the malicious release show
install-time behaviour that its own earlier release did not? And how often do benign consecutive
releases show the same kind of change?

This pilot answers that from **published** OpenSSF package-analysis dynamic-analysis records
only. No package archive was downloaded, installed, executed or unpacked, and no URL, domain or
IP address found inside a record was ever requested.

- Result in one paragraph: [docs/SUMMARY.md](docs/SUMMARY.md)
- Full aggregate results and prediction outcomes: [results/RESULTS.md](results/RESULTS.md)

## Documents

| file | content |
|---|---|
| [docs/STEP0_DATA_AVAILABILITY.md](docs/STEP0_DATA_AVAILABILITY.md) | which records exist; candidates, campaigns, timing (metadata only) |
| [docs/PREREGISTRATION.md](docs/PREREGISTRATION.md) | design, normalisation rules, metrics and predictions, fixed before any record was read; amendments in section 11 |
| [docs/DEVIATIONS.md](docs/DEVIATIONS.md) | interpretations and decisions not settled by the pre-registration |
| [docs/LIMITATIONS.md](docs/LIMITATIONS.md) | limitations, with what the run showed |
| [results/RESULTS.md](results/RESULTS.md) | aggregate results; tables in `results/*.csv` |

## Reproducing

Python 3.11+, standard library only. Run from the repository root. `scratch/` is git-ignored and
holds downloaded inputs and record contents.

```sh
# Step 0 (metadata): see docs/STEP0_DATA_AVAILABILITY.md for the full command list
python3 scripts/sample.py                    # pre-registered sample (seed 20261017)
python3 -m unittest discover -s tests        # normalisation rules on synthetic records
mkdir -p scratch/psl && curl -sSfo scratch/psl/public_suffix_list.dat \
  https://raw.githubusercontent.com/publicsuffix/list/2dbfce14c57bcea83fef2be3bdcb560667d7ef93/public_suffix_list.dat
python3 scripts/fetch_records.py             # fetch + pin records (data/record_pins.csv)
python3 scripts/key_census.py                # key names vs schema (prints key names only)
python3 scripts/results.py                   # re-fetch, verify md5Hash, compute results/
```

`scripts/results.py` re-fetches every pinned record by name and stops if its `md5Hash` differs
from `data/record_pins.csv`. If an object has since been rewritten in the bucket, the run stops
rather than producing different numbers.

## Data policy

- Committed: metadata, sample definitions, per-record pins (object name, generation, md5Hash,
  timeCreated) and aggregate results.
- Never committed: record contents or per-pair item sets. They exist only in `scratch/`.
- Package names appear only as they appear in public advisories.
