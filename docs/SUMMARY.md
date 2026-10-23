# Summary

**The pre-registered compromised-side prediction failed.** Only 7 of 12 evaluable incidents had
a majority of sampled packages with a new install-time capability (58%, 95% CI 32-81%), against
the pre-registered threshold of 80% (H1). By ecosystem, npm incidents were 6 of 8 and PyPI
incidents were 2 of 6. These do not add up to the pooled 7 of 12 because the two Mini Shai-Hulud
incidents published packages on both npm and PyPI: each is counted in both ecosystem cells
(8 + 6 = 14 cells for 12 incidents) and the majority rule is applied within each ecosystem.
Both are positive pooled and in 3 of their 4 ecosystem cells, so the ecosystem positives
(6 + 2 = 8) exceed the pooled 7 by one (`results/EXPLORATORY.md`, unit: incident).

The other four predictions held, none of them clearly:
- **H2 (benign rate low).** Consecutive releases of the same packages showed a new capability in
  7 of 56 pairs (12.5%, CI 4-23%), and in 4 of 39 when the two analyses were under 90 days apart
  (10.3%).
- **H3 (time between analyses matters).** In the pooled benign pairs, the rate rose from 14%
  under 90 days to 44% for analyses more than a year apart (difference +31 points, CI +8 to +53).
- **H4 (contrast under 90 days).** Compromised pairs: 19 of 22 (86%). Benign pairs: 10%. The
  difference is +76 points (CI +47 to +92).
- **H5 (benign credential and network changes rare).** A new credential-file read appeared in
  1.8% of within-package and 3.4% of top-download benign pairs; a new network destination in 1.8%
  of within-package pairs.

At package level, 37 of 44 evaluable compromised pairs showed a new capability (84%, CI 63-95%).
In every one of those 37, a new process spawn was among the changes. Top-download benign pairs,
gap-matched, showed one in 29 of 145 (20.0%).

**Gap between analyses.** The sample's analysis-time gaps (`results/gap_stats.csv`, from
`scripts/gap_stats.py`) were under 90 days for 30 of the 66 sampled compromised pairs, 90-365 days
for 22 and over a year for 14; the median was 102.0 days. Among the 44 evaluable pairs the split
is 22, 14 and 8 (`results/metrics.csv`, M1p denominators).

The sample is small and clustered: 13 incidents in 5 linked groups, and one linked group holds 61
of the 66 sampled packages. Install-time records cannot see payloads that run on import or later.
22 of 66 sampled compromised pairs could not be evaluated because a record's analysis ended in an
error.

Public install-time analysis records showed new capabilities in 37 of 44 compromised releases (7 of 12 incidents), against 12.5% of benign release pairs from the same packages (github.com/raahulkurmi/behavior-drift-pilot).
