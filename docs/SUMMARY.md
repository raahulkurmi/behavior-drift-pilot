# Summary

We compared public OpenSSF package-analysis install-time records for compromised npm and PyPI
releases with records for each package's own last clean release published at least 14 days before
the incident. The sample was pre-registered: at most 10 packages per incident, 66 packages in 13
incidents, almost all Shai-Hulud worm waves and related TeamPCP campaigns.
- **Compromised releases:** of the 44 compromised packages whose two records were both complete,
  37 (84%, 95% CI 63-95%) showed at least one new install-time capability after normalisation.
  In every one of those 37, a new process spawn was among the changes.
- **Benign releases:** consecutive releases of the same packages showed a new capability in 7 of
  56 pairs (12.5%, CI 4-23%). Gap-matched pairs from top-download packages showed one in 29 of 145
  (20.0%, CI 14-26%).
- **Time between analyses matters.** In the pooled benign pairs, the rate rose from 14% when the
  two analyses were under 90 days apart to 44% when they were more than a year apart (difference
  +31 points, CI +8 to +53). A gap of more than a year is the most common gap on the compromised
  side.
- **Incident-level prediction failed.** Only 7 of 12 evaluable incidents had a majority of
  positive packages (58%, CI 32-81%), missing the pre-registered 80%. npm incidents were 6 of 8;
  PyPI incidents were 2 of 6.
- **Other predictions held.** The low benign rate, the gap effect, the contrast in the <90 d
  stratum and the low benign credential and network rates (H2-H5) all held, though none held
  clearly; the intervals are wide.

The sample is small and clustered: 5 linked groups, one of which dominates. Install-time records
cannot see payloads that run on import or later.

**Sentence, filled from `results/summary.csv`** (choose one):

- **Packages:** "Public install-time analysis records of 44 compromised releases showed new
  capabilities in 37 of them, against 12.5% of benign consecutive releases
  (github.com/raahulkurmi/behavior-drift-pilot)."
- **Incidents:** "Public install-time analysis records of 12 compromised-release incidents showed
  new capabilities in 7 of them, against 12.5% of benign consecutive releases
  (github.com/raahulkurmi/behavior-drift-pilot)." Here an incident counts if more than half of its
  sampled packages showed a new capability.

Values used: `incidents_evaluable` 12, `incidents_positive` 7, `packages_evaluable` 44,
`packages_positive` 37, `benign_within_share` 0.1250 (M2, the pre-registered primary benign
comparator). The secondary comparator, top-download releases, gives `benign_baseline_share`
0.2000.
