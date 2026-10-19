# CSV PII Signal Scanner

A standard-library Python CLI for finding potential personal-information signals in CSV exports.
It keeps the original folder-aware scanner and adds masked output, a credit-card checksum filter,
spreadsheet formula escaping and regression tests.

## Run

Requires Python 3.10+. No packages or API keys are required.

```bash
python pii_scanner.py --repo ./synthetic-input --out ./results/flagged.csv --confidence-threshold Medium --max-rows 100
python -m unittest discover -s tests -v
```

Place CSVs inside subdirectories of `synthetic-input`; CSVs directly in the root are not scanned.
The first row is treated as the header. `--max-rows 0` reads all data rows. Folder metadata can use
`DDMMYYYY_JOBCODE_TableName-UUID`, for example `01012026_DEMO_Example-abcd`; other names still work.
The output file is excluded from subsequent scans, including when it is inside an input directory.

## Output and privacy

Reports include file, row, column, signal type and heuristic confidence. Matched values and cell
contents are masked by default; neighbouring context is omitted. To deliberately include raw data,
use `--include-sensitive-values`. Source filenames, headers and folder metadata remain visible and
can themselves be sensitive. Keep reports access-controlled. The scanner reads input; it does not
redact or modify the original CSVs.

Detection covers Australian identifier patterns, emails, phone numbers, dates, addresses and other
signals. A label such as `High` is a rule priority, not a calibrated probability. Numeric patterns
overlap; most identifiers do not have issuer/checksum validation. Card candidates use Luhn.
This is a triage tool with false positives and false negatives, not proof that a dataset is PII-free.
The CLI streams findings into a temporary report and atomically replaces the destination after traversal, instead of collecting all findings in memory. The compatibility `scan_csv_file` function still returns a list. Memory can still grow with a very wide cell or directory listing.

## Validation

10 synthetic regression tests cover: masking, explicit raw-data opt-in, row limits, folder parsing,
card checksum, excluding prior output, negative limits and formula escaping. No real records are bundled.

## Public edition

This is a separately prepared portfolio edition with fresh history. Private deployment settings,
credentials, operational records, uploads, backups and organisation-specific assets are excluded.
See [PUBLIC_EDITION.md](PUBLIC_EDITION.md). No deployment workflows are included.

## Automated checks

GitHub Actions runs offline regression checks on pushes and pull requests. These do not deploy the app, call paid AI services or establish model quality. 

### Memory measurement

A single Python 3.12/Linux run over 5,000 synthetic email rows produced identical report bytes before and after streaming. `tracemalloc` peak allocations fell from 2,692,673 to 199,554 bytes (about 93%). This measures Python allocations for that fixture, not total process memory or a throughput guarantee.
