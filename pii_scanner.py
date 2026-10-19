"""
Traverses a scanning repository where folders are named:
    {DDMMYYYY}_{JobCode}_{TableName}-{UUID}

Reads all CSV files within each folder, scans every cell for PII signals
(TFN, ABN, ACN, BSB/account numbers, names, emails, DOB, phone, Medicare,
passport, driver licence, address, credit card, IP address), and writes a
consolidated flagged-items CSV.

Usage:
    python pii_scanner.py --repo "\\\\server\\share\\Scanning" --out flagged_output.csv

Optional:
    --confidence-threshold  low|medium|high  (default: low = include all)
    --max-rows              int              (default: 0 = unlimited)
    --include-sensitive-values               opt in to raw values and context
"""

import os
import re
import csv
import sys
import argparse
import logging
import tempfile
from datetime import datetime
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Folder name parser
# Pattern: DDMMYYYY_JOBCODE_TableName-UUID
# e.g.  01012026_DEMO_Example-abcd
# ---------------------------------------------------------------------------
FOLDER_PATTERN = re.compile(
    r"^(\d{8})_([^_]+)_([A-Za-z][A-Za-z0-9]*)-([A-Fa-f0-9\-]+)$"
)

def parse_folder_name(folder_name: str) -> dict:
    m = FOLDER_PATTERN.match(folder_name)
    if not m:
        return {
            "scan_date": "",
            "job_code": "",
            "table_name": folder_name,
            "folder_hash": "",
        }
    raw_date, job_code, table_name, folder_hash = m.groups()
    try:
        scan_date = datetime.strptime(raw_date, "%d%m%Y").strftime("%Y-%m-%d")
    except ValueError:
        scan_date = raw_date
    return {
        "scan_date": scan_date,
        "job_code": job_code,
        "table_name": table_name,
        "folder_hash": folder_hash,
    }


# ---------------------------------------------------------------------------
# PII Detection Rules
# Each rule: (label, confidence, compiled_regex)
# ---------------------------------------------------------------------------

def _r(pattern: str, flags=re.IGNORECASE) -> re.Pattern:
    return re.compile(pattern, flags)


PII_RULES = [
    # ---- TFN ---------------------------------------------------------------
    # Australian Tax File Number: 8 or 9 digits, often formatted with spaces/hyphens
    (
        "TFN",
        "High",
        _r(r"\b(\d{3}[ \-]?\d{3}[ \-]?\d{2,3})\b"),
    ),
    # ---- ABN ---------------------------------------------------------------
    # Australian Business Number: 11 digits  XX XXX XXX XXX
    (
        "ABN",
        "High",
        _r(r"\b(\d{2}[ \-]?\d{3}[ \-]?\d{3}[ \-]?\d{3})\b"),
    ),
    # ---- ACN ---------------------------------------------------------------
    # Australian Company Number: 9 digits  XXX XXX XXX
    (
        "ACN",
        "High",
        _r(r"\b(\d{3}[ \-]?\d{3}[ \-]?\d{3})\b"),
    ),
    # ---- BSB + Account Number ----------------------------------------------
    (
        "BSB",
        "High",
        _r(r"\b(\d{3}-\d{3})\b"),
    ),
    (
        "Bank Account Number",
        "Medium",
        _r(r"\b(\d{6,10})\b"),
    ),
    # ---- Medicare Number ---------------------------------------------------
    (
        "Medicare Number",
        "High",
        _r(r"\b([2-6]\d{3}[ \-]?\d{5}[ \-]?\d[ \-]?\d)\b"),
    ),
    # ---- Australian Passport -----------------------------------------------
    (
        "Passport Number",
        "High",
        _r(r"\b([A-Z]{1,2}\d{7,8})\b"),
    ),
    # ---- Driver Licence (various states) -----------------------------------
    (
        "Driver Licence",
        "Medium",
        _r(r"\b([A-Z]{0,2}\d{6,9})\b"),
    ),
    # ---- Credit / Debit Card -----------------------------------------------
    (
        "Credit Card",
        "High",
        _r(r"\b(4\d{3}[ \-]?\d{4}[ \-]?\d{4}[ \-]?\d{4}|5[1-5]\d{2}[ \-]?\d{4}[ \-]?\d{4}[ \-]?\d{4}|3[47]\d{2}[ \-]?\d{6}[ \-]?\d{5}|6011[ \-]?\d{4}[ \-]?\d{4}[ \-]?\d{4})\b"),
    ),
    # ---- Email Address -----------------------------------------------------
    (
        "Email Address",
        "High",
        _r(r"\b([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})\b"),
    ),
    # ---- Phone Number (AU) -------------------------------------------------
    (
        "Phone Number",
        "High",
        _r(r"\b(\+?61[ \-]?|0)([2378]\d{1}[ \-]?\d{4}[ \-]?\d{4}|4\d{2}[ \-]?\d{3}[ \-]?\d{3})\b"),
    ),
    # ---- Date of Birth ------------------------------------------------------
    (
        "Date of Birth",
        "Medium",
        _r(
            r"\b(0?[1-9]|[12]\d|3[01])[\-/\.](0?[1-9]|1[0-2])[\-/\.](\d{2}|\d{4})\b"
            r"|"
            r"\b(\d{4})[\-/\.](0?[1-9]|1[0-2])[\-/\.](0?[1-9]|[12]\d|3[01])\b"
        ),
    ),
    # ---- IP Address --------------------------------------------------------
    (
        "IP Address",
        "Medium",
        _r(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"),
    ),
    # ---- Full Name (heuristic: Title + Lastname or Firstname Lastname) -----
    (
        "Full Name",
        "Low",
        _r(r"\b(Mr\.?|Mrs\.?|Ms\.?|Dr\.?|Prof\.?)\s+[A-Z][a-z]+(\s+[A-Z][a-z]+)?\b"),
    ),
    # ---- Australian Address ------------------------------------------------
    (
        "Street Address",
        "Low",
        _r(
            r"\b\d{1,5}\s+[A-Za-z\s]{3,30}"
            r"\s+(Street|St|Road|Rd|Avenue|Ave|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Place|Pl|Crescent|Cres|Highway|Hwy|Way|Close|Cl)\b",
            re.IGNORECASE,
        ),
    ),
    # ---- Postcode ----------------------------------------------------------
    (
        "Postcode",
        "Low",
        _r(r"\b([0-9]{4})\b"),
    ),
    # ---- Keyword signals (catch-all for column names / freetext) -----------
    (
        "TFN Keyword",
        "Medium",
        _r(r"\b(tax[\s_\-]?file[\s_\-]?number|tfn)\b"),
    ),
    (
        "PII Keyword",
        "Low",
        _r(
            r"\b(date[\s_\-]?of[\s_\-]?birth|dob|surname|last[\s_\-]?name|"
            r"first[\s_\-]?name|given[\s_\-]?name|middle[\s_\-]?name|full[\s_\-]?name|"
            r"gender|nationality|ethnicity|religion|marital[\s_\-]?status|"
            r"passport|licence|license|medicare|health[\s_\-]?card|"
            r"bank[\s_\-]?account|bsb|iban|credit[\s_\-]?card|"
            r"salary|income|employer|employment|occupation)\b"
        ),
    ),
]

CONFIDENCE_RANK = {"Low": 1, "Medium": 2, "High": 3}


# ---------------------------------------------------------------------------
# Luhn check – used only for credit-card candidates (not TFNs)
# ---------------------------------------------------------------------------

def _luhn_valid(digits: str) -> bool:
    try:
        nums = [int(d) for d in digits if d.isdigit()]
        if len(nums) < 8:
            return False
        total = 0
        for i, n in enumerate(reversed(nums)):
            if i % 2 == 1:
                n *= 2
                if n > 9:
                    n -= 9
            total += n
        return total % 10 == 0
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Core scanner
# ---------------------------------------------------------------------------

def scan_value(value: str) -> list[dict]:
    """Return a list of PII hits found in a single cell value."""
    if not value or not isinstance(value, str):
        return []
    findings = []
    seen_labels = set()
    for label, confidence, pattern in PII_RULES:
        for match in pattern.finditer(value):
            matched_text = match.group(0).strip()
            if label == "Credit Card" and not _luhn_valid(matched_text):
                continue
            if not matched_text:
                continue
            # De-duplicate same label on the same value
            key = (label, matched_text)
            if key in seen_labels:
                continue
            seen_labels.add(key)
            findings.append(
                {
                    "pii_type": label,
                    "confidence": confidence,
                    "matched_value": matched_text,
                }
            )
    return findings


def extract_context(row: list, col_index: int, window: int = 2) -> str:
    """Return a brief context snippet from neighbouring cells."""
    start = max(0, col_index - window)
    end = min(len(row), col_index + window + 1)
    parts = []
    for i in range(start, end):
        if i == col_index:
            continue
        cell = str(row[i]).strip()
        if cell:
            parts.append(cell[:60])
    return " | ".join(parts)


# ---------------------------------------------------------------------------
# Main traversal
# ---------------------------------------------------------------------------

OUTPUT_HEADERS = [
    "scan_date",
    "job_code",
    "table_name",
    "folder_hash",
    "source_file",
    "row_number",
    "column_index",
    "column_name",
    "pii_type",
    "confidence",
    "matched_value",
    "full_cell_value",
    "context",
    "folder_name",
]


def iter_csv_findings(
    csv_path: Path,
    folder_meta: dict,
    min_confidence: str,
    max_rows: int,
    include_sensitive_values: bool = False,
):
    """Yield findings while reading one CSV; no report-wide accumulation."""
    min_rank = CONFIDENCE_RANK.get(min_confidence, 1)
    try:
        with open(csv_path, newline="", encoding="utf-8-sig", errors="replace") as fh:
            reader = csv.reader(fh)
            headers = []
            for row_idx, row in enumerate(reader):
                if row_idx == 0:
                    headers = row
                    continue
                if max_rows and row_idx > max_rows:
                    break
                for col_idx, cell in enumerate(row):
                    hits = scan_value(cell)
                    for hit in hits:
                        if CONFIDENCE_RANK.get(hit["confidence"], 1) < min_rank:
                            continue
                        col_name = (
                            headers[col_idx]
                            if col_idx < len(headers)
                            else f"col_{col_idx}"
                        )
                        yield {
                                "scan_date": folder_meta["scan_date"],
                                "job_code": folder_meta["job_code"],
                                "table_name": folder_meta["table_name"],
                                "folder_hash": folder_meta["folder_hash"],
                                "source_file": csv_path.name,
                                "row_number": row_idx,
                                "column_index": col_idx,
                                "column_name": col_name,
                                "pii_type": hit["pii_type"],
                                "confidence": hit["confidence"],
                                "matched_value": hit["matched_value"] if include_sensitive_values else "[REDACTED]",
                                "full_cell_value": cell[:500] if include_sensitive_values else "[REDACTED]",
                                "context": extract_context(row, col_idx) if include_sensitive_values else "",
                                "folder_name": csv_path.parent.name,
                            }
    except Exception as exc:
        log.warning("Could not read %s: %s", csv_path, exc)


def scan_csv_file(csv_path, folder_meta, min_confidence, max_rows,
                  include_sensitive_values=False) -> list[dict]:
    """Compatibility API for callers that need a materialized list."""
    return list(iter_csv_findings(csv_path, folder_meta, min_confidence,
                                 max_rows, include_sensitive_values))


def run_scan(repo_path: str, output_path: str, min_confidence: str, max_rows: int, include_sensitive_values: bool = False):
    repo = Path(repo_path)
    if max_rows < 0:
        raise ValueError("max_rows cannot be negative")
    if not repo.is_dir():
        log.error("Repository path does not exist: %s", repo_path)
        sys.exit(1)

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    output_resolved = out.resolve()
    csv_count = folder_count = hit_count = 0
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", newline="", encoding="utf-8-sig",
                dir=out.parent, prefix=".scan-", suffix=".tmp", delete=False) as fh:
            temporary = Path(fh.name)
            writer = csv.DictWriter(fh, fieldnames=OUTPUT_HEADERS)
            writer.writeheader()
            for item in sorted(repo.iterdir()):
                if not item.is_dir():
                    continue
                folder_count += 1
                meta = parse_folder_name(item.name)
                log.info("Scanning folder [%d] %s (table=%s)", folder_count, item.name, meta["table_name"])
                for csv_file in sorted(item.rglob("*.csv")):
                    if csv_file.resolve() == output_resolved:
                        continue
                    csv_count += 1
                    for result in iter_csv_findings(csv_file, meta, min_confidence,
                            max_rows, include_sensitive_values):
                        # Escape metadata as well as matches for spreadsheet safety.
                        writer.writerow({key: ("'" + value if isinstance(value, str)
                            and value.lstrip().startswith(('=', '+', '-', '@'))
                            else value) for key, value in result.items()})
                        hit_count += 1
        os.replace(temporary, out)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    log.info("Scan complete. Folders=%d, CSVs=%d, Total flagged rows=%d",
             folder_count, csv_count, hit_count)
    log.info("Output written to: %s", out.resolve())
    return hit_count


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description=" PII / TFN Scanner — scans a repository of CSV scan folders."
    )
    parser.add_argument(
        "--repo",
        required=True,
        help="Root path to the scanning repository (e.g. \\\\server\\share\\Scanning)",
    )
    parser.add_argument(
        "--out",
        default="flagged_pii_output.csv",
        help="Output CSV file path (default: flagged_pii_output.csv)",
    )
    parser.add_argument(
        "--confidence-threshold",
        choices=["Low", "Medium", "High"],
        default="Low",
        help="Minimum confidence level to include (default: Low = include all)",
    )
    parser.add_argument(
        "--max-rows",
        type=int,
        default=0,
        help="Max data rows to read per CSV (0 = unlimited)",
    )
    parser.add_argument("--include-sensitive-values", action="store_true", help="Include raw matches, cell text and neighbouring cells. Reports will contain sensitive data.")
    args = parser.parse_args()

    run_scan(
        repo_path=args.repo,
        output_path=args.out,
        min_confidence=args.confidence_threshold,
        max_rows=args.max_rows,
        include_sensitive_values=args.include_sensitive_values,
    )


if __name__ == "__main__":
    main()
