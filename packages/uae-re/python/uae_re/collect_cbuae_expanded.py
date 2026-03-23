"""
CBUAE Quarterly Economic Review (QER) PDF Collector (CBUAE-01)

Downloads known CBUAE QER PDF reports and extracts monetary/banking
data tables using pdfplumber. Covers 5 quarterly reports (Dec 2024
through Dec 2025) with hardcoded URLs (URL slugs are unpredictable).

Extracted data:
- Money supply: M1, M2, M3 (AED billions)
- Interest rates: Base Rate, 3-month EIBOR (percentages)
- Banking: Total Assets, Gross Credit, Deposits (AED billions)

Each QER PDF contains tables with 5 quarterly columns, so a single
PDF can backfill up to 5 quarters of data. Across 5 PDFs this provides
overlapping quarterly coverage from Q3 2023 through Q4 2025.

Bridge pattern:
  Read:  {"outputDir": "/opt/lobsec/data/raw"} from stdin
  Write: {"filePath": str, "rowCount": int} to stdout
  Errors: print to stderr, sys.exit(1)
"""

import io
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import pdfplumber
import requests


# Browser-like User-Agent to avoid Cloudflare blocking
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/121.0.0.0 Safari/537.36"
)

HTTP_TIMEOUT = 60  # seconds per PDF (1-5 MB files)

# Known CBUAE QER PDF URLs (hardcoded -- URL hash slugs are unpredictable)
QER_PDFS: list[tuple[str, str]] = [
    ("2025-Q4", "https://www.centralbank.ae/media/nsoa0sg3/qer-dec-2025.pdf"),
    ("2025-Q3", "https://www.centralbank.ae/media/iamfnixn/qer-sep-2025.pdf"),
    ("2025-Q2", "https://www.centralbank.ae/media/yrilyfz2/qer-june-2025_en.pdf"),
    ("2025-Q1", "https://www.centralbank.ae/media/ysybjwlb/qer-march-2025.pdf"),
    ("2024-Q4", "https://www.centralbank.ae/media/fusfyh0s/qer-dec-2024-23_12-_final.pdf"),
]

# Keywords to identify table rows (case-insensitive matching)
MONEY_SUPPLY_KEYWORDS = {
    "m1": ["m1", "narrow money"],
    "m2": ["m2"],
    "m3": ["m3", "broad money"],
}

RATE_KEYWORDS = {
    "base_rate": ["base rate", "base interest rate", "repo rate"],
    "eibor_3m": ["eibor", "3-month", "3 month", "three month", "3m eibor"],
}

BANKING_KEYWORDS = {
    "total_assets": ["total assets"],
    "gross_credit": ["gross credit", "gross domestic credit", "domestic credit"],
    "deposits": ["total deposits", "bank deposits", "deposits"],
}


def parse_numeric(val: Any) -> Optional[float]:
    """Parse a numeric value from a table cell.

    Handles commas, parentheses (negatives), "n.a.", "-", None, etc.

    Returns:
        Parsed float or None if unparseable.
    """
    if val is None:
        return None

    s = str(val).strip()

    # Common non-numeric markers
    if not s or s.lower() in ("n.a.", "n/a", "-", "--", "...", "…", "n.a"):
        return None

    # Remove commas, spaces within numbers
    s = s.replace(",", "").replace(" ", "")

    # Handle parentheses as negative: (1.5) -> -1.5
    if s.startswith("(") and s.endswith(")"):
        s = "-" + s[1:-1]

    # Remove any trailing % sign
    s = s.rstrip("%")

    try:
        return float(s)
    except ValueError:
        return None


def find_quarter_columns(header_row: list[Any]) -> dict[str, int]:
    """Identify which columns correspond to which quarters.

    Looks for patterns like "Q3 2025", "Q4 2024", "Dec 2025", "Sep-25", etc.

    Returns:
        Dict mapping quarter label ("2025-Q3") to column index.
    """
    quarters: dict[str, int] = {}

    # Pattern: Q1 2025, Q2 2024, etc.
    q_pattern = re.compile(r"Q\s*([1-4])\s*[- ]?\s*(\d{4})", re.IGNORECASE)
    # Pattern: Dec 2025, Sep 2025, Jun 2025, Mar 2025
    month_pattern = re.compile(
        r"(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s*[-.]?\s*(\d{2,4})",
        re.IGNORECASE,
    )
    # Month to quarter mapping
    month_to_quarter = {
        "jan": "Q1", "feb": "Q1", "mar": "Q1",
        "apr": "Q2", "may": "Q2", "jun": "Q2",
        "jul": "Q3", "aug": "Q3", "sep": "Q3",
        "oct": "Q4", "nov": "Q4", "dec": "Q4",
    }

    for idx, cell in enumerate(header_row):
        if cell is None:
            continue
        cell_str = str(cell).strip()

        # Try Q-notation first
        m = q_pattern.search(cell_str)
        if m:
            q_num = m.group(1)
            year = m.group(2)
            label = f"{year}-Q{q_num}"
            quarters[label] = idx
            continue

        # Try month notation
        m = month_pattern.search(cell_str)
        if m:
            month_abbr = m.group(1).lower()[:3]
            year_str = m.group(2)
            if len(year_str) == 2:
                year_str = "20" + year_str
            q = month_to_quarter.get(month_abbr)
            if q:
                label = f"{year_str}-{q}"
                quarters[label] = idx

    return quarters


def match_row_keyword(
    row_label: str, keyword_map: dict[str, list[str]]
) -> Optional[str]:
    """Check if a row label matches any keyword set.

    Args:
        row_label: First column text of a table row.
        keyword_map: {metric_key: [keyword_variants]}

    Returns:
        metric_key if matched, None otherwise.
    """
    label_lower = row_label.lower().strip()

    for metric_key, keywords in keyword_map.items():
        for kw in keywords:
            if kw in label_lower:
                # Avoid matching Y-o-Y percentage rows
                if "y-o-y" in label_lower or "yoy" in label_lower or "%" in label_lower:
                    # Only skip if this is a percentage change row, not
                    # an actual rate (base_rate, eibor are percentages)
                    if metric_key not in ("base_rate", "eibor_3m"):
                        continue
                return metric_key

    return None


def extract_tables_from_pdf(pdf_bytes: bytes, quarter_label: str) -> dict[str, dict[str, Optional[float]]]:
    """Extract monetary/banking data from a CBUAE QER PDF.

    Searches ALL pages for tables containing known keywords. Extracts
    values from the quarterly columns identified in the header row.

    Args:
        pdf_bytes: Raw PDF file content.
        quarter_label: The QER edition label (e.g., "2025-Q4") for logging.

    Returns:
        Dict mapping quarter labels to metric dicts, e.g.:
        {"2025-Q4": {"m1_aed_bn": 1033.0, "base_rate_pct": 3.90, ...}}
    """
    result: dict[str, dict[str, Optional[float]]] = {}

    try:
        pdf = pdfplumber.open(io.BytesIO(pdf_bytes))
    except Exception as e:
        print(f"  WARNING: Cannot open PDF for {quarter_label}: {e}", file=sys.stderr)
        return result

    # Combine all keyword maps
    all_keywords = {}
    all_keywords.update(MONEY_SUPPLY_KEYWORDS)
    all_keywords.update(RATE_KEYWORDS)
    all_keywords.update(BANKING_KEYWORDS)

    # Metric key -> suffix for output
    metric_suffix = {
        "m1": "m1_aed_bn",
        "m2": "m2_aed_bn",
        "m3": "m3_aed_bn",
        "base_rate": "base_rate_pct",
        "eibor_3m": "eibor_3m_pct",
        "total_assets": "total_assets_aed_bn",
        "gross_credit": "gross_credit_aed_bn",
        "deposits": "bank_deposits_aed_bn",
    }

    found_metrics: set[str] = set()

    for page_num, page in enumerate(pdf.pages):
        try:
            tables = page.extract_tables()
        except Exception as e:
            print(f"  WARNING: Table extraction failed on page {page_num + 1}: {e}", file=sys.stderr)
            continue

        if not tables:
            continue

        for table_idx, table in enumerate(tables):
            if not table or len(table) < 2:
                continue

            # Try to find quarter columns in header rows (first 1-3 rows)
            quarter_cols: dict[str, int] = {}
            header_rows_checked = 0
            for row_idx in range(min(3, len(table))):
                row = table[row_idx]
                if row is None:
                    continue
                cols = find_quarter_columns(row)
                if cols:
                    quarter_cols.update(cols)
                    header_rows_checked = row_idx + 1
                    break

            if not quarter_cols:
                # If no quarter columns identified, this table might not be
                # a quarterly data table. Try the text extraction approach
                # for interest rates which might be in a simpler format.
                continue

            # Now scan data rows for matching keywords
            for row in table[header_rows_checked:]:
                if not row or not row[0]:
                    continue

                row_label = str(row[0]).strip()
                if not row_label:
                    continue

                matched_key = match_row_keyword(row_label, all_keywords)
                if matched_key is None:
                    continue

                # Already found this metric? Skip duplicate matches
                if matched_key in found_metrics:
                    continue

                suffix = metric_suffix.get(matched_key)
                if not suffix:
                    continue

                # Extract values from quarter columns
                for q_label, col_idx in quarter_cols.items():
                    if col_idx < len(row):
                        val = parse_numeric(row[col_idx])
                        if val is not None:
                            if q_label not in result:
                                result[q_label] = {}
                            result[q_label][suffix] = val

                found_metrics.add(matched_key)
                print(
                    f"  Found {matched_key} on page {page_num + 1}, "
                    f"table {table_idx + 1}: "
                    f"{sum(1 for q in quarter_cols if q in result and suffix in result.get(q, {}))} quarters",
                    file=sys.stderr,
                )

    pdf.close()

    # Also try text-based extraction for interest rates if not found in tables
    if "base_rate" not in found_metrics or "eibor_3m" not in found_metrics:
        _extract_rates_from_text(pdf_bytes, quarter_label, result, found_metrics)

    print(
        f"  {quarter_label}: extracted {len(found_metrics)}/8 metrics across "
        f"{len(result)} quarters",
        file=sys.stderr,
    )
    return result


def _extract_rates_from_text(
    pdf_bytes: bytes,
    quarter_label: str,
    result: dict[str, dict[str, Optional[float]]],
    found_metrics: set[str],
) -> None:
    """Fallback: extract interest rates from PDF text when table extraction fails.

    Interest rate data is sometimes presented as inline text rather than tables.
    Look for patterns like "Base Rate was lowered to 3.90 percent" or
    "EIBOR (3-month) averaged 4.28 percent".
    """
    try:
        pdf = pdfplumber.open(io.BytesIO(pdf_bytes))
        full_text = ""
        for page in pdf.pages:
            text = page.extract_text()
            if text:
                full_text += text + "\n"
        pdf.close()
    except Exception:
        return

    if not full_text:
        return

    # Try to find base rate
    if "base_rate" not in found_metrics:
        # Pattern: "Base Rate" ... "X.XX" or "X.XX per cent"
        base_patterns = [
            r"[Bb]ase\s+[Rr]ate\s+(?:was\s+)?(?:lowered|raised|maintained|kept|set)?\s*(?:to|at)?\s*(\d+\.?\d*)\s*(?:per\s*cent|percent|%)",
            r"[Bb]ase\s+[Rr]ate\s+(?:of|at)\s+(\d+\.?\d*)\s*(?:per\s*cent|percent|%)",
        ]
        for pattern in base_patterns:
            m = re.search(pattern, full_text)
            if m:
                val = float(m.group(1))
                if 0.0 <= val <= 10.0:
                    # Assign to the QER's own quarter
                    if quarter_label not in result:
                        result[quarter_label] = {}
                    result[quarter_label]["base_rate_pct"] = val
                    found_metrics.add("base_rate")
                    print(f"  Found base_rate from text: {val}%", file=sys.stderr)
                    break

    # Try to find EIBOR 3-month
    if "eibor_3m" not in found_metrics:
        eibor_patterns = [
            r"(?:3-month|3\s*month|three\s*month)\s+EIBOR\s+(?:averaged?|was|stood\s+at|at)\s+(\d+\.?\d*)\s*(?:per\s*cent|percent|%)",
            r"EIBOR\s*\(3[- ]month\)\s+(?:averaged?|was|stood\s+at|at)\s+(\d+\.?\d*)\s*(?:per\s*cent|percent|%)",
            r"EIBOR\b[^.]{0,60}?(\d+\.?\d*)\s*(?:per\s*cent|percent|%)",
        ]
        for pattern in eibor_patterns:
            m = re.search(pattern, full_text, re.IGNORECASE)
            if m:
                val = float(m.group(1))
                if 0.0 <= val <= 10.0:
                    if quarter_label not in result:
                        result[quarter_label] = {}
                    result[quarter_label]["eibor_3m_pct"] = val
                    found_metrics.add("eibor_3m")
                    print(f"  Found eibor_3m from text: {val}%", file=sys.stderr)
                    break


def collect_cbuae_expanded(output_dir: str) -> dict:
    """Download CBUAE QER PDFs and extract monetary/banking data.

    Downloads 5 known QER PDFs, extracts tables with pdfplumber,
    and merges data across PDFs (later PDFs override earlier ones
    for the same quarter, as they may contain revisions).

    Args:
        output_dir: Base directory for output files.

    Returns:
        {"filePath": str, "rowCount": int}
    """
    cbuae_dir = Path(output_dir) / "cbuae-expanded"
    cbuae_dir.mkdir(parents=True, exist_ok=True)

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    out_path = cbuae_dir / f"{today}.json"
    collected_at = datetime.now(timezone.utc).isoformat()

    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/pdf,*/*",
        "Accept-Language": "en-US,en;q=0.9",
    }

    # Merged quarters data (later PDFs override earlier for same quarter)
    all_quarters: dict[str, dict[str, Optional[float]]] = {}
    pdfs_succeeded = 0
    pdfs_failed = 0

    for quarter_label, url in QER_PDFS:
        print(f"Downloading QER PDF: {quarter_label} ({url})...", file=sys.stderr)

        try:
            resp = requests.get(url, headers=headers, timeout=HTTP_TIMEOUT, allow_redirects=True)

            if resp.status_code != 200:
                print(
                    f"  WARNING: HTTP {resp.status_code} for {quarter_label}, skipping",
                    file=sys.stderr,
                )
                pdfs_failed += 1
                continue

            content_type = resp.headers.get("content-type", "")
            if "pdf" not in content_type and "octet" not in content_type:
                # Might be a Cloudflare challenge page
                if len(resp.content) < 10000 and b"challenge" in resp.content.lower():
                    print(
                        f"  WARNING: Cloudflare challenge for {quarter_label}, skipping",
                        file=sys.stderr,
                    )
                    pdfs_failed += 1
                    continue

            pdf_size = len(resp.content)
            print(f"  Downloaded {pdf_size / 1024:.0f} KB", file=sys.stderr)

            # Extract tables from PDF
            quarters_data = extract_tables_from_pdf(resp.content, quarter_label)

            if quarters_data:
                # Merge into all_quarters (later PDFs can override)
                for q_label, metrics in quarters_data.items():
                    if q_label not in all_quarters:
                        all_quarters[q_label] = {}
                    all_quarters[q_label].update(metrics)
                pdfs_succeeded += 1
            else:
                print(
                    f"  WARNING: No data extracted from {quarter_label} PDF",
                    file=sys.stderr,
                )
                pdfs_failed += 1

        except requests.exceptions.Timeout:
            print(f"  WARNING: Timeout downloading {quarter_label}", file=sys.stderr)
            pdfs_failed += 1
        except requests.RequestException as e:
            print(f"  WARNING: Download error for {quarter_label}: {e}", file=sys.stderr)
            pdfs_failed += 1
        except Exception as e:
            print(f"  WARNING: Unexpected error for {quarter_label}: {e}", file=sys.stderr)
            pdfs_failed += 1

    # Count total metric values
    total_values = sum(
        sum(1 for v in metrics.values() if v is not None)
        for metrics in all_quarters.values()
    )

    output = {
        "collectedAt": collected_at,
        "pdfs_succeeded": pdfs_succeeded,
        "pdfs_failed": pdfs_failed,
        "quarters": all_quarters,
    }

    with open(out_path, "w") as f:
        json.dump(output, f, indent=2)

    print(
        f"CBUAE collection complete: {pdfs_succeeded}/{len(QER_PDFS)} PDFs, "
        f"{len(all_quarters)} quarters, {total_values} metric values",
        file=sys.stderr,
    )
    return {"filePath": str(out_path), "rowCount": total_values}


def main() -> None:
    """Entry point: read stdin, collect, write stdout."""
    try:
        input_data = json.load(sys.stdin)
        output_dir = input_data.get("outputDir", "/opt/lobsec/data/raw")

        result = collect_cbuae_expanded(output_dir)

        json.dump(result, sys.stdout)
        sys.stdout.flush()

    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
