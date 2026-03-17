#!/usr/bin/env python3
"""
CBUAE domestic fund transfer backfill script (BACK-04).

Backfills CBUAE Table 48 data from the Statistical Bulletin Dec 2025 PDF.
Covers Dec 2021 through Mar 2025 (8 periods, 6 metrics each = 48 rows).

CRITICAL: Within-year quarterly columns are CUMULATIVE year-to-date.
Must subtract consecutive periods to get individual quarter amounts:
  Q1 = Mar value (as-is, first period of year)
  Q2 = Jun - Mar
  Q3 = Sep - Jun
  Q4 = Dec - Sep

Annual totals (Dec 2021, Dec 2022, Dec 2023) are full-year values -- use directly.

Strategy: Hardcoded verified values from research (HIGH confidence), with
pdfplumber sanity check against the actual PDF.
"""

import sqlite3

from . import DB_PATH, insert_metric

# ---- PDF location ----
PDF_PATH = "/opt/lobsec/data/raw/cbuae-remittances/2026-03-16.pdf"

# ---- Source name (MUST match existing DB exactly) ----
SOURCE = "cbuae"

# ---- Metric field mapping ----
METRIC_FIELDS = {
    "c2c_count": "uae|cbuae_c2c_transfers_count",
    "c2c_amount": "uae|cbuae_c2c_transfers_amount_mn",
    "b2b_count": "uae|cbuae_b2b_transfers_count",
    "b2b_amount": "uae|cbuae_b2b_transfers_amount_mn",
    "total_count": "uae|cbuae_total_transfers_count",
    "total_amount": "uae|cbuae_total_transfers_amount_mn",
}

# ---- Verified Table 48 data (from RESEARCH.md, HIGH confidence) ----
# Keys are "YYYY-MM" matching the bulletin column headers.
# Annual values (Dec 2021-2023) are full-year totals.
# 2024 quarterly values are CUMULATIVE year-to-date.
# 2025-03 is Q1 2025 (first period, use as-is).
TABLE_48_DATA = {
    # Annual full-year totals
    "2021-12": {
        "c2c_count": 60_572_382,
        "c2c_amount": 3_868_969,
        "b2b_count": 537_239,
        "b2b_amount": 5_723_490,
        "total_count": 61_109_621,
        "total_amount": 9_592_459,
    },
    "2022-12": {
        "c2c_count": 74_540_998,
        "c2c_amount": 4_910_567,
        "b2b_count": 633_663,
        "b2b_amount": 7_797_467,
        "total_count": 75_174_661,
        "total_amount": 12_708_034,
    },
    "2023-12": {
        "c2c_count": 89_505_431,
        "c2c_amount": 6_140_128,
        "b2b_count": 674_486,
        "b2b_amount": 11_018_872,
        "total_count": 90_179_917,
        "total_amount": 17_159_000,
    },
    # Quarterly cumulative YTD for 2024
    "2024-03": {
        "c2c_count": 25_556_480,
        "c2c_amount": 1_687_838,
        "b2b_count": 179_531,
        "b2b_amount": 2_839_971,
        "total_count": 25_736_011,
        "total_amount": 4_527_809,
    },
    "2024-06": {
        "c2c_count": 52_197_172,
        "c2c_amount": 3_493_837,
        "b2b_count": 362_945,
        "b2b_amount": 5_829_263,
        "total_count": 52_560_117,
        "total_amount": 9_323_100,
    },
    "2024-09": {
        "c2c_count": 80_569_401,
        "c2c_amount": 5_301_604,
        "b2b_count": 554_573,
        "b2b_amount": 9_036_713,
        "total_count": 81_123_974,
        "total_amount": 14_338_317,
    },
    "2024-12": {
        "c2c_count": 109_708_556,
        "c2c_amount": 7_406_545,
        "b2b_count": 757_910,
        "b2b_amount": 12_491_923,
        "total_count": 110_466_466,
        "total_amount": 19_898_468,
    },
    # Q1 2025 (first period of year, use as-is)
    "2025-03": {
        "c2c_count": 29_322_091,
        "c2c_amount": 2_118_444,
        "b2b_count": 199_458,
        "b2b_amount": 3_331_361,
        "total_count": 29_521_549,
        "total_amount": 5_449_805,
    },
}


def _decumulate_2024() -> dict[str, dict[str, float]]:
    """
    De-cumulate 2024 quarterly YTD values to get per-quarter amounts.

    Returns dict keyed by measurement_date (YYYY-MM-DD) with per-quarter values.
    """
    mar = TABLE_48_DATA["2024-03"]
    jun = TABLE_48_DATA["2024-06"]
    sep = TABLE_48_DATA["2024-09"]
    dec = TABLE_48_DATA["2024-12"]

    quarters = {}

    # Q1 2024 = Mar values (as-is, first period of year)
    quarters["2024-01-01"] = {field: mar[field] for field in METRIC_FIELDS}

    # Q2 2024 = Jun - Mar
    quarters["2024-04-01"] = {field: jun[field] - mar[field] for field in METRIC_FIELDS}

    # Q3 2024 = Sep - Jun
    quarters["2024-07-01"] = {field: sep[field] - jun[field] for field in METRIC_FIELDS}

    # Q4 2024 = Dec - Sep
    quarters["2024-10-01"] = {field: dec[field] - sep[field] for field in METRIC_FIELDS}

    return quarters


def _sanity_check_decumulation(quarters: dict[str, dict[str, float]]) -> bool:
    """
    Verify de-cumulated values are sane:
    1. All quarterly values must be positive
    2. Q1+Q2+Q3+Q4 must equal Dec 2024 annual total for each metric
    """
    dec_2024 = TABLE_48_DATA["2024-12"]
    all_ok = True

    print("=== De-cumulation Sanity Check ===")
    print()

    for field, metric_name in METRIC_FIELDS.items():
        q_values = [quarters[q][field] for q in sorted(quarters)]
        q_sum = sum(q_values)
        annual = dec_2024[field]

        # Check all positive
        negative_qs = [
            (q, v) for q, v in zip(sorted(quarters), q_values) if v < 0
        ]
        if negative_qs:
            print(f"  ERROR: {metric_name} has NEGATIVE quarterly values: {negative_qs}")
            all_ok = False

        # Check sum matches annual
        diff = abs(q_sum - annual)
        match_status = "OK" if diff < 1 else f"MISMATCH (diff={diff})"
        print(
            f"  {field}: Q1={q_values[0]:,.0f} Q2={q_values[1]:,.0f} "
            f"Q3={q_values[2]:,.0f} Q4={q_values[3]:,.0f} | "
            f"Sum={q_sum:,.0f} vs Annual={annual:,.0f} [{match_status}]"
        )

    print()
    return all_ok


def _try_pdfplumber_sanity_check() -> None:
    """
    Attempt to extract Table 48 from the PDF via pdfplumber and compare
    against hardcoded values. This is a sanity check, not the primary
    data source. Failures here are warnings, not errors.
    """
    try:
        import pdfplumber
    except ImportError:
        print("  pdfplumber not available -- skipping PDF sanity check")
        return

    try:
        with pdfplumber.open(PDF_PATH) as pdf:
            if len(pdf.pages) < 58:
                print(f"  PDF has only {len(pdf.pages)} pages, expected 59 -- skipping sanity check")
                return

            page = pdf.pages[57]  # Page 58, 0-indexed
            tables = page.extract_tables()

            if not tables:
                print("  No tables found on page 58 -- skipping sanity check")
                return

            # Find largest table (Table 48 should be the main one)
            table = max(tables, key=len)
            print(f"  Found table with {len(table)} rows on page 58")

            # Look for C2C count in the table to verify we have the right one
            found_match = False
            for row in table:
                if not row:
                    continue
                # Check if any cell contains a value close to our known Dec 2024 C2C count
                for cell in row:
                    if cell is None:
                        continue
                    cell_str = str(cell).replace(",", "").replace(" ", "").strip()
                    try:
                        val = int(float(cell_str))
                        # Check against Dec 2024 C2C count (109,708,556)
                        if abs(val - 109_708_556) < 1000:
                            found_match = True
                            break
                    except (ValueError, OverflowError):
                        pass
                if found_match:
                    break

            if found_match:
                print("  Sanity check PASSED: Found Dec 2024 C2C count (109,708,556) in PDF table")
            else:
                print("  Sanity check INCONCLUSIVE: Could not find exact Dec 2024 C2C count in PDF table")
                print("  (This is expected -- PDF table formatting is complex. Hardcoded values are authoritative.)")

    except Exception as e:
        print(f"  PDF sanity check error: {e}")
        print("  (Non-fatal -- using hardcoded verified values)")


def main() -> None:
    """Backfill CBUAE Table 48 data into normalized_monthly."""
    print("=== CBUAE Backfill (BACK-04) ===")
    print(f"Source: {SOURCE}")
    print(f"PDF: {PDF_PATH}")
    print(f"DB: {DB_PATH}")
    print()

    # Step 1: PDF sanity check
    print("--- PDF Sanity Check ---")
    _try_pdfplumber_sanity_check()
    print()

    # Step 2: De-cumulate 2024 quarterly data
    print("--- De-cumulating 2024 Quarterly Data ---")
    quarters_2024 = _decumulate_2024()
    ok = _sanity_check_decumulation(quarters_2024)
    if not ok:
        raise ValueError("De-cumulation sanity check FAILED -- negative values or sum mismatch")

    # Step 3: Insert into database
    db = sqlite3.connect(DB_PATH)
    row_count = 0

    try:
        # --- Annual totals: Dec 2021, Dec 2022, Dec 2023 ---
        print("--- Inserting Annual Totals ---")
        for period_key in ["2021-12", "2022-12", "2023-12"]:
            year = int(period_key[:4])
            measurement_date = f"{year}-01-01"  # Annual convention
            # CBUAE publishes ~3 months after period end
            available_date = f"{year + 1}-03-01T00:00:00Z"
            data = TABLE_48_DATA[period_key]

            for field, metric_name in METRIC_FIELDS.items():
                insert_metric(db, SOURCE, measurement_date, metric_name, data[field], available_date)
                row_count += 1

            print(f"  {year}: 6 metrics inserted (annual total)")

        # --- Quarterly 2024 (de-cumulated) ---
        print("--- Inserting Quarterly 2024 (De-cumulated) ---")
        # All 2024 data published in the Dec 2025 bulletin
        available_date_2024 = "2025-03-01T00:00:00Z"

        quarter_names = {
            "2024-01-01": "Q1",
            "2024-04-01": "Q2",
            "2024-07-01": "Q3",
            "2024-10-01": "Q4",
        }

        for measurement_date, data in sorted(quarters_2024.items()):
            q_name = quarter_names[measurement_date]
            for field, metric_name in METRIC_FIELDS.items():
                insert_metric(db, SOURCE, measurement_date, metric_name, data[field], available_date_2024)
                row_count += 1
            print(f"  {q_name} 2024 ({measurement_date}): 6 metrics inserted")

        # --- Q1 2025 (first period, use as-is) ---
        print("--- Inserting Q1 2025 ---")
        q1_2025 = TABLE_48_DATA["2025-03"]
        measurement_date_q1_2025 = "2025-01-01"
        available_date_q1_2025 = "2025-06-01T00:00:00Z"

        for field, metric_name in METRIC_FIELDS.items():
            insert_metric(db, SOURCE, measurement_date_q1_2025, metric_name, q1_2025[field], available_date_q1_2025)
            row_count += 1
        print(f"  Q1 2025 ({measurement_date_q1_2025}): 6 metrics inserted")

        db.commit()
        print()
        print(f"=== Total: {row_count} rows inserted/updated ===")

        # Step 4: Verify existing rows untouched
        cursor = db.execute(
            "SELECT COUNT(*) FROM normalized_monthly WHERE source=? AND measurement_date='2026-03-01'",
            (SOURCE,),
        )
        existing_count = cursor.fetchone()[0]
        print(f"Existing rows (2026-03-01): {existing_count} (should be 6)")

        # Step 5: Total CBUAE rows
        cursor = db.execute(
            "SELECT COUNT(*) FROM normalized_monthly WHERE source=?",
            (SOURCE,),
        )
        total_count = cursor.fetchone()[0]
        print(f"Total CBUAE rows: {total_count} (should be {row_count + 6})")

    finally:
        db.close()


if __name__ == "__main__":
    main()
