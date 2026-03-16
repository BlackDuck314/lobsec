#!/usr/bin/env python3
"""
Ingest raw scraper data into normalized_monthly SQLite table.

Reads raw JSON/PDF from /opt/lobsec/data/raw/{source}/ and produces
normalized metrics in the format:
  {source, measurement_date, metric_name, value, available_date}

Handles string→numeric parsing for scraper output (e.g., "33,500,000 AED" → 33500000).

Usage:
  python3 ingest_raw.py [--source SOURCE] [--date YYYY-MM-DD] [--dry-run]

Without --source, processes all available sources.
Without --date, processes the most recent file for each source.
"""

import argparse
import json
import re
import sqlite3
import sys
from datetime import date, datetime
from pathlib import Path
from typing import Any

RAW_DIR = Path("/opt/lobsec/data/raw")
DB_PATH = Path("/opt/lobsec/data/uae-re.db")


def parse_price(s: str | None) -> float | None:
    """Parse price string like '33,500,000 AED' or '4,907,774' to float."""
    if not s:
        return None
    # Remove currency, commas, whitespace
    cleaned = re.sub(r"[A-Za-z,\s]", "", s)
    try:
        return float(cleaned)
    except ValueError:
        return None


def parse_number(s: str | None) -> float | None:
    """Parse a number string, stripping units like 'sqft', 'sqm', '%'."""
    if not s:
        return None
    cleaned = re.sub(r"[A-Za-z%,/\s]", "", s)
    try:
        return float(cleaned)
    except ValueError:
        return None


def parse_int(s: str | None) -> int | None:
    """Parse integer from string, stripping non-digits."""
    if not s:
        return None
    cleaned = re.sub(r"[^0-9]", "", s)
    try:
        return int(cleaned) if cleaned else None
    except ValueError:
        return None


def parse_salary_range(s: str | None) -> tuple[float | None, float | None]:
    """Parse salary range like '$1,500 - $2,000' or 'AED 5,000 - 8,000'."""
    if not s:
        return None, None
    numbers = re.findall(r"[\d,]+(?:\.\d+)?", s.replace(",", ""))
    if len(numbers) >= 2:
        try:
            return float(numbers[0]), float(numbers[1])
        except ValueError:
            pass
    elif len(numbers) == 1:
        try:
            v = float(numbers[0])
            return v, v
        except ValueError:
            pass
    return None, None


def latest_file(source_dir: Path, ext: str = "json") -> Path | None:
    """Find the most recent file in a source directory."""
    files = sorted(source_dir.glob(f"*.{ext}"), reverse=True)
    return files[0] if files else None


# ── PropertyFinder ──────────────────────────────────────────────

def ingest_propertyfinder(file_path: Path, collected_at: str) -> list[dict]:
    """Transform PropertyFinder raw scraper JSON to normalized metrics."""
    with open(file_path) as f:
        data = json.load(f)

    measurement_date = datetime.fromisoformat(collected_at[:10]).replace(day=1).strftime("%Y-%m-%d")
    metrics = []

    for area_data in data:
        area = area_data.get("area", "unknown")
        cards = area_data.get("cards", [])

        # Active listing count
        metrics.append({
            "source": "propertyfinder",
            "measurement_date": measurement_date,
            "metric_name": f"{area}|all|active_listing_count",
            "value": len(cards),
            "available_date": collected_at,
        })

        if not cards:
            continue

        # Parse prices
        prices = [parse_price(c.get("price")) for c in cards]
        prices = [p for p in prices if p is not None and p > 0]

        if prices:
            prices.sort()
            median_price = prices[len(prices) // 2]
            metrics.append({
                "source": "propertyfinder",
                "measurement_date": measurement_date,
                "metric_name": f"{area}|all|median_asking_price",
                "value": median_price,
                "available_date": collected_at,
            })

        # Parse sqft prices
        sqft_prices = [parse_number(c.get("price_per_sqft")) for c in cards]
        sqft_prices = [p for p in sqft_prices if p is not None and p > 0]

        if sqft_prices:
            sqft_prices.sort()
            metrics.append({
                "source": "propertyfinder",
                "measurement_date": measurement_date,
                "metric_name": f"{area}|all|median_price_per_sqft",
                "value": sqft_prices[len(sqft_prices) // 2],
                "available_date": collected_at,
            })

        # Breakdown by property type
        by_type: dict[str, list] = {}
        for card in cards:
            pt = (card.get("property_type") or "unknown").lower().replace(" ", "_")
            by_type.setdefault(pt, []).append(card)

        for pt, type_cards in by_type.items():
            metrics.append({
                "source": "propertyfinder",
                "measurement_date": measurement_date,
                "metric_name": f"{area}|{pt}|active_listing_count",
                "value": len(type_cards),
                "available_date": collected_at,
            })

            type_prices = [parse_price(c.get("price")) for c in type_cards]
            type_prices = [p for p in type_prices if p is not None and p > 0]
            if type_prices:
                type_prices.sort()
                metrics.append({
                    "source": "propertyfinder",
                    "measurement_date": measurement_date,
                    "metric_name": f"{area}|{pt}|median_asking_price",
                    "value": type_prices[len(type_prices) // 2],
                    "available_date": collected_at,
                })

    return metrics


# ── ADREC Abu Dhabi ─────────────────────────────────────────────

def ingest_adrec(file_path: Path, collected_at: str) -> list[dict]:
    """Transform ADREC raw scraper JSON to normalized metrics."""
    with open(file_path) as f:
        data = json.load(f)

    metrics = []

    # Flatten cards from all areas
    all_cards = []
    for area_data in data:
        cards = area_data.get("cards", [])
        all_cards.extend(cards)

    if not all_cards:
        return metrics

    # Group by district
    by_district: dict[str, list] = {}
    for card in all_cards:
        district = card.get("district", "unknown")
        by_district.setdefault(district, []).append(card)

    for district, cards in by_district.items():
        # Parse registration dates to determine measurement month
        dates = []
        for c in cards:
            d = c.get("registration_date", "")
            try:
                dates.append(datetime.strptime(d, "%d/%m/%Y"))
            except (ValueError, TypeError):
                pass

        if dates:
            # Use the most common month
            months = [d.replace(day=1) for d in dates]
            measurement_date = max(set(months), key=months.count).strftime("%Y-%m-%d")
        else:
            measurement_date = datetime.fromisoformat(collected_at[:10]).replace(day=1).strftime("%Y-%m-%d")

        # Transaction volume
        metrics.append({
            "source": "adrec",
            "measurement_date": measurement_date,
            "metric_name": f"{district}|all|volume",
            "value": len(cards),
            "available_date": collected_at,
        })

        # Median price
        prices = [parse_price(c.get("price")) for c in cards]
        prices = [p for p in prices if p is not None and p > 0]
        if prices:
            prices.sort()
            metrics.append({
                "source": "adrec",
                "measurement_date": measurement_date,
                "metric_name": f"{district}|all|median_price",
                "value": prices[len(prices) // 2],
                "available_date": collected_at,
            })

        # Off-plan percentage
        offplan = sum(1 for c in cards if "off-plan" in (c.get("status") or "").lower())
        if len(cards) > 0:
            metrics.append({
                "source": "adrec",
                "measurement_date": measurement_date,
                "metric_name": f"{district}|all|offplan_pct",
                "value": round(offplan / len(cards) * 100, 1),
                "available_date": collected_at,
            })

    return metrics


# ── Bayt / LinkedIn Jobs ────────────────────────────────────────

SECTOR_KEYWORDS = {
    "tech": ["software", "developer", "engineer", "data", "cloud", "devops", "ai", "ml", "tech", "it ", "programmer"],
    "finance": ["finance", "accounting", "audit", "banking", "investment", "risk", "analyst", "accountant", "financial"],
    "hospitality": ["hotel", "restaurant", "chef", "waiter", "hospitality", "tourism", "resort", "catering"],
    "construction": ["construction", "civil", "builder", "contractor", "foreman", "surveyor", "structural"],
    "healthcare": ["doctor", "nurse", "medical", "healthcare", "clinic", "hospital", "physician"],
    "retail": ["retail", "sales", "cashier", "store", "shop", "merchandis", "customer service"],
}


def classify_sector(title: str) -> str:
    title_lower = title.lower()
    for sector, keywords in SECTOR_KEYWORDS.items():
        if any(kw in title_lower for kw in keywords):
            return sector
    return "other"


def ingest_jobs(file_path: Path, collected_at: str, platform: str) -> list[dict]:
    """Transform job listing scraper JSON to normalized metrics."""
    with open(file_path) as f:
        data = json.load(f)

    measurement_date = datetime.fromisoformat(collected_at[:10]).strftime("%Y-%m-%d")
    metrics = []

    # Flatten cards from all pages
    all_cards = []
    for page_data in data:
        cards = page_data.get("cards", [])
        all_cards.extend(cards)

    if not all_cards:
        return metrics

    # Total postings
    metrics.append({
        "source": f"{platform}-jobs",
        "measurement_date": measurement_date,
        "metric_name": f"uae|{platform}_total_postings",
        "value": len(all_cards),
        "available_date": collected_at,
    })

    # Sector breakdown
    sector_counts: dict[str, int] = {}
    salaries: list[float] = []

    for card in all_cards:
        title = card.get("job_title") or card.get("title") or ""
        if title:
            sector = classify_sector(title)
            sector_counts[sector] = sector_counts.get(sector, 0) + 1

        # Parse salary
        salary_str = card.get("salary")
        sal_min, sal_max = parse_salary_range(salary_str)
        if sal_min and sal_max:
            salaries.append((sal_min + sal_max) / 2)

    for sector, count in sector_counts.items():
        metrics.append({
            "source": f"{platform}-jobs",
            "measurement_date": measurement_date,
            "metric_name": f"uae|{platform}_postings_{sector}",
            "value": count,
            "available_date": collected_at,
        })

    if salaries:
        salaries.sort()
        metrics.append({
            "source": f"{platform}-jobs",
            "measurement_date": measurement_date,
            "metric_name": f"uae|{platform}_median_salary",
            "value": salaries[len(salaries) // 2],
            "available_date": collected_at,
        })

    return metrics


# ── KHDA Enrollment (PDF text extraction) ───────────────────────

def ingest_khda(file_path: Path, collected_at: str) -> list[dict]:
    """Extract enrollment metrics from KHDA infographic PDF text."""
    try:
        import pdfplumber
    except ImportError:
        print("ERROR: pdfplumber not installed", file=sys.stderr)
        return []

    with pdfplumber.open(file_path) as pdf:
        text = ""
        for page in pdf.pages:
            text += (page.extract_text() or "") + "\n"

    measurement_date = datetime.fromisoformat(collected_at[:10]).replace(day=1).strftime("%Y-%m-%d")
    metrics = []
    lines = text.split("\n")

    # Extract STUDENTS and SCHOOLS from header+value line pair:
    #   "STUDENTS SCHOOLS"
    #   "387,441 227"
    for i, line in enumerate(lines):
        if "STUDENTS" in line and "SCHOOLS" in line and i + 1 < len(lines):
            values = re.findall(r"[\d,]+", lines[i + 1])
            if len(values) >= 2:
                metrics.append({
                    "source": "khda",
                    "measurement_date": measurement_date,
                    "metric_name": "dubai|khda_total_students",
                    "value": float(values[0].replace(",", "")),
                    "available_date": collected_at,
                })
                metrics.append({
                    "source": "khda",
                    "measurement_date": measurement_date,
                    "metric_name": "dubai|khda_total_schools",
                    "value": float(values[1].replace(",", "")),
                    "available_date": collected_at,
                })
            break

    # Extract total teachers
    m = re.search(r"TEACHERS\s*\n([\d,]+)", text)
    if m:
        metrics.append({
            "source": "khda",
            "measurement_date": measurement_date,
            "metric_name": "dubai|khda_total_teachers",
            "value": float(m.group(1).replace(",", "")),
            "available_date": collected_at,
        })

    # Extract Emirati students
    m = re.search(r"([\d,]+)\s*\n?\s*Emirati students", text)
    if m:
        metrics.append({
            "source": "khda",
            "measurement_date": measurement_date,
            "metric_name": "dubai|khda_emirati_students",
            "value": float(m.group(1).replace(",", "")),
            "available_date": collected_at,
        })

    # Extract enrollment by curriculum
    curriculum_pattern = r"(UK|Indian|US|IB|UK/IB|MoE|French|SABIS|Philippine|Pakistani|Iranian|US/IB|German|Chinese|Russian|Australian|Japanese)\s+([\d,]+)\s+(\d+)"
    for m in re.finditer(curriculum_pattern, text):
        curriculum = m.group(1).lower().replace("/", "_")
        students = float(m.group(2).replace(",", ""))
        schools = float(m.group(3))
        metrics.append({
            "source": "khda",
            "measurement_date": measurement_date,
            "metric_name": f"dubai|khda_{curriculum}_students",
            "value": students,
            "available_date": collected_at,
        })
        metrics.append({
            "source": "khda",
            "measurement_date": measurement_date,
            "metric_name": f"dubai|khda_{curriculum}_schools",
            "value": schools,
            "available_date": collected_at,
        })

    return metrics


# ── CBUAE Banking Indicators ───────────────────────────────────

def ingest_cbuae_mortgages(file_path: Path, collected_at: str) -> list[dict]:
    """Extract banking/credit metrics from CBUAE Banking Indicators PDF.

    The PDF has a dense table with columns grouped by 3 (AD, Dubai, Other Emirates).
    Each group of 3 represents one month. The last 3 non-percentage columns are
    the most recent period. We sum them to get the UAE total (in billions AED).
    """
    try:
        import pdfplumber
    except ImportError:
        print("ERROR: pdfplumber not installed", file=sys.stderr)
        return []

    with pdfplumber.open(file_path) as pdf:
        table = pdf.pages[0].extract_tables()[0]

    measurement_date = datetime.fromisoformat(collected_at[:10]).replace(day=1).strftime("%Y-%m-%d")
    metrics = []

    def extract_latest_total(row: list) -> float | None:
        """Sum the last 3 numeric (non-percentage) values in a row.
        These represent AD + Dubai + Other Emirates for the latest month.
        """
        # Extract numeric values, stopping at percentage columns
        nums = []
        for cell in row[1:]:
            if not cell or "%" in str(cell):
                continue
            try:
                nums.append(float(str(cell).replace(",", "")))
            except (ValueError, TypeError):
                pass
        # Last 3 values are the most recent period (AD, Dubai, Other)
        if len(nums) >= 3:
            return sum(nums[-3:])
        return None

    indicators = {
        "Domestic Credit": "uae|cbuae_domestic_credit_bn",
        "Total Deposits": "uae|cbuae_total_deposits_bn",
    }

    for row in table:
        if not row or not row[0]:
            continue
        label = str(row[0]).strip()
        for pattern, metric_name in indicators.items():
            if pattern in label:
                total = extract_latest_total(row)
                if total is not None:
                    metrics.append({
                        "source": "cbuae",
                        "measurement_date": measurement_date,
                        "metric_name": metric_name,
                        "value": round(total, 1),
                        "available_date": collected_at,
                    })

    return metrics


# ── CBUAE Statistical Bulletin (Remittances/Fund Transfers) ────

def ingest_cbuae_remittances(file_path: Path, collected_at: str) -> list[dict]:
    """Extract fund transfer metrics from CBUAE Statistical Bulletin PDF.

    The table (Table 48) has headers like 'Dec 2021', 'Dec 2022', ..., 'Dec 2025 *'
    and rows for Customer-to-Customer and Bank-to-Bank transfers.
    We extract the LAST column value (most recent period).
    """
    try:
        import pdfplumber
    except ImportError:
        print("ERROR: pdfplumber not installed", file=sys.stderr)
        return []

    metrics = []
    measurement_date = datetime.fromisoformat(collected_at[:10]).replace(day=1).strftime("%Y-%m-%d")

    with pdfplumber.open(file_path) as pdf:
        for page in pdf.pages:
            text = page.extract_text() or ""
            # Must have both "Fund Transfer" and "Number of Transfers" (actual data page, not TOC)
            if "Fund Transfer" not in text or "Number of Transfers" not in text:
                continue

            tables = page.extract_tables()
            if not tables:
                continue

            table = tables[0]
            # Process rows — track which section we're in
            section = None
            for row in table:
                if not row or not row[0]:
                    continue
                label = str(row[0]).strip()

                if "Customer to Customer" in label:
                    section = "c2c"
                elif "Bank to Bank" in label:
                    section = "b2b"
                elif "Total Domestic" in label:
                    section = "total"
                elif "Number of Transfers" in label and section:
                    values = [parse_price(str(c)) for c in row[1:] if c and str(c).strip()]
                    values = [v for v in values if v is not None]
                    if values:
                        metrics.append({
                            "source": "cbuae",
                            "measurement_date": measurement_date,
                            "metric_name": f"uae|cbuae_{section}_transfers_count",
                            "value": values[-1],
                            "available_date": collected_at,
                        })
                elif "Amount" in label and section:
                    values = [parse_price(str(c)) for c in row[1:] if c and str(c).strip()]
                    values = [v for v in values if v is not None]
                    if values:
                        metrics.append({
                            "source": "cbuae",
                            "measurement_date": measurement_date,
                            "metric_name": f"uae|cbuae_{section}_transfers_amount_mn",
                            "value": values[-1],
                            "available_date": collected_at,
                        })

            break

    return metrics


# ── DP World / Jebel Ali Port (RSS from __NEXT_DATA__) ────────

def ingest_dpworld(file_path: Path, collected_at: str) -> list[dict]:
    """Extract Jebel Ali port throughput metrics from DP World RSS feed.

    The news/releases page embeds an RSS feed with 446+ items in __NEXT_DATA__.
    We filter for Jebel Ali throughput releases and extract TEU + cargo figures
    from titles, subtitles, and descriptions.
    """
    html = file_path.read_text(encoding="utf-8", errors="replace")

    # Extract __NEXT_DATA__ JSON
    m = re.search(r'<script id="__NEXT_DATA__"[^>]*>(.*?)</script>', html, re.DOTALL)
    if not m:
        print("  WARN: No __NEXT_DATA__ found in DP World HTML", file=sys.stderr)
        return []

    data = json.loads(m.group(1))
    cp = data.get("props", {}).get("pageProps", {}).get("componentProps", {})

    # Find the RSS feed in componentProps
    items = []
    for comp in cp.values():
        fd = comp.get("params", {}).get("feedData")
        if fd:
            if isinstance(fd, str):
                fd = json.loads(fd)
            items = fd.get("channel", {}).get("item", [])
            break

    if not items:
        print("  WARN: No RSS items found in DP World page", file=sys.stderr)
        return []

    print(f"  Found {len(items)} RSS items, filtering for Jebel Ali...", file=sys.stderr)

    metrics = []

    # Keywords that indicate Jebel Ali / UAE port throughput data
    jebel_ali_keywords = ["jebel ali", "jebel ali port"]
    throughput_keywords = ["teu", "throughput", "cargo volume", "breakbulk"]

    for item in items:
        title = item.get("title", "")
        subtitle = item.get("subtitle", "")
        pub_date = item.get("pubDate", "")
        combined = f"{title} {subtitle}".lower()

        # Must mention Jebel Ali AND have throughput data
        has_jebel_ali = any(kw in combined for kw in jebel_ali_keywords)
        has_throughput = any(kw in combined for kw in throughput_keywords)

        if not (has_jebel_ali and has_throughput):
            continue

        # Parse publication date → measurement date (start of quarter)
        try:
            # pubDate format: "Wed, 19 Feb 2025 13:31:45 +0100"
            from email.utils import parsedate_to_datetime
            pub_dt = parsedate_to_datetime(pub_date)
            # Use start of reporting year (data is annual)
            measurement_date = f"{pub_dt.year - 1}-01-01"
            item_collected_at = pub_dt.isoformat()
        except Exception:
            measurement_date = datetime.fromisoformat(collected_at[:10]).replace(day=1, month=1).strftime("%Y-%m-%d")
            item_collected_at = collected_at

        combined_text = f"{title} {subtitle}"

        # Extract TEU figures: "15.5 million TEUs" or "88.3 million TEUs"
        teu_matches = re.findall(r"([\d,.]+)\s*million\s*TEU", combined_text, re.I)
        if teu_matches:
            # First TEU figure is usually Jebel Ali specific
            teu_value = float(teu_matches[0].replace(",", ""))
            metrics.append({
                "source": "dpworld",
                "measurement_date": measurement_date,
                "metric_name": "dubai|jebel_ali_container_throughput_mn_teu",
                "value": teu_value,
                "available_date": item_collected_at,
            })

        # Extract cargo/breakbulk tonnage: "5.4 million metric tonnes"
        tonnage_matches = re.findall(r"([\d,.]+)\s*million\s*(?:metric\s+)?tonnes", combined_text, re.I)
        if tonnage_matches:
            tonnage = float(tonnage_matches[0].replace(",", ""))
            metrics.append({
                "source": "dpworld",
                "measurement_date": measurement_date,
                "metric_name": "dubai|jebel_ali_breakbulk_cargo_mn_tonnes",
                "value": tonnage,
                "available_date": item_collected_at,
            })

        # Extract YoY growth: "up 8.3%" or "volumes rise 6.7%"
        growth_matches = re.findall(r"(?:up|rise|growth of|grew)\s+([\d,.]+)\s*%", combined_text, re.I)
        if growth_matches:
            growth = float(growth_matches[0].replace(",", ""))
            metrics.append({
                "source": "dpworld",
                "measurement_date": measurement_date,
                "metric_name": "dubai|jebel_ali_volume_yoy_growth_pct",
                "value": growth,
                "available_date": item_collected_at,
            })

        print(f"  Matched: {title[:80]}... → {len([m for m in metrics if m['measurement_date'] == measurement_date])} metrics", file=sys.stderr)

    return metrics


# ── Database insertion ──────────────────────────────────────────

def insert_metrics(db_path: Path, metrics: list[dict], dry_run: bool = False) -> int:
    """Insert normalized metrics into SQLite normalized_monthly table.

    Uses upsert semantics: DELETE existing records for the same
    (source, measurement_date) range, then INSERT new records.
    """
    if not metrics:
        return 0

    if dry_run:
        return len(metrics)

    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()

    # Group by (source, measurement_date) for upsert
    groups: dict[tuple[str, str], list[dict]] = {}
    for m in metrics:
        key = (m["source"], m["measurement_date"])
        groups.setdefault(key, []).append(m)

    inserted = 0
    for (source, mdate), group_metrics in groups.items():
        # Delete existing records for this source+date
        cursor.execute(
            "DELETE FROM normalized_monthly WHERE source = ? AND measurement_date = ?",
            (source, mdate),
        )
        deleted = cursor.rowcount

        # Insert new records
        for m in group_metrics:
            cursor.execute(
                "INSERT INTO normalized_monthly (source, measurement_date, metric_name, value, available_date) "
                "VALUES (?, ?, ?, ?, ?)",
                (m["source"], m["measurement_date"], m["metric_name"], m["value"], m["available_date"]),
            )
            inserted += 1

        if deleted > 0:
            print(f"  Replaced {deleted} existing records for {source}/{mdate}", file=sys.stderr)

    conn.commit()
    conn.close()
    return inserted


# ── Orchestration ───────────────────────────────────────────────

SOURCE_HANDLERS = {
    "propertyfinder-listings": ("json", ingest_propertyfinder),
    "adrec-abu-dhabi": ("json", ingest_adrec),
    "bayt-jobs": ("json", lambda fp, ca: ingest_jobs(fp, ca, "bayt")),
    "linkedin-jobs": ("json", lambda fp, ca: ingest_jobs(fp, ca, "linkedin")),
    "indeed-jobs": ("json", lambda fp, ca: ingest_jobs(fp, ca, "indeed")),
    "khda-enrollment": ("pdf", ingest_khda),
    "cbuae-mortgages": ("pdf", ingest_cbuae_mortgages),
    "cbuae-remittances": ("pdf", ingest_cbuae_remittances),
    "jebel-ali-port": ("html", ingest_dpworld),
}


def main():
    parser = argparse.ArgumentParser(description="Ingest raw scraper data into normalized SQLite")
    parser.add_argument("--source", help="Process only this source (e.g., propertyfinder-listings)")
    parser.add_argument("--date", help="Process specific date (YYYY-MM-DD)")
    parser.add_argument("--dry-run", action="store_true", help="Parse but don't write to DB")
    parser.add_argument("--db", default=str(DB_PATH), help="SQLite database path")
    args = parser.parse_args()

    sources = [args.source] if args.source else list(SOURCE_HANDLERS.keys())
    db_path = Path(args.db)

    total_metrics = 0
    total_inserted = 0

    for source in sources:
        if source not in SOURCE_HANDLERS:
            print(f"SKIP: Unknown source '{source}'", file=sys.stderr)
            continue

        ext, handler = SOURCE_HANDLERS[source]
        source_dir = RAW_DIR / source

        if not source_dir.exists():
            print(f"SKIP: No data directory for {source}", file=sys.stderr)
            continue

        if args.date:
            file_path = source_dir / f"{args.date}.{ext}"
        else:
            file_path = latest_file(source_dir, ext)

        if not file_path or not file_path.exists():
            print(f"SKIP: No {ext} file for {source}", file=sys.stderr)
            continue

        # Use file date as collected_at
        file_date = file_path.stem  # e.g., "2026-03-16"
        collected_at = f"{file_date}T00:00:00Z"

        print(f"Processing {source} from {file_path.name}...", file=sys.stderr)

        try:
            metrics = handler(file_path, collected_at)
            total_metrics += len(metrics)

            if args.dry_run:
                print(f"  {len(metrics)} metrics (dry run)", file=sys.stderr)
                for m in metrics[:5]:
                    print(f"    {m['metric_name']}: {m['value']}", file=sys.stderr)
                if len(metrics) > 5:
                    print(f"    ... and {len(metrics) - 5} more", file=sys.stderr)
            else:
                inserted = insert_metrics(db_path, metrics)
                total_inserted += inserted
                print(f"  {inserted} metrics inserted", file=sys.stderr)

        except Exception as e:
            print(f"ERROR processing {source}: {e}", file=sys.stderr)
            continue

    print(f"\nTotal: {total_metrics} metrics, {total_inserted} inserted", file=sys.stderr)


if __name__ == "__main__":
    main()
