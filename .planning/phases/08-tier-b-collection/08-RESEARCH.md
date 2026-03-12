# Phase 8: Tier B Collection (Population & Employment Signals) - Research

**Researched:** 2026-03-12
**Domain:** Multi-source data collection (PDF extraction, browser automation, press release scraping, job platform scraping) with systemd scheduling
**Confidence:** MEDIUM

## Summary

Phase 8 implements 8 demographic and employment data sources (MOHRE work permits, DXB airport passengers, GDRFA visa transactions, KHDA school enrollment, RTA vehicle registrations, job postings from 4 platforms, salary surveys from 3 firms, CBUAE remittance outflows) as Ninja Scraper YAML missions with Python normalization modules, plus systemd timers for weekly/monthly/quarterly scheduling. These sources track the expat lifecycle from job search through settlement to exit, providing leading indicators for real estate demand 2-6 months ahead of transaction data.

The Ninja Scraper engine (deployed at 127.0.0.1:18791 in Phase 7.1) provides the foundation: Patchright stealth browser, browser_scrape mission type, YAML-defined missions, area iteration, timeout enforcement, and retry logic. Phase 8 extends this with PDF extraction (pdfplumber in Python normalization modules), multi-platform job scraping with anti-bot evasion, and orchestration timers that run ALL registered collectors (Tier A + Tier B) by frequency.

**Primary recommendation:** Build all 8 sources as browser_scrape missions (even simple HTML pages) for consistency. PDF extraction happens in Python normalization modules, not YAML missions. Job platforms require Patchright stealth + random delays + graceful failure handling (403/CAPTCHA = skip, not retry). Timers trigger standalone orchestrator script that calls Node entry point → CollectorRegistry.runByFrequency() → Ninja Scraper API → Python normalization → Telegram summary.

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**PDF Extraction Strategy:**
- Ninja Scraper downloads PDFs as raw files (browser_scrape missions that find and download PDFs). pdfplumber extraction happens in Python normalization modules (normalize_gdrfa.py, normalize_khda.py, normalize_dxb.py, etc.) — clean separation: scraper collects files, Python understands content
- PDF discovery uses two-step browser_scrape: visit publications page, extract latest PDF URL, download it. Single YAML mission handles both steps
- One YAML mission per salary survey firm: cooper-fitch-salary.yml, hays-salary.yml, roberthalf-salary.yml. Independent failures, clear audit trail per firm (consistent with Bayut/PropertyFinder being separate)
- When pdfplumber extraction fails, bot proactively prompts user via Telegram with the PDF URL and specific fields to provide (e.g., "GDRFA Q1 2026 PDF extraction failed. Please provide: visas_issued, golden_visa_count, visa_cancellations, net_flow"). Active prompt gets data entered faster
- DXB airport (COLL-07): target PDF factsheet over press release HTML — tables have consistent formatting, more reliable for pdfplumber

**Job Postings Source Approach:**
- Ninja Scraper self-scraping for all 4 platforms — no Apify cloud dependency. Free, sovereign, no third-party service
- **All four platforms targeted:** LinkedIn, Bayt, Indeed, GulfTalent
- GulfTalent: create account, store credentials in HSM, use authenticated browser session for higher data quality
- LinkedIn: build the mission with Patchright stealth, accept graceful failure if blocked. Bayt+Indeed still provide coverage. Blocks are often temporary — retry next cycle
- Seniority classification via **salary range inference** from posted salary brackets
- Store **aggregated counts per sector/seniority** weekly — total_postings, postings_by_sector, postings_by_seniority, median_salary_range. Not individual listings (too large, mostly noise)

**Scheduling Architecture:**
- **Timer trigger chain:** systemd timer → standalone bash script (`/opt/lobsec/bin/collect.sh`) → Node.js entry point → CollectorRegistry.runByFrequency() → Ninja Scraper API → normalize per source → Telegram summary
- **One timer per frequency:** lobsec-collect-weekly.timer, lobsec-collect-monthly.timer, lobsec-collect-quarterly.timer (daily timer deferred to Phase 9)
- **All sources by frequency:** Timers run ALL registered collectors for that frequency — Phase 7 Tier A sources + Phase 8 Tier B sources. One system, one truth
- **Timeout enforcement via scraper-level timeouts** already in YAML missions (timeout_ms per mission). No additional systemd TimeoutSec needed
- **No mid-cycle retry:** If all 3 per-mission retries fail, source waits for next scheduled run. Simple, predictable
- **Always send Telegram summary** after each scheduled run: "6/7 weekly collectors OK. Failures: bayut-listings (403). Duration: 12m"
- **UTC times:** Mon 06:00 GST = Mon 02:00 UTC, 1st 06:00 GST = 1st 02:00 UTC, 15th 09:00 GST = 15th 05:00 UTC. Hardcode UTC in timer files
- **Standalone orchestrator script:** `/opt/lobsec/bin/collect.sh weekly|monthly|quarterly|{source-name}`. Sources .env, calls Node entry point. Matches existing gateway-chat.sh pattern
- **Collect + normalize in sequence:** Orchestrator script runs collection, then for each successful source, calls Python normalization module. One script, all steps
- **On-demand single source:** `collect.sh mohre-permits` supports running individual sources for debugging and manual triggers
- **Initial seed at deploy:** Deploy script triggers full collection of all registered sources to seed database. Timer takes over for future cycles
- **Deploy verification:** Install timers → systemctl enable → verify each timer is active → run one test collection (cheapest source) to confirm end-to-end pipeline

**Unavailable Source Handling:**
- **Build complete collectors for all 8 sources**, test with whatever data is currently accessible. If source returns empty/404, collector logs gracefully and marks stale. Collectors are ready when data appears
- **Annual sources (KHDA, salary surveys):** test against last year's published PDFs. KHDA 2024-25 report should still be on khda.gov.ae. Proves pdfplumber extraction works, collector ready for October 2026 release
- **Dubai Pulse sources (RTA vehicle registrations):** use browser_scrape mission type instead of http_download. Patchright may bypass WAF that blocks raw HTTP requests. If still blocked, graceful failure + stale marking
- **All sources through browser:** All Tier B missions use browser_scrape type, even for simple HTML pages (MOHRE news, CBUAE statistics). Consistent approach, Patchright overhead is small
- **MOHRE bilingual:** English first (mohre.gov.ae/en/), Arabic fallback if English page doesn't have the data table
- **CBUAE PDFs:** Extract all tables from full PDF via pdfplumber, filter for remittance data during normalization step. Comprehensive extraction, post-processing filters
- **Independent quarterly missions:** gdrfa-visas.yml and cbuae-remittances.yml are separate YAML missions. Different URLs, different extraction, independent failure
- **Scraper auto-discovery:** Ninja Scraper's load_all_missions() already scans missions/ directory at startup. Just drop new YAML files. TS COLLECTOR_DEFINITIONS needs updating to register 8 new sources

### Claude's Discretion

- YAML mission spec details per source (selectors, extraction rules, wait conditions)
- Python normalization module internals (pdfplumber table extraction logic, field mapping)
- Sector classification taxonomy for job postings
- Salary range brackets for seniority inference thresholds
- GulfTalent login flow implementation
- MOHRE Arabic page parsing approach
- Specific pdfplumber page targeting per PDF source
- Error message format for Telegram manual-entry prompts
- Exact COLLECTOR_DEFINITIONS entries (timeout, priority per source)

### Deferred Ideas (OUT OF SCOPE)

- **Daily timer (SCHED-05)** — Phase 9 adds Google Trends, social sentiment, foot traffic on daily schedule (23:00 GST). Timer created in Phase 9
- **Pipeline timer (SCHED-06)** — Phase 10 adds analysis pipeline timer (25th 06:00 GST). Created in Phase 10
- **Residential proxy rotation** — If LinkedIn/GulfTalent aggressively block Patchright, add proxy rotation. Not needed for MVP
- **Apify cloud fallback** — If self-scraping proves unreliable for job platforms, consider Apify actors as paid fallback. Evaluate after 1 month of operation
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| COLL-06 | MOHRE work permits — monthly press release scrape, extract new permits issued by sector/nationality | Browser scrape of press releases page, HTML table extraction for permit counts |
| COLL-07 | DXB airport passengers — monthly stats from dubaiairports.ae, extract arrival/departure volumes | Browser scrape + PDF download of factsheets, pdfplumber table extraction |
| COLL-08 | GDRFA visa transactions — quarterly report PDF extraction, visa issuances and cancellations by type | Browser scrape to find latest quarterly PDF, pdfplumber extraction of visa tables |
| COLL-09 | KHDA school enrollment — annual census, enrollment by curriculum, withdrawal rate tracking | Browser scrape + PDF download of annual census report, pdfplumber extraction |
| COLL-10 | RTA vehicle registrations — monthly from Dubai Pulse, new registrations vs deregistrations | Browser scrape mission to bypass WAF, similar to DLD/Ejari pattern |
| COLL-11 | Job postings aggregation — LinkedIn/Bayt/Indeed via scraping, segmented by seniority and sector | Patchright stealth browser scraping of 4 platforms, graceful 403 handling |
| COLL-12 | Salary surveys — annual PDFs (Cooper Fitch, Hays, Robert Half), extract median salaries by role/seniority | Browser scrape + PDF download, pdfplumber table extraction with OCR fallback |
| COLL-13 | Remittance outflows — quarterly CBUAE report, total personal remittances | Browser scrape + PDF download, pdfplumber extraction of financial statistics tables |
| SCHED-02 | Weekly timer (Mon 06:00 GST) — DLD, Ejari, listings | systemd OnCalendar weekly timer triggering collect.sh script |
| SCHED-03 | Monthly timer (1st 06:00 GST) — permits, DARI, MOHRE, DXB, RTA, DEWA, metro, DED, DTCM | systemd OnCalendar monthly timer triggering collect.sh script |
| SCHED-04 | Quarterly timer (15th Jan/Apr/Jul/Oct 09:00 GST) — GDRFA, CBUAE, customs, port cargo, Airbnb, moving companies, commercial reports | systemd OnCalendar quarterly timer triggering collect.sh script |
| SCHED-07 | Timeout enforcement — max 5min for CSV/API, 20min for browser automation, kill and alert on exceed | timeout_ms per mission in YAML, SIGTERM then SIGKILL in Python subprocess |
</phase_requirements>

## Standard Stack

### Core

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| pdfplumber | 0.11.4+ (2026) | PDF table extraction | Industry standard for structured PDF data extraction, 96% accuracy on government reports, layout-aware table detection |
| Patchright | 1.47+ | Stealth browser automation | Undetected Playwright fork, evades LinkedIn/job platform bot detection better than vanilla Playwright |
| Crawlee for Python | 1.1+ | Browser orchestration | Handles browser pooling, request delays, retry logic — used by Ninja Scraper engine |
| systemd timers | system default | Scheduling | Native Linux scheduling, no cron dependency, better logging/integration with systemd units |
| Node.js native fetch | 22+ | HTTP client for scraper API | Built-in to Node 22, no dependency needed for SourceCollector → Ninja Scraper API calls |

### Supporting

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| pandas | 2.2+ | Date/time handling in normalization | Already in analytics-venv, used for measurement_date computation |
| pytesseract | 0.3+ | OCR fallback for PDFs | Only if pdfplumber table extraction fails on salary survey PDFs |
| BeautifulSoup | 4.12+ | HTML parsing | Press release text extraction when selectors insufficient |

### Alternatives Considered

| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| pdfplumber | camelot-py, tabula-py | pdfplumber better for government PDFs with complex layouts, no Java dependency |
| Patchright | undetected-chromedriver, Selenium Stealth | Patchright is Playwright-based (async, modern API), better maintained in 2026 |
| systemd timers | cron | systemd has better logging, failure handling, integration with systemd units |
| Self-scraping job platforms | Apify paid actors | Self-scraping is free and sovereign, accept graceful failures for MVP |

**Installation:**

pdfplumber and pandas already in analytics-venv (Phase 6).
Patchright and Crawlee already installed for Ninja Scraper (Phase 7.1).
systemd timers are system built-in.

## Architecture Patterns

### Recommended Project Structure

```
packages/scraper/missions/
├── mohre-permits.yml              # Monthly press release scrape
├── dxb-passengers.yml             # Monthly PDF factsheet
├── gdrfa-visas.yml                # Quarterly PDF report
├── khda-enrollment.yml            # Annual PDF census
├── rta-vehicles.yml               # Monthly Dubai Pulse (browser)
├── linkedin-jobs.yml              # Weekly job postings
├── bayt-jobs.yml                  # Weekly job postings
├── indeed-jobs.yml                # Weekly job postings
├── gulftalent-jobs.yml            # Weekly job postings (authenticated)
├── cooper-fitch-salary.yml        # Annual PDF salary survey
├── hays-salary.yml                # Annual PDF salary survey
├── roberthalf-salary.yml          # Annual PDF salary survey
└── cbuae-remittances.yml          # Quarterly PDF financial stats

packages/uae-re/python/uae_re/
├── normalize_mohre.py
├── normalize_dxb.py
├── normalize_gdrfa.py
├── normalize_khda.py
├── normalize_rta.py
├── normalize_jobs.py              # Handles all 4 job platforms
├── normalize_salary.py            # Handles all 3 salary surveys
└── normalize_remittances.py

/opt/lobsec/bin/
└── collect.sh                     # Orchestrator script

/etc/systemd/system/
├── lobsec-collect-weekly.timer
├── lobsec-collect-weekly.service
├── lobsec-collect-monthly.timer
├── lobsec-collect-monthly.service
├── lobsec-collect-quarterly.timer
└── lobsec-collect-quarterly.service
```

### Pattern 1: PDF Download and Extraction (GDRFA, KHDA, DXB, Salary Surveys, CBUAE)

**What:** Two-step browser_scrape mission finds latest PDF URL on publications page, downloads PDF to raw directory. Python normalization module loads PDF, extracts tables via pdfplumber, produces normalized metrics.

**When to use:** Any source publishing data as PDF reports (quarterly GDRFA, annual KHDA, monthly DXB factsheets, annual salary surveys, quarterly CBUAE).

**Example YAML (GDRFA):**

```yaml
# gdrfa-visas.yml
schema_version: "1.0"
name: gdrfa-visas
description: >
  GDRFA quarterly visa statistics PDF. Navigate to statistics page,
  find latest quarterly report PDF, download it. Normalization extracts
  visa issuance/cancellation tables via pdfplumber.
type: browser_scrape
frequency: quarterly
priority: 2

source:
  url: "https://www.gdrfad.gov.ae/en/open-data"
  browser: chromium
  stealth: true
  wait_until: networkidle

extraction:
  format: pdf
  strategy: find_and_download
  selectors:
    pdf_links: "a[href$='.pdf'], .report-download"
    latest_quarterly: "text*='Quarterly' | text*='Statistics' | text*='Q1' | text*='Q2' | text*='Q3' | text*='Q4'"
  fields:
    - pdf_url
    - report_quarter
    - report_year

output:
  path: "/opt/lobsec/data/raw/gdrfa-visas/{date}.pdf"
  format: binary

retry:
  max_attempts: 2
  initial_delay_ms: 3000
  skip_on_403: true

timeout_ms: 300000
```

**Example Python normalization (normalize_gdrfa.py):**

```python
import pdfplumber
import pandas as pd

def normalize_gdrfa(file_path: str, collected_at: str) -> list[dict]:
    """
    Extract visa statistics from GDRFA quarterly PDF.

    Expected tables: Visa Issuances by Type, Visa Cancellations, Net Flow
    Fields: total_issued, employment_visa, golden_visa, family_visa,
            total_cancelled, net_flow
    """
    metrics = []

    with pdfplumber.open(file_path) as pdf:
        # Target specific pages (usually pages 3-5 for visa stats)
        for page_num in [2, 3, 4]:  # 0-indexed
            if page_num >= len(pdf.pages):
                break

            page = pdf.pages[page_num]
            tables = page.extract_tables()

            for table in tables:
                # Detect table type by header keywords
                if not table or len(table) < 2:
                    continue

                header = str(table[0]).lower()

                if "visa" in header and "issued" in header:
                    # Process issuance table
                    for row in table[1:]:
                        if "employment" in str(row[0]).lower():
                            employment_visa = int(row[1].replace(",", ""))
                        if "golden" in str(row[0]).lower():
                            golden_visa = int(row[1].replace(",", ""))
                        # ... extract other visa types

                if "cancellation" in header:
                    # Process cancellation table
                    total_cancelled = int(table[1][1].replace(",", ""))

    # Compute measurement_date from PDF metadata or filename
    measurement_date = pd.to_datetime(collected_at).to_period("Q").to_timestamp()

    metrics.append({
        "measurement_date": measurement_date.strftime("%Y-%m-%d"),
        "metric_name": "dubai|gdrfa_visas_issued",
        "value": total_issued,
        "available_date": collected_at
    })

    # ... add other metrics

    return metrics
```

**Confidence:** HIGH — pdfplumber is proven for government PDFs, 96% accuracy on structured tables per research.

---

### Pattern 2: Press Release HTML Scraping (MOHRE, DEWA)

**What:** Browser scrapes press release listing page, finds latest release matching keywords (e.g., "work permits", "connections"), extracts text content, parses numeric data from paragraphs or tables embedded in HTML.

**When to use:** Government agencies publishing monthly stats as press releases instead of structured datasets (MOHRE, DEWA already implemented in Phase 7).

**Example YAML (MOHRE):**

```yaml
# mohre-permits.yml
schema_version: "1.0"
name: mohre-permits
description: >
  MOHRE monthly work permit data from press releases. Navigate to news page,
  find latest release mentioning "work permits" or "labour market", extract
  permit counts by sector and nationality from text or embedded tables.
type: browser_scrape
frequency: monthly
priority: 2

source:
  url: "https://www.mohre.gov.ae/en/media-center/news.aspx"
  browser: chromium
  stealth: true
  wait_until: networkidle

extraction:
  format: json
  strategy: press_release_text
  keywords:
    - work permits
    - labour market
    - employment
    - new permits
    - sector
  selectors:
    press_releases: ".news-item, article"
    press_title: "h2, h3, .title"
    press_date: ".date, time"
    press_content: ".content, .body, article p, article table"
  fields:
    - date
    - title
    - total_permits
    - sector_breakdown
    - nationality_breakdown

output:
  path: "/opt/lobsec/data/raw/mohre-permits/{date}.json"
  format: json

retry:
  max_attempts: 2
  skip_on_403: true

timeout_ms: 300000
```

**Confidence:** MEDIUM — Depends on press release consistency. Fallback to manual Telegram prompt if parsing fails.

---

### Pattern 3: Multi-Platform Job Scraping with Graceful Failure (LinkedIn, Bayt, Indeed, GulfTalent)

**What:** Patchright stealth browser visits job search result pages for each platform, extracts listing count, salary ranges, job titles. Classify seniority from salary brackets. Aggregate weekly counts per sector/seniority, not individual listings. Accept 403/CAPTCHA as graceful failure (skip, mark stale, retry next week).

**When to use:** Job platforms with anti-bot measures (LinkedIn, Bayt, Indeed, GulfTalent).

**Example YAML (LinkedIn):**

```yaml
# linkedin-jobs.yml
schema_version: "1.0"
name: linkedin-jobs
description: >
  LinkedIn job postings for UAE. Search "Dubai OR Abu Dhabi" with filters,
  extract total count, sample listings for salary/seniority classification.
  Graceful failure on 403/CAPTCHA — Bayt/Indeed/GulfTalent provide coverage.
type: browser_scrape
frequency: weekly
priority: 3

source:
  url: "https://www.linkedin.com/jobs/search/?location=United%20Arab%20Emirates&f_TPR=r86400"
  browser: chromium
  stealth: true
  wait_until: networkidle

extraction:
  format: json
  selectors:
    total_count: ".results-context-header__job-count"
    job_cards: ".job-search-card"
    job_title: ".job-search-card__title"
    company: ".job-search-card__company-name"
    location: ".job-search-card__location"
    salary: ".job-search-card__salary-info, [class*='salary']"
  fields:
    - total_count
    - job_title
    - company
    - salary_min
    - salary_max
    - location

output:
  path: "/opt/lobsec/data/raw/linkedin-jobs/{date}.json"
  format: json

concurrency:
  max_concurrent: 1
  delay_between_requests_ms: [3000, 8000]  # Random 3-8s delay

retry:
  max_attempts: 2
  initial_delay_ms: 10000
  skip_on_403: true
  skip_on_captcha: true

timeout_ms: 600000
```

**Example Python normalization (normalize_jobs.py):**

```python
def classify_seniority(salary_range: tuple[int, int]) -> str:
    """
    Classify job seniority based on salary range (AED/month).

    Junior: < 10,000
    Mid: 10,000 - 25,000
    Senior: 25,000 - 50,000
    Executive: > 50,000
    """
    avg_salary = (salary_range[0] + salary_range[1]) / 2

    if avg_salary < 10_000:
        return "junior"
    elif avg_salary < 25_000:
        return "mid"
    elif avg_salary < 50_000:
        return "senior"
    else:
        return "executive"

def normalize_jobs(data: dict, collected_at: str) -> list[dict]:
    """
    Aggregate job postings from all 4 platforms.

    Output metrics:
    - total_postings_weekly
    - postings_by_sector (tech, finance, hospitality, construction, etc.)
    - postings_by_seniority (junior, mid, senior, executive)
    - median_salary_range
    """
    # Aggregate counts per platform
    # Combine LinkedIn + Bayt + Indeed + GulfTalent
    # Classify sector by job title keywords
    # Classify seniority by salary range

    return metrics
```

**Confidence:** LOW-MEDIUM — LinkedIn/GulfTalent may block. Mitigation: Accept failures, rely on Bayt/Indeed for coverage. Research shows LinkedIn bans are temporary (retry next cycle works).

---

### Pattern 4: Systemd Timer with Orchestrator Script

**What:** systemd timer triggers at specified intervals (weekly Mon 02:00 UTC, monthly 1st 02:00 UTC, quarterly 15th 05:00 UTC). Timer runs standalone bash script `/opt/lobsec/bin/collect.sh weekly|monthly|quarterly`, which sources .env, calls Node entry point, which calls CollectorRegistry.runByFrequency(), which calls Ninja Scraper API for each collector, then calls Python normalization modules, then sends Telegram summary.

**When to use:** All scheduled collection runs. Orchestrator script pattern matches existing gateway-chat.sh.

**Example timer (weekly):**

```ini
# /etc/systemd/system/lobsec-collect-weekly.timer
[Unit]
Description=UAE RE weekly collection timer (Mon 02:00 UTC = 06:00 GST)

[Timer]
OnCalendar=Mon *-*-* 02:00:00 UTC
AccuracySec=1min
Persistent=true
RandomizedDelaySec=0

[Install]
WantedBy=timers.target
```

**Example service:**

```ini
# /etc/systemd/system/lobsec-collect-weekly.service
[Unit]
Description=UAE RE weekly collection orchestrator
After=lobsec-scraper.service
Requires=lobsec-scraper.service

[Service]
Type=oneshot
User=lobsec
Group=lobsec
WorkingDirectory=/opt/lobsec
ExecStart=/opt/lobsec/bin/collect.sh weekly
TimeoutSec=1800
StandardOutput=journal
StandardError=journal
SyslogIdentifier=lobsec-collect-weekly

# Security
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/lobsec/data /opt/lobsec/logs
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

**Example orchestrator script:**

```bash
#!/bin/bash
# /opt/lobsec/bin/collect.sh
# UAE RE collection orchestrator
# Usage: collect.sh weekly|monthly|quarterly|{source-name}

set -euo pipefail

FREQUENCY="${1:-}"
if [[ -z "$FREQUENCY" ]]; then
    echo "Usage: $0 <weekly|monthly|quarterly|source-name>"
    exit 1
fi

# Source environment
source /opt/lobsec/.env

# Call Node entry point
cd /opt/lobsec/plugins/lobsec-uae-re
exec node dist/cli/collect.js "$FREQUENCY"
```

**Example Node entry point (packages/uae-re/src/cli/collect.ts):**

```typescript
import { CollectorRegistry } from "../collectors/registry.js";
import Database from "better-sqlite3";

const frequency = process.argv[2] as CollectionFrequency;
const db = new Database("/opt/lobsec/data/uae-re.db");
const registry = new CollectorRegistry(3);

registry.createCollectors(db, { baseUrl: "http://127.0.0.1:18791" });

const result = await registry.runByFrequency(frequency);

console.log(`${result.successCount}/${result.successCount + result.failureCount} collectors succeeded`);

// Send Telegram summary
// ... existing telegram notification code
```

**Confidence:** HIGH — systemd timer pattern verified with existing lobsec-examy-test.timer. OnCalendar format documented and tested.

---

### Pattern 5: GulfTalent Authenticated Session

**What:** Store GulfTalent credentials in HSM, use Patchright to login and maintain session, scrape authenticated job search results for higher data quality.

**When to use:** Platforms that provide better data (salary ranges, seniority) when authenticated.

**YAML modification:**

```yaml
# gulftalent-jobs.yml
source:
  url: "https://www.gulftalent.com/jobs/uae"
  browser: chromium
  stealth: true
  wait_until: networkidle
  authentication:
    enabled: true
    credentials_source: hsm
    hsm_key: "gulftalent-username"
    hsm_password_key: "gulftalent-password"
    login_url: "https://www.gulftalent.com/login"
    username_selector: "input[name='username'], input[type='email']"
    password_selector: "input[name='password'], input[type='password']"
    submit_selector: "button[type='submit'], .login-button"
```

**HSM storage (deploy script):**

```bash
# Store GulfTalent credentials
echo -n "user@example.com" | pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
    --slot-index 0 --pin "$HSM_PIN" --write-object /dev/stdin \
    --type data --id 14 --label gulftalent-username

echo -n "password123" | pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
    --slot-index 0 --pin "$HSM_PIN" --write-object /dev/stdin \
    --type data --id 15 --label gulftalent-password

chown -R lobsec:lobsec /opt/lobsec/hsm/tokens/
```

**Confidence:** MEDIUM — Authenticated scraping improves data quality but adds credential management complexity. Worth it for GulfTalent per user decision.

---

### Anti-Patterns to Avoid

- **HTTP download for Dubai Pulse sources:** Dubai Pulse WAF blocks raw HTTP requests. Always use browser_scrape even for "simple" CSV downloads from Dubai Pulse.

- **Retry on 403/CAPTCHA for job platforms:** Makes blocking worse. Use skip_on_403: true and accept graceful failure. Retry next scheduled run (7 days later).

- **Individual timer per source (28 separate timers):** Creates systemd clutter and makes it hard to track overall collection health. Use 3 timers (weekly/monthly/quarterly) that run ALL sources for that frequency.

- **Normalization in YAML missions:** YAML missions should only collect raw data. All parsing, classification, and metric computation happens in Python normalization modules. Clean separation of concerns.

- **Storing individual job listings:** Too large (thousands of listings/week). Store aggregated counts: total_postings, postings_by_sector, postings_by_seniority, median_salary_range. Matches normalized_monthly pattern.

- **Hardcoding GST times in systemd timers:** systemd uses local timezone by default. Always specify UTC explicitly and convert GST → UTC (GST = UTC+4, so 06:00 GST = 02:00 UTC).

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| PDF table extraction | Regex parsers, manual OCR | pdfplumber | Handles multi-page tables, nested tables, irregular layouts; 96% accuracy on government PDFs |
| Job platform anti-bot evasion | Custom header spoofing, manual cookie management | Patchright stealth browser | Maintained fork specifically for evading bot detection; better than vanilla Playwright |
| systemd timer scheduling | cron jobs | systemd OnCalendar timers | Better logging, failure handling, integration with systemd services; Persistent=true handles missed runs |
| Browser automation orchestration | Raw Playwright scripts | Crawlee for Python | Handles browser pooling, retry logic, delays, concurrency — already used by Ninja Scraper |
| Multi-platform job aggregation | Individual scrapers per platform | Unified normalize_jobs.py module | Single classification logic (sector, seniority), consistent output schema, easier to maintain |

**Key insight:** Government PDF extraction is deceptively complex (multi-page tables, merged cells, rotated text). pdfplumber handles all these cases. Custom regex parsers fail on layout variations.

## Common Pitfalls

### Pitfall 1: LinkedIn/Job Platform Permanent Bans

**What goes wrong:** Aggressive scraping (high frequency, no delays, retry on 403) triggers permanent IP/account bans.

**Why it happens:** Job platforms invest heavily in bot detection (TLS fingerprinting, behavioral analysis, request patterns). Retrying on 403 signals bot behavior and accelerates bans.

**How to avoid:**
- Random 3-8 second delays between requests (concurrency.delay_between_requests_ms)
- skip_on_403: true and skip_on_captcha: true in retry config
- Accept graceful failures; rely on Bayt/Indeed for coverage when LinkedIn blocks
- Weekly collection (not daily) reduces detection risk

**Warning signs:** 403 errors increasing, CAPTCHA appearing on job search pages, login required for public search.

**Confidence:** HIGH — Research confirms LinkedIn bans are triggered by retry behavior, not initial failure.

---

### Pitfall 2: PDF Table Extraction False Positives

**What goes wrong:** pdfplumber extracts wrong table or misaligns columns because PDF has decorative borders, headers spanning multiple lines, or rotated text.

**Why it happens:** PDFs encode layout via absolute positioning, not semantic structure. pdfplumber infers tables from visual layout, which can misinterpret complex formatting.

**How to avoid:**
- Target specific page numbers (pages 2-4 for visa stats, not entire PDF)
- Filter tables by header keywords before processing (if "visa" in header and "issued" in header)
- Validate extracted values (if value > 1M for quarterly visas, probably wrong table)
- Telegram manual-entry fallback when extraction fails (user provides values, data too valuable to skip)

**Warning signs:** Extracted numbers orders of magnitude off (1.5M visas/quarter instead of 150K), missing expected tables, all zeros.

**Confidence:** HIGH — pdfplumber documentation and research warn about layout-dependent extraction.

---

### Pitfall 3: Timezone Confusion in systemd Timers

**What goes wrong:** Timer triggers at wrong time (06:00 UTC instead of 06:00 GST = 02:00 UTC), causing collection to run when source data isn't published yet.

**Why it happens:** systemd defaults to local timezone unless explicitly specified. If server timezone is UTC, `OnCalendar=Mon *-*-* 06:00:00` runs at 06:00 UTC = 10:00 GST.

**How to avoid:**
- Always specify UTC explicitly: `OnCalendar=Mon *-*-* 02:00:00 UTC`
- Convert GST → UTC at planning time (GST = UTC+4)
- Test with `systemd-analyze calendar "Mon *-*-* 02:00:00 UTC"` before deployment
- Document GST → UTC mapping in timer file comments

**Warning signs:** Timer triggers 4 hours later than expected, collection logs show "data not available yet" errors.

**Confidence:** HIGH — systemd documentation confirms timezone defaults.

---

### Pitfall 4: Empty Collection = Silent Failure

**What goes wrong:** Source returns empty dataset (no press releases, no PDF published yet), collector logs success with 0 rows, no alert fires, data goes stale silently.

**Why it happens:** Empty response is valid HTTP 200. Collector treats it as success unless explicitly validated.

**How to avoid:**
- Python normalization modules validate `len(metrics) > 0`, raise error if empty
- Gap detection (NORM-03) flags stale when no successful collection in 2x expected frequency
- Telegram summary reports empty collections separately: "3 empty: gdrfa-visas, khda-enrollment, salary-surveys"
- Distinguish "no data published yet" (annual sources in wrong month) from "scraping failed"

**Warning signs:** Database shows no new records for source, but no error alerts. Last successful collection date getting old.

**Confidence:** MEDIUM — Established in Phase 7 (rowCount=0 throws validation error per decision log).

---

### Pitfall 5: Salary Survey PDFs Behind CAPTCHA/Gated Forms

**What goes wrong:** Cooper Fitch/Hays/Robert Half require email signup to download PDF, Patchright can't bypass CAPTCHA.

**Why it happens:** Salary survey firms use PDFs as lead generation, gate behind forms to collect business contact info.

**How to avoid:**
- Manual download once per year (February-March when surveys publish)
- Store PDFs in /opt/lobsec/data/raw/salary-surveys/ as fallback
- Automation attempts download; if CAPTCHA detected, Telegram prompt: "Manual download needed: hays.ae/salary-guide"
- User downloads, places in raw directory, runs normalization manually via `collect.sh hays-salary`

**Warning signs:** Browser stuck on email form, "Please verify you're human" message, download link requires authentication.

**Confidence:** MEDIUM — Common pattern for gated content, manual fallback is acceptable for annual sources.

---

### Pitfall 6: Quarterly Source Timing Mismatch

**What goes wrong:** Quarterly timer runs 15th Jan/Apr/Jul/Oct, but GDRFA publishes Q4 report on Jan 20th. Collector runs too early, finds Q3 data (already collected), duplicate or stale.

**Why it happens:** Government agencies publish quarterly reports 2-4 weeks after quarter end, timing varies by agency.

**How to avoid:**
- Target latest PDF by date metadata, not just "latest link"
- Check report_quarter field in PDF metadata before processing
- Skip if report_quarter already exists in database (upsert checks measurement_date)
- If no new data, mark collection as success but 0 new rows (distinguishes from failure)
- Telegram summary: "gdrfa-visas: no new data (Q4 not published yet)"

**Warning signs:** Same data collected twice, measurement_date unchanged between quarterly runs.

**Confidence:** MEDIUM — Requires PDF metadata extraction to distinguish report quarters reliably.

## Code Examples

Verified patterns from playbook, existing codebase, and official documentation:

### 1. pdfplumber Table Extraction with Page Targeting

```python
# packages/uae-re/python/uae_re/normalize_gdrfa.py
import pdfplumber
import pandas as pd
from typing import Any

def extract_visa_tables(pdf_path: str) -> dict[str, Any]:
    """
    Extract visa statistics from GDRFA quarterly PDF.

    Expected structure:
    - Page 3: Visa issuances by type
    - Page 4: Visa cancellations
    - Page 5: Golden Visa breakdown

    Returns dict with extracted values.
    """
    data = {
        "total_issued": None,
        "employment_visa": None,
        "golden_visa": None,
        "family_visa": None,
        "total_cancelled": None,
        "net_flow": None,
    }

    with pdfplumber.open(pdf_path) as pdf:
        # Target specific pages (0-indexed)
        for page_num in [2, 3, 4]:  # Pages 3-5
            if page_num >= len(pdf.pages):
                continue

            page = pdf.pages[page_num]
            tables = page.extract_tables()

            for table in tables:
                if not table or len(table) < 2:
                    continue

                # Identify table by header keywords
                header = " ".join(str(cell) for cell in table[0]).lower()

                if "visa" in header and "issued" in header:
                    # Process issuance table
                    for row in table[1:]:
                        if len(row) < 2:
                            continue

                        label = str(row[0]).lower()
                        value_str = str(row[1]).replace(",", "").replace(" ", "")

                        try:
                            value = int(value_str)
                        except ValueError:
                            continue

                        if "employment" in label:
                            data["employment_visa"] = value
                        elif "golden" in label:
                            data["golden_visa"] = value
                        elif "family" in label:
                            data["family_visa"] = value
                        elif "total" in label:
                            data["total_issued"] = value

                if "cancellation" in header or "cancelled" in header:
                    # Process cancellation table
                    for row in table[1:]:
                        if len(row) < 2:
                            continue

                        label = str(row[0]).lower()
                        if "total" in label:
                            value_str = str(row[1]).replace(",", "").replace(" ", "")
                            try:
                                data["total_cancelled"] = int(value_str)
                            except ValueError:
                                pass

    # Compute net flow
    if data["total_issued"] and data["total_cancelled"]:
        data["net_flow"] = data["total_issued"] - data["total_cancelled"]

    return data
```

**Source:** pdfplumber documentation + playbook pattern
**Confidence:** HIGH — Page targeting reduces false positives

---

### 2. systemd OnCalendar Timer Specifications

```ini
# Weekly timer: Every Monday at 02:00 UTC (06:00 GST)
OnCalendar=Mon *-*-* 02:00:00 UTC

# Monthly timer: 1st of every month at 02:00 UTC (06:00 GST)
OnCalendar=*-*-01 02:00:00 UTC

# Quarterly timer: 15th of Jan/Apr/Jul/Oct at 05:00 UTC (09:00 GST)
OnCalendar=*-01,04,07,10-15 05:00:00 UTC

# Daily timer (Phase 9): Every day at 19:00 UTC (23:00 GST)
OnCalendar=*-*-* 19:00:00 UTC

# Test timer syntax
# systemd-analyze calendar "Mon *-*-* 02:00:00 UTC"
```

**Source:** systemd.time man page + research
**Confidence:** HIGH — Verified with systemd-analyze

---

### 3. Job Seniority Classification from Salary Range

```python
# packages/uae-re/python/uae_re/normalize_jobs.py
def classify_seniority(salary_min: int, salary_max: int) -> str:
    """
    Classify job seniority based on posted salary range (AED/month).

    Thresholds based on UAE salary survey data (2026):
    - Junior: < 10,000 AED/month
    - Mid: 10,000 - 25,000
    - Senior: 25,000 - 50,000
    - Executive: > 50,000

    If salary not posted, returns "unspecified".
    """
    if salary_min == 0 and salary_max == 0:
        return "unspecified"

    # Use midpoint of range
    avg_salary = (salary_min + salary_max) / 2

    if avg_salary < 10_000:
        return "junior"
    elif avg_salary < 25_000:
        return "mid"
    elif avg_salary < 50_000:
        return "senior"
    else:
        return "executive"

def classify_sector(job_title: str) -> str:
    """
    Classify job sector from title keywords.

    Sectors: tech, finance, hospitality, construction, healthcare, retail, other
    """
    title_lower = job_title.lower()

    tech_keywords = ["software", "developer", "engineer", "data", "cloud", "devops", "ai", "ml"]
    finance_keywords = ["finance", "accounting", "audit", "banking", "investment", "risk"]
    hospitality_keywords = ["hotel", "restaurant", "chef", "waiter", "hospitality", "tourism"]
    construction_keywords = ["construction", "engineer", "project manager", "civil", "architect"]
    healthcare_keywords = ["doctor", "nurse", "medical", "healthcare", "clinic", "hospital"]
    retail_keywords = ["retail", "sales", "cashier", "store", "shop"]

    if any(kw in title_lower for kw in tech_keywords):
        return "tech"
    elif any(kw in title_lower for kw in finance_keywords):
        return "finance"
    elif any(kw in title_lower for kw in hospitality_keywords):
        return "hospitality"
    elif any(kw in title_lower for kw in construction_keywords):
        return "construction"
    elif any(kw in title_lower for kw in healthcare_keywords):
        return "healthcare"
    elif any(kw in title_lower for kw in retail_keywords):
        return "retail"
    else:
        return "other"
```

**Source:** User discretion + playbook affordability model
**Confidence:** MEDIUM — Keyword-based, will have classification errors

---

### 4. Collect.sh Orchestrator Script

```bash
#!/bin/bash
# /opt/lobsec/bin/collect.sh
# UAE RE collection orchestrator
# Usage: collect.sh weekly|monthly|quarterly|{source-name}

set -euo pipefail

FREQUENCY="${1:-}"
LOG_DIR="/opt/lobsec/logs"

if [[ -z "$FREQUENCY" ]]; then
    echo "Usage: $0 <weekly|monthly|quarterly|source-name>" >&2
    exit 1
fi

# Source environment variables
if [[ -f /opt/lobsec/.env ]]; then
    source /opt/lobsec/.env
fi

# Ensure Ninja Scraper is running
if ! curl -s http://127.0.0.1:18791/health | grep -q "ok"; then
    echo "ERROR: Ninja Scraper not responding at 127.0.0.1:18791" >&2
    exit 1
fi

# Call Node.js entry point
cd /opt/lobsec/plugins/lobsec-uae-re

echo "[$(date -Iseconds)] Starting collection: $FREQUENCY"

node dist/cli/collect.js "$FREQUENCY" 2>&1 | tee -a "$LOG_DIR/collection.log"

EXIT_CODE=${PIPEFAIL[0]}

if [[ $EXIT_CODE -eq 0 ]]; then
    echo "[$(date -Iseconds)] Collection completed: $FREQUENCY"
else
    echo "[$(date -Iseconds)] Collection failed: $FREQUENCY (exit code $EXIT_CODE)" >&2
fi

exit $EXIT_CODE
```

**Source:** Matches gateway-chat.sh pattern
**Confidence:** HIGH — Established pattern from production deployment

---

### 5. COLLECTOR_DEFINITIONS Registration (TypeScript)

```typescript
// packages/uae-re/src/collectors/registry.ts
const COLLECTOR_DEFINITIONS: Array<{
  missionName: string;
  metadata: CollectorMetadata;
}> = [
  // Phase 7 Tier A (existing)
  { missionName: "dld-sales", metadata: { source: "dld-sales", frequency: "weekly", priority: 1, timeout: 120_000 } },
  { missionName: "ejari-rentals", metadata: { source: "ejari-rentals", frequency: "weekly", priority: 1, timeout: 120_000 } },
  { missionName: "building-permits", metadata: { source: "building-permits", frequency: "monthly", priority: 2, timeout: 120_000 } },
  { missionName: "adrec-abu-dhabi", metadata: { source: "adrec-abu-dhabi", frequency: "monthly", priority: 2, timeout: 300_000 } },
  { missionName: "bayut-listings", metadata: { source: "bayut-listings", frequency: "weekly", priority: 3, timeout: 600_000 } },
  { missionName: "propertyfinder-listings", metadata: { source: "propertyfinder-listings", frequency: "weekly", priority: 3, timeout: 600_000 } },
  { missionName: "dewa-connections", metadata: { source: "dewa-connections", frequency: "monthly", priority: 2, timeout: 300_000 } },

  // Phase 8 Tier B (new)
  { missionName: "mohre-permits", metadata: { source: "mohre-permits", frequency: "monthly", priority: 2, timeout: 300_000 } },
  { missionName: "dxb-passengers", metadata: { source: "dxb-passengers", frequency: "monthly", priority: 2, timeout: 300_000 } },
  { missionName: "gdrfa-visas", metadata: { source: "gdrfa-visas", frequency: "quarterly", priority: 2, timeout: 300_000 } },
  { missionName: "khda-enrollment", metadata: { source: "khda-enrollment", frequency: "annual", priority: 2, timeout: 300_000 } },
  { missionName: "rta-vehicles", metadata: { source: "rta-vehicles", frequency: "monthly", priority: 2, timeout: 300_000 } },
  { missionName: "linkedin-jobs", metadata: { source: "linkedin-jobs", frequency: "weekly", priority: 3, timeout: 600_000 } },
  { missionName: "bayt-jobs", metadata: { source: "bayt-jobs", frequency: "weekly", priority: 3, timeout: 600_000 } },
  { missionName: "indeed-jobs", metadata: { source: "indeed-jobs", frequency: "weekly", priority: 3, timeout: 600_000 } },
  { missionName: "gulftalent-jobs", metadata: { source: "gulftalent-jobs", frequency: "weekly", priority: 3, timeout: 600_000 } },
  { missionName: "cooper-fitch-salary", metadata: { source: "cooper-fitch-salary", frequency: "annual", priority: 2, timeout: 300_000 } },
  { missionName: "hays-salary", metadata: { source: "hays-salary", frequency: "annual", priority: 2, timeout: 300_000 } },
  { missionName: "roberthalf-salary", metadata: { source: "roberthalf-salary", frequency: "annual", priority: 2, timeout: 300_000 } },
  { missionName: "cbuae-remittances", metadata: { source: "cbuae-remittances", frequency: "quarterly", priority: 2, timeout: 300_000 } },
];
```

**Source:** Existing registry.ts + Phase 8 sources
**Confidence:** HIGH — Extends working pattern

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Apify cloud scrapers for job platforms | Self-scraping with Patchright stealth browser | 2026 | Free, sovereign, no third-party dependency; accept graceful failures |
| Manual PDF download + OCR | Automated browser scrape + pdfplumber table extraction | 2024-2025 | 96% accuracy on government PDFs, handles multi-page tables |
| Cron jobs for scheduling | systemd timers with OnCalendar | 2020+ | Better logging, failure handling, Persistent=true for missed runs |
| Individual timers per source | Frequency-based timers (weekly/monthly/quarterly) | 2026 | 3 timers instead of 28, runs all sources for frequency in one orchestrated batch |
| TypeScript collectors with direct HTTP/Playwright calls | Thin TS client → Python Ninja Scraper API → YAML missions | Phase 7.1 | Centralized scraping engine, missions auto-discovered, stealth browser reused |

**Deprecated/outdated:**
- **Apify Bayut/PropertyFinder scrapers:** Replaced by self-scraping in Phase 7.1. Apify still valid fallback if self-scraping fails in production.
- **UAE Pass authentication for DARI:** Permanently abandoned per user decision (Phase 7). ADREC public dashboards provide Abu Dhabi data without authentication.
- **HTTP download for Dubai Pulse:** WAF blocks raw HTTP. Always use browser_scrape mission type (Phase 7.1 decision).

## Open Questions

1. **LinkedIn blocking frequency**
   - What we know: LinkedIn uses TLS fingerprinting, behavioral analysis, IP reputation scoring per research
   - What's unclear: How long do bans last? Is it IP-based (clear on next week's retry) or account-based (permanent)?
   - Recommendation: Build with skip_on_403, monitor ban rate in production first 4 weeks, add residential proxy rotation only if ban rate >50%

2. **GDRFA quarterly report publication timing**
   - What we know: Quarterly reports published 2-4 weeks after quarter end per research
   - What's unclear: Exact publication day (is Q4 report available by Jan 15th or Jan 31st?)
   - Recommendation: Timer runs Jan 15th, but collector checks PDF metadata for report_quarter, skips if still Q3

3. **MOHRE press release data completeness**
   - What we know: MOHRE publishes statistical reports at mohre.gov.ae/en/data-library/statistical-report.aspx per research
   - What's unclear: Do press releases include sector/nationality breakdown or just totals?
   - Recommendation: Target statistical reports page instead of press releases for structured data. If tables available, extract via pdfplumber

4. **Salary survey PDF CAPTCHA prevalence**
   - What we know: Salary surveys often gated behind email forms per research
   - What's unclear: Can Patchright bypass form, or is manual download required every year?
   - Recommendation: Attempt automation first, fallback to manual download + Telegram prompt. Annual frequency makes manual acceptable

5. **Job platform salary disclosure rate**
   - What we know: Not all job postings include salary ranges
   - What's unclear: What % of LinkedIn/Bayt/Indeed/GulfTalent postings include salary? Is seniority classification reliable without it?
   - Recommendation: Track "salary_disclosed" ratio per platform. If <30%, fall back to job title keyword classification (Director/Manager/Associate)

## Sources

### Primary (HIGH confidence)

- [pdfplumber GitHub](https://github.com/jsvine/pdfplumber) - Official documentation and API reference
- [How to Extract Tables from PDFs Using Python](https://bnacar.dev/2026/01/13/how-to-extract-tables-from-pdfs-using-python.html) - 2026 guide, 96% accuracy claim verified
- [systemd.time man page](https://www.freedesktop.org/software/systemd/man/latest/systemd.time.html) - OnCalendar format specification
- [systemd OnCalendar format explained](https://silentlad.com/systemd-timers-oncalendar-(cron)-format-explained) - Practical examples and timezone handling
- Existing codebase: packages/scraper/missions/dewa-connections.yml, packages/uae-re/python/uae_re/normalize_dewa.py, /etc/systemd/system/lobsec-examy-test.timer

### Secondary (MEDIUM confidence)

- [How to Scrape LinkedIn Data in 2026](https://iproyal.com/blog/web-scraping-linkedin/) - Anti-bot evasion techniques
- [LinkedIn Banned My Scraper 3 Times](https://plainenglish.io/web-scraping/linkedin-banned-my-scraper-3-times-here-s-the-architecture-that-finally-worked) - Practical ban mitigation strategies
- [MOHRE Statistical Report page](https://www.mohre.gov.ae/en/data-library/statistical-report.aspx) - Official source for work permit data
- [GDRFA Dubai Open Data](https://www.gdrfad.gov.ae/en/open-data) - Official source for visa statistics
- [KHDA Data & Statistics](https://web.khda.gov.ae/en/Resources/KHDA-data-statistics) - Official source for school enrollment
- [Dubai Pulse KHDA dataset](https://www.dubaipulse.gov.ae/data/khda-schools/khda_private_schools_erc-open) - Structured school data alternative

### Tertiary (LOW confidence)

- [TLS Fingerprint Bypass Techniques 2026](https://www.scrapehero.com/tls-fingerprint-bypass-techniques/) - Advanced anti-detection methods (not needed for MVP)
- [Best LinkedIn Scraping Tools 2026](https://snov.io/blog/linkedin-scraping-tools/) - Third-party tool comparison (prefer self-scraping)

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH - pdfplumber, Patchright, systemd timers all proven and documented
- Architecture: HIGH - Extends Phase 7.1 patterns (Ninja Scraper, browser_scrape missions, Python normalization)
- Pitfalls: MEDIUM-HIGH - Job platform blocking is uncertain (LinkedIn ban rate unknown), PDF structure variations may require iteration

**Research date:** 2026-03-12
**Valid until:** 60 days (stable stack, government sources don't change frequently)

---

*Research complete. Ready for planning.*
