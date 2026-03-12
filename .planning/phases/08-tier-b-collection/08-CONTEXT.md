# Phase 8: Tier B Collection (Population & Employment Signals) - Context

**Gathered:** 2026-03-12
**Status:** Ready for planning

<domain>
## Phase Boundary

Build 8 demographic and employment data collectors (MOHRE work permits, DXB airport passengers, GDRFA visa transactions, KHDA school enrollment, RTA vehicle registrations, job postings from 4 platforms, salary surveys from 3 firms, CBUAE remittance outflows) as Ninja Scraper YAML missions with Python normalization modules. Wire up systemd timers for weekly/monthly/quarterly collection frequencies with timeout enforcement. Timers cover ALL registered sources (Phase 7 Tier A + Phase 8 Tier B).

Requirements: COLL-06, COLL-07, COLL-08, COLL-09, COLL-10, COLL-11, COLL-12, COLL-13, SCHED-02, SCHED-03, SCHED-04, SCHED-07

</domain>

<decisions>
## Implementation Decisions

### PDF Extraction Strategy
- Ninja Scraper downloads PDFs as raw files (browser_scrape missions that find and download PDFs). pdfplumber extraction happens in Python normalization modules (normalize_gdrfa.py, normalize_khda.py, normalize_dxb.py, etc.) — clean separation: scraper collects files, Python understands content
- PDF discovery uses two-step browser_scrape: visit publications page, extract latest PDF URL, download it. Single YAML mission handles both steps
- One YAML mission per salary survey firm: cooper-fitch-salary.yml, hays-salary.yml, roberthalf-salary.yml. Independent failures, clear audit trail per firm (consistent with Bayut/PropertyFinder being separate)
- When pdfplumber extraction fails, bot proactively prompts user via Telegram with the PDF URL and specific fields to provide (e.g., "GDRFA Q1 2026 PDF extraction failed. Please provide: visas_issued, golden_visa_count, visa_cancellations, net_flow"). Active prompt gets data entered faster
- DXB airport (COLL-07): target PDF factsheet over press release HTML — tables have consistent formatting, more reliable for pdfplumber

### Job Postings Source Approach
- Ninja Scraper self-scraping for all 4 platforms — no Apify cloud dependency. Free, sovereign, no third-party service
- **All four platforms targeted:** LinkedIn, Bayt, Indeed, GulfTalent
- GulfTalent: create account, store credentials in HSM, use authenticated browser session for higher data quality
- LinkedIn: build the mission with Patchright stealth, accept graceful failure if blocked. Bayt+Indeed still provide coverage. Blocks are often temporary — retry next cycle
- Seniority classification via **salary range inference** from posted salary brackets
- Store **aggregated counts per sector/seniority** weekly — total_postings, postings_by_sector, postings_by_seniority, median_salary_range. Not individual listings (too large, mostly noise)

### Scheduling Architecture
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

### Unavailable Source Handling
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

</decisions>

<specifics>
## Specific Ideas

- Reuse existing Ninja Scraper engine at 127.0.0.1:18791 — all new collectors are YAML mission files in packages/scraper/missions/
- pdfplumber is already in analytics-venv (Phase 6) — no new Python dependencies needed for PDF extraction
- Telegram manual-entry fallback for PDF failures: bot sends PDF URL + field names, user replies with numbers. Data is too valuable to skip
- GulfTalent credentials stored in HSM following existing pattern (pkcs11-tool + chown lobsec:lobsec)
- The playbook at `.planning/uae-re-playbook.md` has detailed source URLs, field mappings, and collection strategies for all 8 Tier B sources
- Job posting aggregation stores weekly summary metrics, not individual listings — keeps storage manageable and matches normalized_monthly pattern

</specifics>

<code_context>
## Existing Code Insights

### Reusable Assets
- Ninja Scraper engine (127.0.0.1:18791): FastAPI service with browser_scrape, http_download, api_call mission types. 7 missions already running
- Mission YAML schema (packages/scraper/ninja_scraper/engine/mission.py): Pydantic-validated Mission model with retry, concurrency, timeout, areas configs
- Mission handler (engine/handlers.py): execute_mission() dispatches by type, handles area iteration, timeout, error reporting
- CollectorRegistry (packages/uae-re/src/collectors/registry.ts): COLLECTOR_DEFINITIONS array, createCollectors(), runByFrequency(), runAll(), runOne()
- SourceCollector (packages/uae-re/src/collectors/base.ts): Thin API client calling Ninja Scraper, handles audit logging
- Python normalization modules (packages/uae-re/python/uae_re/normalize_*.py): 7 existing modules for Tier A sources
- Pandera schemas (packages/uae-re/python/uae_re/schemas/): Data validation for normalized output
- load_all_missions() (engine/mission.py): Auto-discovers all *.yml files from missions/ directory at startup

### Established Patterns
- YAML mission per source: name, type, source URL, extraction selectors/fields, output path, retry, timeout, areas
- browser_scrape missions: Patchright stealth, area iteration, random delays, skip_on_403
- TS → Scraper: CollectorRegistry calls POST /scrape with mission name, polls for completion
- Raw → Normalized: Orchestrator triggers runPython('normalize_{source}') after successful collection
- HSM credentials: pkcs11-tool --write-object, env var in .env, sourced by ExecStart wrapper

### Integration Points
- Ninja Scraper missions/ directory: 7 existing + 8-11 new YAML files (8 sources, some with multiple per-firm missions)
- COLLECTOR_DEFINITIONS array: Add 8+ new entries with correct frequency/priority/timeout
- Python normalization: New modules — normalize_mohre.py, normalize_dxb.py, normalize_gdrfa.py, normalize_khda.py, normalize_rta.py, normalize_jobs.py, normalize_salary.py, normalize_remittances.py
- systemd timers: 3 new timer+service units (weekly, monthly, quarterly) at /etc/systemd/system/
- Orchestrator script: /opt/lobsec/bin/collect.sh — new bash+node script
- HSM: New GulfTalent credentials (data object)
- Deploy script: Timer installation, enable, verification, initial seed run

</code_context>

<deferred>
## Deferred Ideas

- **Daily timer (SCHED-05)** — Phase 9 adds Google Trends, social sentiment, foot traffic on daily schedule (23:00 GST). Timer created in Phase 9
- **Pipeline timer (SCHED-06)** — Phase 10 adds analysis pipeline timer (25th 06:00 GST). Created in Phase 10
- **Residential proxy rotation** — If LinkedIn/GulfTalent aggressively block Patchright, add proxy rotation. Not needed for MVP
- **Apify cloud fallback** — If self-scraping proves unreliable for job platforms, consider Apify actors as paid fallback. Evaluate after 1 month of operation

</deferred>

---

*Phase: 08-tier-b-collection*
*Context gathered: 2026-03-12*
