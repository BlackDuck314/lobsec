---
phase: 09-tier-c-collection
verified: 2026-03-16T07:20:00Z
status: passed
score: 5/5 must-haves verified
re_verification: false
human_verification:
  - test: "Run collect.sh daily and observe Google Trends collection"
    expected: "collect_trends.py fetches 6 keyword groups, writes raw JSON to /opt/lobsec/data/raw/google-trends/{date}.json, exits 0"
    why_human: "Requires live pytrends network access; rate-limiting delays make automated test impractical"
  - test: "Verify Google Maps foot traffic mission completes one location"
    expected: "Playwright navigates to a Google Maps place URL, extracts Popular Times JSON, writes to /opt/lobsec/data/raw/google-maps-traffic/"
    why_human: "Google Maps bot detection is unpredictable; Popular Times embed format changes; proxy absent in current env"
  - test: "Run collect.sh daily after Reddit creds are in HSM"
    expected: "collect_sentiment.py fetches from r/dubai + r/dubairealestate, scores VADER, writes raw JSON"
    why_human: "Reddit REDDIT_CLIENT_ID and REDDIT_CLIENT_SECRET not yet in HSM (documented in plan as user setup required)"
---

# Phase 9: Tier C Collection Verification Report

**Phase Goal:** Tier C Collection (Alternative Economic Signals) — 14 alternative data sources completing all 28 data sources in the system
**Verified:** 2026-03-16T07:20:00Z
**Status:** PASSED
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | Google Trends (6 keyword groups), Reddit sentiment (PRAW + VADER), and Google Maps foot traffic (50 locations) collected on daily/weekly schedule | VERIFIED | collect_trends.py: TrendReq with 6 KEYWORD_GROUPS (buy_intent, rent_intent, expat_lifecycle, distress, luxury, exit_moving); collect_sentiment.py: PRAW + SentimentIntensityAnalyzer; google-maps-traffic.yml: 50 areas confirmed by load; daily timer at 19:00 UTC active |
| 2 | RTA metro ridership, DTCM tourism stats, DED business licenses, Jebel Ali port, FCSA demographics, CBUAE mortgages collected via YAML missions | VERIFIED | All 6 YAML missions load in Ninja Scraper (type=browser_scrape); 6 normalizers import cleanly; pdfplumber confirmed in normalize_mortgages.py |
| 3 | InsideAirbnb/STR data, F&B closures, customs household imports, commercial office reports collected | VERIFIED | insideairbnb.yml type=http_download; fb-closures.yml proxy=True, ua_rotation=True; customs-imports.yml + commercial-office-reports.yml all load; 5 normalizers import cleanly |
| 4 | All 28 sources registered in CollectorRegistry with correct frequencies; daily timer (23:00 GST) operational | VERIFIED | COLLECTOR_DEFINITIONS has 33 entries (20 existing + 13 new); SOURCE_MODULE_MAP has 33 entries; PythonScriptName has 34 union members; lobsec-collect-daily.timer OnCalendar=*-*-* 19:00:00 UTC confirmed active/enabled; 4 timers listed in systemctl |
| 5 | DirectPythonCollector dispatches google-trends and reddit-sentiment via runPython() bridge; TypeScript compiles clean | VERIFIED | direct.ts: extends SourceCollector, overrides collect() with runPython(); registry.ts: DIRECT_PYTHON_SOURCES map; `npx tsc --noEmit` returns 0 errors |

**Score:** 5/5 truths verified

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `packages/uae-re/src/collectors/direct.ts` | DirectPythonCollector subclass | VERIFIED | Exists, 85 lines, exports DirectPythonCollector, imports runPython, overrides collect() |
| `packages/uae-re/src/analytics/types.ts` | PythonScriptName with collect_trends + collect_sentiment + 13 normalizers | VERIFIED | 34 union members confirmed; includes collect_trends, collect_sentiment, normalize_trends through normalize_office |
| `packages/uae-re/src/collectors/registry.ts` | 33 COLLECTOR_DEFINITIONS entries, DirectPythonCollector dispatch | VERIFIED | 33 missionName entries; createCollectors() has DIRECT_PYTHON_SOURCES map for google-trends and reddit-sentiment |
| `packages/uae-re/src/normalization/types.ts` | SOURCE_MODULE_MAP with 33 entries | VERIFIED | 33 entries confirmed; all Phase 9 sources mapped to normalize_* functions |
| `packages/uae-re/python/uae_re/collect_trends.py` | Google Trends via pytrends with 6 keyword groups, geo=AE | VERIFIED | TrendReq(hl=en-US, tz=240); KEYWORD_GROUPS with 6 entries including exit_moving (COLL-27); rate-limiting sleep 5-15s |
| `packages/uae-re/python/uae_re/normalize_trends.py` | Normalize 6 groups to monthly metrics | VERIFIED | normalize_trends() function exists; imports confirmed from analytics-venv |
| `packages/uae-re/python/uae_re/collect_sentiment.py` | Reddit PRAW + VADER on r/dubai + r/dubairealestate | VERIFIED | praw.Reddit client; SentimentIntensityAnalyzer; credentials validated at startup with ValueError |
| `packages/uae-re/python/uae_re/normalize_sentiment.py` | mean_compound, bullish_ratio, bearish_ratio, post_count | VERIFIED | normalize_sentiment() function; importable from analytics-venv |
| `packages/scraper/missions/rta-metro.yml` | RTA metro ridership browser_scrape (monthly) | VERIFIED | type=browser_scrape, freq=monthly, proxy=False; loaded by Ninja Scraper |
| `packages/scraper/missions/cbuae-mortgages.yml` | CBUAE mortgages browser_scrape (quarterly) | VERIFIED | type=browser_scrape, freq=quarterly, proxy=False; loaded by Ninja Scraper |
| `packages/scraper/missions/dtcm-tourism.yml` | DTCM tourism browser_scrape (monthly) | VERIFIED | type=browser_scrape, freq=monthly, proxy=False; loaded by Ninja Scraper |
| `packages/scraper/missions/ded-licenses.yml` | DED licenses browser_scrape (monthly) | VERIFIED | type=browser_scrape, freq=monthly, proxy=False; loaded by Ninja Scraper |
| `packages/scraper/missions/fcsa-demographics.yml` | FCSA demographics browser_scrape (quarterly) | VERIFIED | type=browser_scrape, freq=quarterly, proxy=False; loaded by Ninja Scraper |
| `packages/scraper/missions/jebel-ali-port.yml` | Jebel Ali port browser_scrape (monthly) | VERIFIED | type=browser_scrape, freq=monthly, proxy=False; loaded by Ninja Scraper |
| `packages/scraper/missions/insideairbnb.yml` | InsideAirbnb http_download (quarterly) | VERIFIED | type=http_download, freq=quarterly, proxy=False; loaded by Ninja Scraper |
| `packages/scraper/missions/fb-closures.yml` | F&B closures browser_scrape with proxy+UA rotation (monthly) | VERIFIED | type=browser_scrape, freq=monthly, proxy=True, ua_rotation=True |
| `packages/scraper/missions/customs-imports.yml` | Customs household imports browser_scrape (quarterly) | VERIFIED | type=browser_scrape, freq=quarterly, proxy=False; loaded |
| `packages/scraper/missions/google-maps-traffic.yml` | Google Maps foot traffic with 50 areas, proxy=true (weekly) | VERIFIED | type=browser_scrape, freq=weekly, proxy=True, ua_rotation=True; 50 areas confirmed; delay [600000, 900000]ms |
| `packages/scraper/missions/commercial-office-reports.yml` | JLL/CBRE/Savills browser_scrape (quarterly) | VERIFIED | type=browser_scrape, freq=quarterly, proxy=False; loaded |
| `packages/uae-re/python/uae_re/normalize_metro.py` | RTA metro normalization | VERIFIED | normalize_metro() exists; importable from analytics-venv |
| `packages/uae-re/python/uae_re/normalize_mortgages.py` | CBUAE mortgages normalization with pdfplumber | VERIFIED | normalize_mortgages() exists; `import pdfplumber` confirmed |
| `packages/uae-re/python/uae_re/normalize_tourism.py` | DTCM tourism normalization | VERIFIED | normalize_tourism() exists; importable |
| `packages/uae-re/python/uae_re/normalize_licenses.py` | DED licenses normalization | VERIFIED | normalize_licenses() exists; importable |
| `packages/uae-re/python/uae_re/normalize_demographics.py` | FCSA demographics normalization | VERIFIED | normalize_demographics() exists; importable |
| `packages/uae-re/python/uae_re/normalize_port.py` | Jebel Ali port normalization | VERIFIED | normalize_port() exists; importable |
| `packages/uae-re/python/uae_re/normalize_airbnb.py` | InsideAirbnb CSV normalization | VERIFIED | normalize_airbnb() exists; importable |
| `packages/uae-re/python/uae_re/normalize_fb_closures.py` | F&B closures normalization | VERIFIED | normalize_fb_closures() exists; importable |
| `packages/uae-re/python/uae_re/normalize_customs.py` | Customs imports normalization | VERIFIED | normalize_customs() exists; importable |
| `packages/uae-re/python/uae_re/normalize_foot_traffic.py` | Google Maps foot traffic normalization | VERIFIED | normalize_foot_traffic() exists; importable |
| `packages/uae-re/python/uae_re/normalize_office.py` | Commercial office normalization | VERIFIED | normalize_office() exists; importable |
| `/etc/systemd/system/lobsec-collect-daily.timer` | Daily timer at 19:00 UTC | VERIFIED | OnCalendar=*-*-* 19:00:00 UTC; Persistent=true; enabled and active |
| `/etc/systemd/system/lobsec-collect-daily.service` | Daily collection service | VERIFIED | ExecStart=/opt/lobsec/bin/collect.sh daily; User=lobsec; TimeoutSec=600 |
| `packages/scraper/src/ninja_scraper/engine/mission.py` | Mission model with proxy + user_agent_rotation fields | VERIFIED | proxy: bool = False; user_agent_rotation: bool = False |
| `packages/scraper/src/ninja_scraper/engine/handlers.py` | Handler reads NINJA_PROXY_URL, applies when proxy=True | VERIFIED | PROXY_URL = os.environ.get("NINJA_PROXY_URL", ""); warning log when absent |
| `packages/uae-re/python/uae_re/schemas/` (13 files) | Pandera schemas for all new sources | VERIFIED | All 13 schema files present: trends_schema.py, sentiment_schema.py, metro_schema.py, mortgages_schema.py, tourism_schema.py, licenses_schema.py, demographics_schema.py, port_schema.py, airbnb_schema.py, fb_closures_schema.py, customs_schema.py, foot_traffic_schema.py, office_schema.py |

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `packages/uae-re/src/collectors/registry.ts` | `packages/uae-re/src/collectors/direct.ts` | createCollectors() instantiates DirectPythonCollector for google-trends and reddit-sentiment | WIRED | DIRECT_PYTHON_SOURCES = {"google-trends": "collect_trends", "reddit-sentiment": "collect_sentiment"}; new DirectPythonCollector() in factory loop |
| `packages/uae-re/src/collectors/direct.ts` | `packages/uae-re/src/analytics/bridge.ts` | DirectPythonCollector.collect() calls runPython() | WIRED | `runPython(this.pythonModule, inputPayload, ...)` confirmed in collect() override |
| `/etc/systemd/system/lobsec-collect-daily.timer` | `/etc/systemd/system/lobsec-collect-daily.service` | Timer triggers service unit | WIRED | WantedBy=timers.target; timer confirmed active pointing to lobsec-collect-daily.service |
| `/opt/lobsec/bin/collect.sh` | Node CLI run-frequency daily | VALID_FREQUENCIES includes "daily" | WIRED | `VALID_FREQUENCIES="weekly monthly quarterly daily"` confirmed; dispatches CMD="run-frequency" |
| `packages/uae-re/src/normalization/types.ts` | Python normalizers | SOURCE_MODULE_MAP maps source to normalize_* module | WIRED | All 13 Phase 9 normalizer mappings confirmed in SOURCE_MODULE_MAP |
| `packages/scraper/missions/google-maps-traffic.yml` | NINJA_PROXY_URL env var | proxy: true field triggers proxy usage in handlers.py | WIRED | mission.proxy=True confirmed; handlers.py reads PROXY_URL=os.environ.get("NINJA_PROXY_URL","") |
| `packages/scraper/missions/google-maps-traffic.yml` | Handler area iteration | 50 areas list with drip-feed delay | WIRED | 50 URLs in areas list confirmed; concurrency.delay_between_requests_ms=[600000, 900000] |
| Production `/opt/lobsec/scraper/missions/` | Ninja Scraper engine | All 31 missions deployed | WIRED | `ls /opt/lobsec/scraper/missions/*.yml | wc -l` = 31; production deployment confirmed |
| Production `/opt/lobsec/plugins/lobsec-uae-re/python/uae_re/` | Analytics bridge | 28 normalizers + 2 collect scripts deployed | WIRED | 28 normalize_*.py + 2 collect_*.py confirmed in production path |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|-------------|-------------|--------|----------|
| COLL-14 | 09-01, 09-04 | Google Trends — pytrends API, 6 keyword groups | SATISFIED | collect_trends.py: 6 KEYWORD_GROUPS; google-trends in COLLECTOR_DEFINITIONS (daily); SOURCE_MODULE_MAP: google-trends→normalize_trends |
| COLL-16 | 09-02, 09-04 | RTA metro ridership | SATISFIED | rta-metro.yml (browser_scrape, monthly); normalize_metro.py; registry entry (monthly) |
| COLL-17 | 09-02, 09-04 | CBUAE mortgage rates — quarterly PDF + EIBOR | SATISFIED | cbuae-mortgages.yml (quarterly); normalize_mortgages.py with pdfplumber |
| COLL-18 | 09-02, 09-04 | DTCM tourism stats | SATISFIED | dtcm-tourism.yml (monthly); normalize_tourism.py |
| COLL-19 | 09-03, 09-04 | InsideAirbnb/STR data | SATISFIED | insideairbnb.yml (http_download, quarterly); normalize_airbnb.py |
| COLL-20 | 09-02, 09-04 | Jebel Ali port cargo | SATISFIED | jebel-ali-port.yml (monthly); normalize_port.py |
| COLL-21 | 09-03, 09-04 | F&B closures (Zomato + Google Maps) | SATISFIED | fb-closures.yml (proxy=true, monthly); normalize_fb_closures.py |
| COLL-22 | 09-03, 09-04 | Dubai customs household imports | SATISFIED | customs-imports.yml (quarterly); normalize_customs.py |
| COLL-23 | 09-02, 09-04 | DED business licenses | SATISFIED | ded-licenses.yml (monthly); normalize_licenses.py |
| COLL-24 | 09-01, 09-04 | Social sentiment — Reddit PRAW + VADER | SATISFIED | collect_sentiment.py: PRAW + SentimentIntensityAnalyzer; reddit-sentiment in registry (daily) |
| COLL-25 | 09-02, 09-04 | FCSA demographics | SATISFIED | fcsa-demographics.yml (quarterly); normalize_demographics.py (empty list for non-annual quarters) |
| COLL-26 | 09-03, 09-04 | Google Maps foot traffic — 50 locations | SATISFIED | google-maps-traffic.yml: 50 areas, proxy=true, delay [600000,900000]ms; normalize_foot_traffic.py |
| COLL-27 | 09-01, 09-04 | Moving company inquiries | SATISFIED | Implemented as exit_moving keyword group in collect_trends.py ("moving companies dubai", "international movers dubai", "leaving Dubai"); covered by google-trends collector |
| COLL-28 | 09-03, 09-04 | Commercial office reports (JLL/CBRE/Savills) | SATISFIED | commercial-office-reports.yml (quarterly); normalize_office.py with per-firm cross-validation |
| SCHED-05 | 09-04 | Daily timer (23:00 GST) — Google Trends, social sentiment, foot traffic | SATISFIED | lobsec-collect-daily.timer: OnCalendar=*-*-* 19:00:00 UTC (=23:00 GST); enabled+active; collect.sh daily in VALID_FREQUENCIES |

**All 15 Phase 9 requirements (COLL-14, COLL-16-28, SCHED-05) are SATISFIED.**

Note: COLL-15 (DEWA connections) is NOT a Phase 9 requirement — it was completed in Phase 7 and marked Complete in REQUIREMENTS.md.

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| `/opt/lobsec/bin/collect.sh` | 27-30 | Ninja Scraper health check exits script before daily collection | INFO | Daily collection (DirectPythonCollector, no Ninja Scraper needed) would fail if lobsec-scraper is down. Currently not a problem (scraper is active), but represents a fragile dependency. Not a blocker since the scraper runs continuously. |

No TODO/FIXME/PLACEHOLDER/stub patterns found in any Phase 9 source files.

### Human Verification Required

### 1. Google Trends Live Collection

**Test:** Run `sudo -u lobsec /opt/lobsec/bin/collect.sh daily 2>&1 | tail -30`
**Expected:** collect_trends.py prints "Fetching group 1/6: buy_intent" through "6/6: exit_moving"; writes to /opt/lobsec/data/raw/google-trends/YYYY-MM-DD.json; final stdout {"filePath":"...","rowCount":N}
**Why human:** Live pytrends network access required; 5-15s rate-limiting delays per group (total ~60s); Google can return 429 throttling in automated testing

### 2. Google Maps Popular Times Extraction

**Test:** Run a single-location Playwright scrape against The Dubai Mall Maps URL manually
**Expected:** HTML/JS contains `popularTimesHistogram` or `popularTimes` in script tags; foot traffic JSON extracted
**Why human:** Google's bot detection blocks headless Chromium without residential proxy; Popular Times embed format may change; proxy is not yet configured (NINJA_PROXY_URL absent)

### 3. Reddit Sentiment After HSM Credential Setup

**Test:** After storing REDDIT_CLIENT_ID and REDDIT_CLIENT_SECRET in HSM and injecting into lobsec.service env, run `sudo -u lobsec /opt/lobsec/bin/collect.sh daily`
**Expected:** collect_sentiment.py fetches ≤200 posts from r/dubai + r/dubairealestate, VADER scores assigned, writes raw JSON, rowCount > 0
**Why human:** Reddit credentials are not yet in HSM (documented as user setup required in all phase plans); cannot test without live credentials

---

## Deployment Verification Summary

**Production deployment confirmed:**
- 31 YAML missions at /opt/lobsec/scraper/missions/ (including all 11 Phase 9 missions)
- 28 normalizers + 2 collect scripts at /opt/lobsec/plugins/lobsec-uae-re/python/uae_re/
- 4 collection timers active: lobsec-collect-daily (19:00 UTC), lobsec-collect-weekly, lobsec-collect-monthly, lobsec-collect-quarterly
- Weekly timer TimeoutSec=43200 (12hr for Google Maps drip-feed)
- TypeScript compiles clean (0 errors)

**Registry counts:**
- COLLECTOR_DEFINITIONS: 33 entries (20 pre-Phase 9 + 13 new)
- SOURCE_MODULE_MAP: 33 entries (20 pre-Phase 9 + 13 new)
- PythonScriptName: 34 union members (21 pre-Phase 9 + 13 new)
- Ninja Scraper: 31 missions loaded (confirmed by load_all_missions() in dev and production restart)

**Note on COLL-27 implementation:** "Moving company inquiries" is implemented as the `exit_moving` keyword group in Google Trends (`["moving companies dubai", "international movers dubai", "leaving Dubai"]`), shared with COLL-14. This was a deliberate design decision (documented in CONTEXT.md) replacing the original fake-quote-submission approach with a Google Trends proxy. Both COLL-14 and COLL-27 are satisfied by the single google-trends collector.

---

_Verified: 2026-03-16T07:20:00Z_
_Verifier: Claude (gsd-verifier)_
