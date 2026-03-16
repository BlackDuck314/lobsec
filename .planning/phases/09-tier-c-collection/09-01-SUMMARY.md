---
phase: 09-tier-c-collection
plan: 01
subsystem: data-collection
tags: [pytrends, praw, vader, pandera, google-trends, reddit, sentiment, proxy, typescript, python]

# Dependency graph
requires:
  - phase: 08-tier-b-collection
    provides: "SourceCollector base class, Python bridge (runPython), analytics-venv with pytrends/praw/vaderSentiment installed"
  - phase: 07.1-ninja-scraper
    provides: "Mission Pydantic model, handlers.py execution pipeline, Ninja Scraper engine"
provides:
  - "DirectPythonCollector TypeScript class (bypasses Ninja Scraper, calls runPython directly)"
  - "Mission model extended with proxy and user_agent_rotation fields (backward-compatible)"
  - "handlers.py updated with NINJA_PROXY_URL proxy routing and UA rotation support"
  - "collect_trends.py: 6 Google Trends keyword groups for UAE (geo=AE)"
  - "normalize_trends.py: per-keyword + group average metrics, monthly resampling"
  - "collect_sentiment.py: Reddit PRAW + VADER compound scoring, r/dubai + r/dubairealestate"
  - "normalize_sentiment.py: mean_compound, bullish/bearish ratios, post_count metrics"
  - "COLL-14 (Google Trends), COLL-24 (Reddit sentiment), COLL-27 (exit/moving via Trends)"
affects:
  - 09-tier-c-collection (remaining plans use DirectPythonCollector pattern)
  - CollectorRegistry (plans that add DirectPythonCollector instances)
  - collect.sh orchestrator (daily timer dispatch in 09-05)
  - Ninja Scraper (proxy/UA rotation ready for Google Maps foot traffic in 09-02)

# Tech tracking
tech-stack:
  added:
    - "pytrends 4.9.2 (already in analytics-venv)"
    - "praw 7.8.1 (already in analytics-venv)"
    - "vaderSentiment 3.3.2 (already in analytics-venv)"
  patterns:
    - "DirectPythonCollector: override collect() with runPython() for API-native sources"
    - "Python collect modules: read {outputDir} from stdin, write {filePath, rowCount} to stdout"
    - "Mission proxy fields: build-now-activate-later pattern (proxy=False default, no-op without env var)"
    - "UA rotation: curated 10-UA list, random.choice per browser context"

key-files:
  created:
    - "packages/uae-re/src/collectors/direct.ts"
    - "packages/uae-re/python/uae_re/collect_trends.py"
    - "packages/uae-re/python/uae_re/normalize_trends.py"
    - "packages/uae-re/python/uae_re/schemas/trends_schema.py"
    - "packages/uae-re/python/uae_re/collect_sentiment.py"
    - "packages/uae-re/python/uae_re/normalize_sentiment.py"
    - "packages/uae-re/python/uae_re/schemas/sentiment_schema.py"
  modified:
    - "packages/uae-re/src/analytics/types.ts (PythonScriptName extended)"
    - "packages/scraper/src/ninja_scraper/engine/mission.py (proxy + user_agent_rotation fields)"
    - "packages/scraper/src/ninja_scraper/engine/handlers.py (proxy/UA routing, refactored dispatch)"

key-decisions:
  - "DirectPythonCollector stores pythonModule as PythonScriptName — type-safe at compile time, bridge validates at runtime"
  - "Mission proxy defaults to False — all 20 existing missions load unchanged, no YAML modifications required"
  - "NINJA_PROXY_URL no-op when absent — logs warning if proxy=True but env var missing, proceeds without proxy"
  - "pytrends 5-15s random sleep between groups — avoids HTTP 429, accepts slow collection (6 groups x ~10s = ~60s)"
  - "collect_trends writes all 6 groups to single daily JSON file — consistent with Ninja Scraper pattern"
  - "normalize_trends resamples weekly Trends data to monthly (MS frequency) — aligns with database monthly time series"
  - "collect_sentiment validates credentials at startup (ValueError if missing) — fail-fast before network calls"
  - "normalize_sentiment uses collection date as measurement_date (daily data) — no weekly resampling needed"
  - "exit_moving keyword group covers COLL-27 — Google Trends proxy replaces ethically questionable fake quote submission"

patterns-established:
  - "DirectPythonCollector pattern: Python collect modules read outputDir from stdin, write filePath+rowCount to stdout"
  - "Collect vs normalize separation: collect.py gathers raw data to JSON, normalize.py transforms to metrics"
  - "Proxy infrastructure: NINJA_PROXY_URL env var + mission.proxy bool field, both handlers.py and Python collect modules check it"

requirements-completed:
  - COLL-14
  - COLL-24
  - COLL-27

# Metrics
duration: 7min
completed: 2026-03-16
---

# Phase 9 Plan 01: DirectPythonCollector + Google Trends + Reddit Sentiment Summary

**DirectPythonCollector TypeScript class + pytrends/PRAW Python collectors with VADER scoring covering 6 Google Trends keyword groups (COLL-14/27) and Reddit dual-subreddit sentiment (COLL-24)**

## Performance

- **Duration:** 7 minutes
- **Started:** 2026-03-16T06:18:44Z
- **Completed:** 2026-03-16T06:25:44Z
- **Tasks:** 2 of 2
- **Files modified:** 10

## Accomplishments

- Created DirectPythonCollector TypeScript class extending SourceCollector — overrides collect() to call runPython() bridge instead of Ninja Scraper API, enabling API-native sources without browser automation
- Extended Ninja Scraper Mission model with proxy (bool=False) and user_agent_rotation (bool=False) fields plus full handler routing — all 20 existing missions load unchanged
- Implemented 3 complete data sources: Google Trends (6 keyword groups, buy/rent/expat/distress/luxury/exit), Reddit PRAW + VADER (r/dubai, r/dubairealestate), and COLL-27 reimplemented as Google Trends exit_moving proxy

## Task Commits

Each task was committed atomically:

1. **Task 1: DirectPythonCollector subclass and proxy infrastructure** - `231bd18` (feat)
2. **Task 2: Google Trends and Reddit sentiment collectors with normalizers** - `6867550` (feat)

**Plan metadata:** `(docs commit — see final commit below)`

## Files Created/Modified

- `packages/uae-re/src/collectors/direct.ts` - DirectPythonCollector class, extends SourceCollector, calls runPython() with outputDir payload
- `packages/uae-re/src/analytics/types.ts` - PythonScriptName union extended with collect_trends and collect_sentiment
- `packages/scraper/src/ninja_scraper/engine/mission.py` - proxy (bool=False) and user_agent_rotation (bool=False) optional fields added to Mission model
- `packages/scraper/src/ninja_scraper/engine/handlers.py` - PROXY_URL module-level constant, UA_LIST (10 curated UAs), proxy routing for http and browser missions, refactored dispatch with _execute_http_mission_with_proxy and _execute_browser_mission_with_proxy
- `packages/uae-re/python/uae_re/collect_trends.py` - pytrends TrendReq, 6 keyword groups, geo=AE, 5-15s sleep between groups, NINJA_PROXY_URL passthrough
- `packages/uae-re/python/uae_re/normalize_trends.py` - weekly-to-monthly resampling (MS), per-keyword + group avg metrics
- `packages/uae-re/python/uae_re/schemas/trends_schema.py` - pandera DataFrameSchema with validate_trends_group() function
- `packages/uae-re/python/uae_re/collect_sentiment.py` - PRAW read-only, VADER SentimentIntensityAnalyzer, 2s sleep between subreddits
- `packages/uae-re/python/uae_re/normalize_sentiment.py` - mean_compound, bullish_ratio (>0.05), bearish_ratio (<-0.05), post_count; per-subreddit variants
- `packages/uae-re/python/uae_re/schemas/sentiment_schema.py` - pandera schema: compound [-1,1], subreddit, post_id, created_utc

## Decisions Made

- DirectPythonCollector stores pythonModule as PythonScriptName — ensures type safety at TypeScript compile time for all script names
- Mission proxy/user_agent_rotation default to False — backward compatible, all 20 existing YAML missions continue loading without modification
- Google Trends rate limiting: random 5-15s sleep between 6 keyword groups — total ~60s collection time, acceptable for daily runs
- pytrends returns weekly data; normalize resamples to month-start (MS) for monthly database time series alignment
- Reddit VADER compound threshold: bullish >0.05, bearish <-0.05 (standard VADER thresholds, neutral range excluded)
- collect_sentiment validates credentials at function start — fail-fast before any network calls with descriptive error message
- COLL-27 implemented as exit_moving Google Trends keyword group — avoids ethical issues of original moving-company fake quotes approach

## Deviations from Plan

None — plan executed exactly as written. Mission.py proxy fields were already present (likely added by a linter/formatter) when re-read; confirmed correct values.

## Issues Encountered

- analytics-venv does not have uae_re in sys.path by default. Bridge.ts sets PYTHONPATH to packages/uae-re/python at runtime (line 54 of bridge.ts). New Python modules were deployed to /opt/lobsec/plugins/lobsec-uae-re/python/uae_re/ (production path) and verified importable with both source and production PYTHONPATH.

## User Setup Required

Reddit API credentials are required for collect_sentiment.py to function:

- `REDDIT_CLIENT_ID`: Create app at https://www.reddit.com/prefs/apps → type: script
- `REDDIT_CLIENT_SECRET`: Copy secret from created app
- Both should be stored in HSM as data objects and injected via lobsec.service environment

collect_trends.py works without credentials (Google Trends is public). NINJA_PROXY_URL is optional for both.

## Next Phase Readiness

- DirectPythonCollector class ready for Phase 9 Plans 02-04 to instantiate additional direct Python collectors
- Proxy infrastructure in Ninja Scraper ready for Google Maps foot traffic mission (proxy=True when NINJA_PROXY_URL set)
- Google Trends and Reddit sentiment collectors need to be added to CollectorRegistry COLLECTOR_DEFINITIONS (daily frequency) in Plan 09-05 (daily timer plan)
- Reddit credentials need HSM storage before collect_sentiment.py can run in production

---
*Phase: 09-tier-c-collection*
*Completed: 2026-03-16*
