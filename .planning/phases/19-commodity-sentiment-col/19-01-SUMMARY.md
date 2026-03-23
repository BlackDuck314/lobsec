---
phase: 19-commodity-sentiment-col
plan: 01
subsystem: uae-re-commodity-sentiment
tags: [commodities, yahoo-finance, brent-crude, gold, news-sentiment, newsapi, vader, reddit, collectors, normalizers]
dependency_graph:
  requires: [06-02 collector-framework, 06-01 python-bridge, 18-01 macro-collectors]
  provides: [commodities-source, news-sentiment-source, reddit-uae-enhancement]
  affects: [normalized_monthly, collection_log, macro-health-product]
tech_stack:
  added: [Yahoo Finance v8 commodities (BZ=F, GC=F), NewsAPI v2 headlines]
  patterns: [DirectPythonCollector, VADER-sentiment-scoring, multi-endpoint-fallback]
key_files:
  created:
    - packages/uae-re/python/uae_re/collect_commodities.py
    - packages/uae-re/python/uae_re/normalize_commodities.py
    - packages/uae-re/python/uae_re/schemas/commodities_schema.py
    - packages/uae-re/python/uae_re/collect_news_sentiment.py
    - packages/uae-re/python/uae_re/normalize_news_sentiment.py
    - packages/uae-re/python/uae_re/schemas/news_sentiment_schema.py
  modified:
    - packages/uae-re/python/uae_re/collect_sentiment.py
    - packages/uae-re/src/analytics/types.ts
    - packages/uae-re/src/normalization/types.ts
    - packages/uae-re/src/collectors/registry.ts
decisions:
  - "Commodities (BZ=F + GC=F) share single collector using Yahoo Finance v8 (same pattern as DFM stocks)"
  - "COST-01 satisfied by existing World Bank CPI data (uae|wb_cpi_inflation_pct) -- no new collector needed"
  - "NewsAPI key deferred to checkpoint -- collector registered and importable but not yet tested end-to-end"
  - "Reddit r/UAE added to existing PRAW collector (minimal change, no new collector)"
metrics:
  duration: 289s
  completed: "2026-03-23T16:43:00Z"
  tasks_completed: 2
  tasks_total: 2
  files_created: 6
  files_modified: 4
---

# Phase 19 Plan 01: Commodity, Sentiment & Cost of Living Summary

2 DirectPythonCollector sources (commodities via Yahoo Finance BZ=F + GC=F, news-sentiment via NewsAPI + VADER), Reddit r/UAE enhancement, producing 208 normalized_monthly rows across 4 commodity metrics with 52 observations each spanning 2021-2026. COST-01 satisfied by existing World Bank CPI.

## What Was Built

### Task 1: Python Collectors, Normalizers, and Schemas (7 files)

**Collectors:**
- `collect_commodities.py` -- Fetches monthly OHLCV data for Brent Crude Oil (BZ=F) and Gold (GC=F) from Yahoo Finance v8 chart API. Uses query2 primary, query1 fallback, 1s rate-limit between requests.
- `collect_news_sentiment.py` -- Fetches UAE real estate news headlines from NewsAPI.org `/v2/everything` endpoint. VADER-scores each article (title + description). Writes scored articles to news-sentiment/{date}.json.
- `collect_sentiment.py` (modified) -- Added "UAE" to SUBREDDITS list alongside "dubai" and "dubairealestate".

**Normalizers:**
- `normalize_commodities.py` -- Maps BZ=F to "brent_crude" and GC=F to "gold_xau". Produces 4 metrics: close price (USD) and volume for each commodity. Skips null close values.
- `normalize_news_sentiment.py` -- Produces 4 daily metrics: mean_compound, bullish_ratio (compound > 0.05), bearish_ratio (compound < -0.05), article_count. Handles empty article lists with zero-value records.

**Schemas:**
- 2 validation schemas (commodities, news_sentiment) -- JSON file existence and structure validation following dfm_stocks_schema pattern.

### Task 2: TS Registration, Build, Deploy, Verification

- Extended `PythonScriptName` union with 4 new entries
- Extended `SOURCE_MODULE_MAP` with 2 new source mappings (commodities, news-sentiment)
- Extended `COLLECTOR_DEFINITIONS` to 40 sources (was 38)
- Extended `DIRECT_PYTHON_SOURCES` to 8 entries (was 6)
- TypeScript build: 0 errors
- Production deployed to `/opt/lobsec/plugins/lobsec-uae-re/`
- Commodities collected and normalized end-to-end

## Production Data

| Source | Metrics | Total Rows | Obs per Metric | Date Range |
|--------|---------|------------|----------------|------------|
| commodities | 4 | 208 | 52 | 2021-04 to 2026-03 |
| **Total new** | **4** | **208** | | |

### Metric Inventory

**Commodities (4 metrics, 52 obs each):**
- `uae|brent_crude_close_usd` -- Recent: $103.36/bbl (Mar 2026)
- `uae|brent_crude_volume` -- Monthly trading volume
- `uae|gold_xau_close_usd` -- Recent: $4,366.80/oz (Mar 2026)
- `uae|gold_xau_volume` -- Monthly trading volume

**News Sentiment (4 metrics, registered but collection deferred):**
- `uae|news_sentiment_mean_compound` -- Mean VADER compound score
- `uae|news_sentiment_bullish_ratio` -- Proportion of bullish articles
- `uae|news_sentiment_bearish_ratio` -- Proportion of bearish articles
- `uae|news_sentiment_article_count` -- Total articles scored

### COST-01 Documentation

COST-01 (Cost of Living) is satisfied by existing World Bank CPI data collected in Phase 18:
- `uae|wb_cpi_inflation_pct` -- 17 observations (2007-2023)
- Numbeo has no free API tier ($260/mo minimum)
- World Bank CPI + existing rental data (Ejari, Bayut) serve as cost-of-living proxy

### Reddit Sentiment Enhancement

- SUBREDDITS list expanded: `["dubai", "dubairealestate", "UAE"]`
- No new collector needed -- existing PRAW-based collector handles the additional subreddit
- Deployed to production

## Database Summary

Total sources in normalized_monthly: **16** (was 15 before this plan)
Total rows: ~1490 (was ~1282)

## Deviations from Plan

None -- plan executed exactly as written.

## Commits

| Task | Commit | Description |
|------|--------|-------------|
| 1 | 517e9ba | 7 Python files: 2 collectors + 2 normalizers + 2 schemas + Reddit enhancement |
| 2 | 5b9c144 | TS registration + build + deploy + commodities collected & normalized |

## Success Criteria Verification

- [x] Brent crude and gold OHLCV data collected from Yahoo Finance and normalized to 4 monthly metrics
- [x] Reddit sentiment collector now monitors 3 subreddits (dubai, dubairealestate, UAE)
- [x] NewsAPI collector registered and deployable (collection deferred until API key available)
- [x] COST-01 documented as satisfied by existing World Bank CPI data
- [x] 16 distinct sources in normalized_monthly (requirement: at least 16)
- [x] TypeScript build passes with 0 errors
- [x] All Python modules importable from analytics-venv

## Self-Check: PASSED

All 10 files verified present. Both commits (517e9ba, 5b9c144) verified in git log.
