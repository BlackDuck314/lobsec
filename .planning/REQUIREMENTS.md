# v1.5 Requirements — Data Expansion (API-First Sources)

**Milestone:** v1.5 Data Expansion
**Goal:** Add 8-10 new API-based data sources with historical backfill to accelerate statistical analysis activation. Activate dormant scraper missions. Target: 20+ sources producing normalized data (up from 11).

## Tier 1: Macro Economic APIs (no auth required)

- [x] **MACRO-01**: World Bank API collector — UAE GDP growth, inflation (CPI), FDI inflows, trade balance, population. REST API, country code ARE. Historical data back to 2000+. Monthly/annual frequency.
- [x] **MACRO-02**: IMF DataMapper API collector — World Economic Outlook historical + forecasts for UAE. Open JSON API, no auth required. Annual frequency with forecasts to 2030.
- [x] **MACRO-03**: S&P Global PMI collector — UAE monthly PMI from press release text extraction. No auth, public press releases. Monthly frequency.
- [x] **MACRO-04**: DFM RE stock collector — monthly OHLCV via Yahoo Finance API. RE sector stocks (Emaar, Emaar Development, Deyaar, Union Properties). No auth required. Monthly frequency.

## Tier 2: Commodity, Sentiment & Cost of Living (free API keys)

- [ ] **COMM-01**: Brent crude oil price collector — monthly OHLCV via Yahoo Finance API (BZ=F symbol). No auth required. Same pattern as DFM stocks.
- [ ] **COMM-02**: Gold price collector — monthly OHLCV via Yahoo Finance API (GC=F symbol). No auth required. Dubai = gold hub, correlates with capital flows.
- [ ] **SENT-01**: Reddit sentiment collector — r/dubai + r/UAE via existing PRAW collector or .json endpoint. VADER sentiment scoring on RE-related posts. Weekly frequency.
- [ ] **SENT-02**: News API headline sentiment — UAE business news from newsapi.org (free key, 100 req/day). Keyword filtering for RE/economy terms. VADER scoring. Daily frequency.
- [ ] **COST-01**: Cost of living proxy — use existing World Bank CPI data (Phase 18) + rental data as cost-of-living signals. Numbeo has no free tier ($260/mo). No new collector needed.
- [ ] **CBUAE-01**: CBUAE expanded monetary data — M1/M2/M3, base rate, EIBOR, banking assets/credit/deposits from QER PDF reports via pdfplumber. Quarterly frequency.

## Tier 3: Dormant Mission Activation

- [ ] **DORM-01**: Audit all 31 deployed missions — identify which ones actually produce usable raw data files vs which are blocked/empty.
- [ ] **DORM-02**: Add normalization handlers for missions producing data but lacking ingest logic (target: 5+ additional sources from existing 22 unhandled missions).
- [ ] **DORM-03**: Fix or retire permanently blocked missions — update mission status, remove from collection timers if confirmed dead.

## Integration & Verification

- [ ] **INTEG-01**: All new API collectors registered in CollectorRegistry with correct frequencies and timeout enforcement.
- [ ] **INTEG-02**: New API domains added to nftables egress allowlist.
- [ ] **INTEG-03**: API keys (where needed) stored in HSM via pkcs11-tool.
- [ ] **INTEG-04**: New source normalizers produce rows in normalized_monthly table.
- [ ] **VERIF-01**: 20+ sources producing normalized data (up from 11).
- [ ] **VERIF-02**: At least 3 metrics with 12+ observations (enabling statistical analysis).
- [ ] **VERIF-03**: Macro health product enhanced — new signal groups (Commodities, Sentiment) with traffic lights.

---
*Created: 2026-03-23*
