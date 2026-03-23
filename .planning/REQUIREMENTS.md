# v1.5 Requirements — Data Expansion (API-First Sources)

**Milestone:** v1.5 Data Expansion
**Goal:** Add 8-10 new API-based data sources with historical backfill to accelerate statistical analysis activation. Activate dormant scraper missions. Target: 20+ sources producing normalized data (up from 11).

## Tier 1: Macro Economic APIs (no auth required)

- [ ] **MACRO-01**: World Bank API collector — UAE GDP growth, inflation (CPI), FDI inflows, trade balance, population. REST API, country code ARE. Historical data back to 2000+. Monthly/annual frequency.
- [ ] **MACRO-02**: IMF DataMapper API collector — World Economic Outlook historical + forecasts for UAE. Open JSON API, no auth required. Annual frequency with forecasts to 2030.
- [ ] **MACRO-03**: S&P Global PMI collector — UAE monthly PMI from press release text extraction. No auth, public press releases. Monthly frequency.
- [ ] **MACRO-04**: DFM RE stock collector — monthly OHLCV via Yahoo Finance API. RE sector stocks (Emaar, Emaar Development, Deyaar, Union Properties). No auth required. Monthly frequency.

## Tier 2: Commodity, Sentiment & Cost of Living (free API keys)

- [ ] **COMM-01**: Brent crude oil price collector — historical daily/weekly prices via free API (EIA, OilPriceAPI, or similar). Store in HSM if API key needed.
- [ ] **COMM-02**: Gold price collector — XAU/USD historical via GoldAPI or similar free tier. Dubai = gold hub, correlates with capital flows.
- [ ] **SENT-01**: Reddit sentiment collector — r/dubai + r/UAE JSON endpoint (.json suffix, no auth). VADER sentiment scoring on posts/comments mentioning real estate keywords. Weekly frequency.
- [ ] **SENT-02**: News API headline sentiment — UAE business news from newsapi.org (free key, 100 req/day). Keyword filtering for RE/economy terms. VADER scoring. Daily frequency.
- [ ] **COST-01**: Numbeo cost of living collector — Dubai and Abu Dhabi indices via API (free key). Rent index, groceries, restaurant prices. Monthly frequency.
- [ ] **CBUAE-01**: CBUAE Open Data expanded — interest rates, money supply, banking indicators from centralbank.ae open data portal (CSV/JSON download). Beyond existing PDF scraping.

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
