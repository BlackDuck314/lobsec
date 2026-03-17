# Requirements: lobsec

**Defined:** 2026-03-17
**Core Value:** No credential or sensitive data ever reaches an LLM provider

## v1.4 Requirements

Requirements for v1.4 UAE RE Intelligence Activation. Make the intelligence system produce real answers.

### Normalization

- [x] **NORM-06**: DXB normalizer handles HTML fact file JSON (extracts passenger counts, top markets, quarterly data)
- [x] **NORM-07**: MOHRE normalizer handles observatory dashboard JSON (workforce growth, establishment growth, Emiratisation counts)
- [x] **NORM-08**: DSC normalizer extracts population data from PDF via pdfplumber (total population, expat/national split, age groups, growth rate)
- [x] **NORM-09**: All 8 existing sources (PropertyFinder, ADREC, Bayt, LinkedIn, Indeed, KHDA, CBUAE, DP World) verified producing normalized_monthly rows after collection

### Backfill

- [x] **BACK-01**: DSC population bulletins backfilled (2022, 2023, 2024) — 3 years of annual demographic data
- [x] **BACK-02**: DXB passenger data backfilled from press archive — at least 12 months of quarterly/annual figures
- [x] **BACK-03**: MOHRE workforce time series backfilled (2021-2025) from observatory dashboard data already captured
- [x] **BACK-04**: CBUAE quarterly banking data backfilled — at least 4 quarters of remittance/transfer data
- [x] **BACK-05**: DP World annual throughput backfilled — at least 3 years of container/cargo data

### Data Sources

- [ ] **DATA-01**: Dubai Pulse API registered and credentials stored in HSM
- [ ] **DATA-02**: DLD sales transaction collector working via Dubai Pulse API
- [ ] **DATA-03**: Ejari rental contract collector working via Dubai Pulse API
- [ ] **DATA-04**: Building permits collector working via Dubai Pulse API

### Automation

- [ ] **AUTO-01**: Scraper -> ingest -> normalize pipeline runs automatically after each collection
- [ ] **AUTO-02**: Analysis pipeline (stationarity, Granger, composites, anomalies) runs monthly on 25th
- [ ] **AUTO-03**: Collection timers verified operational: weekly, monthly, quarterly schedules active

### Verification

- [ ] **VERIF-01**: At least 3 intelligence products return non-null data when queried via Telegram
- [ ] **VERIF-02**: uae_macro_health returns traffic lights for at least 2 of 6 signal groups
- [ ] **VERIF-03**: uae_collection_status shows all active sources with last successful run < 7 days old

## v1.3 Requirements (Shipped)

All 88 requirements from v1.3 shipped (code complete). See MILESTONES.md for details.
Categories: INFRA (7), COLL (28), NORM (5), STAT (8), PROD (8), TOOL (13), SCHED (7), SEC (7), QUAL (5).

## v1.5+ Requirements (Deferred)

### Blocked Source Recovery
- **BLOCK-01**: DEWA connections via browser PDF download or API
- **BLOCK-02**: DET/DTCM tourism statistics via residential proxy or API
- **BLOCK-03**: RTA vehicle registrations via alternative data source
- **BLOCK-04**: Bayut listings via residential proxy (CAPTCHA bypass)

### Advanced Analytics
- **ADV-01**: Forward curve projections verified with 12+ month data
- **ADV-02**: Distress alerts triggered on real area-level data
- **ADV-03**: Expat funnel populated with real lifecycle stage data

## Out of Scope

| Feature | Reason |
|---------|--------|
| Residential proxy setup | Working sources first, blocked sources deferred to v1.5 |
| DEWA/DET/RTA WAF bypass | Focus on the 11+ working sources |
| New intelligence products | 8 products exist, just need data to produce results |
| New plugin tools | 13 tools exist and are registered |
| Multi-tenant | Single-user deployment |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| NORM-06 | Phase 13 | Complete |
| NORM-07 | Phase 13 | Complete |
| NORM-08 | Phase 13 | Complete |
| NORM-09 | Phase 13 | Complete |
| BACK-01 | Phase 14 | Complete |
| BACK-02 | Phase 14 | Complete |
| BACK-03 | Phase 14 | Complete |
| BACK-04 | Phase 14 | Complete |
| BACK-05 | Phase 14 | Complete |
| DATA-01 | Phase 15 | Pending (user action required) |
| DATA-02 | Phase 15 | Pending |
| DATA-03 | Phase 15 | Pending |
| DATA-04 | Phase 15 | Pending |
| AUTO-01 | Phase 16 | Pending |
| AUTO-02 | Phase 16 | Pending |
| AUTO-03 | Phase 16 | Pending |
| VERIF-01 | Phase 17 | Pending |
| VERIF-02 | Phase 17 | Pending |
| VERIF-03 | Phase 17 | Pending |

**Coverage:**
- v1.4 requirements: 19 total (17 active + 2 in Verification mapped to Phase 17)
- Mapped to phases: 17
- Unmapped: 0

---
*Requirements defined: 2026-03-17*
*Last updated: 2026-03-17 after Phase 14 Plan 02 execution (BACK-04 complete, all backfill requirements met)*
