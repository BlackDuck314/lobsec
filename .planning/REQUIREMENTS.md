# v1.6 Requirements — Full Activation

**Milestone:** v1.6 Full Activation
**Goal:** Unlock blocked Dubai government data via Dubai Pulse APIs, run first real Granger causality analysis, make bot intelligence actually useful with scheduled reports and alerts, complete security hardening.

## Dubai Pulse API Integration

- [ ] **PULSE-01**: Dubai Pulse OAuth2 client — register, store API key/secret in HSM, implement token refresh (30-min expiry). Shared client used by all Dubai Pulse collectors.
- [ ] **PULSE-02**: DLD transactions collector — fetch sales transactions via `dld_transactions` API. Normalize to monthly price/volume per area. This is the Granger causality TARGET.
- [ ] **PULSE-03**: Ejari rental contracts collector — fetch via `dld_rent_contracts` API. Normalize to monthly rent levels per area. Enables rental intelligence product.
- [ ] **PULSE-04**: DEWA new connections collector — fetch via `dewa_electricity_new_connection` API. Normalize to monthly new connections (leading indicator for occupancy).
- [ ] **PULSE-05**: Building permits collector — fetch via `dm_building_permits` API. Normalize to monthly residential/commercial permits (supply pipeline indicator).
- [ ] **PULSE-06**: RTA metro ridership collector — fetch via `rta_metro_ridership` API. Normalize to monthly ridership (mobility signal).
- [ ] **PULSE-07**: RTA vehicle registrations collector — fetch via `rta_car_registration` API. Normalize to monthly registrations (spending signal).
- [ ] **PULSE-08**: DTCM tourism collector — fetch via `dtcm_visitors_count_by_nationality` API. Normalize to monthly visitor counts (demand signal).

## Data Quality & Analysis

- [ ] **QUAL-01**: Bayut listings via API — replace broken scraper selectors with bayutapi.com (750 free calls/month). Normalize listing counts, prices, DOM per area.
- [ ] **QUAL-02**: Reddit credentials — register Reddit app, store REDDIT_CLIENT_ID/SECRET in HSM, verify r/dubai + r/UAE sentiment collection.
- [ ] **QUAL-03**: NewsAPI credentials — register at newsapi.org, store NEWSAPI_KEY in HSM, verify headline sentiment collection.
- [ ] **QUAL-04**: First Granger analysis — with DLD transaction data as target, run Granger causality against all 47+ metrics with 12+ observations. Produce validated leading indicators.
- [ ] **QUAL-05**: Composite index — generate first real composite buy/sell signal scores using Granger-validated weights.

## Bot Intelligence UX

- [ ] **BOT-01**: Scheduled weekly digest — automated Telegram message every Monday with market summary, anomalies, key metrics. Uses existing analysis pipeline output.
- [ ] **BOT-02**: Scheduled monthly report — comprehensive market intelligence on the 26th (after analysis pipeline runs on 25th). Includes Granger signals, composite scores, trend analysis.
- [ ] **BOT-03**: Response formatting — Unicode sparklines for trends, comparison tables, data freshness badges, confidence indicators.
- [ ] **BOT-04**: Proactive anomaly alerts — Telegram notification when EWMA detects significant metric changes, collection failures, or distress signals above threshold.

## Security Hardening

- [ ] **SEC-01**: mTLS enforcement — activate generated P-256/ECDSA certificates between gateway, proxy, and plugin services. Mutual authentication on all internal connections.
- [ ] **SEC-02**: Jetson proxy routing — add CF-Access header injection to proxy for Jetson requests. Route all Jetson traffic through proxy with audit logging.
- [ ] **SEC-03**: nftables user separation — create lobsec-proxy system user, configure per-user egress rules. Proxy gets HTTPS egress, gateway gets loopback-only.
- [ ] **SEC-04**: Hardened sandbox activation — switch from openclaw-sandbox:bookworm-slim to lobsec-sandbox:hardened image with seccomp whitelist profile.
- [ ] **SEC-05**: LUKS full-disk encryption — encrypt /opt/lobsec with dm-crypt/LUKS. Auto-unlock via TPM or keyfile during boot.

## Integration & Verification

- [ ] **VERIF-01**: 27+ sources producing normalized data (up from 20, adding 7 Dubai Pulse + Bayut API).
- [ ] **VERIF-02**: Granger causality produces at least 5 validated leading indicators with p < 0.05.
- [ ] **VERIF-03**: Scheduled digest delivered via Telegram at least once (Monday or 26th).
- [ ] **VERIF-04**: All internal service connections use mTLS.
- [ ] **VERIF-05**: Proactive anomaly alert fires on a real or simulated metric change.

---
*Created: 2026-03-25*
