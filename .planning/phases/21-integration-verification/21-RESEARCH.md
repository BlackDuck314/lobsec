# Phase 21: Integration & Verification - Research

**Researched:** 2026-03-25
**Domain:** Data pipeline integration verification, milestone completion assessment
**Confidence:** HIGH

## Summary

This is the final phase of v1.5 milestone. Research investigated every INTEG and VERIF requirement by querying the live production database, inspecting source code, checking nftables egress rules, and auditing HSM credentials. The system is remarkably close to milestone completion: 20 sources are producing normalized data (VERIF-01 met), 47 metrics have 12+ observations (VERIF-02 far exceeded), and the analysis pipeline is running. However, three concrete gaps remain: (1) the macro health product is missing Commodities and has broken Sentiment signal references (VERIF-03), (2) two credential-dependent sources (reddit-sentiment, news-sentiment) have never collected data (INTEG-03 partial), and (3) the deployed plugin code is stale versus the repository source.

**Primary recommendation:** Fix macro health signal groups (add Commodities, fix Sentiment metric names), rebuild and redeploy the plugin, and mark the credential-blocked sources as known limitations.

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| INTEG-01 | All new API collectors registered in CollectorRegistry with correct frequencies and timeouts | DONE. All Phase 18-20 sources verified in registry.ts (lines 196-228): worldbank-macro, imf-weo, dfm-stocks, spglobal-pmi, commodities, news-sentiment, cbuae-expanded. All have correct DirectPythonCollector mappings. |
| INTEG-02 | New API domains added to nftables egress allowlist | DONE. Egress firewall is port-based (not domain-based). TCP 443 is allowed, covering all HTTPS API endpoints. No non-standard ports needed. |
| INTEG-03 | API keys (where needed) stored in HSM via pkcs11-tool | PARTIAL. Most Phase 18-20 sources are auth-free (World Bank, IMF, Yahoo Finance, S&P Global PMI, Google Trends). Reddit needs REDDIT_CLIENT_ID/SECRET (not in HSM or .env). NewsAPI needs NEWSAPI_KEY (not in HSM or .env). Neither has ever collected. |
| INTEG-04 | New source normalizers produce rows in normalized_monthly table | DONE. All new source normalizers are registered in SOURCE_MODULE_MAP and producing data. 20 sources active in normalized_monthly. |
| VERIF-01 | 20+ sources producing normalized data | DONE. Exactly 20 distinct sources confirmed in normalized_monthly. |
| VERIF-02 | At least 3 metrics with 12+ observations | FAR EXCEEDED. 47 metrics have 12+ observations (target was 3). DFM stocks have 61 obs each, commodities 52, IMF 47, World Bank 17-25, Google Trends 13. |
| VERIF-03 | Macro health product enhanced with Commodities and Sentiment signal groups | NOT DONE. Commodities group does not exist. Sentiment group exists but references non-existent metrics. |
</phase_requirements>

## Detailed Per-Requirement Analysis

### INTEG-01: Collector Registry (DONE)

All Phase 18-20 collectors are registered in `packages/uae-re/src/collectors/registry.ts`:

| Source | Type | Frequency | Priority | Timeout | Python Module |
|--------|------|-----------|----------|---------|---------------|
| worldbank-macro | DirectPython | quarterly | 2 | 60s | collect_worldbank |
| imf-weo | DirectPython | quarterly | 2 | 60s | collect_imf |
| dfm-stocks | DirectPython | monthly | 3 | 60s | collect_dfm_stocks |
| spglobal-pmi | DirectPython | monthly | 2 | 120s | collect_pmi |
| commodities | DirectPython | monthly | 2 | 60s | collect_commodities |
| news-sentiment | DirectPython | daily | 1 | 60s | collect_news_sentiment |
| cbuae-expanded | DirectPython | quarterly | 2 | 120s | collect_cbuae_expanded |

Additionally, Phase 20 dormant missions correctly set `enabled: false` for 18 blocked/retired sources.

**Status: No action needed.**

### INTEG-02: nftables Egress (DONE)

The egress firewall at `table inet lobsec_egress` uses port-based filtering for the `lobsec` user (uid 995):
- TCP 443 (HTTPS) -- covers ALL API endpoints
- TCP 587 (SMTP), TCP 993 (IMAP), UDP 53 (DNS), UDP 123 (NTP)
- TCP 11435 to <SOVEREIGN_GPU_HOST> (Ollama)

All Phase 18-20 API sources use standard HTTPS (port 443):
- api.worldbank.org, www.imf.org, query2.finance.yahoo.com
- www.spglobal.com, newsapi.org, oauth.reddit.com, trends.google.com

No domain-specific allowlist is needed because the firewall operates at the port level.

**Status: No action needed.**

### INTEG-03: HSM API Keys (PARTIAL)

HSM objects confirmed via `pkcs11-tool`:
```
scraper-auth-token, jetson-cf-client-secret, perplexity-api-key,
examy-username, radicale-password, telegram-bot-token,
tomorrow-io-api-key, jetson-cf-client-id, gateway-auth-token,
github-pat, anthropic-api-key, gmail-app-password, ollama-api-key,
examy-password, fscrypt-master-key
```

**Missing credentials:**
1. **NEWSAPI_KEY** -- NewsAPI.org free developer key. The `collect_news_sentiment.py` collector reads `NEWSAPI_KEY` from environment (line 46). Not in HSM, not in .env. The `news-sentiment` source has been registered but has never collected data.
2. **REDDIT_CLIENT_ID + REDDIT_CLIENT_SECRET** -- Reddit app credentials for PRAW. The `collect_sentiment.py` collector reads these from environment (lines 48-49). Not in HSM, not in .env. The `reddit-sentiment` source has been registered but has zero raw data files and zero normalized rows.

**Impact:** These two sources contribute zero rows to normalized_monthly. However, 20 other sources are active and the milestone targets are met without them. The requirement says "API keys (where needed)" -- these are needed but not stored.

**Recommendation:** Either:
- (a) Obtain and store these credentials (register at newsapi.org and reddit.com/prefs/apps)
- (b) Document as known limitations and close the requirement as "PARTIAL -- credential-blocked sources deferred"

### INTEG-04: New Source Normalizers (DONE)

All new sources from Phases 18-20 have normalizers in `SOURCE_MODULE_MAP` (`packages/uae-re/src/normalization/types.ts`):

| Source | Module | Status | Rows in DB |
|--------|--------|--------|------------|
| worldbank-macro | normalize_worldbank | Active | 115 |
| imf-weo | normalize_imf | Active | 255 |
| dfm-stocks | normalize_dfm_stocks | Active | 488 |
| spglobal-pmi | normalize_pmi | Active | 1 |
| commodities | normalize_commodities | Active | 208 |
| news-sentiment | normalize_news_sentiment | Registered, no data | 0 |
| cbuae-expanded | normalize_cbuae_expanded | Active | 47 |

Note: `spglobal-pmi` has only 1 row because PMI is monthly and press releases are scraped for the most recent value. Over time this will accumulate.

**Status: No action needed (normalizers work; data absence is a collection/credential issue, not normalization).**

### VERIF-01: 20+ Sources (DONE)

Confirmed 20 distinct sources in normalized_monthly:
```
adrec, bayt-jobs, cbuae, cbuae-expanded, cbuae-mortgages,
commodities, dfm-stocks, dpworld, dxb-passengers, fcsa-demographics,
google-trends, imf-weo, indeed-jobs, jebel-ali-port, khda,
linkedin-jobs, mohre-permits, propertyfinder, spglobal-pmi,
worldbank-macro
```

**Target met exactly at 20.** Reddit-sentiment and news-sentiment would push this to 22 if credentials were provided.

### VERIF-02: 3+ Metrics with 12+ Observations (FAR EXCEEDED)

**47 metrics** have 12+ observations (target was 3):

| Source | Metric | Observations |
|--------|--------|-------------|
| dfm-stocks | All 8 metrics (emaar/emaardev/deyaar/upp close+volume) | 61 each |
| commodities | brent_crude_close/volume, gold_xau_close/volume | 52 each |
| imf-weo | All 5 metrics | 47 each |
| worldbank-macro | 5 metrics | 17-25 each |
| google-trends | 25 metrics | 13 each |

**Stationarity analysis is running:** 22 of these 47 metrics have been tested (all from dfm-stocks, commodities, imf-weo, worldbank-macro). Results: 13 stationary, 5 inconclusive, 2 non-stationary after differencing, 2 non-stationary.

**Granger analysis:** 0 results because it tests against DLD (Dubai Land Department) price/volume targets, and DLD data is blocked (Dubai Pulse WAF). The Granger pipeline is functioning correctly but has no valid target series. This is a pre-existing limitation, not a Phase 21 issue.

### VERIF-03: Macro Health Product Enhanced (NOT DONE)

Current `SIGNAL_GROUPS` in `prod06-macro-health.ts` has 8 groups:
1. Employment -- partially functional (bayt-jobs has data, mohre-permits has 5 obs)
2. Housing -- non-functional (ejari blocked, propertyfinder area-specific)
3. Spending -- non-functional (ded-licenses blocked, rta-vehicles blocked)
4. Mobility -- partially functional (dxb-passengers has data, rta-metro blocked)
5. Sentiment -- **BROKEN: references non-existent metrics**
6. Population -- partially functional (gdrfa blocked, fcsa-demographics has 6 obs)
7. Macro Economy -- **FUNCTIONAL** (worldbank and imf both have data)
8. RE Stocks -- **FUNCTIONAL** (dfm-stocks has 61 obs per metric)

**Problems:**

**Missing Commodities group:** VERIF-03 requires "new signal groups (Commodities, Sentiment)" but Commodities does not exist in SIGNAL_GROUPS. Data is available:
- `commodities | uae|brent_crude_close_usd` -- 52 observations
- `commodities | uae|gold_xau_close_usd` -- 52 observations

**Broken Sentiment group references:**
- Signal 1: `reddit-sentiment / dubai|reddit_bearish_ratio` -- DOES NOT EXIST (0 rows from reddit-sentiment, and actual metric name would be `dubai|sentiment_bearish_ratio`)
- Signal 2: `google-trends / dubai|trends_expat_interest` -- DOES NOT EXIST (actual metric is `dubai|trends_expat_lifecycle_avg` with 13 observations)

**Required code changes for VERIF-03:**

```typescript
// In packages/uae-re/src/products/prod06-macro-health.ts
// Add new Commodities group to SIGNAL_GROUPS array:
{
  name: "Commodities",
  signals: [
    { source: "commodities", metric: "uae|brent_crude_close_usd" },
    { source: "commodities", metric: "uae|gold_xau_close_usd" },
  ],
},

// Fix Sentiment group metric references:
{
  name: "Sentiment",
  signals: [
    { source: "google-trends", metric: "dubai|trends_expat_lifecycle_avg" },
    { source: "google-trends", metric: "dubai|trends_distress_avg", invertScore: true },
  ],
},
```

Note: Since reddit-sentiment has no data, the Sentiment group should reference Google Trends metrics that DO have data (13 observations each). The `trends_expat_lifecycle_avg` measures inbound interest, while `trends_distress_avg` measures tenant distress (inverted: high distress = negative signal).

**Also update tool description** in `index.ts` line 467: change "6 signal groups" to "9 signal groups" (or however many after adding Commodities).

### Deployment Gap

The source `prod06-macro-health.ts` was updated 2026-03-23 but the deployed version at `/opt/lobsec/plugins/lobsec-uae-re/` is from 2026-03-16. After fixing VERIF-03, the plugin must be rebuilt (`pnpm build`) and redeployed.

### Collection Status Tool

The `uae_collection_status` tool (lines 617-678 in `index.ts`) uses `registry.getAll()` which only returns enabled collectors (disabled ones are skipped during `createCollectors`). This correctly excludes retired/dormant missions after Phase 20 changes.

However, it does NOT show blocked/credential-missing sources like reddit-sentiment and news-sentiment, which are enabled but fail on collection. This is acceptable behavior -- the tool shows registered collectors, and these two will show "Last run: (never)" with 0 normalized rows.

### Credential Redactor

The redactor at `/opt/lobsec/plugins/lobsec-security/dist/credential-redactor.js` does NOT have a specific NewsAPI key pattern. However:
- NewsAPI keys are typically 32-character hex strings like `abc123...`
- The `generic-api-key-header` pattern catches `x-api-key|api_key|apikey` assignments with 16+ character values
- The `bearer-token` pattern catches `Bearer` tokens
- NewsAPI uses `X-Api-Key` header, which IS matched by the generic pattern

**Status: Adequately covered by existing generic pattern.** No specific NewsAPI pattern needed.

### Analysis Pipeline Status

| Pipeline Step | Status | Detail |
|---------------|--------|--------|
| Stationarity | Running | 22 metrics tested from 4 sources, 332 skipped (<12 obs) |
| Granger | Running but empty | 0 results -- no DLD target data (blocked source) |
| Anomalies | Running | 4 anomalies detected |
| Composite | Running | 103 composite scores |
| Affordability | Running | 102 affordability records |
| Expat Funnel | Running | 15 funnel entries |
| Digest | Skipped | "insufficient validated signals for digest (0 < 3)" -- no Granger-validated signals |

The pipeline is healthy. The Granger/Digest gap is a pre-existing limitation (no DLD data) that predates v1.5 scope.

## Gap Summary and Required Work

### Must Fix (Blocks milestone completion)

| Gap | Requirement | Work Needed |
|-----|------------|-------------|
| Missing Commodities signal group | VERIF-03 | Add to SIGNAL_GROUPS in prod06-macro-health.ts |
| Broken Sentiment metric references | VERIF-03 | Fix metric names in SIGNAL_GROUPS |
| Tool description outdated | VERIF-03 | Update signal group count in index.ts |
| Deployed plugin stale | VERIF-03 | Rebuild and redeploy plugin |

### Should Fix (Improves quality but not blocking)

| Gap | Requirement | Work Needed |
|-----|------------|-------------|
| Reddit credentials missing | INTEG-03 | Register Reddit app, store in HSM, add to .env |
| NewsAPI key missing | INTEG-03 | Register at newsapi.org, store in HSM, add to .env |

### Known Limitations (Documented, not fixable in v1.5)

| Limitation | Impact |
|------------|--------|
| DLD data blocked (Dubai Pulse WAF) | Granger/Digest pipeline has no target series |
| S&P Global PMI only 1 observation | Will accumulate over time (monthly collection) |
| CBUAE expanded metrics <12 obs | Quarterly frequency, needs 3+ years for 12 obs |
| Reddit-sentiment: zero data | Credential-blocked |
| News-sentiment: zero data | Credential-blocked |

## Verification Commands

After implementing fixes, run these to verify:

```bash
# VERIF-01: Confirm 20+ sources
sudo -u lobsec sqlite3 /opt/lobsec/data/uae-re.db \
  "SELECT COUNT(DISTINCT source) FROM normalized_monthly;"

# VERIF-02: Confirm 3+ metrics with 12+ observations
sudo -u lobsec sqlite3 /opt/lobsec/data/uae-re.db \
  "SELECT COUNT(*) FROM (SELECT source, metric_name FROM normalized_monthly GROUP BY source, metric_name HAVING COUNT(*) >= 12);"

# VERIF-03: Run macro health and check for Commodities + Sentiment groups
# (After rebuilding and redeploying plugin, test via gateway)
sudo -u lobsec /opt/lobsec/bin/gateway-chat.sh "Run the macro health dashboard"

# Quick smoke test: check macro health output includes all groups
# The formattedText should contain "Commodities" and "Sentiment" lines
```

## Architecture Notes

### Data Flow (for planner context)
```
Collector (Python) → raw JSON file → DirectPythonCollector.run()
  → normalizeCollectionResult() → insertNormalized() → normalized_monthly table
  → analyze_stationarity (batch) → stationarity_results table
  → analyze_granger (batch, needs DLD target) → granger_results table
  → prod06-macro-health.ts queries normalized_monthly for z-scores
```

### Rebuild & Deploy Pattern
```bash
cd /root/lobsec/packages/uae-re
pnpm build
# Deploy to production
sudo -u lobsec cp -r dist/ /opt/lobsec/plugins/lobsec-uae-re/dist/
sudo -u lobsec cp -r src/ /opt/lobsec/plugins/lobsec-uae-re/src/
sudo systemctl restart lobsec
```

## Sources

### Primary (HIGH confidence)
- Production SQLite database at `/opt/lobsec/data/uae-re.db` -- live data queries
- Source code: `packages/uae-re/src/collectors/registry.ts` -- collector definitions
- Source code: `packages/uae-re/src/products/prod06-macro-health.ts` -- signal groups
- Source code: `packages/uae-re/src/normalization/types.ts` -- SOURCE_MODULE_MAP
- Source code: `packages/uae-re/src/index.ts` -- plugin entry point + tools
- HSM objects: `pkcs11-tool --list-objects --type data`
- nftables ruleset: `nft list ruleset`

## Metadata

**Confidence breakdown:**
- INTEG-01 status: HIGH -- verified in source code
- INTEG-02 status: HIGH -- verified against live nftables rules
- INTEG-03 status: HIGH -- verified against live HSM and .env
- INTEG-04 status: HIGH -- verified against live database
- VERIF-01 status: HIGH -- verified against live database (20 sources)
- VERIF-02 status: HIGH -- verified against live database (47 metrics >= 12 obs)
- VERIF-03 status: HIGH -- verified Commodities absent and Sentiment broken in source code

**Research date:** 2026-03-25
**Valid until:** N/A (final verification phase)
