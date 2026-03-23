# Phase 19: Commodity, Sentiment & Cost of Living - Research

**Researched:** 2026-03-23
**Domain:** API-based data collection (commodities, sentiment, macro banking)
**Confidence:** HIGH

## Summary

Phase 19 adds 6 new data sources to the UAE RE Intelligence system. Research reveals that 4 of the 6 requirements can be implemented with HIGH confidence using free, tested APIs that follow existing codebase patterns. The remaining 2 require design adjustments: Numbeo has no free tier (requires alternative approach), and CBUAE Open Data is locked behind Cloudflare and published primarily as PDFs (requiring PDF extraction rather than API calls).

The strongest finding is that Yahoo Finance v8 API -- already proven in the codebase for DFM stocks (Phase 18) -- serves both Brent crude (BZ=F) and gold (GC=F) perfectly, eliminating the need for new API keys. The existing Reddit sentiment collector uses PRAW, but the `.json` endpoint works without authentication and is a better match for SENT-01. NewsAPI.org provides a free developer key with 100 req/day, sufficient for daily headline sentiment.

**Primary recommendation:** Use Yahoo Finance for both commodities (no new API keys needed), Reddit `.json` endpoint for sentiment (no PRAW credentials needed), NewsAPI.org with free developer key for headlines, skip Numbeo (use World Bank CPI data as proxy), and extract CBUAE data from their quarterly PDF reports via pdfplumber.

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| COMM-01 | Brent crude oil price collector | Yahoo Finance BZ=F -- tested, 5yr monthly history, no auth |
| COMM-02 | Gold price collector (XAU/USD) | Yahoo Finance GC=F -- tested, 5yr monthly history, no auth |
| SENT-01 | Reddit sentiment r/dubai + r/UAE | Reddit `.json` endpoint -- tested, no auth needed, VADER in venv |
| SENT-02 | News API headline sentiment | NewsAPI.org `/v2/everything` -- needs free developer key |
| COST-01 | Numbeo cost of living | BLOCKED: No free tier ($260/mo min). Alternative: World Bank CPI |
| CBUAE-01 | CBUAE Open Data expanded | PDF extraction from QER reports via pdfplumber |
</phase_requirements>

## Standard Stack

### Core (Already in analytics-venv)
| Library | Version | Purpose | Status |
|---------|---------|---------|--------|
| requests | 2.32.5 | HTTP client for APIs | Installed |
| vaderSentiment | 3.3.2 | VADER sentiment scoring | Installed |
| pdfplumber | 0.11.4 | PDF table extraction | Installed |
| pandas | 2.2.3 | Data manipulation | Installed |
| pandera | 0.20.4 | Schema validation | Installed |
| praw | 7.8.1 | Reddit API (existing collector) | Installed |

### No New Dependencies Required
All 6 collectors can be built with libraries already installed in `/opt/lobsec/analytics-venv/`.

## Architecture Patterns

### Existing Pattern: DirectPythonCollector Bridge
All Phase 19 collectors follow the established `DirectPythonCollector` pattern:

```
TypeScript registry → DirectPythonCollector.collect() → runPython()
  → Python module receives {"outputDir": "/opt/lobsec/data/raw"} via stdin
  → Python module writes raw JSON to {outputDir}/{source-name}/{date}.json
  → Python module returns {"filePath": str, "rowCount": int} via stdout
```

### Files to Create Per Source

For each new source, create:
1. `python/uae_re/collect_{name}.py` -- collector module
2. `python/uae_re/normalize_{name}.py` -- normalizer module
3. `python/uae_re/schemas/{name}_schema.py` -- pandera/validation schema

Then register in:
4. `src/collectors/registry.ts` -- add to `COLLECTOR_DEFINITIONS` and `DIRECT_PYTHON_SOURCES`
5. `src/analytics/types.ts` -- add to `PythonScriptName` union
6. `src/normalization/types.ts` -- add to `SOURCE_MODULE_MAP`

### Recommended Project Structure (New Files)
```
packages/uae-re/python/uae_re/
├── collect_commodities.py      # COMM-01 + COMM-02 (Brent + Gold via Yahoo Finance)
├── collect_news_sentiment.py   # SENT-02 (NewsAPI headlines + VADER)
├── collect_cbuae_expanded.py   # CBUAE-01 (QER PDF extraction)
├── normalize_commodities.py    # Normalizer for Brent + Gold
├── normalize_news_sentiment.py # Normalizer for news headlines
├── normalize_cbuae_expanded.py # Normalizer for CBUAE monetary data
└── schemas/
    ├── commodities_schema.py
    ├── news_sentiment_schema.py
    └── cbuae_expanded_schema.py
```

**Design decision:** Brent crude and gold should share a single collector (`collect_commodities.py`) since they both use Yahoo Finance v8 API with the same code pattern. This avoids code duplication.

**Design decision:** The existing `collect_sentiment.py` (PRAW-based) should NOT be modified. Create a SEPARATE approach for SENT-01 if the Reddit `.json` endpoint is preferred over PRAW. However, since PRAW is already working and registered as `collect_sentiment` in the registry, SENT-01 is essentially already done -- just needs to add r/UAE subreddit to the existing SUBREDDITS list and change the search query. The current collector already covers r/dubai and r/dubairealestate.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Gold/Brent price history | Custom scraper | Yahoo Finance v8 API (same as DFM stocks) | Proven pattern in codebase |
| Sentiment analysis | Custom NLP model | VADER (vaderSentiment 3.3.2) | Already installed, tuned for social media |
| PDF table extraction | Custom PDF parser | pdfplumber (0.11.4) | Already installed, handles complex tables |
| Reddit API auth | OAuth flow | `.json` URL suffix (no auth) or existing PRAW | Either works without new credentials |
| Cost of living index | Web scraper for Numbeo | World Bank CPI indicator (FP.CPI.TOTL.ZG) | Already collected in Phase 18 |

## API Source Details

### COMM-01: Brent Crude Oil (Yahoo Finance)

**Confidence: HIGH** -- Tested and working.

**Endpoint:** `https://query2.finance.yahoo.com/v8/finance/chart/BZ=F`

**Parameters:**
- `interval=1mo` -- monthly OHLCV
- `range=5y` -- 5 years of history (or `range=10y` for deeper)

**Auth:** None required. User-Agent header needed (same as DFM stocks collector).

**Response format:**
```json
{
  "chart": {
    "result": [{
      "timestamp": [1609459200, ...],
      "indicators": {
        "quote": [{
          "open": [...], "high": [...], "low": [...],
          "close": [...], "volume": [...]
        }]
      }
    }]
  }
}
```

**Tested output:** 52 monthly records, most recent `2026-03: $102.69/bbl`.

**Fallback:** `https://query1.finance.yahoo.com/v8/finance/chart/BZ=F` (same as DFM stocks).

**Alternative considered:** EIA API v2 (`api.eia.gov/v2/petroleum/pri/spt/data/`) works with DEMO_KEY, returns 134 monthly records from 2015. Product code `EPCBRENT`, series `RBRTE`. However, Yahoo Finance is already a proven pattern in the codebase and requires no API key at all.

**EIA tested response sample:**
```json
{
  "period": "2024-01",
  "product": "EPCBRENT",
  "product-name": "UK Brent Crude Oil",
  "series-description": "Europe Brent Spot Price FOB (Dollars per Barrel)",
  "value": "80.12",
  "units": "$/BBL"
}
```

### COMM-02: Gold Price XAU/USD (Yahoo Finance)

**Confidence: HIGH** -- Tested and working.

**Endpoint:** `https://query2.finance.yahoo.com/v8/finance/chart/GC=F`

**Parameters:** Same as Brent crude (`interval=1mo`, `range=5y`).

**Auth:** None required.

**Tested output:** 52 monthly records, most recent `2026-03: $4,368.20/oz`.

**Response format:** Identical to Brent crude (same Yahoo Finance v8 API).

**Alternatives considered:**
- gold-api.com: Free current price only, historical requires API key
- goldapi.io: Requires paid API key for historical
- FRED (GOLDAMGBD228NLBM): Requires free FRED API key registration
- metals-api.com: Freemium, limited free tier

**Yahoo Finance is the clear winner** -- same codebase pattern, no key needed.

### SENT-01: Reddit Sentiment (r/dubai + r/UAE)

**Confidence: HIGH** -- Existing collector covers most of this.

**Current state:** `collect_sentiment.py` already exists and is registered. It uses PRAW with OAuth credentials stored in env vars (REDDIT_CLIENT_ID, REDDIT_CLIENT_SECRET). It currently monitors r/dubai and r/dubairealestate.

**What SENT-01 asks for:** r/dubai + r/UAE with VADER scoring, weekly frequency.

**Implementation options:**

**Option A (Recommended): Modify existing collector**
- Add "UAE" to SUBREDDITS list (alongside "dubai", "dubairealestate")
- The existing collector already does VADER scoring and weekly search
- Minimal code change, no new files needed
- Requires existing PRAW credentials to be configured

**Option B: Reddit .json endpoint (no auth)**
- URL: `https://www.reddit.com/r/dubai/search.json?q=rent+apartment+property&sort=relevance&t=week&restrict_sr=on&limit=100`
- Tested and working: returns Listing with children containing `title`, `selftext`, `score`, `created_utc`, `subreddit`, `num_comments`
- **CRITICAL:** Must include `restrict_sr=on` parameter to restrict search to the specific subreddit (without it, search returns results from all subreddits)
- **CRITICAL:** Must include `User-Agent` header (Reddit blocks requests without one)
- Rate limiting: Reddit enforces ~30 requests/minute for unauthenticated JSON

**Reddit .json search response structure:**
```json
{
  "kind": "Listing",
  "data": {
    "children": [
      {
        "kind": "t3",
        "data": {
          "subreddit": "dubai",
          "title": "My apartment is charging me...",
          "selftext": "...",
          "score": 425,
          "num_comments": 319,
          "created_utc": 1773654998.0,
          "id": "abc123"
        }
      }
    ],
    "after": "t3_xyz789"
  }
}
```

**Recommendation:** Use Option A (modify existing collector) since PRAW is already installed and the collector is already registered. Just add "UAE" to the SUBREDDITS list.

### SENT-02: NewsAPI Headline Sentiment

**Confidence: MEDIUM** -- API tested (format verified), but requires free developer key registration.

**Endpoint:** `GET https://newsapi.org/v2/everything`

**Parameters:**
| Param | Value | Notes |
|-------|-------|-------|
| `q` | `"UAE real estate" OR "Dubai property" OR "Dubai rent" OR "Abu Dhabi property"` | Max 500 chars, supports AND/OR/NOT |
| `language` | `en` | English articles only |
| `sortBy` | `publishedAt` | Chronological order |
| `pageSize` | `100` | Max per request |
| `from` / `to` | ISO 8601 dates | 1-month lookback on free tier |
| `apiKey` | Required | Via header `X-Api-Key` or query param |

**Free tier limits:**
- 100 requests/day (daily collector uses 1-2 requests, well within limits)
- 1 month of historical data lookback
- **Development use only** -- technically cannot be used in production
- Returns max 100 articles per request

**Response format:**
```json
{
  "status": "ok",
  "totalResults": 42,
  "articles": [
    {
      "source": {"id": "bbc-news", "name": "BBC News"},
      "author": "...",
      "title": "Dubai property market...",
      "description": "...",
      "url": "https://...",
      "publishedAt": "2026-03-23T10:00:00Z",
      "content": "First 200 chars of article..."
    }
  ]
}
```

**Error response (tested with invalid key):**
```json
{"status":"error","code":"apiKeyInvalid","message":"Your API key is invalid..."}
```

**API key storage:** Register at newsapi.org, store key in HSM as `newsapi-key` data object.

**VADER scoring approach:** Concatenate `title + description` for each article, compute VADER compound score. Aggregate into daily metrics: mean_compound, bullish/bearish ratios, article_count.

**Recommended search query:**
```
"UAE real estate" OR "Dubai property" OR "Dubai rent" OR "Abu Dhabi housing" OR
"Dubai apartment" OR "UAE mortgage" OR "DIFC" OR "Emaar"
```

### COST-01: Numbeo Cost of Living

**Confidence: HIGH (that it's blocked)** -- Numbeo has NO free tier.

**Numbeo API Pricing:**
| Plan | Price | Queries/month |
|------|-------|---------------|
| Basic | $260/month | 200,000 |
| Professional | $480/month | 1,000,000 |
| Enterprise | $1,250/month | 5,000,000 |

**COST-01 cannot be implemented as specified.** There is no free access to Numbeo's API.

**Alternative approach:** Use existing World Bank CPI data already collected in Phase 18:
- `FP.CPI.TOTL.ZG` (CPI inflation %) is already in `collect_worldbank.py`
- For rent-specific cost of living, the existing Ejari and Bayut data already provides Dubai rental price signals
- Consider scraping Numbeo's public web pages (risky -- ToS violation) or using Expatistan (also no clear free API)

**Recommendation:** Mark COST-01 as descoped or convert to "use existing CPI + rental data as cost-of-living proxy." The CPI inflation data from World Bank plus median rents from Ejari/Bayut already give the planner what they need for real estate affordability analysis.

### CBUAE-01: CBUAE Open Data Expanded

**Confidence: MEDIUM** -- Data exists in PDFs, but programmatic access is difficult.

**CBUAE website status:**
- `centralbank.ae` is behind Cloudflare (returns 403 for automated requests)
- No public JSON/CSV API discovered
- Exchange rate API endpoint exists (`/umbraco/api/ExchangeRate/GetExchangeRates`) but is Cloudflare-protected

**Available data source:** Quarterly Economic Review PDFs, published quarterly:
- Latest: `https://www.centralbank.ae/media/nsoa0sg3/qer-dec-2025.pdf` (Dec 2025, 23 pages)
- Pattern: Published quarterly, PDF format, consistent structure

**Data in QER PDFs (verified via pdfplumber extraction):**

Chapter 3 contains:
1. **Money Supply (M1, M2, M3)** -- quarterly values in AED billions with Y-o-Y %
   - Example: M1 = AED 1,033bn (+15.2%), M2 = AED 2,589bn (+15.1%), M3 = AED 3,123bn (+14.8%) (Q3 2025)
2. **Interest Rates** -- Base Rate, EIBOR (3m), DONIA, SOFR
   - Example: Base Rate 4.15% (Q3 2025), lowered to 3.90% (Oct 2025)
3. **Banking Developments** -- Total assets, gross credit, deposits (AED bn with Y-o-Y %)
   - Structured as quarterly tables with Q-4 through Q-0 columns
4. **Financial Soundness Indicators** -- Capital adequacy, NPL ratios, etc.

**PDF table structure (Table 3.1 example):**
```
| Metric       | Q3 2024 | Q4 2024 | Q1 2025 | Q2 2025 | Q3 2025 |
|-------------|---------|---------|---------|---------|---------|
| Total Assets | 4,402   | 4,559   | 4,719   | 4,973   | 5,200   |
| (Y-o-Y, %)  | 11.4    | 12.0    | 10.9    | 15.4    | 18.1    |
| Gross Credit | 2,162   | 2,181   | 2,240   | 2,334   | 2,479   |
```

**Implementation approach:**
1. Download QER PDF from known URL pattern
2. Use pdfplumber to extract tables from pages 19-21
3. Parse the quarterly data tables
4. Map to normalized metrics

**URL pattern (verified):**
- Dec 2025: `centralbank.ae/media/nsoa0sg3/qer-dec-2025.pdf`
- Sep 2025: `centralbank.ae/media/iamfnixn/qer-sep-2025.pdf`
- Jun 2025: `centralbank.ae/media/yrilyfz2/qer-june-2025_en.pdf`
- Mar 2025: `centralbank.ae/media/ysybjwlb/qer-march-2025.pdf`
- Dec 2024: `centralbank.ae/media/fusfyh0s/qer-dec-2024-23_12-_final.pdf`

**Issue:** URLs contain random hash slugs (e.g., `nsoa0sg3`, `iamfnixn`) making them unpredictable. The collector would need to either:
- Hardcode known URLs for historical backfill
- Scrape the publications listing page (blocked by Cloudflare)
- Use a headless browser to navigate the publications page

**Alternative for interest rates:** The CBUAE base rate precisely tracks the US Federal Reserve's IORB rate. The Fed Funds Rate is available from FRED (series `FEDFUNDS`) or can be hardcoded since changes are infrequent (4-8 per year) and well-publicized.

**Alternative for money supply:** World Bank `FM.LBL.BMNY.GD.ZS` (Broad money % of GDP) is available for UAE via the existing World Bank API. However, it's annual, not quarterly.

**Recommendation:** Implement a PDF extractor for a curated list of known QER URLs (hardcoded for backfill). For ongoing quarterly collection, manually add new QER URLs when they're published. This is pragmatic given the Cloudflare protection.

## Common Pitfalls

### Pitfall 1: Yahoo Finance Rate Limiting
**What goes wrong:** Yahoo Finance temporarily blocks requests with 429 status if too many requests are sent in quick succession.
**Why it happens:** Yahoo Finance has undocumented rate limits.
**How to avoid:** Add 1-2 second delays between requests (already done in DFM stocks collector). Use `query2.finance.yahoo.com` as primary with `query1` as fallback.
**Warning signs:** HTTP 429 responses, empty response bodies.

### Pitfall 2: Reddit JSON Rate Limiting
**What goes wrong:** Reddit returns 429 or HTML error pages for unauthenticated JSON requests.
**Why it happens:** Reddit enforces ~30 req/min for unauthenticated access, stricter during peak times.
**How to avoid:** Use existing PRAW-based collector (authenticated, higher limits). If using `.json` endpoint, keep to <1 request per 2 seconds.
**Warning signs:** Response contains HTML instead of JSON, HTTP 429.

### Pitfall 3: Reddit search without restrict_sr
**What goes wrong:** Searching r/UAE returns posts from r/japanlife, r/Austin, etc.
**Why it happens:** Without `restrict_sr=on`, Reddit search is global and returns results from any subreddit.
**How to avoid:** Always include `restrict_sr=on` in search queries.
**Warning signs:** Returned posts have unexpected subreddit values.

### Pitfall 4: NewsAPI Free Tier Production Restriction
**What goes wrong:** NewsAPI blocks requests from non-localhost origins on free tier.
**Why it happens:** Free developer plan is restricted to localhost/development use.
**How to avoid:** The collector runs server-side from localhost, so this works. But be aware that NewsAPI TOS technically prohibits production use on free tier. Evaluate whether the $449/mo Business plan is needed for compliance.
**Warning signs:** API returns `rateLimited` error from non-development environments.

### Pitfall 5: CBUAE PDF Format Changes
**What goes wrong:** PDF table extraction fails silently, producing empty or garbled data.
**Why it happens:** CBUAE changes table layout between QER editions.
**How to avoid:** Use schema validation on extracted data. Log warnings when expected tables aren't found. Validate that M1/M2/M3 values are within reasonable range (AED 500-5000 billion).
**Warning signs:** Zero records extracted, values outside expected range.

### Pitfall 6: Numbeo Web Scraping
**What goes wrong:** Numbeo detects and blocks scraping, ToS violation risks.
**Why it happens:** Numbeo explicitly prohibits scraping and has anti-bot protection.
**How to avoid:** Don't scrape Numbeo. Use World Bank CPI + existing rental data instead.
**Warning signs:** N/A -- don't attempt it.

## Code Examples

### Commodity Collector (Yahoo Finance) -- follows DFM stocks pattern
```python
# Source: /root/lobsec/packages/uae-re/python/uae_re/collect_dfm_stocks.py (adapted)
COMMODITIES = {
    "BZ=F": {"name": "Brent Crude Oil", "unit": "$/bbl"},
    "GC=F": {"name": "Gold (XAU/USD)", "unit": "$/oz"},
}

YF_BASE_URLS = [
    "https://query2.finance.yahoo.com/v8/finance/chart",
    "https://query1.finance.yahoo.com/v8/finance/chart",
]

def collect_commodities(output_dir: str) -> dict:
    commodities_dir = Path(output_dir) / "commodities"
    commodities_dir.mkdir(parents=True, exist_ok=True)
    # ... same pattern as collect_dfm_stocks.py
    for symbol, info in COMMODITIES.items():
        for base_url in YF_BASE_URLS:
            resp = requests.get(
                f"{base_url}/{symbol}",
                params={"interval": "1mo", "range": "5y"},
                headers={"User-Agent": USER_AGENT},
                timeout=30,
            )
            # Parse chart.result[0].timestamp + indicators.quote[0]
```

### Reddit Sentiment Enhancement
```python
# In existing collect_sentiment.py, add "UAE" to SUBREDDITS:
SUBREDDITS = ["dubai", "dubairealestate", "UAE"]
```

### NewsAPI Headline Collector
```python
NEWSAPI_BASE = "https://newsapi.org/v2/everything"
QUERY = '"UAE real estate" OR "Dubai property" OR "Dubai rent" OR "Abu Dhabi housing"'

def collect_news_sentiment(output_dir: str) -> dict:
    api_key = os.getenv("NEWSAPI_KEY", "")
    if not api_key:
        raise ValueError("Missing NEWSAPI_KEY environment variable")

    resp = requests.get(NEWSAPI_BASE, params={
        "q": QUERY,
        "language": "en",
        "sortBy": "publishedAt",
        "pageSize": 100,
        "apiKey": api_key,
    }, timeout=30)
    resp.raise_for_status()
    articles = resp.json().get("articles", [])

    analyzer = SentimentIntensityAnalyzer()
    scored = []
    for article in articles:
        text = f"{article.get('title', '')} {article.get('description', '')}"
        scores = analyzer.polarity_scores(text)
        scored.append({
            "title": article["title"],
            "source": article["source"]["name"],
            "publishedAt": article["publishedAt"],
            "compound": scores["compound"],
        })
    # Write to {output_dir}/news-sentiment/{date}.json
```

### CBUAE PDF Extraction
```python
import pdfplumber

def collect_cbuae_expanded(output_dir: str) -> dict:
    # Known QER PDF URLs (hardcoded for backfill)
    QER_URLS = [
        ("2025-Q4", "https://www.centralbank.ae/media/nsoa0sg3/qer-dec-2025.pdf"),
        ("2025-Q3", "https://www.centralbank.ae/media/iamfnixn/qer-sep-2025.pdf"),
        # ... more URLs
    ]

    for label, url in QER_URLS:
        resp = requests.get(url, timeout=60)
        pdf = pdfplumber.open(io.BytesIO(resp.content))
        # Extract tables from pages 19-21 (Money Supply, Banking)
        for page_num in [18, 19, 20]:  # 0-indexed
            tables = pdf.pages[page_num].extract_tables()
            # Parse quarterly data from tables
```

## Nftables Egress Rules

The existing egress firewall (`/etc/nftables.d/lobsec-egress.conf`) already allows:
- **Port 443 (HTTPS):** All outbound HTTPS is allowed (Yahoo Finance, NewsAPI, Reddit, CBUAE)
- **centralbank.ae** is already in the comment list of approved domains
- **reddit.com / oauth.reddit.com** already approved
- **No new egress rules needed** for any Phase 19 source

The only new domain is `newsapi.org` which should be added to the comment list for documentation (but works already since port 443 is open to all).

## HSM Credential Storage

New credentials to store in HSM:
| Credential | Source | Format |
|-----------|--------|--------|
| `newsapi-key` | newsapi.org free developer key | Data object |

No other new API keys needed (Yahoo Finance = no auth, Reddit = no auth, CBUAE = PDF download).

## Metric Names (Normalized)

### COMM-01 + COMM-02: Commodities
| Metric | Source | Frequency |
|--------|--------|-----------|
| `uae\|brent_crude_close_usd` | commodities | monthly |
| `uae\|gold_xau_close_usd` | commodities | monthly |
| `uae\|brent_crude_volume` | commodities | monthly |
| `uae\|gold_xau_volume` | commodities | monthly |

### SENT-01: Reddit Sentiment (Already Exists)
Already producing metrics via `normalize_sentiment.py`:
- `dubai\|sentiment_mean_compound`
- `dubai\|sentiment_bullish_ratio`
- `dubai\|sentiment_bearish_ratio`
- `dubai\|sentiment_post_count`
- Per-subreddit variants

### SENT-02: News Headlines Sentiment
| Metric | Source | Frequency |
|--------|--------|-----------|
| `uae\|news_sentiment_mean_compound` | news-sentiment | daily |
| `uae\|news_sentiment_bullish_ratio` | news-sentiment | daily |
| `uae\|news_sentiment_bearish_ratio` | news-sentiment | daily |
| `uae\|news_sentiment_article_count` | news-sentiment | daily |

### CBUAE-01: Expanded Monetary Data
| Metric | Source | Frequency |
|--------|--------|-----------|
| `uae\|cbuae_m1_aed_bn` | cbuae-expanded | quarterly |
| `uae\|cbuae_m2_aed_bn` | cbuae-expanded | quarterly |
| `uae\|cbuae_m3_aed_bn` | cbuae-expanded | quarterly |
| `uae\|cbuae_base_rate_pct` | cbuae-expanded | quarterly |
| `uae\|cbuae_eibor_3m_pct` | cbuae-expanded | quarterly |
| `uae\|cbuae_total_assets_aed_bn` | cbuae-expanded | quarterly |
| `uae\|cbuae_gross_credit_aed_bn` | cbuae-expanded | quarterly |
| `uae\|cbuae_bank_deposits_aed_bn` | cbuae-expanded | quarterly |

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| PRAW for Reddit (OAuth required) | `.json` endpoint (no auth) | Always available | Can work without Reddit API credentials |
| EIA API for oil prices | Yahoo Finance v8 (no key) | Phase 18 pattern | Consistent with existing codebase |
| Numbeo API for cost of living | World Bank CPI + existing rental data | N/A | Free alternative, already collected |

## Open Questions

1. **NewsAPI Free Tier vs Production**
   - What we know: Free tier works from localhost, 100 req/day, 1 month lookback
   - What's unclear: Whether running from a server (not localhost) counts as "production" for NewsAPI TOS
   - Recommendation: Register for free developer key, test it. If blocked, consider alternative: TheNewsAPI (thenewsapi.com) or GNews (gnews.io) free tiers

2. **CBUAE PDF URL Discovery**
   - What we know: URLs contain unpredictable hash slugs (e.g., `nsoa0sg3`)
   - What's unclear: Whether there's a pattern or predictable URL scheme
   - Recommendation: Hardcode known URLs for backfill. For ongoing collection, manually update URL list quarterly. Could also try the Ninja Scraper (already deployed) to navigate the publications page.

3. **COST-01 Descoping**
   - What we know: Numbeo has no free tier ($260/mo minimum)
   - What's unclear: Whether the user considers World Bank CPI an acceptable alternative
   - Recommendation: Use existing CPI + rental data. Flag for user decision.

4. **Reddit Credential Status**
   - What we know: Existing collector requires REDDIT_CLIENT_ID and REDDIT_CLIENT_SECRET
   - What's unclear: Whether these credentials are currently stored in HSM / configured
   - Recommendation: Check HSM for existing Reddit credentials. If not configured, either add them or switch to `.json` endpoint approach.

## Sources

### Primary (HIGH confidence)
- Yahoo Finance v8 API -- tested live: `query2.finance.yahoo.com/v8/finance/chart/BZ=F` and `GC=F`
- EIA API v2 -- tested live: `api.eia.gov/v2/petroleum/pri/spt/data/?api_key=DEMO_KEY` (134 records)
- Reddit JSON -- tested live: `reddit.com/r/dubai/search.json?restrict_sr=on`
- Existing codebase -- `collect_dfm_stocks.py`, `collect_sentiment.py`, `collect_worldbank.py`
- CBUAE QER PDF -- downloaded and parsed with pdfplumber (23 pages, tables extracted)
- Analytics venv -- verified: vaderSentiment 3.3.2, pdfplumber 0.11.4, praw 7.8.1 installed

### Secondary (MEDIUM confidence)
- [NewsAPI.org docs](https://newsapi.org/docs/endpoints/everything) -- endpoint format verified, API key required
- [Numbeo API pricing](https://www.numbeo.com/common/api.jsp) -- $260/mo minimum, no free tier
- [EIA API docs](https://www.eia.gov/opendata/documentation.php) -- free key registration, ~9000 req/hour

### Tertiary (LOW confidence)
- CBUAE Open Data portal -- blocked by Cloudflare, couldn't verify API existence
- gold-api.com -- free current price, unclear historical pricing/limits

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH -- all libraries already installed, no new deps
- Architecture: HIGH -- follows proven DirectPythonCollector + bridge pattern
- API availability: HIGH for commodities + Reddit, MEDIUM for NewsAPI, LOW for Numbeo/CBUAE API
- Pitfalls: HIGH -- based on direct testing and existing codebase experience

**Research date:** 2026-03-23
**Valid until:** 2026-04-23 (30 days -- APIs are stable, pricing may change)
