# Phase 9: Tier C Collection (Alternative Economic Signals) - Context

**Gathered:** 2026-03-13
**Status:** Ready for planning

<domain>
## Phase Boundary

Build 14 alternative economic signal collectors completing all 28 sources in the intelligence system. Sources include Google Trends, social sentiment (Reddit), Google Maps foot traffic, RTA metro ridership, DTCM tourism, DED business licenses, CBUAE mortgages, Jebel Ali port cargo, customs household imports, FCSA demographics, InsideAirbnb/STR, F&B closures (Zomato + Google Maps), moving inquiry proxies (Google Trends), and commercial office reports (JLL/CBRE/Savills). Add daily timer (SCHED-05) and residential proxy support to Ninja Scraper.

Requirements: COLL-14, COLL-16, COLL-17, COLL-18, COLL-19, COLL-20, COLL-21, COLL-22, COLL-23, COLL-24, COLL-25, COLL-26, COLL-27, COLL-28, SCHED-05

</domain>

<decisions>
## Implementation Decisions

### API vs Scrape Strategy
- **Google Trends (COLL-14)**: Direct Python via pytrends — call from Python module via runPython(), skip Ninja Scraper. pytrends handles rate limiting internally. Already installed in analytics-venv
- **Reddit sentiment (COLL-24)**: Direct Python via PRAW + vaderSentiment — API-based, no browser needed. Both already installed in analytics-venv. PRAW is sufficient without proxy (generous rate limits for our volume)
- **InsideAirbnb (COLL-19)**: Ninja Scraper http_download mission — CSV bulk download, consistent with DLD/Ejari pattern
- **Google Maps foot traffic (COLL-26)**: Ninja Scraper browser_scrape — extract Popular Times from Google Maps HTML for 50 curated locations. High risk of detection but build it, accept graceful failure
- **All other Tier C sources**: Ninja Scraper browser_scrape missions — consistent with Phase 8 approach for government/institutional sources (RTA metro, DTCM tourism, DED, CBUAE, Jebel Ali, customs, FCSA, F&B closures, commercial reports)

### Proxy & Stealth
- **Build residential proxy support now** — add to Ninja Scraper mission schema as infrastructure. Don't buy proxies yet, but plumbing is ready when needed
- **Per-mission proxy toggle** — YAML missions get optional `proxy: true/false` field. Only sources that need it (Google Maps, Google Trends) get proxied. Others run direct
- **Proxy credentials in HSM** — consistent with all other secrets. Proxy URL + credentials stored as HSM data object
- **Shared proxy config** — one proxy configuration shared across both Ninja Scraper missions and direct Python collectors (pytrends has built-in proxy param). Single source of truth
- **UA rotation option** — add per-mission User-Agent rotation from curated list. Extra stealth layer for aggressive sites like Google
- **Google Maps pacing** — spread 50 location requests across ~10 hours (drip-feed, not batch). Lower detection risk
- **Government sources** — same conservative Patchright approach as Tier B (browser_scrape with standard delays, skip_on_403). Not aggressively anti-bot

### Low-Availability Sources
- **Moving company inquiries (COLL-27)**: Replaced with Google Trends proxy signal — 'moving companies dubai' + 'international movers dubai' keyword groups. Same migration intent signal, no fake quote submissions
- **F&B closures (COLL-21)**: Both Zomato + Google Maps — try Zomato API/scraping, Google Maps 'permanently_closed' as primary. Cross-validate when both available
- **Commercial office reports (COLL-28)**: Scrape public summary pages from JLL/CBRE/Savills websites. Key metrics (vacancy rate, absorption, prime rent) are published publicly even when full PDF is gated
- **Unavailable data sources**: Same approach as Phase 8 — build complete collectors, test against last available data, graceful failure + stale marking if nothing new. Collectors ready when data appears
- **Annual sources (FCSA demographics COLL-25)**: test against last published data. Collector ready for next release

### Daily Timer (SCHED-05)
- **Daily timer at 23:00 GST (19:00 UTC)** — runs Google Trends (6 keyword groups) + Reddit sentiment (2 subreddits). Lightweight sources, seconds per run
- **Foot traffic on weekly timer** — Google Maps 50 locations runs on existing weekly timer (Mon 02:00 UTC), not daily. Reduces detection risk. Popular Times shows weekly patterns anyway
- **F&B closures on monthly timer** — Google Maps permanently_closed checks run monthly, not daily
- **All other Tier C sources** stay on existing monthly/quarterly timers as defined
- **Timer frequency summary**:
  - Daily (SCHED-05, new): Google Trends, Reddit sentiment
  - Weekly (existing): + Google Maps foot traffic
  - Monthly (existing): + RTA metro, DTCM tourism, DED licenses, Jebel Ali port
  - Quarterly (existing): + CBUAE mortgages, customs imports, FCSA demographics, InsideAirbnb, commercial office reports

### Claude's Discretion
- YAML mission spec details per source (selectors, extraction rules, wait conditions)
- Python normalization module internals for each new source
- pytrends keyword group composition (6 groups: buy/rent/expat/distress/luxury/exit)
- Reddit subreddit post selection and VADER scoring aggregation
- Google Maps location list curation (50 locations — which malls, metro stations, areas)
- Zomato API vs scraping approach (API may be deprecated in UAE)
- InsideAirbnb CSV URL format and field mapping
- Commercial office report website selectors for JLL/CBRE/Savills
- Proxy rotation implementation details (round-robin vs random vs sticky)
- UA rotation list curation
- collect.sh updates for daily frequency dispatch

</decisions>

<specifics>
## Specific Ideas

- COLL-27 (moving inquiries) reimagined as Google Trends proxy — original approach of submitting fake quote requests is ethically questionable and fragile. Google Trends for moving-related keywords provides the same migration intent signal
- Residential proxy support is proactive infrastructure — not needed today but Google Maps at 50 locations/week will likely trigger detection eventually. Having the plumbing ready avoids emergency rework
- Direct Python collectors (pytrends, PRAW) follow the same audit/logging pattern as Ninja Scraper missions — runPython() handles audit trail, error reporting, Telegram alerts
- The playbook at `.planning/uae-re-playbook.md` has detailed source URLs, field mappings, and collection strategies for all Tier C sources

</specifics>

<code_context>
## Existing Code Insights

### Reusable Assets
- Ninja Scraper engine (127.0.0.1:18791): 20 missions deployed (7 Tier A + 13 Tier B). FastAPI with browser_scrape, http_download, api_call types
- Mission YAML schema: Pydantic-validated Mission model with retry, concurrency, timeout, areas configs
- load_all_missions(): Auto-discovers *.yml from missions/ directory at startup — just drop new files
- CollectorRegistry + COLLECTOR_DEFINITIONS: TS registry with frequency scheduling, runByFrequency()
- collect.sh orchestrator: Bash script for weekly/monthly/quarterly dispatch. Needs daily frequency addition
- 15 Python normalization modules: Pattern well-established (normalize_{source}.py with pandera validation)
- pytrends, praw, vaderSentiment: Already in analytics-venv requirements.txt — no new Python deps
- 3 systemd timers: weekly/monthly/quarterly active. Daily timer is the only new one
- CollectionFrequency type already includes "daily"

### Established Patterns
- YAML mission per source → Ninja Scraper browser_scrape/http_download
- Direct Python for API-native sources (new pattern for Phase 9: pytrends, PRAW)
- PDF extraction in Python normalization, not YAML missions
- browser_scrape as default for all web sources
- Graceful failure + stale marking for unavailable sources
- HSM for all credentials (proxy creds follow same pattern)
- Per-mission YAML config for timeouts, retries, areas
- collect.sh → Node.js entry point → CollectorRegistry → Ninja Scraper API → normalize

### Integration Points
- Ninja Scraper missions/ directory: 20 existing + ~12 new YAML files
- COLLECTOR_DEFINITIONS array: Add ~14 new entries with correct frequency/priority/timeout
- Python normalization: ~12 new modules (normalize_trends.py, normalize_sentiment.py, normalize_metro.py, normalize_tourism.py, normalize_mortgages.py, normalize_airbnb.py, normalize_port.py, normalize_fb_closures.py, normalize_customs.py, normalize_licenses.py, normalize_demographics.py, normalize_office.py, normalize_foot_traffic.py)
- Ninja Scraper mission schema: Add optional `proxy` and `user_agent_rotation` fields
- systemd: New lobsec-collect-daily.timer + service unit
- collect.sh: Add daily frequency dispatch
- HSM: Proxy credentials (when purchased), Reddit API credentials (for PRAW OAuth)
- analytics-venv: No new Python deps needed (pytrends, praw, vaderSentiment already installed)

</code_context>

<deferred>
## Deferred Ideas

- **Residential proxy purchase** — Plumbing built in Phase 9, but actual proxy service subscription deferred until Google starts blocking. Evaluate after 2+ weeks of operation
- **F&B closure alternatives** — If Zomato API is fully deprecated in UAE, consider Talabat or Deliveroo status tracking as alternative source
- **Google Maps foot traffic to daily** — Could move from weekly to daily if weekly proves stable and detection risk is manageable. Evaluate after 1 month
- **InsideAirbnb STR weekly supplement** — COLL-19 requirement mentions "Apify weekly" in addition to InsideAirbnb quarterly bulk. Apify actor deferred unless InsideAirbnb quarterly data proves too stale
- **Moving company direct data** — Original COLL-27 (quote submission) replaced with Google Trends proxy. Revisit direct approach only if Google Trends moving keywords prove uncorrelated with actual relocation volume

</deferred>

---

*Phase: 09-tier-c-collection*
*Context gathered: 2026-03-13*
