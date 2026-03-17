# Phase 16: Deferred Items

## PropertyFinder CLI Poll Timeout
- **Source:** Task 1 (16-02)
- **Issue:** PropertyFinder scraper takes ~30 minutes for 20 areas x 10 pages. CLI `maxWaitMs: 600_000` (10 minutes) causes 3 poll timeouts, tripping the circuit breaker.
- **Impact:** PropertyFinder data only normalizes from timer-triggered runs (which complete because `collect.sh` uses `TimeoutSec=43200` in systemd). Manual `run-one` for PropertyFinder fails.
- **Suggested fix:** Increase `maxWaitMs` to 2_400_000 (40 minutes) for listing sources, or make it configurable per-source.
- **Severity:** Low (timer path works, only manual testing affected)

## Duplicate Log Lines in analyze.log
- **Source:** Task 2 (16-02)
- **Issue:** Each pipeline step log line appears twice because analyze.sh uses `tee -a` while systemd `StandardOutput=append:` also writes to the same file.
- **Impact:** Cosmetic only. Log file grows 2x faster than necessary.
- **Suggested fix:** Either remove `tee -a` from analyze.sh (systemd already handles logging) or remove `StandardOutput=append:` from the service file.
- **Severity:** Cosmetic
