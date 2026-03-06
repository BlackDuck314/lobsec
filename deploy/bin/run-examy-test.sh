#!/bin/bash
# run-examy-test.sh — Daily automated Examy QA test wrapper
# Called by lobsec-examy-test.timer (daily at 3am UTC) via systemd service.
# Handles: lockfile-based concurrency control, persona rotation by day-of-week,
# direct Node.js invocation (no OpenClaw gateway), crash alerting, zombie cleanup.
#
# Exit codes:
#   0 = success (test ran, even if bugs found — reporting handled by Phase 4)
#   1 = runner crashed (infrastructure alert sent)

set -euo pipefail

# ── Constants ────────────────────────────────────────────────────────────────

LOCK_FILE=/opt/lobsec/logs/examy/run-examy-test.lock
LOG_PREFIX="[examy-runner]"
NODE_BIN=/usr/bin/node
EXAMY_TOOL=/opt/lobsec/plugins/lobsec-tools/dist/examy.js
EMAIL_TOOL=/opt/lobsec/plugins/lobsec-tools/dist/email.js
RESULT_DIR=/opt/lobsec/logs/examy
RECIPIENTS_CONFIG=/opt/lobsec/config/examy-report-recipients.json

# ── Lockfile (non-blocking flock pattern from audit-sign-batch.sh) ───────────

exec 200>"$LOCK_FILE"
if ! flock -n 200; then
  echo "$LOG_PREFIX Previous run still active, skipping" >&2
  exit 0
fi

# ── Cleanup trap ─────────────────────────────────────────────────────────────

cleanup() {
  echo "$LOG_PREFIX Cleaning up zombie processes" >&2
  pkill -u lobsec chrome-headless-shell 2>/dev/null || true
  echo "$LOG_PREFIX Cleanup complete" >&2
}
trap cleanup EXIT

# ── Environment sourcing ─────────────────────────────────────────────────────

# Source HSM-extracted credentials (EXAMY_USERNAME, EXAMY_PASSWORD, GMAIL_APP_PASSWORD, etc.)
# Use `set -a` to auto-export all variables for child processes (Node.js subprocess)
if [ -f /opt/lobsec/.openclaw/.env ]; then
  # shellcheck disable=SC1091
  set -a
  source /opt/lobsec/.openclaw/.env
  set +a
  echo "$LOG_PREFIX Sourced /opt/lobsec/.openclaw/.env" >&2
fi

# Source fallback env if it exists
if [ -f /opt/lobsec/.env ]; then
  # shellcheck disable=SC1091
  set -a
  source /opt/lobsec/.env
  set +a
  echo "$LOG_PREFIX Sourced /opt/lobsec/.env" >&2
fi

# ── Persona rotation (day-of-week modulo 3) ──────────────────────────────────

# date +%u returns 1-7 (Mon-Sun)
DAY_OF_WEEK=$(date +%u)
PERSONA_INDEX=$(( (DAY_OF_WEEK - 1) % 3 ))

case $PERSONA_INDEX in
  0) PERSONA_FILTER="grade4" ;;
  1) PERSONA_FILTER="grade8" ;;
  2) PERSONA_FILTER="grade11" ;;
  *)
    echo "$LOG_PREFIX ERROR: Invalid persona index $PERSONA_INDEX" >&2
    exit 1
    ;;
esac

echo "$LOG_PREFIX Day-of-week: $DAY_OF_WEEK, persona: $PERSONA_FILTER" >&2

# ── Prepare result path ──────────────────────────────────────────────────────

mkdir -p "$RESULT_DIR"
RESULT_PATH="$RESULT_DIR/result-$(date +%Y%m%d-%H%M%S).json"
echo "$LOG_PREFIX Result path: $RESULT_PATH" >&2

# ── Test execution (direct Node.js ESM invocation, NO OpenClaw gateway) ──────

echo "$LOG_PREFIX Starting test (persona=$PERSONA_FILTER) at $(date -Iseconds)" >&2

EXIT_CODE=0
$NODE_BIN --input-type=module -e "
import { runExamyTest } from '$EXAMY_TOOL';
try {
  await runExamyTest('$PERSONA_FILTER', '$RESULT_PATH', false);
  process.exit(0);
} catch (err) {
  console.error('[examy-runner] Test runner crashed:', err.message);
  console.error(err.stack || '');
  process.exit(1);
}
" || EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
  echo "$LOG_PREFIX Test runner crashed with exit code $EXIT_CODE" >&2

  # ── Crash alert (infrastructure failure, NOT test failure) ────────────────

  # Extract first recipient from config (fallback to admin@localhost)
  RECIPIENT=$(cat "$RECIPIENTS_CONFIG" 2>/dev/null | $NODE_BIN -e "
    let data = '';
    process.stdin.on('data', chunk => data += chunk);
    process.stdin.on('end', () => {
      try {
        const recipients = JSON.parse(data);
        console.log(recipients[0] || 'admin@localhost');
      } catch (err) {
        console.log('admin@localhost');
      }
    });
  " || echo "admin@localhost")

  # Send crash alert email
  echo "$LOG_PREFIX Sending crash alert to $RECIPIENT" >&2
  $NODE_BIN --input-type=module -e "
  import { sendEmail } from '$EMAIL_TOOL';
  const to = '$RECIPIENT';
  const subject = '[lobsec] Examy runner crashed';
  const body = \`The Examy QA test runner crashed with exit code $EXIT_CODE on $(date -Iseconds).

Persona: $PERSONA_FILTER
Result path: $RESULT_PATH

Check logs:
  journalctl -u lobsec-examy-test -n 50

This is an infrastructure alert. Test failures are reported separately by the testing framework.\`;

  try {
    await sendEmail(
      { to, subject, body },
      {
        user: '${GMAIL_USER}',
        appPassword: '${GMAIL_APP_PASSWORD}'
      }
    );
    console.error('[examy-runner] Crash alert sent to ' + to);
  } catch (err) {
    console.error('[examy-runner] Failed to send crash alert:', err.message);
  }
  " || echo "$LOG_PREFIX Failed to send crash alert email" >&2

  # Exit with original error code
  exit $EXIT_CODE
fi

echo "$LOG_PREFIX Test completed successfully at $(date -Iseconds)" >&2
exit 0
