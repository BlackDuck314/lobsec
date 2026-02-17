#!/usr/bin/env bash
# lobsec deployment validation / smoke test
# Usage: bash deploy/validate.sh [--dir /etc/lobsec]
set -euo pipefail

DIR="${1:-/etc/lobsec}"
ERRORS=0

echo "=== lobsec deployment validation ==="

# 1. Check Node.js
echo -n "Node.js 22: "
if node --version 2>/dev/null | grep -q "v22"; then
  echo "OK ($(node --version))"
else
  echo "FAIL"
  ((ERRORS++))
fi

# 2. Check pnpm
echo -n "pnpm: "
if command -v pnpm &>/dev/null; then
  echo "OK ($(pnpm --version))"
else
  echo "FAIL"
  ((ERRORS++))
fi

# 3. Check SoftHSM2
echo -n "SoftHSM2: "
if softhsm2-util --show-slots 2>/dev/null | grep -q "lobsec"; then
  echo "OK"
else
  echo "FAIL (no lobsec token)"
  ((ERRORS++))
fi

# 4. Check Docker
echo -n "Docker: "
if docker info &>/dev/null; then
  echo "OK ($(docker --version | head -c 30))"
else
  echo "FAIL (not running)"
  ((ERRORS++))
fi

# 5. Check directory structure
echo -n "Directory structure: "
if [ -d "$DIR/config" ] && [ -d "$DIR/logs" ]; then
  echo "OK"
else
  echo "FAIL (missing directories)"
  ((ERRORS++))
fi

# 6. Check no public ports
echo -n "Public ports: "
PUBLIC_PORTS=$(ss -tlnp 2>/dev/null | grep "0.0.0.0\|:::" | grep -v "127.0.0.1\|::1" || true)
if [ -z "$PUBLIC_PORTS" ]; then
  echo "OK (none)"
else
  echo "WARNING (found public listeners)"
fi

# 7. Run tests
echo -n "Test suite: "
cd "$(dirname "$0")/.."
if pnpm test -- --run 2>/dev/null | tail -1 | grep -q "passed"; then
  TESTS=$(pnpm test -- --run 2>&1 | grep "Tests" | head -1)
  echo "OK ($TESTS)"
else
  echo "FAIL"
  ((ERRORS++))
fi

echo ""
if [ "$ERRORS" -eq 0 ]; then
  echo "=== Validation PASSED ==="
else
  echo "=== Validation FAILED ($ERRORS errors) ==="
  exit 1
fi
