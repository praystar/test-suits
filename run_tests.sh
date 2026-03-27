#!/usr/bin/env bash
# ============================================================
# Security Test Integration Framework -- Local Test Runner
# ============================================================
set -euo pipefail

# Resolve project root so script works from any directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Defaults
TARGET_URL="${TARGET_URL:-http://localhost:8080}"
TEST_SUITE="${1:-all}"
HEADLESS="${HEADLESS:-true}"
BROWSER="${BROWSER:-chrome}"
REPORT_DIR="reports"
VENV_DIR=".venv"

# Colors
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'

log()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC}  $*"; }
ok()   { echo -e "${GREEN}[PASS]${NC}  $*"; }
err()  { echo -e "${RED}[FAIL]${NC}  $*"; }

echo -e "${BOLD}"
cat << 'EOF'
 +---------------------------------------------------+
 |    Security Test Integration Framework            |
 |    Selenium + Jenkins Security Testing Suite      |
 +---------------------------------------------------+
EOF
echo -e "${NC}"

log "Target URL : ${TARGET_URL}"
log "Test Suite : ${TEST_SUITE}"
log "Headless   : ${HEADLESS}"
log "Browser    : ${BROWSER}"

# Setup virtual environment
if [ ! -d "$VENV_DIR" ]; then
    log "Creating virtual environment..."
    python3 -m venv "$VENV_DIR"
fi

source "$VENV_DIR/bin/activate"

log "Installing dependencies..."
pip install --upgrade pip -q
pip install -r requirements.txt
echo ""

# Verify critical imports
log "Verifying imports..."
python3 -c "import selenium; print('  selenium', selenium.__version__)" \
    || { err "selenium import failed"; exit 1; }
python3 -c "import pytest; print('  pytest', pytest.__version__)" \
    || { err "pytest import failed"; exit 1; }
python3 -c "import requests; print('  requests', requests.__version__)" \
    || { err "requests import failed"; exit 1; }
echo ""

# Prepare report directory
mkdir -p "$REPORT_DIR"
rm -f "$REPORT_DIR/security_results.json"

# Determine test targets
case "$TEST_SUITE" in
    xss)          TEST_PATHS="security_tests/xss_tests.py" ;;
    sqli)         TEST_PATHS="security_tests/sql_injection_tests.py" ;;
    auth)         TEST_PATHS="security_tests/auth_tests.py" ;;
    csrf_headers) TEST_PATHS="security_tests/csrf_and_headers_tests.py" ;;
    all|*)        TEST_PATHS="security_tests/" ;;
esac

export TARGET_URL HEADLESS BROWSER

# Dry-run collection to surface import errors
log "Collecting tests..."
python3 -m pytest $TEST_PATHS --collect-only -q --import-mode=importlib 2>&1
echo ""

# Run tests
log "Running security tests: $TEST_PATHS"
echo ""

python3 -m pytest \
    $TEST_PATHS \
    -v \
    --tb=long \
    --import-mode=importlib \
    --junit-xml="$REPORT_DIR/junit_results.xml" \
    --html="$REPORT_DIR/pytest_report.html" \
    --self-contained-html \
    --no-header \
    || true

# Generate HTML report
echo ""
log "Generating security report..."

if [ -f "$REPORT_DIR/security_results.json" ]; then
    python3 scripts/generate_report.py \
        --results "$REPORT_DIR/security_results.json" \
        --output "$REPORT_DIR/security_report.html" \
        --build-url "file://$(pwd)/$REPORT_DIR/security_report.html" \
        --build-number "local-$(date +%Y%m%d-%H%M%S)" \
        --target-url "$TARGET_URL"
else
    warn "No results file found -- check collection output above for import errors."
    exit 1
fi

# Evaluate thresholds
echo ""
log "Evaluating security thresholds..."

python3 scripts/evaluate_thresholds.py \
    --results "$REPORT_DIR/security_results.json" \
    --fail-on-critical true \
    --fail-on-high true \
    --fail-on-warnings false
EXIT_CODE=$?

echo ""
log "Report: $REPORT_DIR/security_report.html"

if [ $EXIT_CODE -eq 0 ]; then
    ok "All security checks passed!"
elif [ $EXIT_CODE -eq 2 ]; then
    warn "Security warnings found -- review report"
else
    err "Security vulnerabilities found -- build failed"
fi

exit $EXIT_CODE
