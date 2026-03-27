# 🔒 Security Test Integration Framework

> **Automated security testing framework** that detects common web vulnerabilities using Selenium browser automation and pytest. Integrates with CI/CD pipelines (GitHub Actions, Jenkins) to catch security issues before production.

![Status](https://img.shields.io/badge/status-active-success) ![Python](https://img.shields.io/badge/Python-3.10+-blue) ![License](https://img.shields.io/badge/License-MIT-green)

---

## 📋 Table of Contents

- [Overview](#overview)
- [What It Does](#what-it-does)
- [How It Works](#how-it-works)
- [Features](#features)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Usage](#usage)
- [CI/CD Integration](#cicd-integration)
- [Test Suites](#test-suites)
- [Reports](#reports)
- [Troubleshooting](#troubleshooting)

---

## 🎯 Overview

This framework automates detection of **20+ security vulnerabilities** across OWASP Top 10 categories by:

1. **Launching a test application** (DVWA - Damn Vulnerable Web Application) in Docker
2. **Automating browser interactions** using Selenium to test attack scenarios
3. **Analyzing responses** for security flaws (injection, XSS, CSRF, authentication issues)
4. **Generating detailed reports** with severity ratings and evidence
5. **Integrating with CI/CD** to block deployments with critical findings

---

## 🔍 What It Does

### Test Coverage

| Category | Tests | Key Scenarios | Severity |
|----------|-------|---------------|----------|
| **🔐 Authentication** | 5 | Brute force, session hijacking, account enumeration | HIGH |
| **💉 SQL Injection** | 5 | Login bypass, blind injection, error disclosure | **CRITICAL** |
| **⚠️ XSS (Cross-Site Scripting)** | 5 | Reflected, DOM-based, header injection | HIGH |
| **🛡️ CSRF & Security Headers** | 5 | CSRF token validation, missing headers, clickjacking | MEDIUM |

**Total: 20 automated security tests** covering real-world attack vectors

### Example Vulnerabilities Detected
- SQL injection in login forms
- Reflected XSS in search/filters
- Missing security headers (CSP, HSTS, X-Frame-Options)
- CSRF token bypass or absence
- Weak brute force protection
- Session fixation attacks
- Account enumeration via timing attacks

---

## 🔧 How It Works

### Architecture

```
┌─────────────────────────────────────────────────────┐
│        Your CI/CD Pipeline (GitHub/Jenkins)         │
└────────────────────┬────────────────────────────────┘
                     │
        ┌────────────▼──────────────┐
        │  1. Start Docker Services │
        │  - DVWA Web App           │
        │  - MariaDB Database       │
        └────────────┬──────────────┘
                     │
        ┌────────────▼──────────────────────────┐
        │  2. Run Automated Security Tests      │
        │  - Selenium browser automation        │
        │  - Attack payload injection           │
        │  - Response analysis                  │
        └────────────┬──────────────────────────┘
                     │
        ┌────────────▼──────────────────────────┐
        │  3. Generate Reports                  │
        │  - HTML report for humans             │
        │  - JSON for integrations              │
        │  - JUnit XML for CI tools             │
        └────────────┬──────────────────────────┘
                     │
        ┌────────────▼──────────────────────────┐
        │  4. Decision: Block or Approve        │
        │  - CRITICAL/HIGH findings → Block     │
        │  - MEDIUM/LOW findings → Warn         │
        └─────────────────────────────────────────┘
```

### Test Execution Flow

**For Each Test:**
1. Navigate to target URL
2. Inject attack payload (XSS string, SQL injection, etc.)
3. Capture server response and DOM state
4. Analyze for vulnerability indicators
5. Record result (PASS/FAIL/WARN) with severity and evidence

**Result:** Detailed security audit with actionable findings

---

## ✨ Features

- ✅ **20+ automated security tests** across OWASP Top 10
- ✅ **Multiple report formats** (HTML, JSON, JUnit XML, CLI)
- ✅ **Docker-based testing environment** - no manual setup
- ✅ **GitHub Actions workflows** - automatic on push/PR
- ✅ **Jenkins integration** - enterprise-ready pipeline
- ✅ **Headless browser support** - runs in CI without display
- ✅ **Detailed evidence collection** - screenshots, logs, payloads
- ✅ **Severity-based blocking** - configurable thresholds
- ✅ **Slack/Teams notifications** - security alerts to teams
- ✅ **Artifact storage** - 30-90 day retention for audits

---

## 📁 Project Structure

```
security-test-framework/
├── 📄 README.md                        # This file
├── 📄 Jenkinsfile                      # Jenkins declarative pipeline
├── 📄 run_tests.sh                     # Local test runner script
├── 📄 pytest.ini                       # Pytest configuration
├── 📄 requirements.txt                 # Python dependencies
├── 📄 docker-compose.yml               # Test app (DVWA) setup
│
├── 📁 .github/
│   ├── workflows/
│   │   ├── docker-compose-tests.yml    # GitHub Actions CI (PRs/Push)
│   │   └── scheduled-tests.yml         # Daily scheduled security scan
│   └── WORKFLOWS.md                    # Workflow documentation
│
├── 📁 config/
│   └── security_config.yaml            # Test configuration & thresholds
│
├── 📁 security_tests/              [20 tests total]
│   ├── base_security_test.py           # Base class, WebDriver, utils
│   ├── auth_tests.py                   # 5 authentication tests
│   ├── sql_injection_tests.py          # 5 SQL injection tests
│   ├── xss_tests.py                    # 5 XSS tests
│   └── csrf_and_headers_tests.py       # 5 CSRF & header tests
│
├── 📁 scripts/
│   ├── generate_report.py              # HTML report generator
│   └── evaluate_thresholds.py          # Severity threshold evaluator
│
└── 📁 reports/                     [Generated after runs]
    ├── pytest_report.html              # Interactive test results
    ├── pytest_report.json              # Machine-readable results
    ├── junit_results.xml               # CI integration format
    ├── security_results.json           # Detailed findings
    └── security_report.html            # Executive summary
```

---

## Installation

### Prerequisites

- **Python:** 3.10 or higher
- **Docker & Docker Compose:** For running DVWA
- **Google Chrome:** Version matching ChromeDriver
- **Git:** For version control

### Step 1: Clone Repository

```bash
git clone <repository-url>
cd security-test-framework
```

### Step 2: Create Virtual Environment

```bash
python3 -m venv .venv
source .venv/bin/activate           # On Linux/Mac
# or
.venv\Scripts\activate              # On Windows
```

### Step 3: Install Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

**Installed packages:**
- `selenium` - Browser automation
- `pytest` - Test framework
- `pytest-html` - HTML reports
- `pytest-json-report` - JSON reports
- `requests` - HTTP testing
- `pyyaml` - Configuration files

### Step 4: Install Chrome & ChromeDriver

**On Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install -y chromium-browser chromium-chromedriver
```

**On macOS:**
```bash
brew install chromium chromedriver
```

**On Windows:**
1. Download from [ChromeDriver](https://chromedriver.chromium.org)
2. Add to PATH

---

## 🚀 Usage

### Option 1: Local Usage (Quick Testing)

**Start the test application:**
```bash
docker compose up -d
# Wait ~15 seconds for database initialization
open http://localhost:8080
# Login: admin / password
# Click "Create/Reset Database" (one-time setup)
```

**Run all tests:**
```bash
bash run_tests.sh all
```

**Run with a specific browser:**
```bash
BROWSER="chrome" bash run_tests.sh all
BROWSER="firefox" bash run_tests.sh all
BROWSER="edge" bash run_tests.sh all
```

**Run specific test suite:**
```bash
bash run_tests.sh xss              # XSS tests only
bash run_tests.sh sqli             # SQL injection tests
bash run_tests.sh auth             # Authentication tests
bash run_tests.sh csrf_headers      # CSRF & headers tests
```

**Custom target URL:**
```bash
TARGET_URL="http://production.example.com" bash run_tests.sh all
```

**View results:**
```bash
# HTML report (open in browser)
open reports/pytest_report.html

# JSON results
cat reports/security_results.json

# Console output
cat reports/pytest_report.txt
```

**Stop containers:**
```bash
docker compose down -v
```

---

### Option 2: GitHub Actions (Automated CI/CD)

Workflows automatically trigger on:
- ✅ Push to `main`, `develop`, or `feature/*` branches
- ✅ Pull requests to `main` or `develop`
- ✅ Daily at 2 AM UTC (scheduled) for regression testing

**View workflow runs:**
1. Go to repo → **Actions** tab
2. Click workflow run
3. View logs and download reports

**Reports automatically:**
- Upload to GitHub artifacts (30-90 day retention)
- Comment on PRs with results
- Block PRs on critical findings (if configured)

---

### Option 3: Jenkins Pipeline

**Trigger a build:**
```bash
# Via Jenkins UI with parameters:
# - TARGET_URL: http://your-app.com
# - TEST_SUITE: all, xss, sqli, auth, csrf_headers
# - FAIL_ON_WARNINGS: true/false
```

**Jenkins automatically:**
- Runs in Docker container
- Generates JUnit reports
- Posts to Slack/Teams
- Blocks deployment on critical findings

---

## 📊 Test Suites

### 🔐 Authentication Tests (5 tests)

**File:** [security_tests/auth_tests.py](security_tests/auth_tests.py)

| Test | What It Checks | How It Works |
|------|---|---|
| **Brute Force Protection** | Rate limiting after failed logins | Attempts 10 rapid logins, checks for lockout/captcha |
| **Session Cookie Security** | HTTPOnly, Secure, SameSite flags | Inspects Set-Cookie headers |
| **Session Fixation** | Pre-login session ID changes | Compares session before/after login |
| **Account Enumeration** | Timing-based user detection | Measures response time for valid/invalid users |
| **Password Policy** | Requirements enforcement | Tests weak passwords vs policy |

---

### 💉 SQL Injection Tests (5 tests)

**File:** [security_tests/sql_injection_tests.py](security_tests/sql_injection_tests.py)

| Test | What It Checks | Attack Vector |
|------|---|---|
| **Login Form SQLi** | Bypass with `' OR '1'='1` | Authentication bypass |
| **Error Disclosure** | Database error messages | Information leakage |
| **Time-Based Blind** | Delays from conditional queries | Stalled responses |
| **Boolean-Based Blind** | True/false responses | Content analysis |
| **Parameterized Queries** | Prepared statements validation | Injected payloads ignored |

---

### ⚠️ XSS Tests (5 tests)

**File:** [security_tests/xss_tests.py](security_tests/xss_tests.py)

| Test | What It Checks | Payload Type |
|------|---|---|
| **Reflected XSS (Query Params)** | Unescaped URL parameters | `?search=<img src=x onerror=alert(1)>` |
| **Reflected XSS (Form Input)** | Unescaped form fields | Same payload in POST data |
| **DOM XSS** | JavaScript source manipulation | `location.hash` processing |
| **CSP Headers** | Content Security Policy presence | `Content-Security-Policy` header check |
| **HTTP Header XSS** | Response header injection | `X-Custom-Header: <script>` |

---

### 🛡️ CSRF & Security Headers (5 tests)

**File:** [security_tests/csrf_and_headers_tests.py](security_tests/csrf_and_headers_tests.py)

| Test | What It Checks | Security Aspect |
|------|---|---|
| **CSRF Token Presence** | Forms include token | Form-based request protection |
| **CSRF Token Validation** | Token verification | Reusing/missing tokens rejected |
| **Security Headers** | Missing security headers | Health check for HSTS, X-Frame-Options, etc |
| **Clickjacking Protection** | X-Frame-Options header | Iframe embedding prevention |
| **CORS Configuration** | Cross-Origin policies | Overly permissive CORS |

---

## 📄 Reports

After running tests, four report formats are generated in `reports/`:

### 1. **HTML Report** (`pytest_report.html`)
Interactive browser-friendly report with:
- Test names and results (✅ PASS / ❌ FAIL / ⚠️ WARN)
- Execution times
- Stacktraces for failures
- Expandable test details

**Open in browser:**
```bash
open reports/pytest_report.html
```

### 2. **Security Report** (`security_report.html`)
Executive summary with:
- Test statistics (passed/failed/skipped)
- Severity breakdown (Critical/High/Medium/Low)
- Vulnerability descriptions
- Remediation guidance

### 3. **JSON Results** (`security_results.json`)
Machine-readable findings for automation:
```json
{
  "results": [
    {
      "test_name": "Brute Force Protection",
      "status": "FAIL",
      "severity": "HIGH",
      "details": "No account lockout after 10 failed attempts",
      "evidence": ["attempt_count: 10", "no_lockout_detected"]
    }
  ],
  "summary": {"passed": 15, "failed": 5, "warnings": 0}
}
```

### 4. **JUnit XML** (`junit_results.xml`)
CI/CD integration format for:
- GitHub Actions
- Jenkins
- GitLab CI
- Azure Pipelines

---

## 🔄 CI/CD Integration

### GitHub Actions (Included)

Two workflows provided in [.github/workflows/](.github/workflows):

**1. Pull Request Tests** (`docker-compose-tests.yml`)
- Runs on every push to `main/develop/feature/*`
- Runs on PRs to `main/develop`
- Reports: 30-day retention
- Blocks PRs on critical findings (optional)

**2. Scheduled Tests** (`scheduled-tests.yml`)
- Daily regression test (2 AM UTC)
- Manual trigger available
- Reports: 90-day retention

See [.github/WORKFLOWS.md](.github/WORKFLOWS.md) for detailed setup.

### Jenkins (Included)

**Jenkinsfile** provides:
- Docker agent (Python 3.12 + Chrome)
- Parameterized builds
- HTML reports
- Slack notifications
- Threshold-based blocking

Usage:
```groovy
// Configure in Jenkins UI
parameters:
  TARGET_URL = "http://your-app.com"
  TEST_SUITE = "all"
  FAIL_ON_WARNINGS = false
```

---

## 🎛️ Configuration

Edit [config/security_config.yaml](config/security_config.yaml) to customize:

```yaml
target:
  base_url: "http://localhost:8080"
  timeout_seconds: 15
  
selenium:
  headless: true
  browser: "chrome"
  window_size: "1920x1080"

test_suites:
  xss:
    enabled: true
  sql_injection:
    enabled: true
  authentication:
    enabled: true
  csrf_headers:
    enabled: true
```

### Environment Variables

```bash
# Override test target
export TARGET_URL="https://your-app.com"

# Run in GUI mode (not headless)
export HEADLESS="false"

# Choose browser: chrome, chromium, firefox, edge
export BROWSER="firefox"

# Custom timeouts
export SELENIUM_TIMEOUT="20"

# Custom paths for browser binaries/drivers
export CHROME_BIN="/usr/bin/chromium-browser"
export CHROMEDRIVER="/usr/bin/chromedriver"
export FIREFOX_BIN="/usr/bin/firefox"
export GECKODRIVER="/usr/bin/geckodriver"
export EDGE_BIN="/usr/bin/microsoft-edge"
export EDGEDRIVER="/usr/bin/msedgedriver"
```

---

## 📈 Understanding Results

### Status Indicators

| Status | Meaning | Action |
|--------|---------|--------|
| ✅ **PASS** | Test ran, vulnerability NOT found | Security control is working |
| ❌ **FAIL** | Test ran, vulnerability FOUND | Requires remediation |
| ⚠️ **WARN** | Suspicious behavior detected | Review and investigate |
| ⏭️ **SKIP** | Test couldn't run (missing element) | Application may differ from expected |

### Severity Levels

| Level | Priority | Examples |
|-------|----------|----------|
| 🔴 **CRITICAL** | Fix immediately | SQL injection, Authentication bypass |
| 🟠 **HIGH** | Fix this sprint | XSS, Brute force |
| 🟡 **MEDIUM** | Fix soon | Missing headers, CSRF |
| 🟢 **LOW** | Monitor | Info disclosure, Weak policy |

---

## 🐛 Troubleshooting

### Chrome/ChromeDriver Issues

**Problem:** `ChromeDriver not found`
```bash
# Solution: Install Chrome
sudo apt-get install chromium-browser chromium-chromedriver

# Or specify path
export CHROME_BIN="/usr/bin/chromium"
export CHROMEDRIVER="/usr/bin/chromedriver"
```

### Docker Issues

**Problem:** `Cannot connect to DVWA`
```bash
# Verify containers running
docker compose ps

# Check logs
docker compose logs dvwa

# Restart containers
docker compose restart
```

### Tests Timeout

**Problem:** `Page load timeout after 10s`
```bash
# Increase timeout
export SELENIUM_TIMEOUT="20"

# Or in docker-compose.yml
environment:
  SELENIUM_TIMEOUT: 20
```

### Port Conflicts

**Problem:** `Port 8080 already in use`
```bash
# Find what's using it
lsof -i :8080

# Use different port
docker compose -e "DVWA_PORT=8081" up

# Update TARGET_URL
export TARGET_URL="http://localhost:8081"
```

---

## 📚 Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [DVWA Documentation](https://github.com/digininja/DVWA)
- [Selenium Documentation](https://www.selenium.dev/documentation/)
- [Pytest Documentation](https://docs.pytest.org/)

---

## 📝 License

MIT License - See LICENSE file for details

---

## 🤝 Contributing

Contributions welcome! Areas to expand:
- Additional test cases
- Support for API security testing
- Performance testing integration
- Container scanning
- Third-party vulnerability scanning

---

## ✅ Quick Reference

| Task | Command |
|------|---------|
| Setup | `python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt` |
| Start test app | `docker compose up -d` |
| Run all tests | `bash run_tests.sh all` |
| View HTML report | `open reports/pytest_report.html` |
| View JSON results | `cat reports/security_results.json` |
| Stop containers | `docker compose down -v` |
| Run in GitHub Actions | Push/create PR to trigger workflows |

---

**Questions?** Check [.github/WORKFLOWS.md](.github/WORKFLOWS.md) for GitHub Actions help or open an issue!

### Local Run

```bash
# Clone and set up
git clone <repo>
cd security-test-framework

# Run all suites against a target
TARGET_URL=https://your-app.com bash run_tests.sh all

# Run only XSS tests
TARGET_URL=https://your-app.com bash run_tests.sh xss

# Run only SQL injection tests
TARGET_URL=https://your-app.com bash run_tests.sh sqli
```

### Jenkins Setup

1. **Create Pipeline job** in Jenkins
2. Set **Pipeline script from SCM** → point to your repo
3. Jenkins reads `Jenkinsfile` automatically
4. Configure parameters:
   - `TARGET_URL` — application to test
   - `TEST_SUITE` — `all | xss | sqli | auth | csrf_headers`
   - `HEADLESS` — `true` (recommended for CI)
   - `FAIL_ON_WARNINGS` — whether WARNs fail the build

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `TARGET_URL` | `http://localhost:8080` | Base URL of the target application |
| `HEADLESS` | `true` | Run Chrome headless |
| `SELENIUM_TIMEOUT` | `10` | WebDriver timeout in seconds |
| `TEST_USER_PASSWORD` | `TestPassword123!` | Password for test account |

---

## Jenkins Pipeline Stages

```
Setup Environment → Pre-Flight Checks → XSS Tests → SQL Injection Tests
    → Auth Tests → CSRF & Headers Tests → Generate Report → Evaluate Thresholds
```

**Build Results:**
- ✅ `SUCCESS` — All tests pass, no vulnerabilities found
- ⚠️ `UNSTABLE` — Warnings or medium/low issues found
- ❌ `FAILURE` — Critical or High severity vulnerabilities detected

---

## Test Results

Each test produces a structured result:

```json
{
  "test_name": "Reflected XSS - Query Parameters",
  "category": "XSS",
  "status": "FAIL",
  "severity": "HIGH",
  "details": "Found 2 potential XSS vector(s)",
  "evidence": [{"param": "q", "payload": "<script>alert('XSS')</script>"}],
  "timestamp": "2025-01-01T00:00:00",
  "duration_ms": 1240
}
```

---

## Reports

After each run, the framework generates:

| File | Description |
|---|---|
| `reports/security_report.html` | Full dashboard with charts and evidence |
| `reports/security_results.json` | Machine-readable results |
| `reports/junit_results.xml` | JUnit XML for Jenkins test trending |
| `reports/security_test.log` | Detailed execution log |

---

## Extending the Framework

### Add a new test

```python
# security_tests/my_new_tests.py
from .base_security_test import BaseSecurityTest, SecurityTestResult

class MyNewTests(BaseSecurityTest):
    CATEGORY = "MY_CATEGORY"

    def test_something(self):
        result = self._new_result("My Test Name", self.CATEGORY)
        result.severity = "HIGH"
        
        # ... your test logic ...
        
        result.status = SecurityTestResult.PASS
        result.details = "All good"
```

### Add to Jenkins pipeline

Add a new stage in `Jenkinsfile`:

```groovy
stage('My New Tests') {
    steps {
        sh 'python -m pytest security_tests/my_new_tests.py -v ...'
    }
}
```

---

## Security Note

This framework is intended for use against **applications you own or have explicit written permission to test**. Never run against systems without authorization.
