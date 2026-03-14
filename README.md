# Security Test Integration Framework

Automated security testing integrated directly into CI/CD pipelines using **Selenium** for browser-based testing and **Jenkins** for pipeline orchestration.

---

## What It Tests

| Suite | Tests | Severity |
|---|---|---|
| **XSS** | Reflected, DOM-based, CSP headers, HTTP header injection | HIGH |
| **SQL Injection** | Login bypass, error disclosure, time-based blind, boolean blind | CRITICAL |
| **Authentication** | Brute force protection, session cookies, session fixation, enumeration, password policy | HIGH |
| **CSRF & Headers** | CSRF tokens, security headers, clickjacking, CORS | MEDIUM–HIGH |

---

## Project Structure

```
security-test-framework/
├── Jenkinsfile                         # Jenkins declarative pipeline
├── requirements.txt                    # Python dependencies
├── run_tests.sh                        # Local test runner
├── config/
│   └── security_config.yaml           # All configuration
├── security_tests/
│   ├── __init__.py
│   ├── base_security_test.py          # Base class, WebDriver setup, result model
│   ├── xss_tests.py                   # XSS test suite (5 tests)
│   ├── sql_injection_tests.py         # SQL injection suite (5 tests)
│   ├── auth_tests.py                  # Authentication suite (5 tests)
│   └── csrf_and_headers_tests.py      # CSRF & headers suite (5 tests)
├── scripts/
│   ├── generate_report.py             # HTML report generator
│   └── evaluate_thresholds.py         # Threshold evaluator (Jenkins exit codes)
└── reports/                           # Generated reports (gitignored)
```

---

## Quick Start

### Prerequisites
- Python 3.10+
- Google Chrome + ChromeDriver (matching versions)
- Jenkins (for pipeline)

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
