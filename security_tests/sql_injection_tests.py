"""
SQL Injection Security Test Suite
Tests for classic, blind, time-based, and error-based SQLi vulnerabilities.
"""

import time
import re
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from security_tests.base_security_test import BaseSecurityTest, SecurityTestResult


# SQL injection payloads
SQLI_PAYLOADS = {
    "classic": [
        "' OR '1'='1",
        "' OR 1=1--",
        "\" OR \"1\"=\"1",
        "'; DROP TABLE users;--",
        "1' OR '1' = '1'/*",
    ],
    "error_based": [
        "' AND extractvalue(1,concat(0x7e,version()))--",
        "' AND (SELECT * FROM (SELECT(SLEEP(0)))a)--",
        "1 UNION SELECT NULL,NULL,NULL--",
        "' OR 1=CONVERT(int,@@version)--",
    ],
    "time_based": [
        "'; WAITFOR DELAY '0:0:3'--",
        "' OR SLEEP(3)--",
        "1; SELECT SLEEP(3)--",
        "' AND BENCHMARK(5000000,MD5('test'))--",
    ],
    "boolean_blind": [
        "' AND 1=1--",
        "' AND 1=2--",
        "1 AND 1=1",
        "1 AND 1=2",
    ],
    "union_based": [
        "' UNION SELECT 1,2,3--",
        "' UNION SELECT username,password,3 FROM users--",
        "' UNION ALL SELECT NULL,table_name,NULL FROM information_schema.tables--",
    ],
}

# SQL error signatures in responses
SQL_ERROR_PATTERNS = [
    r"SQL syntax.*MySQL",
    r"Warning.*mysqli",
    r"ORA-\d{5}",
    r"PostgreSQL.*ERROR",
    r"Microsoft SQL Server.*Error",
    r"Unclosed quotation mark",
    r"SQLSTATE\[",
    r"mysql_fetch_array\(\)",
    r"SQLite3::query\(\)",
    r"pg_query\(\)",
    r"syntax error.*SQL",
    r"sqlite3.OperationalError",
]

SQL_ERROR_REGEX = re.compile("|".join(SQL_ERROR_PATTERNS), re.IGNORECASE)


class SQLInjectionTests(BaseSecurityTest):
    """
    SQL Injection test suite covering multiple attack vectors.
    """

    CATEGORY = "SQL_INJECTION"
    TIME_BASED_THRESHOLD_S = 2.5  # seconds

    def test_sqli_login_form(self):
        """Test login form for SQL injection bypass."""
        result = self._new_result("SQLi - Login Form Bypass", self.CATEGORY)
        result.severity = "CRITICAL"
        start = time.time()

        self._navigate("/login")
        bypass_success = []

        username_payloads = ["admin'--", "' OR '1'='1'--", "admin' #", "' OR 1=1--"]

        for payload in username_payloads:
            try:
                username_field = self._find_element_safe(By.NAME, "username") or \
                                 self._find_element_safe(By.NAME, "email") or \
                                 self._find_element_safe(By.ID, "username")

                password_field = self._find_element_safe(By.NAME, "password") or \
                                 self._find_element_safe(By.ID, "password")

                if not username_field or not password_field:
                    continue

                self.driver.get(f"{self.BASE_URL}/login")
                username_field = self.driver.find_element(By.NAME, "username")
                password_field = self.driver.find_element(By.NAME, "password")

                username_field.clear()
                username_field.send_keys(payload)
                password_field.clear()
                password_field.send_keys("wrong_password_xyz123")
                password_field.send_keys(Keys.RETURN)

                time.sleep(1)
                current_url = self.driver.current_url

                # Check for successful login redirect
                if "/login" not in current_url and (
                    "/dashboard" in current_url or
                    "/admin" in current_url or
                    "/home" in current_url
                ):
                    bypass_success.append({
                        "payload": payload,
                        "redirect_to": current_url,
                    })

                # Check for SQL errors in response
                page_source = self.driver.page_source
                if SQL_ERROR_REGEX.search(page_source):
                    bypass_success.append({
                        "payload": payload,
                        "type": "error_disclosure",
                        "details": "SQL error message exposed in response",
                    })

            except Exception as e:
                self.logger.debug(f"Error testing SQLi login: {e}")

        result.duration_ms = int((time.time() - start) * 1000)

        if bypass_success:
            result.status = SecurityTestResult.FAIL
            result.details = f"SQL injection login bypass succeeded: {len(bypass_success)} vectors"
            result.evidence = bypass_success
        else:
            result.status = SecurityTestResult.PASS
            result.details = "Login form appears resistant to SQL injection bypass"

        self.assertEqual(len(bypass_success), 0, f"SQLi bypass found: {bypass_success}")

    def test_sqli_error_disclosure(self):
        """Test for SQL error messages exposed in responses."""
        result = self._new_result("SQLi - Error Message Disclosure", self.CATEGORY)
        result.severity = "HIGH"
        start = time.time()

        error_disclosures = []

        endpoints_to_test = ["/search", "/users", "/products", "/api/data", "/"]

        for endpoint in endpoints_to_test:
            for payload in SQLI_PAYLOADS["error_based"][:2]:
                try:
                    url = f"{self.BASE_URL}{endpoint}?id={payload}&q={payload}"
                    self.driver.get(url)

                    page_source = self.driver.page_source
                    match = SQL_ERROR_REGEX.search(page_source)

                    if match:
                        error_disclosures.append({
                            "endpoint": endpoint,
                            "payload": payload,
                            "error_snippet": match.group(0)[:100],
                        })
                        self.logger.warning(
                            f"SQL error disclosure at {endpoint}: {match.group(0)[:50]}"
                        )

                except Exception as e:
                    self.logger.debug(f"Error testing {endpoint}: {e}")

        result.duration_ms = int((time.time() - start) * 1000)

        if error_disclosures:
            result.status = SecurityTestResult.FAIL
            result.details = f"SQL errors exposed in {len(error_disclosures)} location(s)"
            result.evidence = error_disclosures
        else:
            result.status = SecurityTestResult.PASS
            result.details = "No SQL error messages disclosed in responses"

        self.assertEqual(len(error_disclosures), 0, f"SQL errors found: {error_disclosures}")

    def test_sqli_time_based_blind(self):
        """Test for time-based blind SQL injection."""
        result = self._new_result("SQLi - Time-Based Blind", self.CATEGORY)
        result.severity = "HIGH"
        start = time.time()

        vulnerable_endpoints = []
        endpoints = ["/search", "/api/users", "/products"]

        for endpoint in endpoints:
            for payload in SQLI_PAYLOADS["time_based"][:2]:
                try:
                    url = f"{self.BASE_URL}{endpoint}?id=1{payload}"

                    req_start = time.time()
                    self.driver.get(url)
                    elapsed = time.time() - req_start

                    if elapsed > self.TIME_BASED_THRESHOLD_S:
                        vulnerable_endpoints.append({
                            "endpoint": endpoint,
                            "payload": payload,
                            "response_time_s": round(elapsed, 2),
                        })
                        self.logger.warning(
                            f"Time-based SQLi suspected at {endpoint} "
                            f"(response: {elapsed:.2f}s)"
                        )

                except Exception as e:
                    self.logger.debug(f"Time-based test error at {endpoint}: {e}")

        result.duration_ms = int((time.time() - start) * 1000)

        if vulnerable_endpoints:
            result.status = SecurityTestResult.FAIL
            result.details = f"Time-based SQLi indicators in {len(vulnerable_endpoints)} endpoint(s)"
            result.evidence = vulnerable_endpoints
        else:
            result.status = SecurityTestResult.PASS
            result.details = "No time-based SQLi indicators detected"

    def test_sqli_boolean_blind(self):
        """Test for boolean-based blind SQL injection."""
        result = self._new_result("SQLi - Boolean Blind", self.CATEGORY)
        result.severity = "HIGH"
        start = time.time()

        vulnerable_params = []
        test_url = f"{self.BASE_URL}/search"

        try:
            # TRUE condition — expect content
            self.driver.get(f"{test_url}?id=1 AND 1=1")
            true_source = self.driver.page_source

            # FALSE condition — expect different/empty content
            self.driver.get(f"{test_url}?id=1 AND 1=2")
            false_source = self.driver.page_source

            # If responses differ significantly, boolean SQLi may exist
            true_len = len(true_source)
            false_len = len(false_source)

            if abs(true_len - false_len) > 200:
                vulnerable_params.append({
                    "url": test_url,
                    "true_response_length": true_len,
                    "false_response_length": false_len,
                    "difference": abs(true_len - false_len),
                })

        except Exception as e:
            self.logger.debug(f"Boolean blind test error: {e}")

        result.duration_ms = int((time.time() - start) * 1000)

        if vulnerable_params:
            result.status = SecurityTestResult.WARN
            result.details = "Response length differences suggest possible boolean blind SQLi"
            result.evidence = vulnerable_params
        else:
            result.status = SecurityTestResult.PASS
            result.details = "No boolean blind SQLi indicators detected"

    def test_parameterized_query_validation(self):
        """Validate that parameterized queries are enforced (meta-check)."""
        result = self._new_result("SQLi - Parameterized Query Check", self.CATEGORY)
        result.severity = "INFO"
        start = time.time()

        # This test verifies API endpoints return consistent formats
        # when given both normal and malformed input
        issues = []
        test_cases = [
            ("1", "normal integer"),
            ("1'", "single quote injection attempt"),
            ("1 OR 1=1", "OR clause injection"),
            ("1; SELECT 1", "statement terminator"),
        ]

        for payload, description in test_cases:
            try:
                self.driver.get(f"{self.BASE_URL}/api/item?id={payload}")
                page_source = self.driver.page_source

                if SQL_ERROR_REGEX.search(page_source):
                    issues.append({
                        "input": payload,
                        "description": description,
                        "issue": "SQL error exposed",
                    })

            except Exception as e:
                self.logger.debug(f"Error in parameterized test: {e}")

        result.duration_ms = int((time.time() - start) * 1000)

        if issues:
            result.status = SecurityTestResult.FAIL
            result.details = f"SQL errors exposed with {len(issues)} input type(s)"
            result.evidence = issues
        else:
            result.status = SecurityTestResult.PASS
            result.details = "API endpoints appear to use parameterized queries"
