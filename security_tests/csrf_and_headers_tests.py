"""
CSRF & Security Headers Test Suite
Tests for CSRF token validation, clickjacking, and security response headers.
"""

import time
import re
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from security_tests.base_security_test import BaseSecurityTest, SecurityTestResult


REQUIRED_SECURITY_HEADERS = {
    "X-Content-Type-Options": {
        "expected": "nosniff",
        "severity": "MEDIUM",
        "description": "Prevents MIME-type sniffing attacks",
    },
    "X-Frame-Options": {
        "expected": ["DENY", "SAMEORIGIN"],
        "severity": "MEDIUM",
        "description": "Prevents clickjacking attacks",
    },
    "Strict-Transport-Security": {
        "expected": "max-age",
        "severity": "HIGH",
        "description": "Enforces HTTPS (HSTS)",
    },
    "X-XSS-Protection": {
        "expected": ["1; mode=block", "0"],
        "severity": "LOW",
        "description": "Legacy XSS filter header",
    },
    "Referrer-Policy": {
        "expected": ["no-referrer", "strict-origin", "same-origin"],
        "severity": "LOW",
        "description": "Controls referrer information",
    },
    "Permissions-Policy": {
        "expected": None,  # Just check existence
        "severity": "LOW",
        "description": "Controls browser features/permissions",
    },
}


class CSRFAndHeadersTests(BaseSecurityTest):
    """
    CSRF protection and security response headers test suite.
    """

    CATEGORY = "CSRF_AND_HEADERS"

    def test_csrf_token_presence(self):
        """Verify CSRF tokens are present in forms."""
        result = self._new_result("CSRF Token Presence", self.CATEGORY)
        result.severity = "HIGH"
        start = time.time()

        self._navigate("/")
        forms_without_csrf = []

        # Find all forms on the page
        forms = self.driver.find_elements(By.TAG_NAME, "form")

        for idx, form in enumerate(forms):
            method = (form.get_attribute("method") or "get").upper()

            if method != "POST":
                continue

            # Look for CSRF token inputs
            csrf_found = False
            csrf_names = [
                "csrf", "csrf_token", "_token", "authenticity_token",
                "csrfmiddlewaretoken", "_csrf", "xsrf_token"
            ]

            inputs = form.find_elements(By.TAG_NAME, "input")
            for inp in inputs:
                inp_name = (inp.get_attribute("name") or "").lower()
                inp_type = (inp.get_attribute("type") or "").lower()

                if any(csrf_name in inp_name for csrf_name in csrf_names):
                    csrf_found = True
                    break

                if inp_type == "hidden" and inp.get_attribute("value"):
                    # Could be an unnamed CSRF token — check value entropy
                    value = inp.get_attribute("value")
                    if len(value) >= 20:
                        csrf_found = True
                        break

            if not csrf_found:
                form_action = form.get_attribute("action") or "unknown"
                forms_without_csrf.append({
                    "form_index": idx,
                    "action": form_action,
                    "method": method,
                })
                self.logger.warning(f"Form without CSRF token: action={form_action}")

        result.duration_ms = int((time.time() - start) * 1000)

        if forms_without_csrf:
            result.status = SecurityTestResult.FAIL
            result.details = f"{len(forms_without_csrf)} POST form(s) lack CSRF token"
            result.evidence = forms_without_csrf
        elif not forms:
            result.status = SecurityTestResult.SKIP
            result.details = "No forms found on homepage to evaluate"
        else:
            result.status = SecurityTestResult.PASS
            result.details = f"All {len(forms)} POST form(s) appear to have CSRF protection"

        self.assertEqual(
            len(forms_without_csrf), 0,
            f"Forms without CSRF tokens: {forms_without_csrf}"
        )

    def test_csrf_token_validation(self):
        """Attempt to submit a form with a tampered/missing CSRF token."""
        result = self._new_result("CSRF Token Validation", self.CATEGORY)
        result.severity = "CRITICAL"
        start = time.time()

        try:
            import requests
            import urllib3
            urllib3.disable_warnings()

            # Get valid session cookies from Selenium
            self._navigate("/login")
            selenium_cookies = self.driver.get_cookies()
            cookie_dict = {c["name"]: c["value"] for c in selenium_cookies}

            # Attempt POST with invalid CSRF token
            forged_payloads = [
                {"csrfmiddlewaretoken": "invalid_token_xyz"},
                {"_token": "forged12345"},
                {},  # Missing token entirely
            ]

            csrf_bypass = []

            for payload in forged_payloads:
                try:
                    resp = requests.post(
                        f"{self.BASE_URL}/api/update-profile",
                        data={**payload, "name": "CSRF_TEST"},
                        cookies=cookie_dict,
                        timeout=5,
                        verify=False,
                        allow_redirects=False,
                    )

                    if resp.status_code in (200, 302) and resp.status_code != 403:
                        csrf_bypass.append({
                            "payload": payload,
                            "status": resp.status_code,
                            "potential_bypass": True,
                        })

                except Exception as e:
                    self.logger.debug(f"CSRF validation test error: {e}")

            result.duration_ms = int((time.time() - start) * 1000)

            if csrf_bypass:
                result.status = SecurityTestResult.WARN
                result.details = "Requests with invalid/missing CSRF tokens were not rejected (403)"
                result.evidence = csrf_bypass
            else:
                result.status = SecurityTestResult.PASS
                result.details = "CSRF token validation appears to be enforced"

        except ImportError:
            result.status = SecurityTestResult.SKIP
            result.details = "requests library not available — CSRF validation test skipped"
            result.duration_ms = int((time.time() - start) * 1000)

    def test_security_response_headers(self):
        """Check for all required security response headers."""
        result = self._new_result("Security Response Headers", self.CATEGORY)
        result.severity = "MEDIUM"
        start = time.time()

        try:
            import requests
            import urllib3
            urllib3.disable_warnings()

            resp = requests.get(self.BASE_URL, timeout=5, verify=False)
            headers = {k.lower(): v for k, v in resp.headers.items()}

            missing_headers = []
            weak_headers = []

            for header_name, config in REQUIRED_SECURITY_HEADERS.items():
                header_lower = header_name.lower()

                if header_lower not in headers:
                    missing_headers.append({
                        "header": header_name,
                        "severity": config["severity"],
                        "description": config["description"],
                    })
                else:
                    actual_value = headers[header_lower]
                    expected = config.get("expected")

                    if expected is not None:
                        if isinstance(expected, list):
                            match = any(e.lower() in actual_value.lower() for e in expected)
                        else:
                            match = expected.lower() in actual_value.lower()

                        if not match:
                            weak_headers.append({
                                "header": header_name,
                                "actual": actual_value,
                                "expected": expected,
                            })

            result.duration_ms = int((time.time() - start) * 1000)
            all_issues = missing_headers + weak_headers

            if all_issues:
                high_severity = [h for h in missing_headers if h.get("severity") == "HIGH"]
                result.status = SecurityTestResult.FAIL if high_severity else SecurityTestResult.WARN
                result.details = (
                    f"{len(missing_headers)} missing header(s), "
                    f"{len(weak_headers)} misconfigured header(s)"
                )
                result.evidence = {
                    "missing": missing_headers,
                    "misconfigured": weak_headers,
                    "present": [h for h in REQUIRED_SECURITY_HEADERS if h.lower() in headers],
                }
            else:
                result.status = SecurityTestResult.PASS
                result.details = "All required security headers are present and configured correctly"

        except ImportError:
            result.status = SecurityTestResult.SKIP
            result.details = "requests library not available — header check skipped"
            result.duration_ms = int((time.time() - start) * 1000)

    def test_clickjacking_protection(self):
        """Test for clickjacking via iframe embedding."""
        result = self._new_result("Clickjacking Protection", self.CATEGORY)
        result.severity = "MEDIUM"
        start = time.time()

        # Create a test page that tries to iframe the target
        test_html = f"""
        <html><body>
            <iframe id="target-frame" src="{self.BASE_URL}" width="800" height="600"></iframe>
            <script>
                window.frameLoaded = false;
                document.getElementById('target-frame').onload = function() {{
                    window.frameLoaded = true;
                }};
            </script>
        </body></html>
        """

        # Write test file
        import tempfile, os
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".html", delete=False, dir="/tmp"
        ) as f:
            f.write(test_html)
            tmp_path = f.name

        try:
            self.driver.get(f"file://{tmp_path}")
            time.sleep(2)

            frame_loaded = self._inject_script("return window.frameLoaded;")
            can_access_frame = False

            try:
                self.driver.switch_to.frame("target-frame")
                frame_content = self.driver.page_source
                can_access_frame = len(frame_content) > 100
                self.driver.switch_to.default_content()
            except Exception:
                pass  # Expected if X-Frame-Options prevents framing

            result.duration_ms = int((time.time() - start) * 1000)

            if can_access_frame and frame_loaded:
                result.status = SecurityTestResult.FAIL
                result.details = "Page can be embedded in iframes — clickjacking vulnerability exists"
                result.evidence = {"iframe_accessible": True, "frame_loaded": frame_loaded}
            else:
                result.status = SecurityTestResult.PASS
                result.details = "Page appears to be protected against iframe embedding"

        finally:
            os.unlink(tmp_path)

    def test_cors_configuration(self):
        """Validate CORS configuration is not overly permissive."""
        result = self._new_result("CORS Configuration", self.CATEGORY)
        result.severity = "HIGH"
        start = time.time()

        cors_issues = []

        try:
            import requests
            import urllib3
            urllib3.disable_warnings()

            malicious_origins = [
                "https://evil.attacker.com",
                "null",
                "https://sub.target.com.evil.com",
            ]

            for origin in malicious_origins:
                try:
                    resp = requests.options(
                        f"{self.BASE_URL}/api/",
                        headers={"Origin": origin, "Access-Control-Request-Method": "GET"},
                        timeout=5,
                        verify=False,
                    )

                    acao = resp.headers.get("Access-Control-Allow-Origin", "")
                    acac = resp.headers.get("Access-Control-Allow-Credentials", "")

                    if acao == "*":
                        cors_issues.append({
                            "issue": "Wildcard ACAO — all origins permitted",
                            "origin_tested": origin,
                        })
                    elif origin in acao:
                        cors_issues.append({
                            "issue": f"Malicious origin '{origin}' allowed",
                            "acao": acao,
                            "acac": acac,
                        })

                    if acac.lower() == "true" and acao == "*":
                        cors_issues.append({
                            "issue": "ACAC=true with wildcard ACAO — credentials exposed",
                        })

                except Exception as e:
                    self.logger.debug(f"CORS test error for {origin}: {e}")

            result.duration_ms = int((time.time() - start) * 1000)

            if cors_issues:
                result.status = SecurityTestResult.FAIL
                result.details = f"CORS misconfiguration(s) found: {len(cors_issues)} issue(s)"
                result.evidence = cors_issues
            else:
                result.status = SecurityTestResult.PASS
                result.details = "CORS configuration appears properly restricted"

        except ImportError:
            result.status = SecurityTestResult.SKIP
            result.details = "requests library not available — CORS test skipped"
            result.duration_ms = int((time.time() - start) * 1000)
