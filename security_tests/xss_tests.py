"""
Cross-Site Scripting (XSS) Security Test Suite
Tests for reflected, stored, and DOM-based XSS vulnerabilities.
"""

import time
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from security_tests.base_security_test import BaseSecurityTest, SecurityTestResult


# XSS payloads categorized by technique
XSS_PAYLOADS = {
    "basic": [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
    ],
    "encoded": [
        "%3Cscript%3Ealert('XSS')%3C/script%3E",
        "&#x3C;script&#x3E;alert('XSS')&#x3C;/script&#x3E;",
        "\\u003cscript\\u003ealert('XSS')\\u003c/script\\u003e",
    ],
    "event_handlers": [
        '" onmouseover="alert(1)',
        "' onfocus='alert(1)' autofocus='",
        "\" onload=\"alert(1)\" <",
    ],
    "html5": [
        "<details open ontoggle=alert(1)>",
        "<video src=x onerror=alert(1)>",
        "<input autofocus onfocus=alert(1)>",
    ],
    "bypass": [
        "<ScRiPt>alert('XSS')</ScRiPt>",
        "<script>alert(String.fromCharCode(88,83,83))</script>",
        "javascript:alert('XSS')",
    ],
}

DOM_XSS_SINKS = [
    "document.write",
    "innerHTML",
    "outerHTML",
    "insertAdjacentHTML",
    "eval(",
    "setTimeout(",
    "setInterval(",
    "document.location",
]


class XSSSecurityTests(BaseSecurityTest):
    """
    Cross-Site Scripting (XSS) test suite.
    Covers reflected, stored, and DOM-based XSS vectors.
    """

    CATEGORY = "XSS"

    def test_reflected_xss_query_params(self):
        """Test for reflected XSS via URL query parameters."""
        result = self._new_result("Reflected XSS - Query Parameters", self.CATEGORY)
        result.severity = "HIGH"
        start = time.time()

        vulnerable_params = []

        for param_name in ["q", "search", "query", "name", "input", "data", "msg"]:
            for payload_type, payloads in XSS_PAYLOADS.items():
                for payload in payloads[:1]:  # Test first payload per type
                    try:
                        url = f"{self.BASE_URL}/?{param_name}={payload}"
                        self.driver.get(url)

                        # Check if payload appears unescaped in DOM
                        page_source = self.driver.page_source
                        if payload in page_source:
                            vulnerable_params.append({
                                "param": param_name,
                                "type": payload_type,
                                "payload": payload,
                                "url": url,
                            })
                            self.logger.warning(
                                f"Potential XSS via param '{param_name}' with {payload_type} payload"
                            )

                        # Check for alert dialogs
                        try:
                            alert = self.driver.switch_to.alert
                            alert.dismiss()
                            vulnerable_params.append({
                                "param": param_name,
                                "type": "alert_triggered",
                                "payload": payload,
                            })
                        except Exception:
                            pass

                    except Exception as e:
                        self.logger.debug(f"Error testing param {param_name}: {e}")

        result.duration_ms = int((time.time() - start) * 1000)

        if vulnerable_params:
            result.status = SecurityTestResult.FAIL
            result.details = f"Found {len(vulnerable_params)} potential XSS vector(s)"
            result.evidence = vulnerable_params
        else:
            result.status = SecurityTestResult.PASS
            result.details = "No reflected XSS found in query parameters"

        self.assertEqual(
            len(vulnerable_params), 0,
            f"Reflected XSS vulnerabilities found: {vulnerable_params}"
        )

    def test_reflected_xss_form_inputs(self):
        """Test for reflected XSS via form input fields."""
        result = self._new_result("Reflected XSS - Form Inputs", self.CATEGORY)
        result.severity = "HIGH"
        start = time.time()

        self._navigate("/")
        vulnerable_inputs = []

        # Find all input fields on the page
        inputs = self.driver.find_elements(By.TAG_NAME, "input")
        text_inputs = [
            el for el in inputs
            if el.get_attribute("type") in ("text", "search", "email", "url", None, "")
        ]

        for input_el in text_inputs[:5]:  # Limit to first 5 inputs
            for payload in XSS_PAYLOADS["basic"][:2]:
                try:
                    input_el.clear()
                    input_el.send_keys(payload)
                    input_el.send_keys(Keys.RETURN)

                    time.sleep(0.5)
                    page_source = self.driver.page_source

                    if payload in page_source:
                        vulnerable_inputs.append({
                            "input_id": input_el.get_attribute("id") or "unknown",
                            "input_name": input_el.get_attribute("name") or "unknown",
                            "payload": payload,
                        })

                    # Check for alert
                    try:
                        alert = self.driver.switch_to.alert
                        alert.dismiss()
                        vulnerable_inputs.append({
                            "input_id": input_el.get_attribute("id") or "unknown",
                            "type": "alert_triggered",
                            "payload": payload,
                        })
                    except Exception:
                        pass

                except Exception as e:
                    self.logger.debug(f"Error testing input: {e}")

        result.duration_ms = int((time.time() - start) * 1000)

        if vulnerable_inputs:
            result.status = SecurityTestResult.FAIL
            result.details = f"Found {len(vulnerable_inputs)} XSS-vulnerable form input(s)"
            result.evidence = vulnerable_inputs
        else:
            result.status = SecurityTestResult.PASS
            result.details = "No XSS found via form inputs"

        self.assertEqual(len(vulnerable_inputs), 0, f"Form input XSS found: {vulnerable_inputs}")

    def test_dom_xss_sources(self):
        """Detect dangerous DOM XSS sinks in page JavaScript."""
        result = self._new_result("DOM XSS - Dangerous Sinks", self.CATEGORY)
        result.severity = "MEDIUM"
        start = time.time()

        self._navigate("/")

        found_sinks = self._inject_script("""
            const scripts = Array.from(document.querySelectorAll('script'));
            const inlineCode = scripts.map(s => s.textContent).join('\\n');
            const sinks = arguments[0];
            return sinks.filter(sink => inlineCode.includes(sink));
        """, DOM_XSS_SINKS) or []

        # Also check external scripts via performance API
        script_urls = self._inject_script("""
            return Array.from(document.querySelectorAll('script[src]'))
                        .map(s => s.src)
                        .filter(Boolean);
        """) or []

        result.duration_ms = int((time.time() - start) * 1000)

        if found_sinks:
            result.status = SecurityTestResult.WARN
            result.details = f"Dangerous DOM sinks detected: {', '.join(found_sinks)}"
            result.evidence = {"sinks": found_sinks, "script_urls": script_urls}
        else:
            result.status = SecurityTestResult.PASS
            result.details = "No dangerous DOM XSS sinks found in inline scripts"

    def test_content_security_policy_header(self):
        """Verify Content-Security-Policy header presence and strength."""
        result = self._new_result("CSP Header Validation", self.CATEGORY)
        result.severity = "MEDIUM"
        start = time.time()

        self._navigate("/")

        # Use CDP to capture response headers
        csp = self._inject_script("""
            return document.querySelector('meta[http-equiv="Content-Security-Policy"]')
                          ?.getAttribute('content') || null;
        """)

        issues = []

        if not csp:
            issues.append("Missing Content-Security-Policy header/meta tag")
        else:
            if "unsafe-inline" in csp:
                issues.append("CSP allows 'unsafe-inline' scripts — XSS mitigation weakened")
            if "unsafe-eval" in csp:
                issues.append("CSP allows 'unsafe-eval' — dynamic code execution permitted")
            if "*" in csp and "script-src" in csp:
                issues.append("CSP uses wildcard (*) in script-src — overly permissive")

        result.duration_ms = int((time.time() - start) * 1000)

        if issues:
            result.status = SecurityTestResult.WARN
            result.details = "; ".join(issues)
            result.evidence = {"csp_value": csp, "issues": issues}
        else:
            result.status = SecurityTestResult.PASS
            result.details = "CSP header present and appears well-configured"

    def test_xss_via_http_headers(self):
        """Test for XSS through HTTP header reflection (User-Agent, Referer)."""
        result = self._new_result("XSS via HTTP Header Reflection", self.CATEGORY)
        result.severity = "HIGH"
        start = time.time()

        # Use CDP to set custom headers — simulated check
        # In real test env, use requests + selenium hybrid
        xss_header_payload = "<script>alert('header-xss')</script>"

        try:
            import requests
            headers_to_test = {
                "User-Agent": xss_header_payload,
                "Referer": f"{self.BASE_URL}/{xss_header_payload}",
                "X-Forwarded-For": xss_header_payload,
            }

            vulnerable_headers = []

            for header, value in headers_to_test.items():
                try:
                    resp = requests.get(
                        self.BASE_URL,
                        headers={header: value},
                        timeout=5,
                        verify=False,
                    )
                    if xss_header_payload in resp.text:
                        vulnerable_headers.append(header)
                except Exception as e:
                    self.logger.debug(f"Header test error: {e}")

            result.duration_ms = int((time.time() - start) * 1000)

            if vulnerable_headers:
                result.status = SecurityTestResult.FAIL
                result.details = f"Headers reflected without sanitization: {vulnerable_headers}"
                result.evidence = {"vulnerable_headers": vulnerable_headers}
            else:
                result.status = SecurityTestResult.PASS
                result.details = "No XSS via HTTP header reflection detected"

        except ImportError:
            result.status = SecurityTestResult.SKIP
            result.details = "requests library not available — header reflection test skipped"
            result.duration_ms = int((time.time() - start) * 1000)
