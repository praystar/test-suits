"""
Authentication & Session Security Test Suite
Tests for broken authentication, weak sessions, and account enumeration.
"""

import time
import re
import hashlib
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from security_tests.base_security_test import BaseSecurityTest, SecurityTestResult


class AuthenticationSecurityTests(BaseSecurityTest):
    """
    Authentication security tests covering session management,
    brute force protection, and credential security.
    """

    CATEGORY = "AUTHENTICATION"

    def test_brute_force_protection(self):
        """Verify account lockout or rate limiting after repeated failed logins."""
        result = self._new_result("Brute Force Protection", self.CATEGORY)
        result.severity = "HIGH"
        start = time.time()

        self._navigate("/login")
        lockout_triggered = False
        attempts_before_lockout = None
        responses = []

        for attempt in range(1, 11):
            try:
                self.driver.get(f"{self.BASE_URL}/login")
                username = self._find_element_safe(By.NAME, "username") or \
                           self._find_element_safe(By.NAME, "email")
                password = self._find_element_safe(By.NAME, "password")

                if not username or not password:
                    result.status = SecurityTestResult.SKIP
                    result.details = "Login form not found"
                    return

                username.clear()
                username.send_keys("admin@test.com")
                password.clear()
                password.send_keys(f"wrong_password_{attempt}")
                password.send_keys(Keys.RETURN)

                time.sleep(0.5)
                page_source = self.driver.page_source
                current_url = self.driver.current_url

                responses.append({
                    "attempt": attempt,
                    "url": current_url,
                    "has_captcha": "captcha" in page_source.lower() or "recaptcha" in page_source.lower(),
                    "has_lockout": any(word in page_source.lower() for word in [
                        "locked", "too many attempts", "temporarily disabled", "blocked"
                    ]),
                })

                if responses[-1]["has_lockout"] or responses[-1]["has_captcha"]:
                    lockout_triggered = True
                    attempts_before_lockout = attempt
                    self.logger.info(f"Lockout/CAPTCHA triggered after {attempt} attempts")
                    break

            except Exception as e:
                self.logger.debug(f"Error in brute force test attempt {attempt}: {e}")

        result.duration_ms = int((time.time() - start) * 1000)

        if lockout_triggered:
            result.status = SecurityTestResult.PASS
            result.details = f"Account protection triggered after {attempts_before_lockout} attempt(s)"
            result.evidence = {"responses": responses, "lockout_at": attempts_before_lockout}
        else:
            result.status = SecurityTestResult.FAIL
            result.details = "No brute force protection detected after 10 failed attempts"
            result.evidence = {"responses": responses}

        self.assertTrue(lockout_triggered, "Brute force protection not detected")

    def test_session_cookie_security(self):
        """Verify session cookies have Secure, HttpOnly, and SameSite flags."""
        result = self._new_result("Session Cookie Security Flags", self.CATEGORY)
        result.severity = "HIGH"
        start = time.time()

        self._navigate("/")
        cookies = self.driver.get_cookies()

        session_cookie_names = ["session", "sessionid", "PHPSESSID", "JSESSIONID",
                                "connect.sid", "auth_token", "access_token"]

        issues = []
        checked_cookies = []

        for cookie in cookies:
            cookie_name = cookie.get("name", "")
            is_session = any(
                name.lower() in cookie_name.lower()
                for name in session_cookie_names
            )

            if not is_session:
                continue

            cookie_issues = []

            if not cookie.get("httpOnly", False):
                cookie_issues.append("Missing HttpOnly flag — accessible via JavaScript")

            if not cookie.get("secure", False):
                cookie_issues.append("Missing Secure flag — transmitted over HTTP")

            same_site = cookie.get("sameSite", "").lower()
            if same_site not in ("strict", "lax"):
                cookie_issues.append(
                    f"SameSite not set to Strict/Lax (current: '{same_site}') — CSRF risk"
                )

            # Check for predictable session IDs
            value = cookie.get("value", "")
            if len(value) < 16:
                cookie_issues.append(f"Session token too short ({len(value)} chars)")

            checked_cookies.append({
                "name": cookie_name,
                "httpOnly": cookie.get("httpOnly", False),
                "secure": cookie.get("secure", False),
                "sameSite": cookie.get("sameSite", ""),
                "value_length": len(value),
                "issues": cookie_issues,
            })

            if cookie_issues:
                issues.extend(cookie_issues)

        result.duration_ms = int((time.time() - start) * 1000)

        if issues:
            result.status = SecurityTestResult.FAIL
            result.details = f"Session cookie issues: {'; '.join(issues[:3])}"
            result.evidence = checked_cookies
        elif not checked_cookies:
            result.status = SecurityTestResult.WARN
            result.details = "No recognizable session cookies found to evaluate"
        else:
            result.status = SecurityTestResult.PASS
            result.details = f"All {len(checked_cookies)} session cookie(s) have proper security flags"

    def test_session_fixation(self):
        """Test for session fixation vulnerability."""
        result = self._new_result("Session Fixation", self.CATEGORY)
        result.severity = "HIGH"
        start = time.time()

        self._navigate("/login")

        # Get pre-login session token
        pre_login_cookies = {
            c["name"]: c["value"]
            for c in self.driver.get_cookies()
        }

        pre_session = None
        for name in ["session", "sessionid", "PHPSESSID", "JSESSIONID"]:
            if name in pre_login_cookies:
                pre_session = pre_login_cookies[name]
                break

        # Attempt login
        try:
            username = self._find_element_safe(By.NAME, "username")
            password = self._find_element_safe(By.NAME, "password")

            if username and password:
                username.clear()
                username.send_keys("testuser@example.com")
                password.clear()
                password.send_keys("TestPassword123!")
                password.send_keys(Keys.RETURN)
                time.sleep(1)
        except Exception:
            pass

        # Get post-login session token
        post_login_cookies = {
            c["name"]: c["value"]
            for c in self.driver.get_cookies()
        }

        post_session = None
        for name in ["session", "sessionid", "PHPSESSID", "JSESSIONID"]:
            if name in post_login_cookies:
                post_session = post_login_cookies[name]
                break

        result.duration_ms = int((time.time() - start) * 1000)

        if pre_session and post_session:
            if pre_session == post_session:
                result.status = SecurityTestResult.FAIL
                result.details = "Session token not regenerated after login — session fixation risk"
                result.evidence = {
                    "pre_login_token_hash": hashlib.md5(pre_session.encode()).hexdigest(),
                    "post_login_token_hash": hashlib.md5(post_session.encode()).hexdigest(),
                    "same_token": True,
                }
            else:
                result.status = SecurityTestResult.PASS
                result.details = "Session token regenerated after login — session fixation mitigated"
        else:
            result.status = SecurityTestResult.SKIP
            result.details = "Could not compare session tokens — login may have failed or session cookie not found"

    def test_account_enumeration_login(self):
        """Detect account enumeration via different error messages."""
        result = self._new_result("Account Enumeration - Login", self.CATEGORY)
        result.severity = "MEDIUM"
        start = time.time()

        enumeration_possible = False
        messages = {}

        test_cases = [
            ("nonexistent_user_xyz123@test.com", "InvalidPass123!"),
            ("admin@example.com", "WrongPassword456!"),
        ]

        for email, password in test_cases:
            try:
                self.driver.get(f"{self.BASE_URL}/login")
                username_el = self._find_element_safe(By.NAME, "username") or \
                              self._find_element_safe(By.NAME, "email")
                password_el = self._find_element_safe(By.NAME, "password")

                if not username_el or not password_el:
                    break

                username_el.clear()
                username_el.send_keys(email)
                password_el.clear()
                password_el.send_keys(password)
                password_el.send_keys(Keys.RETURN)
                time.sleep(0.5)

                page_text = self.driver.find_element(By.TAG_NAME, "body").text.lower()

                # Capture error message
                for phrase in ["invalid", "incorrect", "not found", "doesn't exist",
                               "wrong password", "no account"]:
                    if phrase in page_text:
                        messages[email] = phrase
                        break
                else:
                    messages[email] = "generic_or_none"

            except Exception as e:
                self.logger.debug(f"Enumeration test error: {e}")

        result.duration_ms = int((time.time() - start) * 1000)

        unique_messages = set(messages.values())
        if len(unique_messages) > 1 and "generic_or_none" not in unique_messages:
            enumeration_possible = True
            result.status = SecurityTestResult.FAIL
            result.details = "Different error messages for valid/invalid users enable account enumeration"
            result.evidence = messages
        else:
            result.status = SecurityTestResult.PASS
            result.details = "Login form uses generic error messages — enumeration mitigated"

    def test_password_policy_enforcement(self):
        """Verify strong password policy on registration/change forms."""
        result = self._new_result("Password Policy Enforcement", self.CATEGORY)
        result.severity = "MEDIUM"
        start = time.time()

        weak_passwords = ["123456", "password", "abc", "12345678", "qwerty"]
        weak_accepted = []

        for pwd in weak_passwords:
            try:
                self.driver.get(f"{self.BASE_URL}/register")
                username_el = self._find_element_safe(By.NAME, "username")
                password_el = self._find_element_safe(By.NAME, "password")

                if not username_el or not password_el:
                    continue

                username_el.clear()
                username_el.send_keys(f"testuser_{int(time.time())}")
                password_el.clear()
                password_el.send_keys(pwd)
                password_el.send_keys(Keys.RETURN)

                time.sleep(0.5)
                page_text = self.driver.find_element(By.TAG_NAME, "body").text.lower()

                # Check if password was rejected
                rejected = any(phrase in page_text for phrase in [
                    "too weak", "too short", "must be", "password requirements",
                    "at least", "minimum", "invalid password"
                ])

                if not rejected and "/register" not in self.driver.current_url:
                    weak_accepted.append(pwd)

            except Exception as e:
                self.logger.debug(f"Password policy test error: {e}")

        result.duration_ms = int((time.time() - start) * 1000)

        if weak_accepted:
            result.status = SecurityTestResult.FAIL
            result.details = f"Weak passwords accepted: {weak_accepted}"
            result.evidence = {"weak_accepted": weak_accepted}
        else:
            result.status = SecurityTestResult.PASS
            result.details = "Password policy appears to reject common weak passwords"
