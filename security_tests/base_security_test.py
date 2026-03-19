"""
Base Security Test Class
Provides common setup, utilities, and reporting for all security tests.
"""

import unittest
import logging
import json
import time
import os
from datetime import datetime, timezone
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("reports/security_test.log", mode="a"),
    ],
)


class SecurityTestResult:
    """Represents a single security test result."""

    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"
    SKIP = "SKIP"

    def __init__(self, test_name: str, category: str):
        self.test_name = test_name
        self.category = category
        self.status = self.SKIP
        self.severity = "LOW"
        self.details = ""
        self.evidence = []
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.duration_ms = 0

    def to_dict(self) -> dict:
        return {
            "test_name": self.test_name,
            "category": self.category,
            "status": self.status,
            "severity": self.severity,
            "details": self.details,
            "evidence": self.evidence,
            "timestamp": self.timestamp,
            "duration_ms": self.duration_ms,
        }


class BaseSecurityTest(unittest.TestCase):
    """
    Base class for all security tests.
    Handles WebDriver setup, teardown, and result collection.
    """

    BASE_URL = os.getenv("TARGET_URL", "http://localhost:8080")
    HEADLESS = os.getenv("HEADLESS", "true").lower() == "true"
    TIMEOUT = int(os.getenv("SELENIUM_TIMEOUT", "10"))
    RESULTS_FILE = "reports/security_results.json"

    results: list[SecurityTestResult] = []
    driver: webdriver.Chrome = None

    @classmethod
    def setUpClass(cls):
        """Initialize WebDriver and results list."""
        cls.logger = logging.getLogger(cls.__name__)
        cls.logger.info(f"Setting up security test suite: {cls.__name__}")
        cls.results = []

        chrome_options = Options()
        if cls.HEADLESS:
            chrome_options.add_argument("--headless=new")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--window-size=1920,1080")
        # Security-relevant options
        chrome_options.add_argument("--disable-web-security")
        chrome_options.add_argument("--allow-running-insecure-content")
        chrome_options.add_argument("--disable-blink-features=AutomationControlled")
        chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])

        try:
            # Try custom paths first, then fall back to auto-detection
            chromedriver_path = os.getenv("CHROMEDRIVER")
            chrome_binary = os.getenv("CHROME_BIN")
            
            # If no custom binary specified, try common locations
            if not chrome_binary:
                common_paths = [
                    "/usr/bin/chromium-browser",      # Linux (Chromium)
                    "/usr/bin/chromium",              # Linux (Chromium alt)
                    "/usr/bin/google-chrome",         # Linux (Google Chrome)
                    "/usr/bin/google-chrome-stable",  # Linux (Google Chrome stable)
                    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",  # macOS
                    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",     # Windows
                ]
                for path in common_paths:
                    if os.path.exists(path):
                        chrome_binary = path
                        cls.logger.info(f"Using Chrome binary: {chrome_binary}")
                        break
            
            if chrome_binary:
                chrome_options.binary_location = chrome_binary
            
            if chromedriver_path and os.path.exists(chromedriver_path):
                cls.driver = webdriver.Chrome(service=Service(chromedriver_path), options=chrome_options)
            else:
                cls.driver = webdriver.Chrome(options=chrome_options)
            
            cls.driver.set_page_load_timeout(cls.TIMEOUT)
            cls.wait = WebDriverWait(cls.driver, cls.TIMEOUT)
            cls.logger.info("WebDriver initialized successfully")
        except Exception as e:
            cls.logger.error(f"Failed to initialize WebDriver: {e}")
            raise

    @classmethod
    def tearDownClass(cls):
        """Cleanup WebDriver and write results."""
        if cls.driver:
            cls.driver.quit()
            cls.logger.info("WebDriver closed")

        cls._write_results()

    @classmethod
    def _write_results(cls):
        """Append results to JSON report file."""
        os.makedirs("reports", exist_ok=True)
        existing = []

        if os.path.exists(cls.RESULTS_FILE):
            try:
                with open(cls.RESULTS_FILE, "r") as f:
                    existing = json.load(f)
            except Exception:
                existing = []

        existing.extend([r.to_dict() for r in cls.results])

        with open(cls.RESULTS_FILE, "w") as f:
            json.dump(existing, f, indent=2)

        cls.logger.info(f"Results written to {cls.RESULTS_FILE}")

    def _new_result(self, test_name: str, category: str) -> SecurityTestResult:
        """Create and register a new test result."""
        result = SecurityTestResult(test_name, category)
        self.results.append(result)
        return result

    def _navigate(self, path: str = ""):
        """Navigate to a URL path."""
        url = f"{self.BASE_URL}{path}"
        self.driver.get(url)
        self.logger.debug(f"Navigated to {url}")

    def _get_response_headers(self) -> dict:
        """Extract response headers via JavaScript."""
        return self.driver.execute_script(
            "return Object.fromEntries(new Headers(performance.getEntriesByType('navigation')[0]?.responseHeaders || []));"
        )

    def _inject_script(self, script: str) -> any:
        """Execute JavaScript and return result."""
        return self.driver.execute_script(script)

    def _find_element_safe(self, by: By, value: str):
        """Find element without raising exception."""
        try:
            return self.driver.find_element(by, value)
        except Exception:
            return None

    def _timed_test(self, func):
        """Measure execution time of a test function."""
        start = time.time()
        result = func()
        elapsed_ms = int((time.time() - start) * 1000)
        return result, elapsed_ms
