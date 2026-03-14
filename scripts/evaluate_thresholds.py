#!/usr/bin/env python3
"""
Security Threshold Evaluator
Parses test results and exits with appropriate codes for Jenkins.

Exit codes:
  0 — All tests passed, no issues
  1 — Critical or High severity failures found
  2 — Only warnings found (UNSTABLE)
  3 — Results file not found or parse error
"""

import argparse
import json
import sys
import os
from collections import defaultdict


SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def parse_args():
    parser = argparse.ArgumentParser(description="Evaluate security test thresholds")
    parser.add_argument("--results", default="reports/security_results.json")
    parser.add_argument("--fail-on-critical", default="true")
    parser.add_argument("--fail-on-high", default="true")
    parser.add_argument("--fail-on-warnings", default="false")
    return parser.parse_args()


def load_results(path: str) -> list:
    if not os.path.exists(path):
        print(f"❌ Results file not found: {path}")
        sys.exit(3)

    with open(path) as f:
        try:
            return json.load(f)
        except json.JSONDecodeError as e:
            print(f"❌ Failed to parse results JSON: {e}")
            sys.exit(3)


def summarize(results: list) -> dict:
    summary = defaultdict(list)
    for r in results:
        status = r.get("status", "SKIP")
        summary[status].append(r)
    return summary


def print_summary(summary: dict, results: list):
    total = len(results)
    print("\n" + "=" * 60)
    print("  SECURITY TEST RESULTS SUMMARY")
    print("=" * 60)

    for status in ("PASS", "FAIL", "WARN", "SKIP"):
        items = summary.get(status, [])
        icon = {"PASS": "✅", "FAIL": "❌", "WARN": "⚠️ ", "SKIP": "⏭️ "}.get(status, "  ")
        print(f"  {icon}  {status:<6} : {len(items):>3}")

    print(f"\n  Total Tests: {total}")
    print("=" * 60)

    # Print failures grouped by severity
    failures = summary.get("FAIL", [])
    if failures:
        print("\n🚨 FAILURES:")
        by_severity = defaultdict(list)
        for f in failures:
            by_severity[f.get("severity", "LOW")].append(f)

        for sev in sorted(by_severity.keys(), key=lambda s: -SEVERITY_ORDER.get(s, 0)):
            for item in by_severity[sev]:
                print(f"   [{sev}] {item['category']} — {item['test_name']}")
                print(f"          {item.get('details', '')}")

    warnings = summary.get("WARN", [])
    if warnings:
        print("\n⚠️  WARNINGS:")
        for w in warnings:
            print(f"   [{w.get('severity', 'LOW')}] {w['category']} — {w['test_name']}")
            print(f"          {w.get('details', '')}")

    print()


def main():
    args = parse_args()
    fail_on_critical = args.fail_on_critical.lower() == "true"
    fail_on_high = args.fail_on_high.lower() == "true"
    fail_on_warnings = args.fail_on_warnings.lower() == "true"

    results = load_results(args.results)
    summary = summarize(results)

    print_summary(summary, results)

    failures = summary.get("FAIL", [])
    warnings = summary.get("WARN", [])

    critical_failures = [f for f in failures if f.get("severity") == "CRITICAL"]
    high_failures = [f for f in failures if f.get("severity") == "HIGH"]

    if fail_on_critical and critical_failures:
        print(f"❌ {len(critical_failures)} CRITICAL vulnerability/ies found — FAILING BUILD")
        sys.exit(1)

    if fail_on_high and high_failures:
        print(f"❌ {len(high_failures)} HIGH severity issue(s) found — FAILING BUILD")
        sys.exit(1)

    if failures:
        medium_low = [f for f in failures if f.get("severity") not in ("CRITICAL", "HIGH")]
        print(f"⚠️  {len(medium_low)} medium/low severity failure(s) — marking UNSTABLE")
        sys.exit(2)

    if warnings and fail_on_warnings:
        print(f"⚠️  {len(warnings)} warning(s) found and FAIL_ON_WARNINGS=true — UNSTABLE")
        sys.exit(2)

    print("✅ All security thresholds passed!")
    sys.exit(0)


if __name__ == "__main__":
    main()
