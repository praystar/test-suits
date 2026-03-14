#!/usr/bin/env python3
"""
Security Report Generator
Generates a rich HTML report from JSON test results.
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from collections import defaultdict


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--results", default="reports/security_results.json")
    p.add_argument("--output", default="reports/security_report.html")
    p.add_argument("--build-url", default="#")
    p.add_argument("--build-number", default="local")
    p.add_argument("--target-url", default="http://localhost")
    return p.parse_args()


def load_results(path):
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return json.load(f)


SEVERITY_COLOR = {
    "CRITICAL": "#ff2d55",
    "HIGH": "#ff6b35",
    "MEDIUM": "#ffcc00",
    "LOW": "#34c759",
    "INFO": "#007aff",
}

STATUS_COLOR = {
    "PASS": "#34c759",
    "FAIL": "#ff3b30",
    "WARN": "#ff9500",
    "SKIP": "#8e8e93",
}

STATUS_ICON = {
    "PASS": "✅",
    "FAIL": "❌",
    "WARN": "⚠️",
    "SKIP": "⏭",
}


def generate_html(results, build_url, build_number, target_url):
    by_category = defaultdict(list)
    for r in results:
        by_category[r.get("category", "UNCATEGORIZED")].append(r)

    total = len(results)
    passed = sum(1 for r in results if r.get("status") == "PASS")
    failed = sum(1 for r in results if r.get("status") == "FAIL")
    warned = sum(1 for r in results if r.get("status") == "WARN")
    skipped = sum(1 for r in results if r.get("status") == "SKIP")
    score = int((passed / total * 100)) if total > 0 else 0

    critical_count = sum(1 for r in results if r.get("severity") == "CRITICAL" and r.get("status") == "FAIL")
    high_count = sum(1 for r in results if r.get("severity") == "HIGH" and r.get("status") == "FAIL")

    rows = ""
    for r in results:
        sev = r.get("severity", "LOW")
        sta = r.get("status", "SKIP")
        evidence_html = ""
        if r.get("evidence"):
            ev_json = json.dumps(r["evidence"], indent=2)
            evidence_html = f'<pre class="evidence">{ev_json}</pre>'

        rows += f"""
        <tr>
            <td><span class="badge" style="background:{STATUS_COLOR.get(sta,'#ccc')}">{STATUS_ICON.get(sta,'')} {sta}</span></td>
            <td><span class="sev-badge" style="background:{SEVERITY_COLOR.get(sev,'#ccc')}">{sev}</span></td>
            <td class="cat-cell">{r.get('category','')}</td>
            <td class="test-name">{r.get('test_name','')}</td>
            <td>{r.get('details','')}</td>
            <td class="duration">{r.get('duration_ms',0)}ms</td>
        </tr>
        {'<tr><td colspan="6">' + evidence_html + '</td></tr>' if evidence_html else ''}
        """

    category_cards = ""
    for cat, items in sorted(by_category.items()):
        cat_pass = sum(1 for i in items if i.get("status") == "PASS")
        cat_fail = sum(1 for i in items if i.get("status") == "FAIL")
        cat_warn = sum(1 for i in items if i.get("status") == "WARN")
        cat_total = len(items)
        cat_pct = int(cat_pass / cat_total * 100) if cat_total else 0
        color = "#34c759" if cat_fail == 0 and cat_warn == 0 else ("#ff9500" if cat_fail == 0 else "#ff3b30")

        category_cards += f"""
        <div class="cat-card">
            <div class="cat-header" style="border-left: 4px solid {color}">
                <span class="cat-name">{cat.replace('_', ' ')}</span>
                <span class="cat-score" style="color:{color}">{cat_pct}%</span>
            </div>
            <div class="cat-stats">
                <span class="stat-pass">✅ {cat_pass}</span>
                <span class="stat-fail">❌ {cat_fail}</span>
                <span class="stat-warn">⚠️ {cat_warn}</span>
            </div>
            <div class="progress-bar">
                <div class="progress-fill" style="width:{cat_pct}%; background:{color}"></div>
            </div>
        </div>
        """

    overall_color = "#34c759" if failed == 0 and warned == 0 else ("#ff9500" if failed == 0 else "#ff3b30")
    overall_label = "SECURE" if failed == 0 and warned == 0 else ("WARNINGS" if failed == 0 else "VULNERABLE")
    report_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Test Report — Build #{build_number}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Syne:wght@400;700;800&display=swap');
  :root {{
    --bg: #0a0e1a;
    --surface: #111827;
    --border: #1f2937;
    --text: #e5e7eb;
    --muted: #6b7280;
    --accent: #3b82f6;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'Syne', sans-serif; min-height: 100vh; }}
  header {{ background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 100%); padding: 48px 40px 36px; border-bottom: 1px solid var(--border); position: relative; overflow: hidden; }}
  header::before {{ content: ''; position: absolute; top: -60px; right: -60px; width: 240px; height: 240px; border-radius: 50%; background: radial-gradient(circle, rgba(59,130,246,0.15) 0%, transparent 70%); }}
  .header-grid {{ display: grid; grid-template-columns: 1fr auto; gap: 32px; align-items: center; max-width: 1280px; margin: 0 auto; }}
  .header-title {{ font-size: 13px; letter-spacing: 3px; text-transform: uppercase; color: var(--accent); margin-bottom: 12px; }}
  h1 {{ font-size: 36px; font-weight: 800; letter-spacing: -1px; }}
  .header-meta {{ font-size: 13px; color: var(--muted); margin-top: 10px; font-family: 'JetBrains Mono', monospace; }}
  .header-meta a {{ color: var(--accent); text-decoration: none; }}
  .score-ring {{ text-align: center; }}
  .score-num {{ font-size: 56px; font-weight: 800; line-height: 1; color: {overall_color}; font-family: 'JetBrains Mono', monospace; }}
  .score-label {{ font-size: 11px; letter-spacing: 2px; text-transform: uppercase; color: {overall_color}; margin-top: 4px; }}
  .score-sub {{ font-size: 11px; color: var(--muted); margin-top: 2px; }}
  .main {{ max-width: 1280px; margin: 0 auto; padding: 40px; }}
  .stats-row {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 40px; }}
  .stat-card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 20px 24px; }}
  .stat-card .value {{ font-size: 36px; font-weight: 800; font-family: 'JetBrains Mono', monospace; }}
  .stat-card .label {{ font-size: 12px; letter-spacing: 2px; text-transform: uppercase; color: var(--muted); margin-top: 4px; }}
  .categories {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); gap: 16px; margin-bottom: 40px; }}
  .cat-card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 20px; }}
  .cat-header {{ display: flex; justify-content: space-between; align-items: center; padding-left: 12px; margin-bottom: 12px; }}
  .cat-name {{ font-weight: 700; font-size: 14px; text-transform: capitalize; }}
  .cat-score {{ font-size: 20px; font-weight: 800; font-family: 'JetBrains Mono', monospace; }}
  .cat-stats {{ display: flex; gap: 16px; font-size: 13px; font-family: 'JetBrains Mono', monospace; margin-bottom: 10px; }}
  .progress-bar {{ height: 4px; background: var(--border); border-radius: 2px; overflow: hidden; }}
  .progress-fill {{ height: 100%; border-radius: 2px; transition: width 0.3s; }}
  .section-title {{ font-size: 11px; letter-spacing: 3px; text-transform: uppercase; color: var(--muted); margin-bottom: 16px; font-family: 'JetBrains Mono', monospace; }}
  table {{ width: 100%; border-collapse: collapse; background: var(--surface); border-radius: 12px; overflow: hidden; border: 1px solid var(--border); }}
  th {{ background: #0f172a; font-size: 11px; letter-spacing: 2px; text-transform: uppercase; padding: 14px 16px; text-align: left; color: var(--muted); font-family: 'JetBrains Mono', monospace; }}
  td {{ padding: 14px 16px; font-size: 13px; border-top: 1px solid var(--border); vertical-align: top; }}
  tr:hover td {{ background: rgba(255,255,255,0.02); }}
  .badge {{ padding: 4px 10px; border-radius: 20px; font-size: 11px; font-weight: 700; font-family: 'JetBrains Mono', monospace; color: #fff; white-space: nowrap; }}
  .sev-badge {{ padding: 3px 8px; border-radius: 4px; font-size: 10px; font-weight: 700; font-family: 'JetBrains Mono', monospace; color: #000; white-space: nowrap; }}
  .test-name {{ font-family: 'JetBrains Mono', monospace; font-size: 12px; }}
  .cat-cell {{ font-size: 11px; color: var(--muted); font-family: 'JetBrains Mono', monospace; }}
  .duration {{ font-size: 11px; color: var(--muted); font-family: 'JetBrains Mono', monospace; text-align: right; }}
  .evidence {{ background: #0a0e1a; padding: 12px; border-radius: 6px; font-size: 11px; overflow-x: auto; color: var(--muted); font-family: 'JetBrains Mono', monospace; white-space: pre-wrap; word-break: break-all; }}
  .alert-bar {{ padding: 14px 20px; border-radius: 10px; margin-bottom: 28px; font-size: 13px; display: flex; align-items: center; gap: 12px; }}
  .alert-bar.critical {{ background: rgba(255,45,85,0.1); border: 1px solid rgba(255,45,85,0.3); }}
  footer {{ text-align: center; padding: 28px; color: var(--muted); font-size: 12px; font-family: 'JetBrains Mono', monospace; border-top: 1px solid var(--border); margin-top: 40px; }}
</style>
</head>
<body>

<header>
  <div class="header-grid">
    <div>
      <div class="header-title">Security Test Integration Framework</div>
      <h1>Security Report</h1>
      <div class="header-meta">
        🎯 Target: <a href="{target_url}" target="_blank">{target_url}</a> &nbsp;|&nbsp;
        🔨 Build: <a href="{build_url}" target="_blank">#{build_number}</a> &nbsp;|&nbsp;
        🕐 {report_time}
      </div>
    </div>
    <div class="score-ring">
      <div class="score-num">{score}%</div>
      <div class="score-label">{overall_label}</div>
      <div class="score-sub">{passed}/{total} tests passed</div>
    </div>
  </div>
</header>

<div class="main">

  {"" if not critical_count and not high_count else f'<div class="alert-bar critical">🚨 <strong>{critical_count} CRITICAL</strong> and <strong>{high_count} HIGH</strong> severity vulnerabilities detected — immediate remediation required</div>'}

  <div class="stats-row">
    <div class="stat-card"><div class="value" style="color:#34c759">{passed}</div><div class="label">Passed</div></div>
    <div class="stat-card"><div class="value" style="color:#ff3b30">{failed}</div><div class="label">Failed</div></div>
    <div class="stat-card"><div class="value" style="color:#ff9500">{warned}</div><div class="label">Warnings</div></div>
    <div class="stat-card"><div class="value" style="color:#8e8e93">{skipped}</div><div class="label">Skipped</div></div>
  </div>

  <div class="section-title">Results by Category</div>
  <div class="categories">{category_cards}</div>

  <div class="section-title">Detailed Test Results</div>
  <table>
    <thead><tr>
      <th>Status</th><th>Severity</th><th>Category</th>
      <th>Test</th><th>Details</th><th>Duration</th>
    </tr></thead>
    <tbody>{rows if rows else '<tr><td colspan="6" style="text-align:center;color:#6b7280;padding:40px">No test results found</td></tr>'}</tbody>
  </table>

</div>

<footer>
  Generated by Security Test Integration Framework &nbsp;|&nbsp; Build #{build_number} &nbsp;|&nbsp; {report_time}
</footer>
</body>
</html>"""


def main():
    args = parse_args()
    results = load_results(args.results)
    html = generate_html(results, args.build_url, args.build_number, args.target_url)
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w") as f:
        f.write(html)
    print(f"✅ Report written to: {args.output}")


if __name__ == "__main__":
    main()
