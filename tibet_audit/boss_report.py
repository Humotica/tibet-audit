"""
tibet_audit.boss_report — Professional HTML/PDF Compliance Report
=================================================================

Boss Mode: Generate a report your manager will actually read.
No emoji, no ASCII art, no terminal colors. Just clean, professional compliance data.

Usage:
    tibet-audit scan --boss-mode
    tibet-audit scan --boss-mode --boss-output report.html
    tibet-audit scan --boss-mode --org "Acme B.V." --framework gdpr

Authors: Jasper van de Meent & Root AI
License: MIT
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Dict, List, Optional
from pathlib import Path

from .checks.base import Status, Severity, CheckResult
from . import __version__


def generate_boss_report(
    result,
    org_name: str = "Organization",
    framework: Optional[str] = None,
    output_path: Optional[str] = None,
    logo_path: Optional[str] = None,
) -> str:
    """Generate a professional HTML compliance report.

    Args:
        result: ScanResult from scanner
        org_name: Organization name for the report header
        framework: Optional framework filter (gdpr, ai_act, nis2, etc.)
        output_path: Optional path to write HTML file
        logo_path: Optional path to logo image (PNG/JPG/SVG)

    Returns:
        HTML string of the report
    """
    now = datetime.now()
    date_str = now.strftime("%Y-%m-%d")
    time_str = now.strftime("%H:%M:%S")

    # Categorize results
    passed = [r for r in result.results if r.status == Status.PASSED]
    warnings = [r for r in result.results if r.status == Status.WARNING]
    failed = [r for r in result.results if r.status == Status.FAILED]
    skipped = [r for r in result.results if r.status == Status.SKIPPED]

    # Group by category
    categories = {}
    for r in result.results:
        cat = getattr(r, "category", "general") or "general"
        if cat not in categories:
            categories[cat] = {"passed": 0, "warning": 0, "failed": 0, "total": 0}
        categories[cat]["total"] += 1
        if r.status == Status.PASSED:
            categories[cat]["passed"] += 1
        elif r.status == Status.WARNING:
            categories[cat]["warning"] += 1
        elif r.status == Status.FAILED:
            categories[cat]["failed"] += 1

    # Critical/high severity failures
    critical_failures = [
        r for r in failed
        if r.severity in (Severity.CRITICAL, Severity.HIGH)
    ]

    # Score color
    if result.score >= 80:
        score_color = "#22c55e"  # green
        score_label = "Good"
    elif result.score >= 60:
        score_color = "#eab308"  # yellow
        score_label = "Needs Attention"
    else:
        score_color = "#ef4444"  # red
        score_label = "Critical"

    # Grade color
    grade_colors = {
        "A": "#22c55e", "B": "#86efac", "C": "#eab308",
        "D": "#f97316", "F": "#ef4444",
    }
    grade_color = grade_colors.get(result.grade, "#6b7280")

    # Build category rows
    category_rows = ""
    cat_labels = {
        "gdpr": "GDPR (EU Privacy)",
        "ai_act": "EU AI Act",
        "nis2": "NIS2 Directive",
        "jis": "JIS Compliance",
        "sovereignty": "Data Sovereignty",
        "provider": "Provider Security",
        "humotica": "Humotica Pillars",
        "health": "System Health",
        "pipa": "PIPA (Korea)",
        "appi": "APPI (Japan)",
        "pdpa": "PDPA (Singapore)",
        "au_privacy": "Privacy Act (Australia)",
        "lgpd": "LGPD (Brazil)",
        "gulf": "Gulf PDPL",
        "ndpr": "NDPR (Nigeria)",
        "ucp": "UCP Commerce",
        "penguin": "Penguin Act (Antarctica)",
    }

    for cat, counts in sorted(categories.items()):
        label = cat_labels.get(cat, cat.upper())
        pct = int(counts["passed"] / counts["total"] * 100) if counts["total"] else 0
        bar_color = "#22c55e" if pct >= 80 else "#eab308" if pct >= 60 else "#ef4444"
        category_rows += f"""
            <tr>
                <td style="font-weight:500;">{label}</td>
                <td style="text-align:center;">{counts['passed']}</td>
                <td style="text-align:center;">{counts['warning']}</td>
                <td style="text-align:center;">{counts['failed']}</td>
                <td style="text-align:center;">{counts['total']}</td>
                <td>
                    <div style="background:#e5e7eb;border-radius:4px;height:8px;width:100%;">
                        <div style="background:{bar_color};border-radius:4px;height:8px;width:{pct}%;"></div>
                    </div>
                    <span style="font-size:11px;color:#6b7280;">{pct}%</span>
                </td>
            </tr>"""

    # Build failed checks table
    failed_rows = ""
    for r in sorted(failed, key=lambda x: _severity_order(x.severity)):
        sev_color = _severity_color(r.severity)
        cat_label = cat_labels.get(getattr(r, "category", ""), getattr(r, "category", ""))
        failed_rows += f"""
            <tr>
                <td><code>{r.check_id}</code></td>
                <td>{r.name}</td>
                <td style="text-align:center;"><span style="color:{sev_color};font-weight:600;">{r.severity.value.upper()}</span></td>
                <td style="font-size:12px;">{cat_label}</td>
                <td style="font-size:12px;">{r.message or ''}</td>
                <td style="font-size:12px;color:#059669;">{r.recommendation or ''}</td>
            </tr>"""

    # Build warning checks table
    warning_rows = ""
    for r in sorted(warnings, key=lambda x: _severity_order(x.severity)):
        sev_color = _severity_color(r.severity)
        warning_rows += f"""
            <tr>
                <td><code>{r.check_id}</code></td>
                <td>{r.name}</td>
                <td style="text-align:center;"><span style="color:{sev_color};">{r.severity.value.upper()}</span></td>
                <td style="font-size:12px;">{r.message or ''}</td>
            </tr>"""

    # Executive summary bullet points
    exec_bullets = []
    if result.score >= 80:
        exec_bullets.append("Overall compliance posture is <strong>good</strong>. No critical blockers identified.")
    elif result.score >= 60:
        exec_bullets.append("Compliance posture requires <strong>attention</strong>. Action items identified below.")
    else:
        exec_bullets.append("Compliance posture is <strong>critical</strong>. Immediate remediation required.")

    if critical_failures:
        exec_bullets.append(
            f"<strong>{len(critical_failures)}</strong> high/critical severity issue(s) require immediate attention."
        )

    fixable = sum(1 for r in result.results if r.can_auto_fix and r.status != Status.PASSED)
    if fixable:
        exec_bullets.append(
            f"<strong>{fixable}</strong> issue(s) can be automatically remediated using <code>tibet-audit fix --auto</code>."
        )

    exec_bullets.append(
        f"Scan covered <strong>{len(result.results)}</strong> compliance checks across "
        f"<strong>{len(categories)}</strong> regulatory framework(s)."
    )

    exec_bullets_html = "\n".join(f"<li>{b}</li>" for b in exec_bullets)

    # Logo embedding (base64 for self-contained HTML)
    logo_html = ""
    if logo_path:
        logo_file = Path(logo_path)
        if logo_file.exists():
            import base64
            suffix = logo_file.suffix.lower()
            mime_types = {
                ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
                ".svg": "image/svg+xml", ".gif": "image/gif", ".webp": "image/webp",
            }
            mime = mime_types.get(suffix, "image/png")
            b64 = base64.b64encode(logo_file.read_bytes()).decode("ascii")
            logo_html = f'<img src="data:{mime};base64,{b64}" alt="{org_name}" style="height:48px;margin-bottom:12px;">'

    # Framework subtitle
    framework_subtitle = ""
    if framework:
        framework_subtitle = f"<p style='color:#6b7280;margin-top:4px;'>Framework: {framework.upper()}</p>"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Compliance Report - {org_name} - {date_str}</title>
<style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
        color: #1f2937;
        background: #ffffff;
        line-height: 1.6;
        font-size: 14px;
    }}
    .container {{ max-width: 900px; margin: 0 auto; padding: 40px 32px; }}
    .header {{
        border-bottom: 3px solid #1e3a5f;
        padding-bottom: 24px;
        margin-bottom: 32px;
    }}
    .header h1 {{
        font-size: 24px;
        font-weight: 700;
        color: #1e3a5f;
        margin-bottom: 4px;
    }}
    .header .subtitle {{
        font-size: 16px;
        color: #4b5563;
    }}
    .header .meta {{
        font-size: 12px;
        color: #9ca3af;
        margin-top: 12px;
    }}
    .score-card {{
        display: flex;
        align-items: center;
        gap: 32px;
        background: #f9fafb;
        border: 1px solid #e5e7eb;
        border-radius: 8px;
        padding: 24px 32px;
        margin-bottom: 32px;
    }}
    .score-circle {{
        width: 100px;
        height: 100px;
        border-radius: 50%;
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        color: white;
        font-weight: 700;
        flex-shrink: 0;
    }}
    .score-circle .number {{ font-size: 32px; line-height: 1; }}
    .score-circle .label {{ font-size: 11px; opacity: 0.9; }}
    .score-details {{ flex: 1; }}
    .score-details .grade {{
        font-size: 18px;
        font-weight: 700;
        margin-bottom: 8px;
    }}
    .score-details .counts {{
        display: flex;
        gap: 24px;
    }}
    .score-details .count-item {{
        font-size: 13px;
    }}
    .score-details .count-item .num {{
        font-weight: 700;
        font-size: 18px;
    }}
    .section {{
        margin-bottom: 32px;
    }}
    .section h2 {{
        font-size: 16px;
        font-weight: 700;
        color: #1e3a5f;
        border-bottom: 1px solid #e5e7eb;
        padding-bottom: 8px;
        margin-bottom: 16px;
    }}
    table {{
        width: 100%;
        border-collapse: collapse;
        font-size: 13px;
    }}
    th {{
        background: #f3f4f6;
        font-weight: 600;
        text-align: left;
        padding: 8px 12px;
        border-bottom: 2px solid #d1d5db;
        font-size: 12px;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        color: #4b5563;
    }}
    td {{
        padding: 8px 12px;
        border-bottom: 1px solid #e5e7eb;
        vertical-align: top;
    }}
    tr:hover {{ background: #f9fafb; }}
    ul {{ padding-left: 20px; }}
    li {{ margin-bottom: 6px; }}
    code {{
        background: #f3f4f6;
        padding: 2px 6px;
        border-radius: 3px;
        font-size: 12px;
        font-family: 'SF Mono', 'Consolas', 'Monaco', monospace;
    }}
    .footer {{
        margin-top: 48px;
        padding-top: 16px;
        border-top: 1px solid #e5e7eb;
        font-size: 11px;
        color: #9ca3af;
    }}
    .footer a {{ color: #6b7280; text-decoration: none; }}
    @media print {{
        body {{ font-size: 12px; }}
        .container {{ max-width: 100%; padding: 20px; }}
        .score-card {{ break-inside: avoid; }}
        table {{ font-size: 11px; }}
        tr {{ break-inside: avoid; }}
    }}
</style>
</head>
<body>
<div class="container">

    <div class="header">
        {logo_html}
        <h1>Compliance Audit Report</h1>
        <div class="subtitle">{org_name}</div>
        {framework_subtitle}
        <div class="meta">
            Date: {date_str} {time_str} &nbsp;|&nbsp;
            Scan ID: {result.scan_id} &nbsp;|&nbsp;
            Tool: tibet-audit v{__version__} &nbsp;|&nbsp;
            Duration: {result.duration_seconds}s
        </div>
    </div>

    <div class="score-card">
        <div class="score-circle" style="background:{score_color};">
            <span class="number">{result.score}</span>
            <span class="label">/ 100</span>
        </div>
        <div class="score-details">
            <div class="grade" style="color:{grade_color};">Grade {result.grade} — {score_label}</div>
            <div class="counts">
                <div class="count-item">
                    <span class="num" style="color:#22c55e;">{result.passed}</span><br>Passed
                </div>
                <div class="count-item">
                    <span class="num" style="color:#eab308;">{result.warnings}</span><br>Warnings
                </div>
                <div class="count-item">
                    <span class="num" style="color:#ef4444;">{result.failed}</span><br>Failed
                </div>
                <div class="count-item">
                    <span class="num" style="color:#6b7280;">{len(result.results)}</span><br>Total Checks
                </div>
            </div>
        </div>
    </div>

    <div class="section">
        <h2>Executive Summary</h2>
        <ul>
            {exec_bullets_html}
        </ul>
    </div>

    <div class="section">
        <h2>Compliance by Framework</h2>
        <table>
            <thead>
                <tr>
                    <th>Framework</th>
                    <th style="text-align:center;">Passed</th>
                    <th style="text-align:center;">Warnings</th>
                    <th style="text-align:center;">Failed</th>
                    <th style="text-align:center;">Total</th>
                    <th style="width:120px;">Coverage</th>
                </tr>
            </thead>
            <tbody>
                {category_rows}
            </tbody>
        </table>
    </div>

    {"" if not failed else f'''
    <div class="section">
        <h2>Failed Checks — Action Required</h2>
        <table>
            <thead>
                <tr>
                    <th>Check ID</th>
                    <th>Name</th>
                    <th style="text-align:center;">Severity</th>
                    <th>Framework</th>
                    <th>Issue</th>
                    <th>Recommendation</th>
                </tr>
            </thead>
            <tbody>
                {failed_rows}
            </tbody>
        </table>
    </div>
    '''}

    {"" if not warnings else f'''
    <div class="section">
        <h2>Warnings</h2>
        <table>
            <thead>
                <tr>
                    <th>Check ID</th>
                    <th>Name</th>
                    <th style="text-align:center;">Severity</th>
                    <th>Details</th>
                </tr>
            </thead>
            <tbody>
                {warning_rows}
            </tbody>
        </table>
    </div>
    '''}

    <div class="section">
        <h2>Scan Details</h2>
        <table>
            <tbody>
                <tr><td style="width:200px;font-weight:500;">Scan Path</td><td>{result.scan_path}</td></tr>
                <tr><td style="font-weight:500;">Total Checks Executed</td><td>{len(result.results)}</td></tr>
                <tr><td style="font-weight:500;">Frameworks Covered</td><td>{len(categories)}</td></tr>
                <tr><td style="font-weight:500;">Auto-Fixable Issues</td><td>{fixable}</td></tr>
                <tr><td style="font-weight:500;">Scan Duration</td><td>{result.duration_seconds} seconds</td></tr>
                <tr><td style="font-weight:500;">Tool Version</td><td>tibet-audit v{__version__}</td></tr>
            </tbody>
        </table>
    </div>

    <div class="footer">
        <p>
            Generated by <a href="https://humotica.com">tibet-audit</a> v{__version__}
            &nbsp;|&nbsp; {date_str} {time_str}
            &nbsp;|&nbsp; Scan ID: {result.scan_id}
        </p>
        <p style="margin-top:4px;">
            IETF Draft: <a href="https://datatracker.ietf.org/doc/draft-vandemeent-jis-identity/">draft-vandemeent-jis-identity</a>
            &nbsp;|&nbsp; Research: <a href="https://doi.org/10.5281/zenodo.18712238">doi:10.5281/zenodo.18712238</a>
        </p>
    </div>

</div>
</body>
</html>"""

    # Write to file if path specified
    if output_path:
        Path(output_path).write_text(html, encoding="utf-8")

    return html


def _severity_order(severity: Severity) -> int:
    """Sort order: CRITICAL first."""
    return {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFO: 4,
    }.get(severity, 5)


def _severity_color(severity: Severity) -> str:
    """HTML color for severity."""
    return {
        Severity.CRITICAL: "#dc2626",
        Severity.HIGH: "#ef4444",
        Severity.MEDIUM: "#eab308",
        Severity.LOW: "#22c55e",
        Severity.INFO: "#6b7280",
    }.get(severity, "#6b7280")
