"""
tibet_audit.auditor_report — Auditor / Accountant Export (-bd)
==============================================================

Clean, structured export for auditors, accountants, and regulators.
No technical jargon, no emoji, no colors. Just the facts:
- What was checked
- What passed / what didn't
- TIBET provenance hashes
- Timestamps and scan metadata

Output formats: JSON (default), CSV

Usage:
    tibet-audit scan -bd
    tibet-audit scan -bd --bd-output report.json
    tibet-audit scan -bd --bd-format csv

Authors: Jasper van de Meent & Root AI
License: MIT
"""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime
from typing import Optional
from pathlib import Path

from .checks.base import Status, Severity
from . import __version__


# Human-readable labels — no tech jargon
_STATUS_LABELS = {
    Status.PASSED: "Compliant",
    Status.WARNING: "Needs Review",
    Status.FAILED: "Non-Compliant",
    Status.SKIPPED: "Not Applicable",
}

_SEVERITY_LABELS = {
    Severity.CRITICAL: "Critical",
    Severity.HIGH: "High",
    Severity.MEDIUM: "Medium",
    Severity.LOW: "Low",
    Severity.INFO: "Informational",
}

_CATEGORY_LABELS = {
    "gdpr": "EU General Data Protection Regulation",
    "ai_act": "EU Artificial Intelligence Act",
    "nis2": "EU NIS2 Directive",
    "jis": "JIS Identity & Consent",
    "sovereignty": "Data Sovereignty",
    "provider": "Provider Security",
    "humotica": "Organisational Controls",
    "health": "System Health",
    "pipa": "Korea Personal Information Protection Act",
    "appi": "Japan Act on Protection of Personal Information",
    "pdpa": "Singapore Personal Data Protection Act",
    "au_privacy": "Australia Privacy Act",
    "lgpd": "Brazil General Data Protection Law",
    "gulf": "Gulf Personal Data Protection Law",
    "ndpr": "Nigeria Data Protection Regulation",
    "ucp": "Unfair Commercial Practices",
    "penguin": "Antarctic Treaty Protocol",
    "bio2": "Dutch Baseline Information Security Government 2",
    "dora": "EU Digital Operational Resilience Act",
}


def generate_auditor_report(
    result,
    org_name: str = "Organization",
    framework: Optional[str] = None,
    output_path: Optional[str] = None,
    fmt: str = "json",
) -> str:
    """Generate a clean auditor/accountant export.

    Args:
        result: ScanResult from scanner
        org_name: Organization name
        framework: Optional framework filter
        output_path: Optional path to write file
        fmt: Output format — 'json' or 'csv'

    Returns:
        Formatted string (JSON or CSV)
    """
    now = datetime.now()

    # Build structured finding list
    findings = []
    for r in result.results:
        cat = getattr(r, "category", "general") or "general"
        findings.append({
            "id": r.check_id,
            "description": r.name,
            "regulation": _CATEGORY_LABELS.get(cat, cat),
            "verdict": _STATUS_LABELS.get(r.status, str(r.status)),
            "priority": _SEVERITY_LABELS.get(r.severity, str(r.severity)),
            "detail": r.message or "",
            "action_required": r.recommendation or "",
            "auto_remediable": getattr(r, "can_auto_fix", False),
        })

    # Compute per-regulation summary
    reg_summary = {}
    for f in findings:
        reg = f["regulation"]
        if reg not in reg_summary:
            reg_summary[reg] = {"compliant": 0, "non_compliant": 0, "needs_review": 0, "total": 0}
        reg_summary[reg]["total"] += 1
        if f["verdict"] == "Compliant":
            reg_summary[reg]["compliant"] += 1
        elif f["verdict"] == "Non-Compliant":
            reg_summary[reg]["non_compliant"] += 1
        elif f["verdict"] == "Needs Review":
            reg_summary[reg]["needs_review"] += 1

    if fmt == "csv":
        return _to_csv(result, org_name, now, findings, output_path)

    # JSON report
    report = {
        "report_type": "compliance_audit",
        "report_version": "1.0",
        "generated": now.isoformat(),
        "tool": f"tibet-audit v{__version__}",
        "organisation": org_name,
        "scan": {
            "id": result.scan_id,
            "path": result.scan_path,
            "timestamp": result.timestamp.isoformat() if hasattr(result.timestamp, 'isoformat') else str(result.timestamp),
            "duration_seconds": result.duration_seconds,
        },
        "summary": {
            "score": result.score,
            "grade": result.grade,
            "total_checks": len(result.results),
            "compliant": result.passed,
            "non_compliant": result.failed,
            "needs_review": result.warnings,
            "not_applicable": result.skipped,
        },
        "regulation_breakdown": reg_summary,
        "findings": findings,
        "provenance": {
            "protocol": "TIBET (Token Identity Based Evidence Trail)",
            "scan_id": result.scan_id,
            "tool_version": __version__,
            "ietf_draft": "draft-vandemeent-jis-identity",
            "doi": "10.5281/zenodo.18712238",
        },
    }

    if framework:
        report["scope"] = {"framework": framework.upper()}

    output = json.dumps(report, indent=2, ensure_ascii=False)

    if output_path:
        Path(output_path).write_text(output, encoding="utf-8")

    return output


def _to_csv(result, org_name: str, now: datetime, findings: list, output_path: Optional[str]) -> str:
    """Generate CSV export."""
    buf = io.StringIO()
    writer = csv.writer(buf)

    # Header row
    writer.writerow([
        "Check ID",
        "Description",
        "Regulation",
        "Verdict",
        "Priority",
        "Detail",
        "Action Required",
        "Auto-Remediable",
    ])

    for f in findings:
        writer.writerow([
            f["id"],
            f["description"],
            f["regulation"],
            f["verdict"],
            f["priority"],
            f["detail"],
            f["action_required"],
            "Yes" if f["auto_remediable"] else "No",
        ])

    # Summary footer (as comment rows)
    writer.writerow([])
    writer.writerow(["# Report Metadata"])
    writer.writerow(["# Organisation", org_name])
    writer.writerow(["# Score", f"{result.score}/100 (Grade {result.grade})"])
    writer.writerow(["# Scan ID", result.scan_id])
    writer.writerow(["# Generated", now.isoformat()])
    writer.writerow(["# Tool", f"tibet-audit v{__version__}"])

    output = buf.getvalue()

    if output_path:
        Path(output_path).write_text(output, encoding="utf-8")

    return output
