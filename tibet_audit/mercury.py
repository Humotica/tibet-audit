"""Project MERCURY helpers: report building, roadmap, upgrades, diff, high-five."""

from __future__ import annotations

import json
import os
import time
import uuid
import hashlib
from typing import Any, Dict, List, Optional

from .checks.base import Status, Severity, CheckResult
from . import __version__


def build_report(result, profile: Optional[str] = None, include_tibet: bool = True) -> Dict[str, Any]:
    """Build a structured report dict from ScanResult.

    Args:
        result: ScanResult from scanner
        profile: Optional scan profile name
        include_tibet: Include TIBET stack recommendations for failed checks
    """
    # Enrich results with TIBET recommendations if requested
    if include_tibet:
        from .tibet_recommendations import enrich_results
        enrich_results(result.results)

    return {
        "meta": {
            "tool_version": __version__,
            "scan_time": result.timestamp.isoformat(),
            "target": result.scan_path,
            "profile": profile or "default",
        },
        "summary": {
            "score": result.score,
            "grade": result.grade,
            "failed": result.failed,
            "passed": result.passed,
            "warnings": result.warnings,
            "skipped": result.skipped,
            "duration_seconds": result.duration_seconds,
        },
        "results": [_result_dict(r) for r in result.results],
    }


def generate_roadmap(result) -> List[Dict[str, Any]]:
    """Create a staged roadmap from failed/warned checks."""
    stage_1 = []
    stage_2 = []
    stage_3 = []

    for r in result.results:
        if r.status == Status.PASSED:
            continue
        item = {
            "check_id": r.check_id,
            "name": r.name,
            "severity": r.severity.value,
            "status": r.status.value,
            "rationale": r.message,
        }
        if r.can_auto_fix or r.severity in (Severity.LOW, Severity.MEDIUM):
            stage_1.append(item)
        elif r.severity == Severity.HIGH:
            stage_2.append(item)
        else:
            stage_3.append(item)

    return [
        {"stage": "Stage 1 - Quick Wins", "items": stage_1[:10]},
        {"stage": "Stage 2 - Policy + Process", "items": stage_2[:10]},
        {"stage": "Stage 3 - High Risk / Strategic", "items": stage_3[:10]},
    ]


def generate_upgrades(result) -> List[Dict[str, Any]]:
    """Create value-based upgrade suggestions."""
    scored = []
    for r in result.results:
        if r.status == Status.PASSED:
            continue
        score = _severity_weight(r.severity) * 10 + (r.score_impact or 0)
        if r.can_auto_fix:
            score += 5
        scored.append((score, r))

    scored.sort(key=lambda x: x[0], reverse=True)
    upgrades = []
    for score, r in scored[:5]:
        upgrades.append({
            "title": r.name,
            "check_id": r.check_id,
            "roi_score": score,
            "rationale": r.message,
        })
    return upgrades


def diff_reports(old_report: Dict[str, Any], new_report: Dict[str, Any]) -> Dict[str, Any]:
    """Compute compliance drift between two reports."""
    old_score = old_report.get("summary", {}).get("score", 0)
    new_score = new_report.get("summary", {}).get("score", 0)

    old_failed = {r["check_id"] for r in old_report.get("results", []) if r["status"] == "failed"}
    new_failed = {r["check_id"] for r in new_report.get("results", []) if r["status"] == "failed"}

    newly_failed = sorted(new_failed - old_failed)
    resolved = sorted(old_failed - new_failed)

    return {
        "score_delta": new_score - old_score,
        "newly_failed": newly_failed,
        "resolved": resolved,
    }


# High-five endpoint is OFF by default — a sovereign audit tool phones no one.
# Opt in with AUDIT_HIGH_FIVE_URL (or pass server_url) to send a handshake ping.
DEFAULT_HIGH_FIVE_URL = ""


def high_five(server_url: Optional[str] = None) -> Dict[str, Any]:
    """Send a signed handshake ping. No scan data is transmitted.

    Off by default: with no endpoint configured this is a no-op (sovereign,
    local-only, no external party). Opt in via AUDIT_HIGH_FIVE_URL or server_url.
    """
    url = server_url or os.getenv("AUDIT_HIGH_FIVE_URL", DEFAULT_HIGH_FIVE_URL)
    if not url:
        return {"status": "skipped",
                "reason": "no high-five endpoint configured (off by default)"}

    payload = {
        "timestamp": int(time.time()),
        "nonce": str(uuid.uuid4()),
        "tool_version": __version__,
    }
    payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    secret = os.getenv("TIBET_SECRET", "dev-secret")
    key_id = os.getenv("TIBET_KEY_ID", "default")

    signature = _sign_payload(payload_json, secret, key_id)

    body = {
        "payload": payload,
        "signature": signature,
        "key_id": key_id,
        "context": "audit-tool:high-five",
    }

    try:
        import requests
        resp = requests.post(url, json=body, timeout=1.5)
        return {"status": "ok", "http_status": resp.status_code}
    except Exception as exc:
        return {"status": "error", "error": str(exc)}


def _result_dict(r: CheckResult) -> Dict[str, Any]:
    d = {
        "check_id": r.check_id,
        "name": r.name,
        "status": r.status.value,
        "severity": r.severity.value,
        "message": r.message,
        "recommendation": r.recommendation,
        "references": r.references,
        "score_impact": r.score_impact,
        "category": getattr(r, "category", None),
        "fix_action": _fix_dict(r.fix_action) if r.fix_action else None,
    }
    # Include TIBET recommendation if enriched
    tibet_rec = getattr(r, "tibet_recommendation", None)
    if tibet_rec:
        d["tibet_recommendation"] = {
            "title": tibet_rec.get("title"),
            "packages": tibet_rec.get("packages", []),
            "install": tibet_rec.get("install"),
            "description": tibet_rec.get("description"),
            "snippet": tibet_rec.get("snippet"),
            "references": tibet_rec.get("references", []),
        }
    return d


def _fix_dict(fix) -> Dict[str, Any]:
    return {
        "description": fix.description,
        "command": fix.command,
        "risk_level": fix.risk_level,
    }


def _severity_weight(sev: Severity) -> int:
    return {
        Severity.CRITICAL: 5,
        Severity.HIGH: 4,
        Severity.MEDIUM: 3,
        Severity.LOW: 2,
        Severity.INFO: 1,
    }.get(sev, 1)


def _sign_payload(payload_json: str, secret: str, key_id: str) -> str:
    try:
        import tibet_rs
        return tibet_rs.tibet_sign_ctx_kid(payload_json, secret, "audit-tool:high-five", key_id)
    except Exception:
        raw = f"{key_id}:{payload_json}:{secret}".encode()
        return hashlib.sha256(raw).hexdigest()
