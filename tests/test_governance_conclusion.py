from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from tibet_audit.checks.base import CheckResult, Severity, Status
from tibet_audit.governance_conclusion import build_governance_conclusion, evaluate_coffee_lane
from tibet_audit.scanner import ScanResult


def _result(check_id: str, category: str, status: Status) -> CheckResult:
    return CheckResult(
        check_id=check_id,
        name=check_id,
        status=status,
        severity=Severity.MEDIUM,
        category=category,
        message="",
    )


def test_governance_conclusion_uses_direct_evidence_and_category_results(tmp_path: Path):
    (tmp_path / "ai-sbom.json").write_text("{}", encoding="utf-8")
    (tmp_path / "ains_registry.json").write_text('{"domains":{}}', encoding="utf-8")
    (tmp_path / "jis_grants.json").write_text('{"grants":[]}', encoding="utf-8")
    tibet_dir = tmp_path / ".tibet" / "provenance"
    tibet_dir.mkdir(parents=True)
    (tibet_dir / "audit.jsonl").write_text("", encoding="utf-8")

    scan = ScanResult(
        timestamp=datetime.now(),
        scan_path=str(tmp_path),
        score=90,
        grade="A",
        passed=3,
        warnings=0,
        failed=0,
        skipped=0,
        results=[
            _result("TIBET-001", "tibet", Status.PASSED),
            _result("AINS-001", "ains", Status.PASSED),
            _result("JIS-001", "jis", Status.PASSED),
        ],
        duration_seconds=0.1,
    )

    conclusion = build_governance_conclusion(scan, tmp_path)
    assert conclusion["what_status"] == "partial" or conclusion["what_status"] == "sufficient"
    assert conclusion["how_status"] == "sufficient"
    assert conclusion["who_status"] == "sufficient"
    assert conclusion["why_status"] == "sufficient"
    assert conclusion["overall_governance_confidence"] in {"high", "medium"}
    assert conclusion["governance_profile"] in {"full", "substantiated", "fully-compliant-candidate"}
    assert conclusion["evidence_refs"]["cbom_evidence_ref"]["direct"]
    assert conclusion["coffee_lane_recommendation"]["coffee_lane_policy"] == "sip_anyway"


def test_governance_conclusion_degrades_when_evidence_is_absent(tmp_path: Path):
    scan = ScanResult(
        timestamp=datetime.now(),
        scan_path=str(tmp_path),
        score=20,
        grade="F",
        passed=0,
        warnings=0,
        failed=1,
        skipped=0,
        results=[
            _result("JIS-001", "jis", Status.FAILED),
        ],
        duration_seconds=0.1,
    )

    conclusion = build_governance_conclusion(scan, tmp_path)
    assert conclusion["why_status"] == "partial"
    assert conclusion["overall_governance_confidence"] == "low"
    assert conclusion["governance_profile"] == "baseline"
    assert conclusion["coffee_lane_recommendation"]["coffee_lane_policy"] == "polite_avoid"


def test_evaluate_coffee_lane_supports_time_diff_and_failure_paths():
    assert evaluate_coffee_lane("actor", time_diff_seconds=15)["coffee_lane_policy"] == "freeze_resume"
    assert evaluate_coffee_lane("actor", time_diff_seconds=300)["coffee_lane_policy"] == "fork_on_hop_off"
    assert evaluate_coffee_lane("actor", recent_failures=4)["coffee_lane_policy"] == "rebuild"
    assert evaluate_coffee_lane("actor", endpoint_down=True)["coffee_lane_policy"] == "offline_fallback"


def test_governance_conclusion_collects_operational_lane_summary(tmp_path: Path):
    (tmp_path / "gateway.jsonl").write_text(
        json.dumps({
            "observation_layer": "tibet-gateway",
            "lane_class": "agent-high",
            "lane_collision_policy": "graceful_yield",
            "coffee_lane_policy": "fork_on_hop_off",
            "_emitter": "cap-bus-runtime",
        }) + "\n" + json.dumps({
            "observation_layer": "tibet-gateway",
            "lane_class": "fork-alpha",
            "lane_collision_policy": "override_all",
            "coffee_lane_policy": "sip_anyway",
            "_emitter": "cap-bus-runtime",
        }) + "\n",
        encoding="utf-8",
    )

    scan = ScanResult(
        timestamp=datetime.now(),
        scan_path=str(tmp_path),
        score=70,
        grade="B",
        passed=1,
        warnings=1,
        failed=0,
        skipped=0,
        results=[_result("TIBET-001", "tibet", Status.PASSED)],
        duration_seconds=0.1,
    )

    conclusion = build_governance_conclusion(scan, tmp_path)
    summary = conclusion["operational_lane_summary"]
    assert summary["event_count"] == 2
    assert summary["lane_classes"]["agent-high"] == 1
    assert summary["lane_collision_policies"]["override_all"] == 1
    assert summary["coffee_lane_policies"]["fork_on_hop_off"] == 1
    assert summary["emitters"]["cap-bus-runtime"] == 2
