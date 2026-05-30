from __future__ import annotations

import json
from pathlib import Path

from tibet_audit.cockpit import (
    build_cockpit_snapshot,
    classify_event,
    discover_evidence_sources,
    load_tail_events,
    summarize_posture,
)
from tibet_audit.correlation import build_evidence_chains
from tibet_audit.evidence_adapters import assess_sources


def test_discover_evidence_sources_counts_jsonl_records(tmp_path: Path):
    audit_log = tmp_path / "continuityd-audit.jsonl"
    audit_log.write_text(
        json.dumps({"ts": 1, "name": "first", "disposition_hint": "reseal-candidate"}) + "\n"
        + json.dumps({"ts": 2, "name": "second", "disposition_hint": "trusted-candidate"}) + "\n",
        encoding="utf-8",
    )

    sources = discover_evidence_sources(tmp_path)
    by_name = {source.name: source for source in sources}

    assert "continuityd-audit.jsonl" in by_name
    assert by_name["continuityd-audit.jsonl"].records == 2
    assert by_name["continuityd-audit.jsonl"].latest_ts == "2"
    assert by_name["continuityd-audit.jsonl"].status == "active"


def test_load_tail_events_parses_recent_jsonl(tmp_path: Path):
    log = tmp_path / "gateway.jsonl"
    log.write_text(
        "\n".join(json.dumps({"ts": i, "event_id": f"evt_{i}"}) for i in range(5)) + "\n",
        encoding="utf-8",
    )

    events = load_tail_events(log, lines=2)

    assert [event["event_id"] for event in events] == ["evt_3", "evt_4"]
    assert events[0]["_source"] == str(log)


def test_classify_event_marks_quarantine_as_warning():
    finding = classify_event({
        "name": "agent-drop.exe",
        "disposition_hint": "quarantine",
        "intake_class": "executable",
    })

    assert finding.severity == "warning"
    assert "quarantine" in finding.message


def test_build_cockpit_snapshot_surfaces_posture_and_summary(tmp_path: Path):
    (tmp_path / "cap-bus-events.jsonl").write_text(
        json.dumps({
            "ts": 10,
            "intent": "posture.transition.v1",
            "surface": "posture-transition:quarantine_external_ai",
            "switches_changed": ["deny_external_ai_inbound"],
        }) + "\n",
        encoding="utf-8",
    )

    snapshot = build_cockpit_snapshot(tmp_path, lines=5)

    assert snapshot["summary"]["active_evidence_sources"] == 1
    assert snapshot["summary"]["latest_events"] == 1
    assert snapshot["findings"][0]["severity"] == "info"
    assert snapshot["posture"] in {"observed", "attention", "degraded"}
    assert snapshot["posture_summary"]["deny_external_ai_inbound"] is True
    assert snapshot["readiness_lanes"]
    assert snapshot["next_actions"]


def test_summarize_posture_extracts_switch_contract():
    summary = summarize_posture([
        {
            "event_id": "posture_demo",
            "intent": "posture.transition.v1",
            "from_posture": "normal_zero_trust",
            "to_posture": "quarantine_external_ai",
            "switches_changed": [
                "deny_external_ai_inbound",
                "require_airlock_marker_on_tokens",
            ],
        },
        {
            "name": "drop.exe",
            "disposition_hint": "quarantine",
            "intake_class": "executable",
        },
    ])

    assert summary["current_posture"] == "quarantine_external_ai"
    assert summary["deny_external_ai_inbound"] is True
    assert summary["require_airlock_marker_on_tokens"] is True
    assert summary["quarantine_events"] == 1


def test_evidence_adapters_assess_typed_sources():
    assessments = assess_sources({
        "continuityd-audit.jsonl": [
            {"stage": "sniff", "intake_class": "json-text", "disposition_hint": "reseal-candidate"},
            {"stage": "sniff", "intake_class": "executable", "disposition_hint": "quarantine"},
        ],
        "snaft-audit.jsonl": [
            {"engine": "snaft", "default_policy": "deny", "fail_mode": "closed", "verdict": "deny"},
        ],
        "cmail-events.jsonl": [
            {"kind": "cmail.message.v1", "content_hash": "sha256:abc", "message_type": "command"},
        ],
        "cortex-events.jsonl": [
            {"system": "tibet-cortex", "cortex_level": "L4"},
        ],
    })

    by_adapter = {item["adapter"]: item for item in assessments}
    assert by_adapter["continuityd"]["status"] == "attention"
    assert by_adapter["snaft"]["signals"]["fail_closed"] is True
    assert by_adapter["cmail"]["signals"]["commands"] == 1
    assert by_adapter["tibet-cortex"]["signals"]["levels"]["L4"] == 1


def test_build_evidence_chains_correlates_external_ai_containment():
    chains = build_evidence_chains([
        {
            "_source": "cap-bus-events.jsonl",
            "intent": "posture.transition.v1",
            "from_posture": "normal_zero_trust",
            "to_posture": "quarantine_external_ai",
            "switches_changed": ["deny_external_ai_inbound"],
        },
        {
            "_source": "snaft-audit.jsonl",
            "engine": "snaft",
            "verdict": "deny",
            "reason": "deny_external_ai_inbound ON",
        },
        {
            "_source": "continuityd-audit.jsonl",
            "name": "agent-drop.exe",
            "disposition_hint": "quarantine",
        },
        {
            "_source": "cmail-events.jsonl",
            "kind": "cmail.message.v1",
            "subject": "External AI quarantined",
            "message_type": "command",
            "content_hash": "sha256:abc",
        },
    ])

    by_id = {chain["chain_id"]: chain for chain in chains}
    chain = by_id["chain_external_ai_containment"]
    assert chain["status"] == "partial"
    assert len(chain["steps"]) == 4
    assert "gateway lane policy event" in chain["missing_links"]
