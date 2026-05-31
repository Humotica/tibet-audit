"""Tests for tibet_audit.genesis — T-1 Genesis assessment for M4 pre-grant gap."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tibet_audit.genesis import (
    assess_genesis_events,
    is_genesis_event,
)


FIXTURE_PATH = (
    Path(__file__).resolve().parent.parent
    / "examples"
    / "p520-passive"
    / "genesis-events.jsonl"
)


def _load_fixture_records():
    if not FIXTURE_PATH.exists():
        pytest.skip(f"fixture missing at {FIXTURE_PATH}")
    out = []
    for line in FIXTURE_PATH.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        out.append(json.loads(line))
    return out


def test_is_genesis_event_recognises_t1_kind():
    assert is_genesis_event({"kind": "tibet.genesis.t-1.v1"}) is True
    assert is_genesis_event({"kind": "gateway-event.v1"}) is False
    assert is_genesis_event({}) is False


def test_assess_on_empty_records_returns_absent():
    a = assess_genesis_events([])
    assert a["status"] == "absent"
    assert a["candidate_count"] == 0


def test_assess_on_fixture_covers_4_variants():
    """Codex' p520 fixture covers 4 M4 variants — clean, dirty, fork, blocked."""
    records = _load_fixture_records()
    a = assess_genesis_events(records)
    assert a["candidate_count"] == len(records)
    # Status should be attention because we have blocked + forked
    assert a["status"] == "attention"
    assert a["ready_count"] >= 1
    assert a["blocked_count"] >= 1
    assert a["forked_count"] >= 1


def test_assess_content_hash_is_stable():
    """Same input → same content_hash (assessment is deterministic)."""
    records = _load_fixture_records()
    a1 = assess_genesis_events(records)
    a2 = assess_genesis_events(records)
    assert a1["content_hash"] == a2["content_hash"]


def test_ready_candidate_marks_ok_finding():
    ready_record = {
        "kind": "tibet.genesis.t-1.v1",
        "tool_id": "mcp:filesystem",
        "airlock_verdict": "clean",
        "merge_to_t0_verdict": "ready",
    }
    a = assess_genesis_events([ready_record])
    assert a["ready_count"] == 1
    assert a["status"] == "ready"
    assert a["findings"][0]["severity"] == "ok"


def test_blocked_candidate_marks_warning():
    blocked_record = {
        "kind": "tibet.genesis.t-1.v1",
        "tool_id": "mcp:hostile",
        "airlock_verdict": "poisoned",
        "merge_to_t0_verdict": "no-grant",
    }
    a = assess_genesis_events([blocked_record])
    assert a["blocked_count"] == 1
    assert a["status"] == "attention"


def test_forked_candidate_marks_warning():
    forked_record = {
        "kind": "tibet.genesis.t-1.v1",
        "tool_id": "mcp:mutated",
        "airlock_verdict": "fork",
        "merge_to_t0_verdict": "fork",
    }
    a = assess_genesis_events([forked_record])
    assert a["forked_count"] == 1
    assert a["status"] == "attention"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
