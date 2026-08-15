from __future__ import annotations

import json
import hashlib
from pathlib import Path

from tibet_audit.iab import (
    build_iab_mirror,
    filter_iab_mirror,
    render_iab_report_html,
    render_iab_report_markdown,
)

LEGACY_AINT = "test" + ".aint"
LEGACY_PERSON = "rich" + "ard"
LEGACY_CODE = "red" + "baron"
LEGACY_CODE_SPACED = "red" + " baron"
LEGACY_LAB_ONE = "hack" + "box"
LEGACY_LAB_TWO = "are" + "na"


def _append(path: Path, *records: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(record) for record in records) + "\n", encoding="utf-8")


def _chain(path: Path, *records: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    prev = ""
    lines = []
    for record in records:
        row = dict(record)
        row["prev"] = prev
        line = json.dumps(row) + "\n"
        lines.append(line)
        prev = hashlib.sha256(line.encode()).hexdigest()
    path.write_text("".join(lines), encoding="utf-8")


def test_iab_mirror_projects_human_ai_roles_and_raints(tmp_path: Path):
    _append(
        tmp_path / "tibet" / "history.jsonl",
        {
            "ts": 1,
            "phase": "presence",
            "actor": "jasper.aint",
            "presence": True,
            "rvp": "rvp-1",
            "method": "pam-fingerprint",
            "assurance": "H1",
            "raint": f"raint-alpha.{LEGACY_AINT}",
            "status": "0x4000",
        },
        {
            "ts": 2,
            "phase": "actor.work",
            "actor": "qwen.aint",
            "surface": "tool.echo.waint",
            "raint": f"raint-alpha.{LEGACY_AINT}",
            "status": "0x4000",
        },
        {
            "ts": 3,
            "phase": "system.seal",
            "actor": "system.saint",
            "raint": f"raint-beta.{LEGACY_AINT}",
            "status": "0x0000:surface-not-in-relation",
        },
    )

    mirror = build_iab_mirror(tmp_path)

    assert mirror["summary"]["runtimes"] == 1
    assert mirror["summary"]["events"] == 3
    assert mirror["summary"]["binding_counts"]["human"] == 1
    assert mirror["summary"]["binding_counts"]["ai"] == 2
    assert mirror["summary"]["role_counts"]["operator"] == 1
    assert mirror["summary"]["role_counts"]["waint"] == 1
    assert mirror["summary"]["role_counts"]["saint"] == 1

    by_raint = {row["raint"]: row for row in mirror["raints"]}
    assert by_raint["raint-alpha"]["state"] == "live"
    assert by_raint["raint-beta"]["state"] == "dark"
    assert "tool.echo.waint" in by_raint["raint-alpha"]["surfaces"]

    controls = {item["id"]: item for item in mirror["framework_controls"]}
    assert controls["runtime_traceability"]["status"] == "PASS"
    assert controls["human_oversight_and_accountability"]["status"] == "PASS"
    assert "DORA ICT risk management" in controls["runtime_traceability"]["frameworks"]
    assert mirror["framework_summary"]["DORA"]["PASS"] >= 1
    assert mirror["fleet"]["posture"] == "governed"
    assert mirror["fleet"]["materiality"] == "low"


def test_iab_mirror_marks_dark_jis_as_no_binding(tmp_path: Path):
    _append(
        tmp_path / "triage" / "events.jsonl",
        {
            "ts": 10,
            "event": "raised",
            "actor": "qwen.aint",
            "target": "egress",
            "jis": {"actor": {"state": "dark"}},
            "raint": f"raint-dark.{LEGACY_AINT}",
        },
    )

    mirror = build_iab_mirror(tmp_path)

    event = mirror["events"][0]
    assert event["binding"]["class"] == "no-binding"
    assert event["binding"]["reason"] == "actor-jis-dark"
    assert mirror["conclusions"]["iab.human_oversight"]["status"] == "FAIL"
    assert mirror["fleet"]["materiality"] == "high"
    assert mirror["fleet"]["posture"] == "needs-review"


def test_iab_mirror_filters_by_binding_role_surface_and_status(tmp_path: Path):
    _append(
        tmp_path / "enclave" / "mux-events.jsonl",
        {
            "ts": 1,
            "phase": "route",
            "from_aint": f"raint-a.{LEGACY_AINT}",
            "surface": "audit.aint",
            "result": "0x4000",
        },
        {
            "ts": 2,
            "phase": "route",
            "from_aint": f"raint-b.{LEGACY_AINT}",
            "surface": "capture.this",
            "result": "0x0000:surface-not-in-relation",
        },
    )

    mirror = build_iab_mirror(tmp_path)

    refused = filter_iab_mirror(mirror, status_prefix="0x0000")
    assert len(refused["events"]) == 1
    assert refused["events"][0]["surface"] == "capture.this"

    audit_surface = filter_iab_mirror(mirror, surface="audit.aint")
    assert len(audit_surface["events"]) == 1
    assert audit_surface["events"][0]["status"] == "0x4000"

    raint_a = filter_iab_mirror(mirror, raint="raint-a")
    assert len(raint_a["events"]) == 1
    assert raint_a["events"][0]["raint"] == "raint-a"


def test_iab_mirror_reads_legacy_raw_notes_without_overcounting_no_binding(tmp_path: Path):
    _append(
        tmp_path / "tibet" / "history.jsonl",
        {
            "kind": "org.ainternet.box.tibet-tick.v1",
            "phase": "enroll",
            "ts": 1,
            "note": "ceremony: p520.aint (human) named as this box identity",
            "prev": "",
        },
        {
            "kind": "org.ainternet.box.tibet-tick.v1",
            "phase": "presence.unbound",
            "ts": 2,
            "note": "operator chose --no-binding (bare, unsafe)",
            "prev": "",
        },
        {
            "kind": "org.ainternet.box.tibet-tick.v1",
            "phase": "up",
            "ts": 3,
            "note": "session enrollment (genesis)",
            "prev": "",
        },
        {
            "kind": "org.ainternet.box.tibet-tick.v1",
            "phase": "handshake-recv-sealed",
            "ts": 4,
            "note": "opened sealed offer from jasper.aint",
            "prev": "",
        },
    )

    mirror = build_iab_mirror(tmp_path)

    assert mirror["summary"]["binding_counts"]["human"] == 1
    assert mirror["summary"]["binding_counts"]["ai"] == 1
    assert mirror["summary"]["binding_counts"]["no-binding"] == 2
    assert mirror["summary"]["binding_posture_counts"]["system_infra"] == 1
    assert mirror["events"][0]["actor"] == "p520.aint"
    assert mirror["events"][3]["actor"] == "jasper.aint"
    assert mirror["events"][1]["binding"]["reason"] == "explicit-no-binding"


def test_iab_mirror_reads_normalized_audit_projection_records(tmp_path: Path):
    _append(
        tmp_path / "audit_projection.jsonl",
        {
            "kind": "org.ainternet.audit.projection.v1",
            "projection_id": "proj-1",
            "box_id": "p520.aint",
            "runtime_id": "run-live",
            "session_id": "sess-1",
            "raint": f"raint-proj.{LEGACY_AINT}",
            "role": "waint",
            "actor": f"{LEGACY_PERSON}.{LEGACY_AINT}",
            "operator": "jasper.aint",
            "binding": {
                "class": "human",
                "reason": f"presence from {LEGACY_PERSON}.{LEGACY_AINT}",
                "presence": True,
            },
            "surface": "audit.aint",
            "lane": "session",
            "action": "doom.session.start",
            "status": "0x4000",
            "materiality": "medium",
            "box_posture": "bound",
            "runtime_posture": "active",
            "prev": "",
            "self": "abc123",
            "head": "abc123",
            "chain_id": "projection-main",
            "ts": 5,
        },
    )

    mirror = build_iab_mirror(tmp_path)
    event = mirror["events"][0]
    payload = json.dumps(mirror).lower()
    html = render_iab_report_html(mirror).lower()

    assert event["source"] == "projection"
    assert event["projection_id"] == "proj-1"
    assert event["box_id"] == "p520.aint"
    assert event["session_id"] == "sess-1"
    assert event["raint"] == "raint-proj"
    assert event["role"] == "waint"
    assert event["binding"]["class"] == "human"
    assert event["binding"]["presence"] is True
    assert event["materiality"] == "medium"
    assert event["box_posture"] == "bound"
    assert event["runtime_posture"] == "active"
    assert LEGACY_AINT not in payload
    assert LEGACY_PERSON not in payload
    assert LEGACY_AINT not in html
    assert LEGACY_PERSON not in html


def test_iab_projection_suppresses_raw_twin_by_source_ref(tmp_path: Path):
    raw = tmp_path / "tibet" / "history.jsonl"
    _append(
        raw,
        {
            "kind": "org.ainternet.box.tibet-tick.v1",
            "phase": "enroll",
            "ts": 1,
            "note": "ceremony: jasper.aint (human)",
            "prev": "",
            "self": "raw-head",
        },
    )
    _append(
        tmp_path / "tibet" / "audit_projection.jsonl",
        {
            "kind": "org.ainternet.audit.projection.v1",
            "projection_id": "proj-dedup",
            "source_ref": {"path": str(raw), "line": 1, "sha256": "box-side"},
            "box_id": "jasper.aint",
            "raint": "raint-dedup.aint",
            "role": "operator",
            "actor": "jasper.aint",
            "binding": {"class": "human", "reason": "enroll-human-ceremony", "presence": True},
            "action": "enroll",
            "status": "0x4000",
            "ts": 1,
            "causal_head": "raw-head",
        },
    )

    mirror = build_iab_mirror(tmp_path)

    assert mirror["summary"]["events"] == 1
    assert mirror["events"][0]["source"] == "projection.tibet"
    assert mirror["events"][0]["projection_id"] == "proj-dedup"
    assert mirror["events"][0]["causal"]["head"] == "raw-head"
    assert mirror["summary"]["binding_counts"] == {"human": 1, "ai": 0, "no-binding": 0}


def test_iab_binding_posture_splits_system_and_authorized_headless_without_fourth_class(tmp_path: Path):
    _append(
        tmp_path / "tibet" / "audit_projection.jsonl",
        {
            "kind": "org.ainternet.audit.projection.v1",
            "projection_id": "sys",
            "role": "system",
            "binding": {"class": "no-binding", "reason": "missing-actor-and-presence"},
            "action": "launch",
            "ts": 1,
        },
        {
            "kind": "org.ainternet.audit.projection.v1",
            "projection_id": "headless",
            "role": "actor",
            "actor": "worker.aint",
            "granted_by": "jasper.aint",
            "mandate": "grant:headless-ok",
            "binding": {"class": "no-binding", "reason": "headless-mandate"},
            "action": "run",
            "ts": 2,
        },
        {
            "kind": "org.ainternet.audit.projection.v1",
            "projection_id": "escaped",
            "role": "actor",
            "actor": "unknown.aint",
            "binding": {"class": "no-binding", "reason": "explicit-no-binding"},
            "action": "run",
            "ts": 3,
        },
    )

    mirror = build_iab_mirror(tmp_path)
    postures = mirror["summary"]["binding_posture_counts"]

    assert mirror["summary"]["binding_counts"] == {"human": 0, "ai": 0, "no-binding": 3}
    assert postures["system_infra"] == 1
    assert postures["authorized_headless"] == 1
    assert postures["escaped_unbound"] == 1
    assert mirror["events"][1]["granted_by"] == "jasper.aint"
    assert mirror["events"][1]["binding_posture"]["class"] == "authorized_headless"
    assert mirror["conclusions"]["iab.human_oversight"]["status"] == "FAIL"
    assert mirror["fleet"]["materiality"] == "high"


def test_iab_system_infra_no_binding_is_not_human_oversight_failure(tmp_path: Path):
    _append(
        tmp_path / "tibet" / "audit_projection.jsonl",
        {
            "kind": "org.ainternet.audit.projection.v1",
            "projection_id": "sys",
            "role": "system",
            "binding": {"class": "no-binding", "reason": "missing-actor-and-presence"},
            "action": "reseed",
            "ts": 1,
        },
    )

    mirror = build_iab_mirror(tmp_path)

    assert mirror["summary"]["binding_counts"]["no-binding"] == 1
    assert mirror["summary"]["binding_posture_counts"]["system_infra"] == 1
    assert mirror["conclusions"]["iab.human_oversight"]["status"] == "PASS"
    assert mirror["fleet"]["materiality"] == "low"


def test_iab_audit_summary_tick_note_is_not_read_as_explicit_no_binding(tmp_path: Path):
    # The local-audit tick records the audit's OWN counts ("... no-binding 3 ...") — a self-describing summary,
    # not a no-binding ACTION. Its descriptive note must never trip explicit-no-binding / escaped_unbound, or the
    # audit would flag its own governance summary as a risk (a self-referential false positive). Converges the
    # box projector and the tibet mirror on the same reading.
    _append(
        tmp_path / "enclave" / "work-ledger.jsonl",
        {
            "kind": "org.ainternet.box.tibet-tick.v1",
            "event": "local-audit",
            "ts": 1,
            "note": "governance view: human 64 · ai 97 · no-binding 3 · causal-broken",
            "prev": "",
        },
    )

    mirror = build_iab_mirror(tmp_path)

    ev = mirror["events"][0]
    assert ev["binding"]["reason"] != "explicit-no-binding"
    assert ev["binding_posture"]["class"] != "escaped_unbound"
    assert mirror["summary"]["binding_posture_counts"]["escaped_unbound"] == 0


def test_iab_node_up_is_system_infra_even_with_actor_like_subject(tmp_path: Path):
    _append(
        tmp_path / "tibet" / "audit_projection.jsonl",
        {
            "kind": "org.ainternet.audit.projection.v1",
            "projection_id": "node-up",
            "event": "node.up",
            "note": "base runtime · raint-dc867ad0.test.aint",
            "actor": "raint-dc867ad0.test.aint",
            "binding": {"class": "ai", "reason": "actor-only"},
            "ts": 1,
        },
    )

    mirror = build_iab_mirror(tmp_path)
    ev = mirror["events"][0]

    assert ev["role"] == "system"
    assert ev["role_reason"] == "runtime-lifecycle"
    assert ev["binding"] == {"class": "no-binding", "reason": "system-event"}
    assert ev["binding_posture"]["class"] == "system_infra"
    assert mirror["conclusions"]["iab.human_oversight"]["status"] == "PASS"


def test_iab_node_up_does_not_absorb_causal_break_as_binding_risk(tmp_path: Path):
    _append(
        tmp_path / "enclave" / "work-ledger.jsonl",
        {
            "ts": 1,
            "event": "doom.close",
            "actor": "worker.aint",
            "note": "close previous workload",
            "prev": "",
        },
        {
            "ts": 2,
            "event": "node.up",
            "note": "base runtime · raint-dc867ad0.test.aint",
            "prev": "not-the-previous-head",
        },
    )

    mirror = build_iab_mirror(tmp_path)
    node_up = [event for event in mirror["events"] if event["action"] == "node.up"][0]

    assert node_up["binding_posture"]["class"] == "system_infra"
    assert mirror["causal_integrity"]["verdict"] == "broken"
    assert mirror["conclusions"]["iab.causal_integrity"]["status"] == "FAIL"
    assert mirror["conclusions"]["iab.human_oversight"]["status"] == "PASS"


def test_iab_session_governance_groups_lifecycle_and_open_sessions(tmp_path: Path):
    _append(
        tmp_path / "audit_projection.jsonl",
        {
            "kind": "org.ainternet.audit.projection.v1",
            "projection_id": "start",
            "session_id": "sess-open",
            "raint": "raint-session.aint",
            "actor": "worker.aint",
            "binding": {"class": "ai", "reason": "actor-only"},
            "action": "doom.session.start",
            "ts": 1,
        },
        {
            "kind": "org.ainternet.audit.projection.v1",
            "projection_id": "resume",
            "session_id": "sess-open",
            "raint": "raint-session.aint",
            "actor": "worker.aint",
            "binding": {"class": "ai", "reason": "actor-only"},
            "action": "doom.session.resume",
            "ts": 2,
        },
        {
            "kind": "org.ainternet.audit.projection.v1",
            "projection_id": "closed-start",
            "session_id": "sess-closed",
            "raint": "raint-session.aint",
            "actor": "worker.aint",
            "binding": {"class": "ai", "reason": "actor-only"},
            "action": "doom.session.start",
            "ts": 3,
        },
        {
            "kind": "org.ainternet.audit.projection.v1",
            "projection_id": "closed-stop",
            "session_id": "sess-closed",
            "raint": "raint-session.aint",
            "actor": "worker.aint",
            "binding": {"class": "ai", "reason": "actor-only"},
            "action": "doom.session.stop",
            "ts": 4,
        },
    )

    mirror = build_iab_mirror(tmp_path)
    sessions = {row["session_id"]: row for row in mirror["sessions"]}
    report = render_iab_report_markdown(mirror)

    assert mirror["summary"]["sessions"] == 2
    assert mirror["summary"]["open_sessions"] == 1
    assert sessions["sess-open"]["open"] is True
    assert sessions["sess-open"]["starts"] == 1
    assert sessions["sess-open"]["resumes"] == 1
    assert sessions["sess-closed"]["open"] is False
    assert sessions["sess-closed"]["stops"] == 1
    assert "## Session Governance" in report


def test_iab_actor_aint_does_not_become_raint_bucket(tmp_path: Path):
    _append(
        tmp_path / "tibet" / "history.jsonl",
        {
            "kind": "org.ainternet.box.tibet-tick.v1",
            "phase": "identity-import",
            "node": "jasper.aint",
            "actor": "codie.aint",
            "note": "actor-only tick",
            "ts": 1,
        },
    )

    mirror = build_iab_mirror(tmp_path)

    assert mirror["events"][0]["raint"] == "raint:unknown"
    assert mirror["summary"]["unknown_raints"] == 1
    assert {row["raint"] for row in mirror["raints"]} == {"raint:unknown"}


def test_iab_mirror_reports_intact_causal_chain(tmp_path: Path):
    _chain(
        tmp_path / "tibet" / "history.jsonl",
        {"ts": 1, "phase": "allocate", "raint": f"raint-chain.{LEGACY_AINT}", "status": "0x4000"},
        {"ts": 2, "phase": "seal", "raint": f"raint-chain.{LEGACY_AINT}", "status": "0x4000"},
    )

    mirror = build_iab_mirror(tmp_path)

    assert mirror["causal_integrity"]["verdict"] == "intact"
    assert mirror["causal_integrity"]["checked"] == 1
    assert mirror["conclusions"]["iab.causal_integrity"]["status"] == "PASS"


def test_iab_mirror_fails_broken_causal_chain(tmp_path: Path):
    path = tmp_path / "tibet" / "history.jsonl"
    _chain(
        path,
        {"ts": 1, "phase": "allocate", "raint": f"raint-broken.{LEGACY_AINT}", "status": "0x4000"},
        {"ts": 2, "phase": "seal", "raint": f"raint-broken.{LEGACY_AINT}", "status": "0x4000"},
    )
    path.write_text(path.read_text(encoding="utf-8").replace("allocate", "tampered", 1), encoding="utf-8")

    mirror = build_iab_mirror(tmp_path)

    assert mirror["causal_integrity"]["verdict"] == "broken"
    assert mirror["conclusions"]["iab.causal_integrity"]["status"] == "FAIL"
    assert mirror["causal_integrity"]["broken"][0]["source"] == "ledger"
    assert mirror["fleet"]["materiality"] == "critical"
    assert mirror["fleet"]["posture"] == "blocked"


def test_iab_report_marks_open_tail_as_governance_warning(tmp_path: Path):
    _chain(
        tmp_path / "enclave" / "work-ledger.jsonl",
        {
            "ts": 1,
            "phase": "request",
            "note": "awaiting validation",
            "actor": "qwen.aint",
            "raint": f"raint-open.{LEGACY_AINT}",
        },
    )

    mirror = build_iab_mirror(tmp_path)
    report = render_iab_report_markdown(mirror)
    dora_report = render_iab_report_markdown(mirror, framework="dora")

    assert mirror["conclusions"]["iab.causal_integrity"]["status"] == "WARN"
    assert mirror["framework_controls"][3]["id"] == "tamper_evident_evidence"
    assert mirror["framework_controls"][3]["status"] == "WARN"
    assert mirror["fleet"]["materiality"] == "medium"
    assert "## Open Tails" in report
    assert "## Framework Control Mapping" in report
    assert "## Framework Control Mapping (dora)" in dora_report
    assert "`DORA operational resilience`" in dora_report
    assert "`EU AI Act human oversight`" not in dora_report
    assert "awaiting validation" in report


def test_iab_html_report_renders_standalone_and_escapes_values(tmp_path: Path):
    _append(
        tmp_path / "tibet" / "history.jsonl",
        {
            "ts": 1,
            "phase": "presence<script>",
            "actor": "jasper.aint",
            "presence": True,
            "raint": f"raint-html.{LEGACY_AINT}",
            "status": "0x4000",
        },
    )

    mirror = build_iab_mirror(tmp_path)
    html = render_iab_report_html(mirror, framework="nis2")

    assert "<!doctype html>" in html
    assert "Fleet Overview" in html
    assert "Framework Readout" in html
    assert "Framework Control Mapping" in html
    assert "NIS2 Art.21" in html
    assert "presence&lt;script&gt;" in html
    assert "presence<script>" not in html


def test_iab_reports_scrub_legacy_test_and_redteam_refs(tmp_path: Path):
    _append(
        tmp_path / "tibet" / "history.jsonl",
        {
            "ts": 1,
            "phase": f"{LEGACY_CODE} handoff",
            "actor": f"{LEGACY_PERSON}.{LEGACY_AINT}",
            "note": f"{LEGACY_CODE_SPACED} legacy-lab from raint-clean.{LEGACY_AINT}",
            "surface": f"{LEGACY_LAB_TWO}.{LEGACY_LAB_ONE}",
            "raint": f"raint-clean.{LEGACY_AINT}",
            "status": "0x4000",
        },
    )

    mirror = build_iab_mirror(tmp_path)
    payload = json.dumps(mirror).lower()
    markdown = render_iab_report_markdown(mirror).lower()
    html = render_iab_report_html(mirror).lower()

    for rendered in (payload, markdown, html):
        assert LEGACY_AINT not in rendered
        assert LEGACY_PERSON not in rendered
        assert LEGACY_CODE not in rendered
        assert LEGACY_CODE_SPACED not in rendered
        assert LEGACY_LAB_ONE not in rendered
    assert mirror["events"][0]["actor"] == "legacy-redteam"
    assert mirror["events"][0]["raint"] == "raint-clean"


def test_iab_mirror_discovers_multiple_child_runs_as_network(tmp_path: Path):
    _append(
        tmp_path / "box-a" / "tibet" / "history.jsonl",
        {
            "ts": 1,
            "phase": "presence",
            "actor": "jasper.aint",
            "presence": True,
            "raint": f"raint-a.{LEGACY_AINT}",
            "status": "0x4000",
        },
    )
    _append(
        tmp_path / "box-b" / "enclave" / "mux-events.jsonl",
        {
            "ts": 2,
            "phase": "route",
            "from_aint": f"raint-b.{LEGACY_AINT}",
            "surface": "audit.aint",
            "result": "0x4000",
        },
    )

    mirror = build_iab_mirror(tmp_path)

    assert mirror["summary"]["runtimes"] == 2
    assert mirror["summary"]["raints"] == 2
    assert {row["raint"] for row in mirror["raints"]} == {"raint-a", "raint-b"}
