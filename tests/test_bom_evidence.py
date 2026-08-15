from __future__ import annotations

import json
from pathlib import Path

from tibet_audit.bom_evidence import build_bom_evidence
from tibet_audit.iab import build_iab_mirror


def _write(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj), encoding="utf-8")


def test_bom_evidence_grades_present_and_missing_tolerantly(tmp_path: Path):
    # a runtime system-bom with hash + components + a runtime link → complete
    _write(tmp_path / "system-bom-abc.json", {
        "kind": "org.ainternet.box.system-bom.v1",
        "system_bom_sha256": "deadbeef", "sensors": [1, 2, 3], "host": "box.aint", "timestamp": 1,
    })
    bom = build_bom_evidence(str(tmp_path))
    fam = {e["key"]: e for e in bom["family"]}
    assert fam["system-bom"]["present"] is True
    assert fam["system-bom"]["posture"] == "complete"
    assert fam["system-bom"]["component_count"] == 3
    # a missing family member is a POSTURE, never a hard failure
    assert fam["ai-sbom"]["present"] is False
    assert fam["ai-sbom"]["posture"] == "missing"
    assert bom["summary"]["present"] == 1


def test_bom_ai_sbom_kind_is_not_grabbed_by_sbom_substring(tmp_path: Path):
    # ai-sbom.json must match the ai-sbom member by KIND, never fall to sbom because "sbom" ⊂ "ai-sbom"
    _write(tmp_path / "ai-sbom.json", {"kind": "org.ainternet.iab.ai-sbom.v1", "models": []})
    _write(tmp_path / "sbom.json", {"kind": "org.ainternet.iab.sbom.v1", "primary_components": [1, 2]})
    bom = build_bom_evidence(str(tmp_path))
    fam = {e["key"]: e for e in bom["family"]}
    assert fam["ai-sbom"]["present"] is True
    assert fam["sbom"]["present"] is True
    assert fam["sbom"].get("instances", 1) == 1  # sbom did not also swallow ai-sbom


def test_bom_extra_roots_and_revived_instance_count(tmp_path: Path):
    # runtime holds one sys-bom; a separate manifests dir (extra_roots) holds the shipped family; a revived box can
    # carry two sys-boms → newest is the headline but the instance count states the mess.
    run = tmp_path / "run"
    man = tmp_path / "manifests"
    _write(run / "system-bom-old.json", {"kind": "org.ainternet.box.system-bom.v1", "hash": "a", "host": "b", "timestamp": 1})
    _write(run / "system-bom-new.json", {"kind": "org.ainternet.box.system-bom.v1", "hash": "b", "host": "b", "timestamp": 9})
    _write(man / "cbom.json", {"kind": "org.ainternet.iab.cbom.v1", "algorithms": ["ed25519"]})
    bom = build_bom_evidence(str(run), extra_roots=[str(man)])
    fam = {e["key"]: e for e in bom["family"]}
    assert fam["system-bom"]["instances"] == 2
    assert fam["system-bom"]["timestamp"] == 9  # newest kept as headline
    assert fam["cbom"]["present"] is True


def test_build_iab_mirror_carries_bom_evidence(tmp_path: Path):
    _write(tmp_path / "tibet" / "history.jsonl", {"kind": "org.ainternet.box.tibet-tick.v1", "phase": "up", "ts": 1, "note": "boot", "prev": ""})
    _write(tmp_path / "system-bom-x.json", {"kind": "org.ainternet.box.system-bom.v1", "system_bom_sha256": "ab", "sensors": [1], "host": "b.aint", "timestamp": 1})
    mirror = build_iab_mirror(tmp_path)
    assert "bom_evidence" in mirror
    fam = {e["key"]: e for e in mirror["bom_evidence"]["family"]}
    assert fam["system-bom"]["present"] is True
