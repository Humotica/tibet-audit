"""Governance conclusion synthesis for tibet-audit."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .checks.base import Status


DIRECT_EVIDENCE_NAMES = {
    "what": (
        "ai-sbom.json",
        "sbom.json",
        "bom.json",
    ),
    "how": (
        "audit.jsonl",
        "trail.jsonl",
        "tibet-trail.jsonl",
        "cbom.json",
        "continuity.json",
        "continuityd-audit.jsonl",
        "gateway.jsonl",
    ),
    "who": (
        "ains_registry.json",
        "aindex.json",
    ),
    "why": (
        "jis_grants.json",
        "ainternet_sessions.json",
        "phantom_sessions.json",
        "ai_teams_sessions.json",
        "kevin_sessions.json",
        "jis_handoff_history.json",
    ),
}

STACK_PACKAGE_MAP = {
    "what": ("tibet-ai-sbom", "tibet-sbom"),
    "how": ("tibet-core", "tibet-cbom"),
    "who": ("ainternet",),
    "why": ("jis-core",),
}

INDIRECT_PATTERNS = {
    "what": (
        r"\btibet-ai-sbom\b",
        r"\btibet-sbom\b",
        r"\bai-sbom\b",
        r"\bsbom\b",
    ),
    "how": (
        r"\btibet-cbom\b",
        r"\bcbom\b",
        r"\bprovenance\b",
        r"\bcontinuity\b",
        r"\btibet\b",
    ),
    "who": (
        r"\bains\b",
        r"\.aint\b",
        r"\baindex\b",
        r"\bactor\b",
    ),
    "why": (
        r"\bjis\b",
        r"\bpubkey_fingerprint\b",
        r"\bsignature\b",
        r"\battestation\b",
    ),
}

CATEGORY_MAP = {
    "how": {"tibet"},
    "who": {"ains"},
    "why": {"jis"},
}


def _candidate_files(scan_path: Path, limit: int = 250) -> list[Path]:
    """Collect a bounded set of files for light governance evidence scanning."""
    discovered: list[Path] = []
    seen: set[str] = set()

    preferred = (
        "pyproject.toml",
        "requirements.txt",
        "README.md",
        "ai-sbom.json",
        "sbom.json",
        "ains_registry.json",
        "aindex.json",
        "jis_grants.json",
    )
    for name in preferred:
        path = scan_path / name
        if path.exists() and path.is_file():
            seen.add(str(path))
            discovered.append(path)

    for path in scan_path.rglob("*"):
        if len(discovered) >= limit:
            break
        if not path.is_file():
            continue
        if any(part.startswith(".git") or part == ".venv" or part == "__pycache__" for part in path.parts):
            continue
        key = str(path)
        if key in seen:
            continue
        seen.add(key)
        discovered.append(path)
    return discovered


def _safe_read_text(path: Path, max_chars: int = 20000) -> str:
    """Read file text conservatively for pattern matching."""
    try:
        return path.read_text(encoding="utf-8", errors="ignore")[:max_chars]
    except Exception:
        return ""


def _collect_evidence_refs(scan_path: Path) -> dict[str, dict[str, list[str]]]:
    """Collect direct and indirect evidence refs per governance dimension."""
    refs: dict[str, dict[str, list[str]]] = {
        key: {"direct": [], "indirect": []}
        for key in ("what", "how", "who", "why")
    }

    files = _candidate_files(scan_path)
    for path in files:
        name_l = path.name.lower()
        text_l = _safe_read_text(path).lower()

        for dim, names in DIRECT_EVIDENCE_NAMES.items():
            if name_l in names or any(token in str(path).lower() for token in names):
                refs[dim]["direct"].append(str(path))

        for dim, patterns in INDIRECT_PATTERNS.items():
            if any(re.search(pattern, text_l, re.IGNORECASE) for pattern in patterns):
                refs[dim]["indirect"].append(str(path))

    for dim in refs:
        refs[dim]["direct"] = sorted(set(refs[dim]["direct"]))[:20]
        refs[dim]["indirect"] = sorted(set(refs[dim]["indirect"]))[:20]
    return refs


def _workspace_root_candidates(scan_path: Path) -> list[Path]:
    """Return likely workspace roots around the scan path."""
    candidates = [scan_path]
    current = scan_path
    for _ in range(5):
        current = current.parent
        candidates.append(current)
    return candidates


def _detect_stack_sources(scan_path: Path) -> dict[str, list[dict[str, str]]]:
    """Detect nearby upstream stack packages and supporting documents."""
    sources: dict[str, list[dict[str, str]]] = {
        key: []
        for key in ("what", "how", "who", "why")
    }
    seen: set[tuple[str, str]] = set()

    for root in _workspace_root_candidates(scan_path):
        packages_dir = root / "packages"
        if packages_dir.exists():
            for dim, package_names in STACK_PACKAGE_MAP.items():
                for name in package_names:
                    package_root = packages_dir / name
                    if package_root.exists():
                        key = (dim, str(package_root))
                        if key in seen:
                            continue
                        seen.add(key)
                        sources[dim].append({
                            "kind": "package",
                            "name": name,
                            "path": str(package_root),
                        })
        compliance_dir = root / "compliance"
        if compliance_dir.exists():
            for name in ("sbom.json", "ai-sbom.json", "cbom.json"):
                path = compliance_dir / name
                if not path.exists():
                    continue
                dim = "what" if "sbom" in name and "cbom" not in name else "how"
                key = (dim, str(path))
                if key in seen:
                    continue
                seen.add(key)
                sources[dim].append({
                    "kind": "document",
                    "name": name,
                    "path": str(path),
                })
    return sources


def _category_summary(results: list[Any], categories: set[str]) -> dict[str, int]:
    """Summarize passed/warning/failed counts for relevant categories."""
    summary = {"passed": 0, "warning": 0, "failed": 0}
    for result in results:
        category = getattr(result, "category", None)
        if category not in categories:
            continue
        if result.status == Status.PASSED:
            summary["passed"] += 1
        elif result.status == Status.WARNING:
            summary["warning"] += 1
        elif result.status == Status.FAILED:
            summary["failed"] += 1
    return summary


def _dimension_status(
    direct_refs: list[str],
    indirect_refs: list[str],
    category_summary: dict[str, int] | None = None,
) -> str:
    """Translate evidence presence into sufficient/partial/weak/absent."""
    category_summary = category_summary or {"passed": 0, "warning": 0, "failed": 0}
    if direct_refs:
        if category_summary["failed"] == 0 and (category_summary["passed"] > 0 or category_summary["warning"] > 0):
            return "sufficient"
        return "partial"
    if indirect_refs:
        return "weak"
    if category_summary["passed"] > 0 or category_summary["warning"] > 0 or category_summary["failed"] > 0:
        return "partial"
    return "absent"


def _iter_event_like_records(scan_path: Path, limit: int = 500) -> list[dict[str, Any]]:
    """Collect lightweight event-like records from JSON/JSONL files near the scan path."""
    records: list[dict[str, Any]] = []
    candidates = [
        scan_path / "gateway.jsonl",
        scan_path / "ai-sbom.json",
        scan_path / "sbom.json",
        scan_path / "compliance" / "ai-sbom.json",
        scan_path / "compliance" / "sbom.json",
    ]
    for path in candidates:
        if not path.exists() or not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore").strip()
        except Exception:
            continue
        if not text:
            continue
        if path.suffix.lower() == ".jsonl":
            for line in text.splitlines():
                if len(records) >= limit:
                    return records
                line = line.strip()
                if not line:
                    continue
                try:
                    payload = json.loads(line)
                except Exception:
                    continue
                if isinstance(payload, dict):
                    records.append(payload)
            continue
        try:
            payload = json.loads(text)
        except Exception:
            continue
        if isinstance(payload, dict):
            governance = payload.get("governance")
            if isinstance(governance, dict) and isinstance(governance.get("usage_events"), list):
                for item in governance["usage_events"]:
                    if len(records) >= limit:
                        return records
                    if isinstance(item, dict):
                        records.append(item)
            elif isinstance(payload.get("usage_events"), list):
                for item in payload["usage_events"]:
                    if len(records) >= limit:
                        return records
                    if isinstance(item, dict):
                        records.append(item)
            else:
                records.append(payload)
    return records


def _operational_lane_summary(scan_path: Path) -> dict[str, Any]:
    """Summarize lane/collision/coffee semantics observed in nearby event evidence."""
    records = _iter_event_like_records(scan_path)
    summary: dict[str, Any] = {
        "event_count": 0,
        "sources": [],
        "lane_classes": {},
        "lane_collision_policies": {},
        "coffee_lane_policies": {},
        "emitters": {},
    }
    for record in records:
        route = record.get("route") if isinstance(record.get("route"), dict) else record
        evidence = record.get("evidence") if isinstance(record.get("evidence"), dict) else {}
        source = evidence.get("source") or record.get("observation_layer")
        if source:
            summary["sources"].append(str(source))
        summary["event_count"] += 1
        for key, bucket_name in (
            ("lane_class", "lane_classes"),
            ("lane_collision_policy", "lane_collision_policies"),
            ("coffee_lane_policy", "coffee_lane_policies"),
        ):
            value = route.get(key)
            if isinstance(value, str) and value:
                bucket = summary[bucket_name]
                bucket[value] = int(bucket.get(value, 0)) + 1
        emitter = evidence.get("emitter") or record.get("_emitter")
        if isinstance(emitter, str) and emitter:
            emitters = summary["emitters"]
            emitters[emitter] = int(emitters.get(emitter, 0)) + 1
    summary["sources"] = sorted(set(summary["sources"]))[:20]
    return summary


def evaluate_coffee_lane(
    actor_id: str,
    *,
    is_known: bool = True,
    trust_score: float | None = None,
    recent_failures: int = 0,
    endpoint_down: bool = False,
    time_diff_seconds: float | None = None,
    diff_threshold_seconds: int = 3600,
) -> dict[str, Any]:
    """Return a coffee-lane recommendation from live governance signals."""
    if time_diff_seconds is not None:
        if time_diff_seconds < 60:
            return {"actor_id": actor_id, "coffee_lane_policy": "freeze_resume", "coffee_reason": f"time_diff_seconds={time_diff_seconds:.0f}<60"}
        if time_diff_seconds < diff_threshold_seconds:
            return {"actor_id": actor_id, "coffee_lane_policy": "fork_on_hop_off", "coffee_reason": f"time_diff_seconds={time_diff_seconds:.0f}<{diff_threshold_seconds}"}
        if time_diff_seconds < 86400:
            return {"actor_id": actor_id, "coffee_lane_policy": "rebuild", "coffee_reason": f"time_diff_seconds={time_diff_seconds:.0f}>=diff_threshold"}
        return {"actor_id": actor_id, "coffee_lane_policy": "hard_avoid", "coffee_reason": f"time_diff_seconds={time_diff_seconds:.0f}>=86400"}
    if not is_known:
        return {"actor_id": actor_id, "coffee_lane_policy": "polite_avoid", "coffee_reason": "actor_unknown"}
    if trust_score is not None and trust_score < 0.3:
        return {"actor_id": actor_id, "coffee_lane_policy": "hard_avoid", "coffee_reason": f"actor_trust_score={trust_score:.2f}"}
    if recent_failures > 3:
        return {"actor_id": actor_id, "coffee_lane_policy": "rebuild", "coffee_reason": f"recent_failures={recent_failures}"}
    if endpoint_down:
        return {"actor_id": actor_id, "coffee_lane_policy": "offline_fallback", "coffee_reason": "endpoint_down"}
    return {"actor_id": actor_id, "coffee_lane_policy": "sip_anyway", "coffee_reason": "healthy_lane"}


def build_governance_conclusion(result: Any, scan_path: str | Path) -> dict[str, Any]:
    """Synthesize a governance conclusion over WHAT/HOW/WHO/WHY."""
    root = Path(scan_path).resolve()
    refs = _collect_evidence_refs(root)
    stack_sources = _detect_stack_sources(root)
    operational_summary = _operational_lane_summary(root)
    statuses: dict[str, str] = {}
    summaries: dict[str, dict[str, int]] = {}

    for dim in ("what", "how", "who", "why"):
        categories = CATEGORY_MAP.get(dim, set())
        summary = _category_summary(result.results, categories) if categories else {"passed": 0, "warning": 0, "failed": 0}
        summaries[dim] = summary
        direct_refs = refs[dim]["direct"] + [item["path"] for item in stack_sources.get(dim, [])]
        statuses[dim] = _dimension_status(sorted(set(direct_refs)), refs[dim]["indirect"], summary)

    sufficient = sum(1 for status in statuses.values() if status == "sufficient")
    absent = sum(1 for status in statuses.values() if status == "absent")
    weak = sum(1 for status in statuses.values() if status == "weak")

    if absent == 0 and weak == 0 and sufficient >= 3:
        confidence = "high"
    elif absent <= 1 and weak <= 2:
        confidence = "medium"
    else:
        confidence = "low"

    if sufficient == 4 and result.failed == 0 and result.score >= 90:
        profile = "fully-compliant-candidate"
    elif sufficient >= 3 and confidence == "high":
        profile = "full"
    elif confidence in {"high", "medium"}:
        profile = "substantiated"
    else:
        profile = "baseline"

    coffee_lane = evaluate_coffee_lane(
        "system",
        is_known=statuses["who"] != "absent",
        trust_score=0.2 if statuses["why"] == "absent" else 0.8,
        recent_failures=result.failed,
        endpoint_down=False,
        time_diff_seconds=None,
    )

    return {
        "what_status": statuses["what"],
        "how_status": statuses["how"],
        "who_status": statuses["who"],
        "why_status": statuses["why"],
        "overall_governance_confidence": confidence,
        "governance_profile": profile,
        "conclusion_basis": ["ai-sbom", "cbom", "ains", "jis"],
        "coffee_lane_recommendation": coffee_lane,
        "operational_lane_summary": operational_summary,
        "stack_sources": stack_sources,
        "evidence_refs": {
            "ai_sbom_evidence_ref": {
                **refs["what"],
                "stack": stack_sources["what"],
            },
            "cbom_evidence_ref": {
                **refs["how"],
                "stack": stack_sources["how"],
            },
            "ains_evidence_ref": {
                **refs["who"],
                "stack": stack_sources["who"],
            },
            "jis_evidence_ref": {
                **refs["why"],
                "stack": stack_sources["why"],
            },
        },
        "category_summaries": summaries,
    }
