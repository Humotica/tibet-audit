"""Operational audit cockpit helpers.

This module keeps the professional operator surface separate from the legacy
scanner/reporting commands. It only reads local files and package metadata.
"""

from __future__ import annotations

import importlib.metadata
import json
import shutil
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable

from .correlation import build_evidence_chains
from .evidence_adapters import assess_sources


JSONL_HINTS = (
    "audit.jsonl",
    "continuityd-audit.jsonl",
    "continuityd.jsonl",
    "gateway.jsonl",
    "gateway-events.jsonl",
    "cap-bus.jsonl",
    "cap-bus-events.jsonl",
    "snaft.jsonl",
    "snaft-audit.jsonl",
    "pol-verdicts.jsonl",
    "cmail.jsonl",
    "cmail-events.jsonl",
    "cortex.jsonl",
    "cortex-events.jsonl",
    "trail.jsonl",
    "tibet-trail.jsonl",
)

JSON_HINTS = (
    "ai-sbom.json",
    "sbom.json",
    "cbom.json",
    "nis2.json",
    "wayback.json",
    "tibet-system.json",
)

SEARCH_DIRS = (
    ".",
    ".tibet",
    ".tibet/provenance",
    ".tibet/audit",
    "audit",
    "audits",
    "evidence",
    "reports",
    "compliance",
    "logs",
    "var/log/tibet",
    "var/lib/tibet",
)

SYSTEM_DIRS = (
    "/var/log/tibet",
    "/var/lib/tibet",
    "/root/.tibet",
    "/root/.snaft",
)

PACKAGE_GROUPS = {
    "core": ("tibet-core", "jis-core"),
    "daemon": ("tibet-continuityd", "tibet-gateway", "tibet-cap-bus"),
    "evidence": (
        "tibet-audit",
        "tibet-sbom",
        "tibet-cbom",
        "tibet-ai-sbom",
        "ai-sbom",
        "tibet-wayback",
        "tibet-report",
        "tibet-trail",
        "tibet-nis2",
    ),
    "agentic": ("ainternet", "ipoll", "tibet-cmail", "tibet-phantom", "tibet-context"),
    "safety": ("snaft", "tibet-airlock", "tibet-triage", "tibet-pol"),
    "runtime": ("tibet-trust-kernel", "snaft-core", "tibet-zip-core", "tibet-cortex-core"),
}

BINARIES = (
    "tibet",
    "tibet-continuityd",
    "tcd",
    "tibet-gateway",
    "tibet-cap-bus",
    "snaft",
    "tibet-pol",
    "tibet-ping",
    "ipoll",
    "tibet-cmail",
    "cmail",
    "tbz",
    "tibet-zip",
)


@dataclass(frozen=True)
class EvidenceSource:
    name: str
    path: str
    kind: str
    exists: bool
    records: int
    latest_ts: str | None
    status: str


@dataclass(frozen=True)
class ComponentStatus:
    name: str
    kind: str
    group: str
    status: str
    version: str | None = None
    path: str | None = None


@dataclass(frozen=True)
class CockpitFinding:
    severity: str
    source: str
    message: str
    record: dict[str, Any]


@dataclass(frozen=True)
class ReadinessLane:
    name: str
    status: str
    reason: str
    required: tuple[str, ...]
    observed: tuple[str, ...]


def _candidate_dirs(root: Path, include_system: bool) -> list[Path]:
    dirs = [root / rel for rel in SEARCH_DIRS]
    if include_system:
        dirs.extend(Path(p) for p in SYSTEM_DIRS)
    seen: set[str] = set()
    unique = []
    for path in dirs:
        key = str(path.resolve()) if path.exists() else str(path)
        if key not in seen:
            seen.add(key)
            unique.append(path)
    return unique


def _read_json_line(line: str) -> dict[str, Any] | None:
    try:
        value = json.loads(line)
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, dict) else None


def _latest_ts(records: Iterable[dict[str, Any]]) -> str | None:
    latest: Any = None
    for record in records:
        ts = record.get("ts") or record.get("timestamp") or record.get("time") or record.get("created_at")
        if ts is not None:
            latest = ts
    return str(latest) if latest is not None else None


def _summarize_jsonl(path: Path) -> tuple[int, str | None]:
    count = 0
    recent: list[dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                if not line.strip():
                    continue
                count += 1
                record = _read_json_line(line)
                if record:
                    recent.append(record)
                    recent = recent[-25:]
    except OSError:
        return 0, None
    return count, _latest_ts(recent)


def _summarize_json(path: Path) -> tuple[int, str | None]:
    try:
        value = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return 0, None
    if isinstance(value, list):
        records = len(value)
    elif isinstance(value, dict):
        records = 1
    else:
        records = 0
    latest = _latest_ts(value if isinstance(value, list) else [value] if isinstance(value, dict) else [])
    return records, latest


def discover_evidence_sources(path: str | Path = ".", include_system: bool = False) -> list[EvidenceSource]:
    root = Path(path)
    candidates: dict[Path, str] = {}
    for directory in _candidate_dirs(root, include_system):
        for name in JSONL_HINTS:
            candidates[directory / name] = "jsonl"
        for name in JSON_HINTS:
            candidates[directory / name] = "json"

    sources: list[EvidenceSource] = []
    for candidate, kind in sorted(candidates.items(), key=lambda item: str(item[0])):
        if not candidate.exists() or not candidate.is_file():
            continue
        records, latest = _summarize_jsonl(candidate) if kind == "jsonl" else _summarize_json(candidate)
        status = "active" if records else "empty"
        sources.append(
            EvidenceSource(
                name=candidate.name,
                path=str(candidate),
                kind=kind,
                exists=True,
                records=records,
                latest_ts=latest,
                status=status,
            )
        )
    return sources


def load_tail_events(path: str | Path, lines: int = 25) -> list[dict[str, Any]]:
    source = Path(path)
    if not source.exists():
        return []
    raw: list[str] = []
    try:
        with source.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                if line.strip():
                    raw.append(line)
                    raw = raw[-max(lines, 1):]
    except OSError:
        return []
    events: list[dict[str, Any]] = []
    for line in raw:
        record = _read_json_line(line)
        if record is None:
            record = {"message": line.strip(), "_parse_error": True}
        record.setdefault("_source", str(source))
        events.append(record)
    return events


def latest_events(sources: list[EvidenceSource], lines: int = 25) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for source in sources:
        if source.kind == "jsonl":
            events.extend(load_tail_events(source.path, lines=min(lines, 10)))
    return events[-max(lines, 1):]


def source_event_map(sources: list[EvidenceSource], lines_per_source: int = 200) -> dict[str, list[dict[str, Any]]]:
    mapped: dict[str, list[dict[str, Any]]] = {}
    for source in sources:
        if source.kind == "jsonl":
            mapped[source.path] = load_tail_events(source.path, lines=lines_per_source)
    return mapped


def detect_components() -> list[ComponentStatus]:
    components: list[ComponentStatus] = []
    for group, packages in PACKAGE_GROUPS.items():
        for package in packages:
            try:
                version = importlib.metadata.version(package)
            except importlib.metadata.PackageNotFoundError:
                version = None
            components.append(
                ComponentStatus(
                    name=package,
                    kind="package",
                    group=group,
                    status="installed" if version else "missing",
                    version=version,
                )
            )

    for binary in BINARIES:
        path = shutil.which(binary)
        components.append(
            ComponentStatus(
                name=binary,
                kind="binary",
                group="operator",
                status="available" if path else "missing",
                path=path,
            )
        )
    return components


def classify_event(record: dict[str, Any]) -> CockpitFinding:
    source = str(record.get("_source") or record.get("observation_layer") or record.get("_emitter") or "event")
    disposition = str(record.get("disposition_hint") or "")
    intake = str(record.get("intake_class") or "")
    name = str(
        record.get("name")
        or record.get("event_id")
        or record.get("kind")
        or record.get("intent")
        or record.get("subject")
        or record.get("lane_class")
        or record.get("verdict")
        or record.get("cortex_level")
        or "event"
    )
    switches = record.get("switches_changed") or record.get("switches") or []

    if disposition in {"quarantine", "reject", "triage-disguised"}:
        return CockpitFinding("warning", source, f"{name}: {disposition} ({intake})", record)
    if "cmail" in str(record.get("kind", "")):
        subject = record.get("subject") or name
        message_type = record.get("message_type") or "message"
        return CockpitFinding("info", source, f"cmail {message_type}: {subject}", record)
    if record.get("engine") == "snaft" or "snaft" in source:
        verdict = record.get("verdict") or record.get("action") or "verdict"
        reason = record.get("reason") or "-"
        severity = "warning" if verdict in {"deny", "block", "quarantine"} else "ok"
        return CockpitFinding(severity, source, f"SNAFT {verdict}: {reason}", record)
    if record.get("operator") == "tibet-pol" or "pol-verdict" in source:
        state = record.get("approval_state") or record.get("decision") or "decision"
        subject = record.get("subject") or name
        return CockpitFinding("info", source, f"tibet-pol {state}: {subject}", record)
    if record.get("observation_layer") == "tibet-gateway" or "gateway" in source:
        lane = record.get("lane_class") or name
        policy = record.get("lane_collision_policy") or "-"
        return CockpitFinding("info", source, f"gateway lane {lane}: {policy}", record)
    if record.get("system") == "tibet-cortex" or "cortex" in source:
        level = record.get("cortex_level") or record.get("trust_level") or name
        subject = record.get("subject") or "-"
        return CockpitFinding("info", source, f"cortex {level}: {subject}", record)
    if record.get("posture") or "posture" in str(record.get("intent", "")):
        return CockpitFinding("info", source, f"{name}: posture event", record)
    if switches:
        count = len(switches) if isinstance(switches, list) else "multiple"
        return CockpitFinding("info", source, f"{name}: {count} switches changed", record)
    if disposition:
        return CockpitFinding("ok", source, f"{name}: {disposition} ({intake})", record)
    if record.get("_parse_error"):
        return CockpitFinding("warning", source, f"{name}: unparsed log line", record)
    return CockpitFinding("info", source, name, record)


def summarize_posture(events: list[dict[str, Any]]) -> dict[str, Any]:
    transitions: list[dict[str, Any]] = []
    active_switches: set[str] = set()
    quarantine_events = 0
    current_posture: str | None = None

    for event in events:
        intent = str(event.get("intent") or "")
        surface = str(event.get("surface") or "")
        disposition = str(event.get("disposition_hint") or "")
        switches = event.get("switches_changed") or event.get("switches") or []
        if not isinstance(switches, list):
            switches = [str(switches)]

        if "posture" in intent or "posture-transition" in surface:
            from_posture = event.get("from_posture")
            to_posture = event.get("to_posture") or event.get("posture")
            current_posture = str(to_posture) if to_posture else current_posture
            transitions.append({
                "event_id": event.get("event_id") or event.get("name") or intent,
                "from": from_posture,
                "to": to_posture,
                "switches_changed": switches,
                "ts": event.get("ts") or event.get("timestamp"),
            })

        for switch in switches:
            active_switches.add(str(switch))

        if disposition in {"quarantine", "triage-disguised", "reject"}:
            quarantine_events += 1

    return {
        "current_posture": current_posture or "unknown",
        "transitions": transitions,
        "active_switches": sorted(active_switches),
        "deny_external_ai_inbound": "deny_external_ai_inbound" in active_switches,
        "require_airlock_marker_on_tokens": "require_airlock_marker_on_tokens" in active_switches,
        "quarantine_events": quarantine_events,
    }


def _component_names(components: list[ComponentStatus], status: str | None = None) -> set[str]:
    names: set[str] = set()
    for component in components:
        if status is not None and component.status != status:
            continue
        names.add(component.name)
    return names


def _evidence_names(sources: list[EvidenceSource]) -> set[str]:
    return {source.name for source in sources if source.records > 0}


def build_readiness_lanes(
    components: list[ComponentStatus],
    sources: list[EvidenceSource],
    posture_summary: dict[str, Any],
) -> list[ReadinessLane]:
    installed = _component_names(components, status="installed") | _component_names(components, status="available")
    evidence = _evidence_names(sources)

    lane_defs = [
        (
            "Identity + provenance",
            ("tibet-core", "jis-core"),
            "OSAPI pair packages are available",
        ),
        (
            "Continuity daemon",
            ("tibet-continuityd", "continuityd-audit.jsonl"),
            "continuityd package and audit lane are present",
        ),
        (
            "Evidence spine",
            ("tibet-audit", "tibet-sbom", "tibet-cbom", "ai-sbom.json"),
            "audit/SBOM/CBOM package surface and an AI-SBOM artifact are present",
        ),
        (
            "Agent communication",
            ("ainternet", "ipoll", "cmail"),
            "AInternet, I-Poll package and Cmail operator surface are available",
        ),
        (
            "Immune controls",
            ("snaft", "tibet-airlock", "tibet-triage", "tibet-pol"),
            "SNAFT, airlock, triage and policy operator packages are available",
        ),
        (
            "Runtime hardening",
            ("tibet-trust-kernel", "snaft-core", "tibet-zip-core"),
            "compiled trust kernel / SNAFT core / TBZ runtime pieces are available",
        ),
    ]

    lanes: list[ReadinessLane] = []
    available = installed | evidence
    for name, required, ok_reason in lane_defs:
        observed = tuple(item for item in required if item in available)
        missing = tuple(item for item in required if item not in available)
        if not missing:
            status = "ready"
            reason = ok_reason
        elif observed:
            status = "partial"
            reason = "Missing: " + ", ".join(missing)
        else:
            status = "missing"
            reason = "No required signals observed"
        lanes.append(ReadinessLane(name, status, reason, tuple(required), observed))

    if posture_summary["deny_external_ai_inbound"] or posture_summary["quarantine_events"]:
        lanes.append(ReadinessLane(
            "External AI containment",
            "active",
            "Posture/evidence shows external AI containment or quarantine activity",
            ("deny_external_ai_inbound", "quarantine evidence"),
            tuple(
                item for item in ("deny_external_ai_inbound", "quarantine evidence")
                if (
                    item == "deny_external_ai_inbound" and posture_summary["deny_external_ai_inbound"]
                ) or (
                    item == "quarantine evidence" and posture_summary["quarantine_events"]
                )
            ),
        ))
    else:
        lanes.append(ReadinessLane(
            "External AI containment",
            "baseline",
            "No containment event observed in the indexed evidence window",
            ("deny_external_ai_inbound", "quarantine evidence"),
            (),
        ))

    return lanes


def recommend_next_actions(snapshot: dict[str, Any]) -> list[str]:
    actions: list[str] = []
    lanes = snapshot.get("readiness_lanes", [])
    by_name = {lane["name"]: lane for lane in lanes}
    components = {component["name"]: component for component in snapshot.get("components", [])}
    sources = {source["name"]: source for source in snapshot.get("evidence_sources", [])}
    posture = snapshot.get("posture_summary", {})

    if by_name.get("Continuity daemon", {}).get("status") != "ready":
        actions.append("Start or point tibet-audit at continuityd audit output: continuityd-audit.jsonl.")
    if by_name.get("Evidence spine", {}).get("status") != "ready":
        actions.append("Generate AI-SBOM/SBOM/CBOM artifacts and keep them beside the audit run.")
    if components.get("ipoll", {}).get("kind") == "binary" and components.get("ipoll", {}).get("status") == "missing":
        actions.append("Package gap: ipoll is installed as a library but has no operator CLI binary.")
    if by_name.get("Runtime hardening", {}).get("status") != "ready":
        actions.append("Install or expose Rust runtime pieces: tibet-trust-kernel, tibet-zip-core and snaft-core.")
    if posture.get("deny_external_ai_inbound") and not posture.get("require_airlock_marker_on_tokens"):
        actions.append("Containment is active without an observed airlock-marker requirement; verify tibet-pol posture contract.")
    if not sources:
        actions.append("No evidence files found; run with --system or pass the directory containing /var/log/tibet exports.")
    return actions[:8]


def build_cockpit_snapshot(
    path: str | Path = ".",
    include_system: bool = False,
    lines: int = 25,
) -> dict[str, Any]:
    sources = discover_evidence_sources(path, include_system=include_system)
    components = detect_components()
    events = latest_events(sources, lines=lines)
    events_by_source = source_event_map(sources)
    all_source_events = [event for source_events in events_by_source.values() for event in source_events]
    adapter_assessments = assess_sources(events_by_source)
    evidence_chains = build_evidence_chains(all_source_events)
    findings = [classify_event(event) for event in events]
    posture_summary = summarize_posture(events)
    readiness_lanes = build_readiness_lanes(components, sources, posture_summary)

    installed_packages = [
        component for component in components
        if component.kind == "package" and component.status == "installed"
    ]
    missing_runtime = [
        component for component in components
        if component.group in {"core", "daemon", "safety", "runtime"} and component.status == "missing"
    ]
    active_sources = [source for source in sources if source.records > 0]
    warnings = [finding for finding in findings if finding.severity == "warning"]

    if missing_runtime:
        posture = "degraded"
    elif warnings:
        posture = "attention"
    elif any(lane.status in {"missing", "partial"} for lane in readiness_lanes):
        posture = "partial"
    elif active_sources:
        posture = "observed"
    else:
        posture = "baseline"

    snapshot = {
        "path": str(path),
        "posture": posture,
        "summary": {
            "packages_installed": len(installed_packages),
            "components_total": len(components),
            "evidence_sources": len(sources),
            "active_evidence_sources": len(active_sources),
            "latest_events": len(events),
            "warnings": len(warnings),
        },
        "components": [asdict(component) for component in components],
        "evidence_sources": [asdict(source) for source in sources],
        "events": events,
        "findings": [asdict(finding) for finding in findings],
        "adapter_assessments": adapter_assessments,
        "evidence_chains": evidence_chains,
        "posture_summary": posture_summary,
        "readiness_lanes": [asdict(lane) for lane in readiness_lanes],
    }
    snapshot["next_actions"] = recommend_next_actions(snapshot)
    return snapshot
