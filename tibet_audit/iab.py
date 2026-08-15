"""IAB runtime mirror for tibet-audit.

This module is deliberately read-only. It turns IAB's scattered runtime
evidence into a small governance mirror: runtime, raints, roles, binding, and
causal health. IAB remains the emitter; tibet-audit reads and concludes.
"""

from __future__ import annotations

import hashlib
import html
import json
import os
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .causal_integrity import verify_file


IAB_SOURCES: tuple[tuple[str, str], ...] = (
    ("projection", "audit_projection.jsonl"),
    ("projection.audit", "audit/projection.jsonl"),
    ("projection.tibet", "tibet/audit_projection.jsonl"),
    ("ledger", "tibet/history.jsonl"),
    ("mux", "enclave/mux-events.jsonl"),
    ("work", "enclave/work-ledger.jsonl"),
    ("triage", "triage/events.jsonl"),
    ("gateway", "gateway.jsonl"),
)

STATUS_RE = re.compile(r"0x[0-9a-fA-F]{4}(?::[a-zA-Z0-9._-]+)?")
RAINT_RE = re.compile(r"\b(raint-[A-Za-z0-9_-]+)(?:\.[A-Za-z0-9_.-]+)?")
AINT_RE = re.compile(r"\b([A-Za-z0-9][A-Za-z0-9_-]*(?:\.[A-Za-z0-9_-]+)*\.aint)\b")
LEGACY_DOMAIN_RE = re.compile(r"\.test\.aint\b", re.I)
LEGACY_CODENAME_RE = re.compile(
    r"\b(?:"
    + "rich" + r"ard(?:\.[A-Za-z0-9_.-]+)?|"
    + "red" + r"\s*" + "baron|"
    + "red" + "baron"
    + r")\b",
    re.I,
)
LEGACY_LAB_RE = re.compile(r"\b(?:" + "hack" + "box|" + "are" + "na" + r")\b", re.I)
ROLE_VALUES = {"raint", "maint", "saint", "waint", "operator", "actor", "system", "unknown"}
RUNTIME_LIFECYCLE_ACTIONS = {
    "node.up",
    "launch",
    "reseed",
    "boot",
    "up",
    "runtime.launch",
    "runtime.reseed",
    "runtime.boot",
    "runtime.up",
    "box.launch",
    "box.boot",
    "box.up",
}


@dataclass(frozen=True)
class IabSource:
    name: str
    path: str
    status: str
    records: int


@dataclass(frozen=True)
class IabRuntime:
    kind: str
    runtime_id: str
    run: str
    sources: list[dict[str, Any]]
    source_health: dict[str, str]


@dataclass
class IabEvent:
    kind: str = "org.ainternet.audit.event.v1"
    _source: str = "iab.audit-projection"
    runtime_id: str = ""
    source: str = ""
    projection_id: str = ""
    box_id: str = ""
    session_id: str = ""
    granted_by: str = ""
    mandate: str = ""
    ts: int = 0
    role: str = "unknown"
    role_confidence: str = "unknown"
    role_reason: str = ""
    raint: str = "raint:unknown"
    actor: str = ""
    operator: str = ""
    surface: str = ""
    lane: str = ""
    action: str = ""
    status: str | None = None
    binding: dict[str, Any] = field(default_factory=dict)
    binding_posture: dict[str, Any] = field(default_factory=dict)
    causal: dict[str, Any] = field(default_factory=dict)
    materiality: str = ""
    box_posture: str = ""
    runtime_posture: str = ""
    note: str = ""
    source_ref: dict[str, Any] = field(default_factory=dict)


def discover_iab_runs(path: str | Path = ".", include_system: bool = False) -> list[Path]:
    """Find likely IAB run roots. Explicit paths win; system paths are opt-in."""
    root = Path(path)
    runs: list[Path] = []
    candidates = [root]
    env_home = os.environ.get("AINTERNET_BOX_HOME")
    if env_home:
        candidates.append(Path(env_home))
    if include_system:
        candidates.extend([
            Path("/var/lib/ainternet-box"),
            Path("/var/lib/ainternet-box/run"),
        ])
        try:
            candidates.extend(Path("/var/lib/ainternet-box").glob("run-*"))
        except OSError:
            pass

    seen: set[Path] = set()
    for candidate in candidates:
        try:
            resolved = candidate.resolve()
        except OSError:
            resolved = candidate
        if resolved in seen:
            continue
        seen.add(resolved)
        if _has_iab_source(resolved):
            runs.append(resolved)
            continue
        if resolved.is_dir():
            try:
                for child in sorted(resolved.iterdir()):
                    if not child.is_dir():
                        continue
                    try:
                        child_resolved = child.resolve()
                    except OSError:
                        child_resolved = child
                    if child_resolved in seen:
                        continue
                    seen.add(child_resolved)
                    if _has_iab_source(child_resolved):
                        runs.append(child_resolved)
            except OSError:
                pass
    return runs


def _discover_bom_roots(path: str | Path) -> list[str]:
    """Best-effort: find a shipped `manifests/` dir near the run root (co-located installs). A split dev layout
    (runtime under /var, manifests in the install tree) passes the location explicitly via bom_roots / --bom-root."""
    p = Path(path)
    out = []
    for cand in (p / "manifests", p.parent / "manifests", p.parent.parent / "manifests"):
        try:
            if cand.is_dir():
                out.append(str(cand))
        except OSError:
            pass
    return out


def build_iab_mirror(path: str | Path = ".", include_system: bool = False, bom_roots=()) -> dict[str, Any]:
    from .bom_evidence import build_bom_evidence
    runs = discover_iab_runs(path, include_system=include_system)
    mirrors = [_mirror_run(run) for run in runs]
    events = _dedupe_projection_events([event for mirror in mirrors for event in mirror["events"]])
    raints = _summarize_raints(events)
    sessions = _summarize_sessions(events)
    causal = _merge_causal(mirrors)
    conclusions = _build_conclusions(mirrors, events, raints, causal)
    framework_controls = _framework_controls(events, raints, causal, conclusions)
    fleet = _fleet_summary(mirrors, events, causal)
    newest_ts = max((int(event.get("ts") or 0) for event in events), default=None)
    bom = build_bom_evidence(str(path), extra_roots=list(bom_roots) + _discover_bom_roots(path), now_ts=newest_ts)
    return {
        "kind": "org.ainternet.audit.iab-mirror.v1",
        "runs": [mirror["runtime"] for mirror in mirrors],
        "events": events,
        "raints": raints,
        "sessions": sessions,
        "causal_integrity": causal,
        "fleet": fleet,
        "summary": _summary(mirrors, events, raints),
        "conclusions": conclusions,
        "framework_controls": framework_controls,
        "framework_summary": _framework_summary(framework_controls),
        "bom_evidence": bom,
    }


def filter_iab_mirror(
    mirror: dict[str, Any],
    *,
    raint: str | None = None,
    binding: str | None = None,
    role: str | None = None,
    surface: str | None = None,
    status_prefix: str | None = None,
) -> dict[str, Any]:
    events = []
    for event in mirror.get("events", []):
        if raint and event.get("raint") != raint:
            continue
        if binding and event.get("binding", {}).get("class") != binding:
            continue
        if role and event.get("role") != role:
            continue
        if surface and event.get("surface") != surface:
            continue
        if status_prefix and not str(event.get("status") or "").startswith(status_prefix):
            continue
        events.append(event)
    out = dict(mirror)
    out["events"] = events
    out["raints"] = _summarize_raints(events)
    out["sessions"] = _summarize_sessions(events)
    out["summary"] = _summary([{"runtime": run} for run in mirror.get("runs", [])], events, out["raints"])
    out["conclusions"] = _build_conclusions([], events, out["raints"], mirror.get("causal_integrity", {}))
    out["fleet"] = _fleet_summary(
        [{"runtime": run} for run in mirror.get("runs", [])],
        events,
        mirror.get("causal_integrity", {}),
    )
    out["framework_controls"] = _framework_controls(
        events,
        out["raints"],
        mirror.get("causal_integrity", {}),
        out["conclusions"],
    )
    out["framework_summary"] = _framework_summary(out["framework_controls"])
    return out


def render_iab_report_markdown(mirror: dict[str, Any], framework: str | None = None) -> str:
    """Render an enterprise-readable IAB mirror report."""
    summary = mirror.get("summary", {})
    binding = summary.get("binding_counts", {})
    roles = summary.get("role_counts", {})
    causal = mirror.get("causal_integrity", {})
    framework_filter = _framework_filter(framework)
    controls = [
        control for control in mirror.get("framework_controls", [])
        if _control_matches_framework(control, framework_filter)
    ]
    lines = [
        "# IAB Audit Mirror Report",
        "",
        "Audit as a precondition: this report mirrors the runtime evidence before it turns into a governance claim.",
        "",
        "## Executive Summary",
        "",
        f"- Runtimes: {summary.get('runtimes', 0)}",
        f"- Raints: {summary.get('raints', 0)}",
        f"- Events: {summary.get('events', 0)}",
        f"- Human-bound events: {binding.get('human', 0)}",
        f"- AI-autonomous events: {binding.get('ai', 0)}",
        f"- No-binding events: {binding.get('no-binding', 0)}",
        f"- Authorized-headless events: {summary.get('binding_posture_counts', {}).get('authorized_headless', 0)}",
        f"- Escaped-unbound events: {summary.get('binding_posture_counts', {}).get('escaped_unbound', 0)}",
        f"- Open sessions: {summary.get('open_sessions', 0)}",
        f"- Causal integrity: {causal.get('verdict', 'unknown')} ({causal.get('checked', 0)} source(s) checked)",
        f"- Open tails: {len(causal.get('stalled', []))}",
        f"- Fleet posture: {mirror.get('fleet', {}).get('posture', 'unknown')}",
        f"- Materiality: {mirror.get('fleet', {}).get('materiality', 'unknown')}",
        "",
        "## Governance Conclusions",
        "",
        "| Control | Status | Summary |",
        "|---|---:|---|",
    ]
    for name, item in sorted(mirror.get("conclusions", {}).items()):
        lines.append(f"| `{name}` | `{item.get('status', 'UNKNOWN')}` | {item.get('summary', '')} |")

    lines.extend([
        "",
        "## Fleet Overview",
        "",
        "| Runtime | Events | Raints | Human | AI | No-binding | Causal | Materiality |",
        "|---|---:|---:|---:|---:|---:|---|---|",
    ])
    for row in mirror.get("fleet", {}).get("runtimes", []):
        counts = row.get("binding_counts", {})
        lines.append(
            "| `{}` | {} | {} | {} | {} | {} | `{}` | `{}` |".format(
                row.get("runtime_id", ""),
                row.get("events", 0),
                row.get("raints", 0),
                counts.get("human", 0),
                counts.get("ai", 0),
                counts.get("no-binding", 0),
                row.get("causal_verdict", "unknown"),
                row.get("materiality", "unknown"),
            )
        )
    if not mirror.get("fleet", {}).get("runtimes"):
        lines.append("| - | 0 | 0 | 0 | 0 | 0 | `absent` | `unknown` |")

    lines.extend([
        "",
        "## Framework Readout",
        "",
        "| Framework | PASS | WARN | FAIL | UNKNOWN |",
        "|---|---:|---:|---:|---:|",
    ])
    framework_summary = mirror.get("framework_summary", {})
    for name in sorted(framework_summary):
        if framework_filter and _framework_filter(name) != framework_filter:
            continue
        counts = framework_summary[name]
        lines.append(
            f"| `{name}` | {counts.get('PASS', 0)} | {counts.get('WARN', 0)} | {counts.get('FAIL', 0)} | {counts.get('UNKNOWN', 0)} |"
        )
    if not framework_summary:
        lines.append("| - | 0 | 0 | 0 | 0 |")

    lines.extend([
        "",
        "## Framework Control Mapping" + (f" ({framework})" if framework else ""),
        "",
        "| Control | Status | Materiality | Frameworks | Runtime Evidence | Rationale |",
        "|---|---:|---|---|---|---|",
    ])
    for control in controls:
        frameworks = ", ".join(f"`{item}`" for item in control.get("frameworks", [])) or "-"
        evidence = ", ".join(control.get("evidence", [])) or "-"
        lines.append(
            "| `{}` | `{}` | `{}` | {} | {} | {} |".format(
                control.get("id", ""),
                control.get("status", "UNKNOWN"),
                control.get("materiality", "unknown"),
                frameworks,
                evidence,
                control.get("rationale", ""),
            )
        )
    if not controls:
        lines.append("| - | `UNKNOWN` | `unknown` | - | No matching framework controls | - |")

    lines.extend([
        "",
        "## Role And Binding Mirror",
        "",
        "| Role | Count |",
        "|---|---:|",
    ])
    for role, count in sorted(roles.items()):
        lines.append(f"| `{role}` | {count} |")
    if not roles:
        lines.append("| `none` | 0 |")

    lines.extend([
        "",
        "| Binding | Count |",
        "|---|---:|",
    ])
    for name, count in sorted(binding.items()):
        lines.append(f"| `{name}` | {count} |")

    lines.extend([
        "",
        "| Binding posture | Count |",
        "|---|---:|",
    ])
    for name, count in sorted(summary.get("binding_posture_counts", {}).items()):
        lines.append(f"| `{name}` | {count} |")

    lines.extend([
        "",
        "## Session Governance",
        "",
        "| Session | Runtime | Events | Raints | Starts | Stops | Reseeds | Resumes | Open | Materiality |",
        "|---|---|---:|---|---:|---:|---:|---:|---|---|",
    ])
    for row in mirror.get("sessions", []):
        lines.append(
            "| `{}` | `{}` | {} | {} | {} | {} | {} | {} | `{}` | `{}` |".format(
                row.get("session_id", ""),
                row.get("runtime_id", ""),
                row.get("events", 0),
                ", ".join(f"`{raint}`" for raint in row.get("raints", [])) or "-",
                row.get("starts", 0),
                row.get("stops", 0),
                row.get("reseeds", 0),
                row.get("resumes", 0),
                "yes" if row.get("open") else "no",
                row.get("materiality", "unknown"),
            )
        )
    if not mirror.get("sessions"):
        lines.append("| - | - | 0 | - | 0 | 0 | 0 | 0 | `no` | `unknown` |")

    lines.extend([
        "",
        "## Raints",
        "",
        "| Raint | State | Actors | Surfaces | Human | AI | No-binding |",
        "|---|---|---|---|---:|---:|---:|",
    ])
    for row in mirror.get("raints", []):
        counts = row.get("binding_counts", {})
        lines.append(
            "| `{}` | `{}` | {} | {} | {} | {} | {} |".format(
                row.get("raint", "-"),
                row.get("state", "unknown"),
                ", ".join(f"`{actor}`" for actor in row.get("actors", [])) or "-",
                ", ".join(f"`{surface}`" for surface in row.get("surfaces", [])) or "-",
                counts.get("human", 0),
                counts.get("ai", 0),
                counts.get("no-binding", 0),
            )
        )
    if not mirror.get("raints"):
        lines.append("| - | `absent` | - | - | 0 | 0 | 0 |")

    if causal.get("broken"):
        lines.extend(["", "## Causal Breaks", "", "| Source | Record |", "|---|---:|"])
        for item in causal.get("broken", []):
            lines.append(f"| `{item.get('source', '?')}` | {item.get('break_at', '?')} |")
    if causal.get("stalled"):
        lines.extend(["", "## Open Tails", "", "| Source | Action | Note |", "|---|---|---|"])
        for item in causal.get("stalled", []):
            lines.append(f"| `{item.get('source', '?')}` | `{item.get('action', '')}` | {item.get('note', '')} |")

    lines.extend([
        "",
        "## Latest Events",
        "",
        "| TS | Raint | Role | Binding | Action | Status |",
        "|---:|---|---|---|---|---|",
    ])
    for event in mirror.get("events", [])[-20:]:
        lines.append(
            "| {} | `{}` | `{}` | `{}` | `{}` | `{}` |".format(
                event.get("ts") or "",
                event.get("raint") or "",
                event.get("role") or "",
                event.get("binding", {}).get("class", ""),
                event.get("action") or "",
                event.get("status") or "",
            )
        )
    if not mirror.get("events"):
        lines.append("| - | - | - | - | No IAB runtime evidence found | - |")
    from .bom_evidence import render_bom_markdown
    lines.extend(render_bom_markdown(mirror.get("bom_evidence")))
    return "\n".join(lines) + "\n"


def render_iab_report_html(mirror: dict[str, Any], framework: str | None = None) -> str:
    """Render a standalone enterprise HTML report."""
    summary = mirror.get("summary", {})
    binding = summary.get("binding_counts", {})
    causal = mirror.get("causal_integrity", {})
    fleet = mirror.get("fleet", {})
    framework_filter = _framework_filter(framework)
    controls = [
        control for control in mirror.get("framework_controls", [])
        if _control_matches_framework(control, framework_filter)
    ]
    framework_summary = {
        name: counts
        for name, counts in mirror.get("framework_summary", {}).items()
        if not framework_filter or _framework_filter(name) == framework_filter
    }
    cards = [
        ("Runtimes", summary.get("runtimes", 0)),
        ("Raints", summary.get("raints", 0)),
        ("Events", summary.get("events", 0)),
        ("Human-bound", binding.get("human", 0)),
        ("AI-autonomous", binding.get("ai", 0)),
        ("No-binding", binding.get("no-binding", 0)),
        ("Authorized-headless", summary.get("binding_posture_counts", {}).get("authorized_headless", 0)),
        ("Escaped-unbound", summary.get("binding_posture_counts", {}).get("escaped_unbound", 0)),
        ("Open sessions", summary.get("open_sessions", 0)),
        ("Causal", causal.get("verdict", "unknown")),
        ("Materiality", fleet.get("materiality", "unknown")),
    ]
    body = [
        "<!doctype html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        "<title>IAB Audit Mirror Report</title>",
        "<style>",
        _IAB_REPORT_CSS,
        "</style>",
        "</head>",
        "<body>",
        "<main>",
        "<header>",
        "<p class=\"eyebrow\">tibet-audit runtime governance</p>",
        "<h1>IAB Audit Mirror Report</h1>",
        "<p class=\"lede\">Audit as a precondition: runtime evidence is mirrored before it becomes a governance claim.</p>",
        f"<div class=\"posture posture-{_slug(fleet.get('materiality', 'unknown'))}\">Fleet posture: {_e(fleet.get('posture', 'unknown'))} &middot; materiality {_e(fleet.get('materiality', 'unknown'))}</div>",
        "</header>",
        "<section class=\"cards\">",
        *[f"<article><span>{_e(label)}</span><strong>{_e(value)}</strong></article>" for label, value in cards],
        "</section>",
        "<section>",
        "<h2>Governance Conclusions</h2>",
        _html_table(
            ["Control", "Status", "Summary"],
            [
                [name, _status_badge(item.get("status", "UNKNOWN")), item.get("summary", "")]
                for name, item in sorted(mirror.get("conclusions", {}).items())
            ],
        ),
        "</section>",
        "<section>",
        "<h2>Fleet Overview</h2>",
        _html_table(
            ["Runtime", "Events", "Raints", "Human", "AI", "No-binding", "Causal", "Materiality"],
            [
                [
                    row.get("runtime_id", ""),
                    row.get("events", 0),
                    row.get("raints", 0),
                    row.get("binding_counts", {}).get("human", 0),
                    row.get("binding_counts", {}).get("ai", 0),
                    row.get("binding_counts", {}).get("no-binding", 0),
                    row.get("causal_verdict", "unknown"),
                    row.get("materiality", "unknown"),
                ]
                for row in fleet.get("runtimes", [])
            ],
        ),
        "</section>",
        "<section>",
        "<h2>Framework Readout</h2>",
        _html_table(
            ["Framework", "PASS", "WARN", "FAIL", "UNKNOWN"],
            [
                [name, counts.get("PASS", 0), counts.get("WARN", 0), counts.get("FAIL", 0), counts.get("UNKNOWN", 0)]
                for name, counts in sorted(framework_summary.items())
            ],
        ),
        "</section>",
        "<section>",
        f"<h2>Framework Control Mapping{f' ({_e(framework)})' if framework else ''}</h2>",
        _html_table(
            ["Control", "Status", "Materiality", "Frameworks", "Runtime Evidence", "Rationale"],
            [
                [
                    control.get("id", ""),
                    _status_badge(control.get("status", "UNKNOWN")),
                    control.get("materiality", "unknown"),
                    ", ".join(control.get("frameworks", [])),
                    ", ".join(control.get("evidence", [])),
                    control.get("rationale", ""),
                ]
                for control in controls
            ],
        ),
        "</section>",
        "<section>",
        "<h2>Binding Posture</h2>",
        _html_table(
            ["Posture", "Count"],
            [
                [name, count]
                for name, count in sorted(summary.get("binding_posture_counts", {}).items())
            ],
        ),
        "</section>",
        "<section>",
        "<h2>Session Governance</h2>",
        _html_table(
            ["Session", "Runtime", "Events", "Raints", "Starts", "Stops", "Reseeds", "Resumes", "Open", "Materiality"],
            [
                [
                    row.get("session_id", ""),
                    row.get("runtime_id", ""),
                    row.get("events", 0),
                    ", ".join(row.get("raints", [])),
                    row.get("starts", 0),
                    row.get("stops", 0),
                    row.get("reseeds", 0),
                    row.get("resumes", 0),
                    "yes" if row.get("open") else "no",
                    row.get("materiality", "unknown"),
                ]
                for row in mirror.get("sessions", [])
            ],
        ),
        "</section>",
        "<section>",
        "<h2>Raints</h2>",
        _html_table(
            ["Raint", "State", "Actors", "Surfaces", "Human", "AI", "No-binding"],
            [
                [
                    row.get("raint", ""),
                    row.get("state", "unknown"),
                    ", ".join(row.get("actors", [])),
                    ", ".join(row.get("surfaces", [])),
                    row.get("binding_counts", {}).get("human", 0),
                    row.get("binding_counts", {}).get("ai", 0),
                    row.get("binding_counts", {}).get("no-binding", 0),
                ]
                for row in mirror.get("raints", [])
            ],
        ),
        "</section>",
        *_html_exception_sections(causal),
        "<section>",
        "<h2>Latest Events</h2>",
        _html_table(
            ["TS", "Raint", "Role", "Binding", "Action", "Status"],
            [
                [
                    event.get("ts") or "",
                    event.get("raint") or "",
                    event.get("role") or "",
                    event.get("binding", {}).get("class", ""),
                    event.get("action") or "",
                    event.get("status") or "",
                ]
                for event in mirror.get("events", [])[-20:]
            ],
        ),
        "</section>",
        "</main>",
        "</body>",
        "</html>",
    ]
    from .bom_evidence import render_bom_html
    bom_html = render_bom_html(mirror.get("bom_evidence"))
    if bom_html:
        body.insert(body.index("</main>"), bom_html)
    return "\n".join(body) + "\n"


def _has_iab_source(run: Path) -> bool:
    return any((run / rel).is_file() for _, rel in IAB_SOURCES)


def _mirror_run(run: Path) -> dict[str, Any]:
    source_rows: list[dict[str, Any]] = []
    events: list[dict[str, Any]] = []
    causal_sources: dict[str, dict[str, Any]] = {}
    broken: list[dict[str, Any]] = []
    stalled: list[dict[str, Any]] = []
    runtime_id = _runtime_id(run)
    for label, rel in IAB_SOURCES:
        source = run / rel
        records = _read_jsonl(source)
        check = verify_file(source)
        if check:
            check = dict(check)
            check["source"] = label
            check["path"] = str(source)
            causal_sources[label] = check
            if check.get("kind") == "chain" and not check.get("intact"):
                broken.append({"runtime_id": runtime_id, "source": label, "break_at": check.get("break_at")})
            if check.get("open_tail"):
                stalled.append({"runtime_id": runtime_id, "source": label, **check["open_tail"]})
        source_rows.append(asdict(IabSource(
            name=label,
            path=str(source),
            status="present" if source.is_file() else "absent",
            records=len(records),
        )))
        for idx, record in enumerate(records, 1):
            events.append(asdict(_project_event(runtime_id, label, source, idx, record)))

    runtime = asdict(IabRuntime(
        kind="org.ainternet.audit.iab-runtime.v1",
        runtime_id=runtime_id,
        run=str(run),
        sources=source_rows,
        source_health={row["name"]: row["status"] for row in source_rows},
    ))
    events.sort(key=lambda event: (event.get("ts") or 0, event.get("source") or ""))
    causal = {
        "verdict": "broken" if broken else "intact",
        "checked": len(causal_sources),
        "sources": causal_sources,
        "broken": broken,
        "stalled": stalled,
    }
    return {"runtime": runtime, "events": events, "causal_integrity": causal}


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    records: list[dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                if not line.strip():
                    continue
                try:
                    value = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(value, dict):
                    records.append(value)
    except OSError:
        return []
    return records


def _project_event(runtime_id: str, source_label: str, source_path: Path, line: int, record: dict[str, Any]) -> IabEvent:
    raw_note = _first_str(record, "note", "reason", "detail", "message")
    raw_actor = _first_str(record, "actor", "aint", "from_aint", "from", "requested_by", "subject") or _infer_aint(raw_note)
    raw_operator = _first_str(record, "operator", "by", "granted_by", "root")
    raw_action = _first_str(record, "action", "event", "phase", "kind", "op", "intent")
    raw_surface = _first_str(record, "surface", "target_surface")
    raw_box = _first_str(record, "box_id", "node_aint", "node", "box")
    raw_session = _first_str(record, "session_id", "session", "run_id")
    raw_granted_by = _first_str(record, "granted_by", "mandate_by", "authorized_by")
    raw_mandate = _first_str(record, "mandate", "mandate_id", "grant_id", "grant")
    target = _first_str(record, "target", "object_id", "lane_id")
    actor = _clean_legacy_text(raw_actor)
    operator = _clean_legacy_text(raw_operator)
    action = _clean_legacy_text(raw_action)
    note = _clean_legacy_text(raw_note)
    surface = _clean_legacy_text(raw_surface)
    box_id = _clean_legacy_text(raw_box)
    session_id = _clean_legacy_text(raw_session)
    granted_by = _clean_legacy_text(raw_granted_by)
    mandate = _clean_legacy_text(raw_mandate)
    lifecycle_event = _is_runtime_lifecycle_event(action)
    role, confidence, reason = _infer_role(record, actor, operator, surface, source_label, action)
    if lifecycle_event:
        role, confidence, reason = "system", "inferred", "runtime-lifecycle"
    status = _detect_status(record, raw_action, raw_note)
    raint = _infer_raint(record, raw_actor, target, raw_note)
    binding = _explicit_binding(record) or _classify_binding(record, actor, operator, role, action, note)
    if lifecycle_event:
        binding = {"class": "no-binding", "reason": "system-event"}
    binding_posture = _binding_posture(binding, role, granted_by, mandate)
    return IabEvent(
        runtime_id=runtime_id,
        source=source_label,
        projection_id=_clean_legacy_text(_first_str(record, "projection_id", "event_id", "id")),
        box_id=box_id,
        session_id=session_id,
        granted_by=granted_by,
        mandate=mandate,
        ts=_int(record.get("ts") or record.get("timestamp") or record.get("time")),
        role=role,
        role_confidence=confidence,
        role_reason=reason,
        raint=raint,
        actor=actor,
        operator=operator,
        surface=surface,
        lane=_infer_lane(source_label, record),
        action=action,
        status=status,
        binding=binding,
        binding_posture=binding_posture,
        causal={
            "prev": str(record.get("prev") or ""),
            "self": str(record.get("self") or record.get("id") or ""),
            "head": str(record.get("causal_head") or record.get("head") or record.get("self") or ""),
            "chain_id": _clean_legacy_text(_first_str(record, "chain_id", "chain", "lane")),
            "chain": "observed",
        },
        materiality=_clean_legacy_text(_first_str(record, "materiality", "severity")),
        box_posture=_clean_legacy_text(_first_str(record, "box_posture", "posture")),
        runtime_posture=_clean_legacy_text(_first_str(record, "runtime_posture", "session_boundary")),
        note=note,
        source_ref=_source_ref(record, source_path, line),
    )


def _first_str(record: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = record.get(key)
        if value is None:
            continue
        if isinstance(value, (dict, list)):
            continue
        text = str(value)
        if text:
            return text
    return ""


def _int(value: Any) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return 0


def _detect_status(record: dict[str, Any], *texts: str) -> str | None:
    for key in ("route", "seal_state", "status", "banner", "verdict", "result"):
        value = record.get(key)
        if isinstance(value, str):
            match = STATUS_RE.search(value)
            if match:
                return match.group(0)
    for text in texts:
        match = STATUS_RE.search(text or "")
        if match:
            return match.group(0)
    return None


def _infer_raint(record: dict[str, Any], *texts: str) -> str:
    for key in ("raint", "subject_raint", "node", "box", "session_raint"):
        value = record.get(key)
        if value:
            match = RAINT_RE.search(str(value))
            if match:
                return match.group(1)
            if key in {"raint", "subject_raint", "session_raint"}:
                return str(value)
    for text in texts:
        match = RAINT_RE.search(text or "")
        if match:
            return match.group(1)
    return "raint:unknown"


def _source_ref(record: dict[str, Any], source_path: Path, line: int) -> dict[str, Any]:
    ref = record.get("source_ref")
    if isinstance(ref, dict):
        return {
            "path": _clean_legacy_text(ref.get("path") or source_path),
            "line": _int(ref.get("line") or line),
            "sha256": _clean_legacy_text(ref.get("sha256") or ""),
            "projection_path": _clean_legacy_text(str(source_path)),
            "projection_line": line,
        }
    return {
        "path": _clean_legacy_text(str(source_path)),
        "line": line,
        "sha256": hashlib.sha256(json.dumps(record, sort_keys=True).encode()).hexdigest(),
    }


def _dedupe_projection_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    projection_keys = {
        key
        for event in events
        if str(event.get("source") or "").startswith("projection")
        for key in _source_ref_dedupe_keys(event.get("source_ref", {}))
    }
    if not projection_keys:
        return events
    out = []
    for event in events:
        if str(event.get("source") or "").startswith("projection"):
            out.append(event)
            continue
        keys = _source_ref_dedupe_keys(event.get("source_ref", {}))
        if keys and projection_keys.intersection(keys):
            continue
        out.append(event)
    return out


def _source_ref_dedupe_keys(ref: dict[str, Any]) -> set[tuple[str, int]]:
    path = _clean_legacy_text(ref.get("path") or "")
    line = _int(ref.get("line"))
    if not path or not line:
        return set()
    normalized = path.rstrip("/")
    parts = [part for part in normalized.split("/") if part]
    keys = {(normalized, line)}
    if len(parts) >= 3:
        keys.add(("/".join(parts[-3:]), line))
    if len(parts) >= 2:
        keys.add(("/".join(parts[-2:]), line))
    return keys


def _infer_aint(text: str) -> str:
    for match in AINT_RE.finditer(text or ""):
        value = match.group(1)
        if value.startswith("raint-"):
            continue
        return value
    return ""


def _clean_legacy_text(value: Any) -> str:
    text = "" if value is None else str(value)
    if not text:
        return ""
    text = LEGACY_DOMAIN_RE.sub("", text)
    text = LEGACY_CODENAME_RE.sub("legacy-redteam", text)
    text = LEGACY_LAB_RE.sub("legacy-lab", text)
    return text


def _is_runtime_lifecycle_event(action: str) -> bool:
    return str(action or "").strip().lower() in RUNTIME_LIFECYCLE_ACTIONS


def _explicit_binding(record: dict[str, Any]) -> dict[str, Any] | None:
    binding = record.get("binding")
    if not isinstance(binding, dict):
        binding_class = record.get("binding_class")
        if binding_class:
            binding = {"class": binding_class, "reason": record.get("binding_reason") or "projection-field"}
        else:
            return None
    binding_class = str(binding.get("class") or "")
    if binding_class not in {"human", "ai", "no-binding"}:
        return None
    return _clean_value_map(binding)


def _binding_posture(
    binding: dict[str, Any],
    role: str,
    granted_by: str,
    mandate: str,
) -> dict[str, Any]:
    cls = str(binding.get("class") or "no-binding")
    reason = str(binding.get("reason") or "")
    has_mandate = bool(granted_by or mandate or binding.get("granted_by") or binding.get("mandate"))
    if cls == "human":
        posture = "human_bound"
        materiality = "low"
    elif cls == "ai":
        posture = "ai_bound"
        materiality = "medium"
    elif role == "system" and reason in {"missing-actor-and-presence", "system-event"}:
        posture = "system_infra"
        materiality = "low"
    elif has_mandate:
        posture = "authorized_headless"
        materiality = "medium"
    elif "dark" in reason or "explicit-no-binding" in reason:
        posture = "escaped_unbound"
        materiality = "high"
    else:
        posture = "unknown_no_mandate"
        materiality = "high"
    return {
        "class": posture,
        "materiality": materiality,
        "granted_by": _clean_legacy_text(granted_by or binding.get("granted_by") or ""),
        "mandate": _clean_legacy_text(mandate or binding.get("mandate") or ""),
        "reason": _clean_legacy_text(reason),
    }


def _clean_value_map(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _clean_value_map(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_clean_value_map(item) for item in value]
    if isinstance(value, str):
        return _clean_legacy_text(value)
    return value


def _infer_role(
    record: dict[str, Any],
    actor: str,
    operator: str,
    surface: str,
    source: str,
    action: str,
) -> tuple[str, str, str]:
    explicit = str(record.get("role") or record.get("subject_role") or record.get("runtime_role") or "")
    if explicit in ROLE_VALUES:
        return explicit, "explicit", "field:role"

    blob = " ".join(str(part) for part in (actor, operator, surface, record.get("kind", ""), action))
    if "system.saint" in blob or ".saint" in blob:
        return "saint", "inferred", "suffix:.saint"
    if ".waint" in blob:
        return "waint", "inferred", "suffix:.waint"
    if "maint" in blob or ".maint" in blob:
        return "maint", "inferred", "name:maint"
    if RAINT_RE.search(blob):
        return "raint", "inferred", "name:raint-*"
    if _has_human_evidence(record):
        return "operator", "inferred", "human-evidence"
    if operator or source == "triage" and "decid" in action:
        return "operator", "inferred", "operator-field"
    if actor:
        return "actor", "inferred", "actor-field"
    if source == "ledger" and (str(record.get("kind") or "").startswith("org.ainternet.box") or "system" in action):
        return "system", "inferred", "box-ledger"
    return "unknown", "unknown", "no-role-signal"


def _classify_binding(
    record: dict[str, Any],
    actor: str,
    operator: str,
    role: str,
    action: str,
    note: str,
) -> dict[str, Any]:
    note_l = note.lower()
    action_l = str(action).lower()
    # An audit/governance SUMMARY tick literally spells out its own counts ("... no-binding 3 ...") — that is the
    # audit recording ITSELF, not a no-binding ACTION. Never let a self-describing audit note trip
    # explicit-no-binding (self-referential false positive). Converges with the box projector, which does not
    # text-scan such ticks; a real go-dark still rides the JIS-dark path below.
    is_audit_summary = action_l in {"local-audit", "audit", "governance-view"} or note_l.startswith("governance view")
    if is_audit_summary:
        # the audit's own summary tick is a bare infrastructure record, not an accountable action — read it as a
        # quiet system-event so it settles into system_infra, never a risky no-binding on its own descriptive text.
        return {"class": "no-binding", "reason": "system-event"}
    if "no-binding" in note_l or "unbound" in action_l:
        return {"class": "no-binding", "reason": "explicit-no-binding"}
    actor_jis = _jis_state(record, "actor")
    operator_jis = _jis_state(record, "operator")
    if actor_jis in {"dark", "unknown", "reanchor"} and actor:
        return {"class": "no-binding", "reason": f"actor-jis-{actor_jis}"}
    if operator_jis in {"dark", "unknown", "reanchor"} and operator:
        return {"class": "no-binding", "reason": f"operator-jis-{operator_jis}"}
    if _has_human_evidence(record):
        return {
            "class": "human",
            "reason": _human_reason(record),
            "presence": bool(record.get("presence")),
            "method": record.get("method"),
            "assurance": record.get("assurance"),
            "rvp": record.get("rvp") or record.get("receipt"),
        }
    if actor and ("human" in note_l or "ceremony" in note_l):
        return {
            "class": "human",
            "reason": "note-human",
            "presence": False,
            "method": None,
            "assurance": None,
            "rvp": None,
        }
    if actor:
        return {"class": "ai", "reason": "actor-only"}
    if role == "system":
        return {"class": "ai", "reason": "system-event"}
    return {"class": "no-binding", "reason": "missing-actor-and-presence"}


def _has_human_evidence(record: dict[str, Any]) -> bool:
    return bool(
        record.get("presence")
        or record.get("rvp")
        or record.get("method")
        or record.get("assurance")
        or record.get("spoken")
        or (record.get("by") and record.get("receipt"))
    )


def _human_reason(record: dict[str, Any]) -> str:
    if record.get("presence") or record.get("rvp") or record.get("method") or record.get("assurance"):
        return "presence-rvp"
    if record.get("by") and record.get("receipt"):
        return "triage-by-with-receipt"
    if record.get("spoken"):
        return "spoken-go-dark"
    return "human-evidence"


def _jis_state(record: dict[str, Any], subject: str) -> str | None:
    jis = record.get("jis")
    if not isinstance(jis, dict):
        return None
    value = jis.get(subject)
    if isinstance(value, dict):
        state = value.get("state") or value.get("status")
        return str(state) if state else None
    return None


def _infer_lane(source: str, record: dict[str, Any]) -> str:
    return _first_str(record, "lane", "lane_id", "lane_class") or source


def _runtime_id(run: Path) -> str:
    return "iab:" + hashlib.sha256(str(run).encode()).hexdigest()[:12]


def _summarize_raints(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_raint: dict[str, dict[str, Any]] = {}
    for event in events:
        rid = event.get("raint") or "raint:unknown"
        row = by_raint.setdefault(rid, {
            "kind": "org.ainternet.audit.raint.v1",
            "raint": rid,
            "state": "unknown",
            "actors": set(),
            "surfaces": set(),
            "binding_counts": {"human": 0, "ai": 0, "no-binding": 0},
            "roles": {},
        })
        if event.get("actor"):
            row["actors"].add(event["actor"])
        if event.get("surface"):
            row["surfaces"].add(event["surface"])
        binding = event.get("binding", {}).get("class", "no-binding")
        row["binding_counts"][binding] = row["binding_counts"].get(binding, 0) + 1
        role = event.get("role") or "unknown"
        row["roles"][role] = row["roles"].get(role, 0) + 1
        status = str(event.get("status") or "")
        if status.startswith("0x4000"):
            row["state"] = "live"
        elif status.startswith("0x0000") and row["state"] == "unknown":
            row["state"] = "dark"

    out = []
    for row in by_raint.values():
        row["actors"] = sorted(row["actors"])
        row["surfaces"] = sorted(row["surfaces"])
        row["causal"] = {"intact": True, "open_tail": False}
        out.append(row)
    return sorted(out, key=lambda item: item["raint"])


def _summarize_sessions(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_session: dict[tuple[str, str], dict[str, Any]] = {}
    for event in events:
        session_id = str(event.get("session_id") or "")
        if not session_id:
            continue
        runtime_id = str(event.get("runtime_id") or "iab:unknown")
        key = (runtime_id, session_id)
        row = by_session.setdefault(key, {
            "kind": "org.ainternet.audit.iab-session.v1",
            "runtime_id": runtime_id,
            "session_id": session_id,
            "events": 0,
            "first_ts": 0,
            "last_ts": 0,
            "raints": set(),
            "actors": set(),
            "binding_counts": {"human": 0, "ai": 0, "no-binding": 0},
            "binding_posture_counts": {},
            "starts": 0,
            "stops": 0,
            "reseeds": 0,
            "resumes": 0,
        })
        row["events"] += 1
        ts = _int(event.get("ts"))
        if ts and (not row["first_ts"] or ts < row["first_ts"]):
            row["first_ts"] = ts
        if ts and ts > row["last_ts"]:
            row["last_ts"] = ts
        if event.get("raint"):
            row["raints"].add(event["raint"])
        if event.get("actor"):
            row["actors"].add(event["actor"])
        cls = event.get("binding", {}).get("class", "no-binding")
        row["binding_counts"][cls] = row["binding_counts"].get(cls, 0) + 1
        posture = event.get("binding_posture", {}).get("class", "unknown_no_mandate")
        row["binding_posture_counts"][posture] = row["binding_posture_counts"].get(posture, 0) + 1
        lifecycle = _session_lifecycle(event)
        if lifecycle:
            row[lifecycle + "s"] += 1

    out = []
    for row in by_session.values():
        row["raints"] = sorted(row["raints"])
        row["actors"] = sorted(row["actors"])
        row["open"] = row["starts"] > row["stops"]
        row["materiality"] = _session_materiality(row)
        out.append(row)
    return sorted(out, key=lambda item: (item["runtime_id"], item["session_id"]))


def _session_lifecycle(event: dict[str, Any]) -> str:
    blob = " ".join(str(event.get(key) or "").lower() for key in ("action", "lane", "note", "runtime_posture"))
    if any(word in blob for word in ("stop", "close", "destroy", "shutdown")):
        return "stop"
    if "reseed" in blob:
        return "reseed"
    if "resume" in blob:
        return "resume"
    if any(word in blob for word in ("start", "open", "spawn", "boot")):
        return "start"
    return ""


def _session_materiality(row: dict[str, Any]) -> str:
    postures = row.get("binding_posture_counts", {})
    if postures.get("escaped_unbound") or postures.get("unknown_no_mandate"):
        return "high"
    if row.get("open") or postures.get("authorized_headless"):
        return "medium"
    if row.get("events"):
        return "low"
    return "unknown"


def _summary(mirrors: list[dict[str, Any]], events: list[dict[str, Any]], raints: list[dict[str, Any]]) -> dict[str, Any]:
    binding_counts = {"human": 0, "ai": 0, "no-binding": 0}
    binding_posture_counts = {
        "human_bound": 0,
        "ai_bound": 0,
        "authorized_headless": 0,
        "escaped_unbound": 0,
        "unknown_no_mandate": 0,
        "system_infra": 0,
    }
    role_counts: dict[str, int] = {}
    for event in events:
        cls = event.get("binding", {}).get("class", "no-binding")
        binding_counts[cls] = binding_counts.get(cls, 0) + 1
        posture = event.get("binding_posture", {}).get("class", "unknown_no_mandate")
        binding_posture_counts[posture] = binding_posture_counts.get(posture, 0) + 1
        role = event.get("role") or "unknown"
        role_counts[role] = role_counts.get(role, 0) + 1
    sessions = _summarize_sessions(events)
    return {
        "runtimes": len(mirrors),
        "events": len(events),
        "raints": len(raints),
        "sessions": len(sessions),
        "open_sessions": sum(1 for item in sessions if item.get("open")),
        "binding_counts": binding_counts,
        "binding_posture_counts": binding_posture_counts,
        "role_counts": role_counts,
        "unknown_raints": sum(1 for item in raints if item.get("raint") == "raint:unknown"),
    }


def _build_conclusions(
    mirrors: list[dict[str, Any]],
    events: list[dict[str, Any]],
    raints: list[dict[str, Any]],
    causal: dict[str, Any],
) -> dict[str, dict[str, str]]:
    source_present = any(
        source.get("records", 0) > 0
        for mirror in mirrors
        for source in mirror.get("runtime", {}).get("sources", [])
    ) if mirrors else bool(events)
    risk = _binding_risk_counts(events)
    risky_no_binding = risk["escaped_unbound"] + risk["unknown_no_mandate"]
    authorized_headless = risk["authorized_headless"]
    system_infra = risk["system_infra"]
    unknown_roles = [event for event in events if event.get("role") == "unknown"]
    unknown_raints = [item for item in raints if item.get("raint") == "raint:unknown"]
    dark_refusals = [event for event in events if str(event.get("status") or "").startswith("0x0000")]
    grants = [event for event in events if str(event.get("status") or "").startswith("0x4000")]
    causal_status = "FAIL" if causal.get("verdict") == "broken" else "WARN" if causal.get("stalled") else "PASS"
    causal_summary = (
        f"{causal.get('checked', 0)} source(s) checked, "
        f"{len(causal.get('broken', []))} break(s), {len(causal.get('stalled', []))} open tail(s)"
    )
    return {
        "iab.audit_right": _conclusion("PASS" if source_present else "FAIL", "IAB evidence projection is present" if source_present else "No IAB evidence sources found"),
        "iab.human_oversight": _conclusion(
            "FAIL" if risky_no_binding else "WARN" if authorized_headless else "PASS",
            f"{risky_no_binding} risky no-binding event(s), {authorized_headless} authorized-headless, {system_infra} system-infra",
        ),
        "iab.role_integrity": _conclusion("WARN" if unknown_roles else "PASS", f"{len(unknown_roles)} event(s) have unknown role"),
        "iab.raint_inventory": _conclusion("WARN" if unknown_raints else "PASS", f"{len(unknown_raints)} unknown raint bucket(s)"),
        "iab.dark_by_default": _conclusion("PASS" if dark_refusals or not grants else "WARN", f"{len(dark_refusals)} refusal(s), {len(grants)} grant(s) observed"),
        "iab.causal_integrity": _conclusion(causal_status, causal_summary),
    }


def _merge_causal(mirrors: list[dict[str, Any]]) -> dict[str, Any]:
    sources: dict[str, Any] = {}
    broken: list[dict[str, Any]] = []
    stalled: list[dict[str, Any]] = []
    for mirror in mirrors:
        runtime = mirror.get("runtime", {})
        runtime_id = runtime.get("runtime_id", "iab:unknown")
        causal = mirror.get("causal_integrity", {})
        for name, item in causal.get("sources", {}).items():
            sources[f"{runtime_id}:{name}"] = item
        broken.extend(causal.get("broken", []))
        stalled.extend(causal.get("stalled", []))
    return {
        "verdict": "broken" if broken else "intact",
        "checked": len(sources),
        "sources": sources,
        "broken": broken,
        "stalled": stalled,
    }


def _fleet_summary(
    mirrors: list[dict[str, Any]],
    events: list[dict[str, Any]],
    causal: dict[str, Any],
) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for mirror in mirrors:
        runtime = mirror.get("runtime", {})
        runtime_id = runtime.get("runtime_id", "iab:unknown")
        runtime_events = [event for event in events if event.get("runtime_id") == runtime_id]
        runtime_raints = _summarize_raints(runtime_events)
        runtime_causal = mirror.get("causal_integrity", {})
        if not runtime_causal and causal:
            runtime_causal = _causal_for_runtime(runtime_id, causal)
        runtime_summary = _summary([], runtime_events, runtime_raints)
        materiality = _materiality(runtime_events, runtime_causal)
        rows.append({
            "runtime_id": runtime_id,
            "run": runtime.get("run", ""),
            "events": len(runtime_events),
            "raints": len(runtime_raints),
            "binding_counts": runtime_summary["binding_counts"],
            "binding_posture_counts": runtime_summary["binding_posture_counts"],
            "role_counts": runtime_summary["role_counts"],
            "source_health": runtime.get("source_health", {}),
            "causal_verdict": runtime_causal.get("verdict", "unknown"),
            "causal_breaks": len(runtime_causal.get("broken", [])),
            "open_tails": len(runtime_causal.get("stalled", [])),
            "materiality": materiality,
            "posture": _posture_from_materiality(materiality),
        })
    materiality = _max_materiality(row.get("materiality", "unknown") for row in rows)
    return {
        "kind": "org.ainternet.audit.iab-fleet.v1",
        "runtimes": rows,
        "posture": _posture_from_materiality(materiality) if rows else "absent",
        "materiality": materiality,
        "no_binding_runtimes": [row["runtime_id"] for row in rows if row.get("binding_counts", {}).get("no-binding", 0)],
        "risky_unbound_runtimes": [
            row["runtime_id"] for row in rows
            if row.get("binding_posture_counts", {}).get("escaped_unbound", 0)
            or row.get("binding_posture_counts", {}).get("unknown_no_mandate", 0)
        ],
        "authorized_headless_runtimes": [
            row["runtime_id"] for row in rows
            if row.get("binding_posture_counts", {}).get("authorized_headless", 0)
        ],
        "system_infra_runtimes": [
            row["runtime_id"] for row in rows
            if row.get("binding_posture_counts", {}).get("system_infra", 0)
        ],
        "open_tail_runtimes": [row["runtime_id"] for row in rows if row.get("open_tails", 0)],
        "broken_runtimes": [row["runtime_id"] for row in rows if row.get("causal_breaks", 0)],
    }


def _causal_for_runtime(runtime_id: str, causal: dict[str, Any]) -> dict[str, Any]:
    broken = [item for item in causal.get("broken", []) if item.get("runtime_id") == runtime_id]
    stalled = [item for item in causal.get("stalled", []) if item.get("runtime_id") == runtime_id]
    return {
        "verdict": "broken" if broken else "intact",
        "broken": broken,
        "stalled": stalled,
    }


def _framework_controls(
    events: list[dict[str, Any]],
    raints: list[dict[str, Any]],
    causal: dict[str, Any],
    conclusions: dict[str, dict[str, str]],
) -> list[dict[str, Any]]:
    summary = _summary([], events, raints)
    binding = summary["binding_counts"]
    roles = summary["role_counts"]
    has_events = bool(events)
    has_human = binding.get("human", 0) > 0
    has_ai = binding.get("ai", 0) > 0
    no_binding = binding.get("no-binding", 0)
    risk = _binding_risk_counts(events)
    risky_no_binding = risk["escaped_unbound"] + risk["unknown_no_mandate"]
    authorized_headless = risk["authorized_headless"]
    unknown_roles = roles.get("unknown", 0)
    broken = len(causal.get("broken", []))
    open_tails = len(causal.get("stalled", []))
    return [
        _framework_control(
            "runtime_traceability",
            "PASS" if has_events else "FAIL",
            "high" if not has_events else "low",
            ["NIS2 Art.21", "DORA ICT risk management", "SOC2 CC7"],
            [
                f"{len(events)} runtime event(s)",
                f"{len(raints)} raint(s)",
                f"{causal.get('checked', 0)} causal source(s)",
            ],
            "Runtime actions are projected into an auditable raint/event view."
            if has_events else
            "No runtime projection evidence found.",
        ),
        _framework_control(
            "human_oversight_and_accountability",
            "FAIL" if risky_no_binding else "WARN" if authorized_headless or (has_ai and not has_human) else "PASS" if has_human else "FAIL",
            "high" if risky_no_binding else "medium" if authorized_headless or (has_ai and not has_human) else "low",
            ["ISO/IEC 42001", "EU AI Act human oversight", "SR 26-2 broader governance"],
            [
                f"{binding.get('human', 0)} human-bound",
                f"{binding.get('ai', 0)} ai-autonomous",
                f"{no_binding} no-binding",
                f"{authorized_headless} authorized-headless",
                f"{risky_no_binding} risky-unbound",
            ],
            "Human/AI/no-binding split is visible for accountable challenge.",
        ),
        _framework_control(
            "role_integrity",
            "WARN" if unknown_roles else "PASS" if has_events else "FAIL",
            "medium" if unknown_roles else "low",
            ["NIS2 accountability", "SOC2 logical access", "ISO/IEC 42001 roles"],
            [f"{unknown_roles} unknown role event(s)", ", ".join(sorted(roles)) or "no roles"],
            "Raint, maint, saint, waint, operator, actor, and system roles are classified.",
        ),
        _framework_control(
            "tamper_evident_evidence",
            conclusions.get("iab.causal_integrity", {}).get("status", "FAIL"),
            "critical" if broken else "medium" if open_tails else "low",
            ["NIS2 logging", "DORA operational resilience", "SOC2 processing integrity"],
            [f"{broken} break(s)", f"{open_tails} open tail(s)"],
            "Evidence is checked against causal lineage, not just wall-clock order.",
        ),
        _framework_control(
            "agentic_ai_scope_bridge",
            "FAIL" if risky_no_binding else "WARN" if authorized_headless or open_tails or unknown_roles else "PASS" if has_events else "FAIL",
            "high" if risky_no_binding else "medium" if authorized_headless or open_tails or unknown_roles else "low",
            ["SR 26-2 governance gap", "NIST AI RMF", "ISO/IEC 23894"],
            [
                "agentic runtime evidence",
                f"{binding.get('ai', 0)} autonomous event(s)",
                f"{no_binding} no-binding event(s)",
                f"{authorized_headless} authorized-headless event(s)",
            ],
            "Bridges traditional model-risk scope to runtime governance for agentic AI.",
        ),
    ]


def _framework_control(
    control_id: str,
    status: str,
    materiality: str,
    frameworks: list[str],
    evidence: list[str],
    rationale: str,
) -> dict[str, Any]:
    return {
        "id": control_id,
        "status": status,
        "materiality": materiality,
        "frameworks": frameworks,
        "evidence": evidence,
        "rationale": rationale,
    }


def _framework_summary(controls: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    out: dict[str, dict[str, int]] = {}
    for control in controls:
        status = control.get("status", "UNKNOWN")
        for framework in control.get("frameworks", []):
            key = _framework_family(framework)
            row = out.setdefault(key, {"PASS": 0, "WARN": 0, "FAIL": 0, "UNKNOWN": 0})
            row[status if status in row else "UNKNOWN"] += 1
    return out


def _framework_family(value: str) -> str:
    lower = value.lower()
    if lower.startswith("nis2"):
        return "NIS2"
    if lower.startswith("dora"):
        return "DORA"
    if lower.startswith("soc2") or lower.startswith("soc 2"):
        return "SOC2"
    if lower.startswith("iso/iec 42001"):
        return "ISO/IEC 42001"
    if lower.startswith("iso/iec 23894"):
        return "ISO/IEC 23894"
    if lower.startswith("eu ai act"):
        return "EU AI Act"
    if lower.startswith("nist"):
        return "NIST AI RMF"
    if lower.startswith("sr 26-2"):
        return "SR 26-2"
    return value


def _framework_filter(value: str | None) -> str | None:
    if not value:
        return None
    aliases = {
        "nis2": "NIS2",
        "dora": "DORA",
        "soc2": "SOC2",
        "soc 2": "SOC2",
        "iso42001": "ISO/IEC 42001",
        "iso_42001": "ISO/IEC 42001",
        "iso-42001": "ISO/IEC 42001",
        "ai_act": "EU AI Act",
        "eu_ai_act": "EU AI Act",
        "nist": "NIST AI RMF",
        "nist_ai_rmf": "NIST AI RMF",
        "sr26-2": "SR 26-2",
        "sr_26_2": "SR 26-2",
    }
    normalized = value.strip().lower()
    return aliases.get(normalized, _framework_family(value))


def _control_matches_framework(control: dict[str, Any], framework: str | None) -> bool:
    if not framework:
        return True
    return any(_framework_family(item) == framework for item in control.get("frameworks", []))


def _materiality(events: list[dict[str, Any]], causal: dict[str, Any]) -> str:
    if causal.get("broken"):
        return "critical"
    risk = _binding_risk_counts(events)
    if risk["escaped_unbound"] or risk["unknown_no_mandate"]:
        return "high"
    if risk["authorized_headless"] or causal.get("stalled") or any(event.get("role") == "unknown" for event in events):
        return "medium"
    if events:
        return "low"
    return "unknown"


def _binding_risk_counts(events: list[dict[str, Any]]) -> dict[str, int]:
    counts = {
        "authorized_headless": 0,
        "escaped_unbound": 0,
        "unknown_no_mandate": 0,
        "system_infra": 0,
    }
    for event in events:
        posture = event.get("binding_posture", {}).get("class")
        if posture in counts:
            counts[posture] += 1
    return counts


def _max_materiality(values) -> str:
    order = {"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    best = "unknown"
    for value in values:
        if order.get(str(value), 0) > order[best]:
            best = str(value)
    return best


def _posture_from_materiality(materiality: str) -> str:
    return {
        "critical": "blocked",
        "high": "needs-review",
        "medium": "watch",
        "low": "governed",
        "unknown": "unknown",
    }.get(materiality, "unknown")


_IAB_REPORT_CSS = """
:root {
  color-scheme: light;
  --ink: #17202a;
  --muted: #5d6875;
  --line: #d8dee7;
  --panel: #f7f9fc;
  --pass: #116b45;
  --warn: #8a5a00;
  --fail: #a61b1b;
  --unknown: #596273;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: #eef2f7;
  color: var(--ink);
  font: 14px/1.45 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}
main {
  width: min(1180px, calc(100% - 32px));
  margin: 24px auto;
  background: #fff;
  border: 1px solid var(--line);
  border-radius: 8px;
  overflow: hidden;
}
header {
  padding: 28px 32px 24px;
  border-bottom: 1px solid var(--line);
}
.eyebrow {
  margin: 0 0 8px;
  color: var(--muted);
  text-transform: uppercase;
  font-size: 12px;
  letter-spacing: .08em;
}
h1 {
  margin: 0;
  font-size: 30px;
  line-height: 1.15;
}
h2 {
  margin: 0 0 14px;
  font-size: 18px;
}
.lede {
  max-width: 760px;
  margin: 10px 0 18px;
  color: var(--muted);
}
.posture {
  display: inline-flex;
  padding: 6px 10px;
  border-radius: 6px;
  border: 1px solid var(--line);
  background: var(--panel);
  font-weight: 650;
}
.posture-critical, .posture-high { color: var(--fail); }
.posture-medium { color: var(--warn); }
.posture-low { color: var(--pass); }
.cards {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(132px, 1fr));
  gap: 1px;
  background: var(--line);
  border-bottom: 1px solid var(--line);
}
.cards article {
  background: #fff;
  padding: 16px;
}
.cards span {
  display: block;
  color: var(--muted);
  font-size: 12px;
}
.cards strong {
  display: block;
  margin-top: 6px;
  font-size: 22px;
}
section {
  padding: 24px 32px;
  border-bottom: 1px solid var(--line);
}
table {
  width: 100%;
  border-collapse: collapse;
  table-layout: fixed;
}
th, td {
  padding: 9px 10px;
  border-bottom: 1px solid var(--line);
  text-align: left;
  vertical-align: top;
  overflow-wrap: anywhere;
}
th {
  color: var(--muted);
  background: var(--panel);
  font-size: 12px;
  text-transform: uppercase;
}
.badge {
  display: inline-block;
  min-width: 56px;
  padding: 2px 7px;
  border-radius: 999px;
  font-weight: 700;
  text-align: center;
  border: 1px solid currentColor;
}
.badge-pass { color: var(--pass); }
.badge-warn { color: var(--warn); }
.badge-fail { color: var(--fail); }
.badge-unknown { color: var(--unknown); }
@media print {
  body { background: #fff; }
  main { width: 100%; margin: 0; border: 0; }
  section, header { break-inside: avoid; }
}
"""


def _html_table(headers: list[str], rows: list[list[Any]]) -> str:
    if not rows:
        rows = [["-" for _ in headers]]
    head = "".join(f"<th>{_e(item)}</th>" for item in headers)
    body = []
    for row in rows:
        body.append("<tr>" + "".join(_html_cell(value) for value in row) + "</tr>")
    return "<table><thead><tr>{}</tr></thead><tbody>{}</tbody></table>".format(
        head,
        "".join(body),
    )


def _html_cell(value: Any) -> str:
    if isinstance(value, str) and value.startswith("<span class=\"badge "):
        return f"<td>{value}</td>"
    return f"<td>{_e(value)}</td>"


def _html_exception_sections(causal: dict[str, Any]) -> list[str]:
    sections: list[str] = []
    if causal.get("broken"):
        sections.extend([
            "<section>",
            "<h2>Causal Breaks</h2>",
            _html_table(
                ["Runtime", "Source", "Record"],
                [
                    [item.get("runtime_id", ""), item.get("source", ""), item.get("break_at", "")]
                    for item in causal.get("broken", [])
                ],
            ),
            "</section>",
        ])
    if causal.get("stalled"):
        sections.extend([
            "<section>",
            "<h2>Open Tails</h2>",
            _html_table(
                ["Runtime", "Source", "Action", "Note"],
                [
                    [item.get("runtime_id", ""), item.get("source", ""), item.get("action", ""), item.get("note", "")]
                    for item in causal.get("stalled", [])
                ],
            ),
            "</section>",
        ])
    return sections


def _status_badge(status: str) -> str:
    value = str(status or "UNKNOWN").upper()
    cls = value.lower() if value in {"PASS", "WARN", "FAIL"} else "unknown"
    return f"<span class=\"badge badge-{cls}\">{_e(value)}</span>"


def _e(value: Any) -> str:
    return html.escape(str(value))


def _slug(value: Any) -> str:
    return re.sub(r"[^a-z0-9_-]+", "-", str(value).lower()).strip("-") or "unknown"


def _conclusion(status: str, summary: str) -> dict[str, str]:
    return {"status": status, "summary": summary}
