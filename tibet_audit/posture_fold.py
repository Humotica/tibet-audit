"""System-posture fold — the one-line header over the six-pane dashboard.

Root AI's contribution to the shared tibet-audit cockpit. The readiness lanes the
dashboard already computes (cockpit.build_readiness_lanes) ARE a posture tree.
Folding them with the MEET (per-digit minimum) gives ONE system posture: a single
#RCTAM that is only as strong as the weakest proven lane. One missing lane is the
bottom element (#00000) and darkens the whole system — dark-by-default as
arithmetic, not a compliance grade.

Doctrine: audit is not a revenue gate and not an external party's verdict. It is a
sovereign capability — you, and every actor, covering yourselves, locally, with no
one to phone. This header reads ONLY the local readiness lanes. It scores nothing;
it numbers the proven route. For humAnIty.

Prefers tibet_mux.posture_algebra.compose (single source of truth); falls back to a
local meet if tibet-mux is not installed, so the dashboard never hard-fails.
"""
from __future__ import annotations

from typing import Any

try:  # single source of truth
    from tibet_mux.posture_algebra import compose as _compose, verify_tree as _verify_tree
    _HAVE_MUX = True
except Exception:  # pragma: no cover - graceful fallback
    _HAVE_MUX = False

    def _compose(*postures: str) -> str:
        bodies = [p[1:] if p.startswith("#") else p for p in postures]
        return "#" + "".join(min(col) for col in zip(*bodies))

# Readiness status -> a readiness-derived posture. Placeholder mapping until
# Gravity's tibet-audit-through-posture core emits a real per-lane #RCTAM from
# events; the FOLD behaviour (weakest lane wins, missing = dark) is the point.
STATUS_POSTURE = {
    "ready":    "#34358",   # all required signals present
    "active":   "#34358",   # control actively working (e.g. containment)
    "partial":  "#34308",   # present but a dimension unproven (audit lowered)
    "baseline": "#34328",   # no event exercised this window (audit mid)
    "missing":  "#00000",   # nothing observed -> bottom -> floors the system
}
FULL_GREEN = "#34358"


def _status(lane: Any) -> str:
    return (lane.get("status") if isinstance(lane, dict) else getattr(lane, "status", "")) or ""


def _name(lane: Any) -> str:
    return (lane.get("name") if isinstance(lane, dict) else getattr(lane, "name", "")) or "?"


def lane_posture(lane: Any) -> str:
    return STATUS_POSTURE.get(_status(lane), "#34328")


def system_posture(lanes: list[Any]) -> dict[str, Any]:
    """Fold the lanes into one system posture + a smoke verdict against full-green."""
    if not lanes:
        return {"system": "#00000", "smoke_ok": False, "per_lane": [],
                "weakest": "no lanes observed"}
    postures = [lane_posture(l) for l in lanes]
    system = _compose(*postures)
    per_lane = [{"name": _name(l), "status": _status(l), "posture": p}
                for l, p in zip(lanes, postures)]
    if _HAVE_MUX:
        v = _verify_tree(postures, FULL_GREEN)
        smoke_ok, weakest = v.ok, v.weakest
    else:
        smoke_ok, weakest = (system == FULL_GREEN), ("" if system == FULL_GREEN else "below full-green")
    return {"system": system, "smoke_ok": smoke_ok, "per_lane": per_lane, "weakest": weakest}


def header_line(lanes: list[Any], evidence_active: int | None = None,
                evidence_total: int | None = None) -> str:
    """One-line dashboard header: the folded system posture + smoke + evidence."""
    fold = system_posture(lanes)
    smoke = "GREEN" if fold["smoke_ok"] else "RED"
    parts = [f"SYSTEM POSTURE {fold['system']}", f"smoke {smoke}"]
    if not fold["smoke_ok"] and fold["weakest"]:
        parts[-1] += f" ({fold['weakest']})"
    if evidence_active is not None and evidence_total is not None:
        parts.append(f"{evidence_active}/{evidence_total} evidence active")
    parts.append("sovereign · local-only · no external party")
    return "  ·  ".join(parts)
