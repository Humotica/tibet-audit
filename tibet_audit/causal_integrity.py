"""causal_integrity.py — verify evidence against the box's OWN causal lineage, not wall-clock (gap #1).

tibet-audit reads JSONL evidence as records ordered by timestamp. But the box hash-chains its ticks:
`prev = sha256(previous raw line)`. This module verifies THAT chain — so the audit conclusion can carry
"the evidence is causally intact / broken at record K / has a process that never resolved" instead of
trusting a wall-clock order that can be back-dated.

Vendored (a self-contained mirror of the box audit-koepel `tick_trail` primitive) so tibet-audit has no hard
dependency on the box tools directory. Read-only; never mutates evidence.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

# Hash-chained sources worth verifying under a scan path (others are treated as event-logs, nothing to chain).
_KNOWN_CHAINED = [
    "tibet-trail.jsonl", "trail.jsonl", "audit.jsonl", "continuityd-audit.jsonl", "continuityd.jsonl",
    "gateway.jsonl", "pol-verdicts.jsonl", "cmail.jsonl", "cap-bus.jsonl", "snaft-audit.jsonl",
    "tibet/history.jsonl", "enclave/work-ledger.jsonl", "triage/events.jsonl",
    # tibet-cascade — the stack-wide causal-correlation feed (JIS→TIBET→cap-bus→gateway→ping→continuityd→
    # Phantom→evidence). Its events.jsonl is another causal spoor to verify; it correlates the sources above.
    "cascade/events.jsonl", "cascade-events.jsonl", ".tibet/cascade/events.jsonl",
]

_STATUS_RE = re.compile(r"0x[0-9a-fA-F]{4}(?::[a-zA-Z0-9._-]+)?")
_OPEN_RE = re.compile(r"pending|await|start|open|offer|request|hold|invite|enroll", re.I)
_TERMINAL_RE = re.compile(r"seal|done|complete|closed|confirmed|retire|revoke|refus|deni|reject|grant|stop", re.I)


def _cands(raw: str) -> set[str]:
    """The box hashes the raw line; emitters differ on the trailing newline, so accept all three forms."""
    s = raw
    return {
        hashlib.sha256(s.encode()).hexdigest(),
        hashlib.sha256(s.rstrip("\n").encode()).hexdigest(),
        hashlib.sha256((s.rstrip("\n") + "\n").encode()).hexdigest(),
    }


def _fields(d: dict[str, Any]) -> dict[str, Any]:
    action = d.get("action") or d.get("event") or d.get("phase") or d.get("kind") or d.get("op") or ""
    note = d.get("note") or d.get("reason") or d.get("detail") or ""
    status = None
    for f in ("route", "seal_state", "status", "banner", "verdict", "note", "reason", "action", "event", "phase", "kind"):
        v = d.get(f)
        if isinstance(v, str):
            m = _STATUS_RE.search(v)
            if m:
                status = m.group(0)
                break
    return {"prev": str(d.get("prev") or d.get("parent") or ""), "action": action, "note": note, "status": status}


def _tick_state(f: dict[str, Any]) -> str:
    """terminal (resolved — granted/sealed/dark-refused) · open (started, unresolved) · plain."""
    st = f.get("status") or ""
    if st.startswith("0x4000") or st.startswith("0x0000"):
        return "terminal"
    blob = (f.get("action") or "") + " " + (f.get("note") or "")
    if _OPEN_RE.search(blob):
        return "open"
    if _TERMINAL_RE.search(blob):
        return "terminal"
    return "plain"


def verify_file(path: Path) -> dict[str, Any] | None:
    """Verify one JSONL evidence file against its own hash chain. None if unreadable/empty."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    raw_lines = [ln for ln in text.splitlines(keepends=True) if ln.strip()]
    if not raw_lines:
        return None
    parsed: list[dict[str, Any] | None] = []
    for ln in raw_lines:
        try:
            d = json.loads(ln.strip())
            parsed.append(_fields(d) if isinstance(d, dict) else None)
        except Exception:
            parsed.append(None)
    chained = sum(1 for p in parsed if p and p.get("prev"))
    if chained == 0:
        return {"source": path.name, "kind": "event-log", "records": len(raw_lines), "intact": True, "break_at": None}
    intact, break_at = True, None
    for i in range(1, len(raw_lines)):
        pv = parsed[i]["prev"] if parsed[i] else ""
        if not pv:                                      # empty prev mid-stream = a chain restart (genesis)
            continue
        if pv not in _cands(raw_lines[i - 1]):
            intact, break_at = False, i
            break
    result: dict[str, Any] = {"source": path.name, "kind": "chain", "records": len(raw_lines),
                              "intact": intact, "break_at": break_at}
    last = next((p for p in reversed(parsed) if p), None)
    if last and _tick_state(last) == "open":            # started, never resolved — the Pol'n symptom
        result["open_tail"] = {"action": last["action"], "note": last["note"]}
    return result


def scan_causal_integrity(scan_path: str | Path, max_files: int = 60) -> dict[str, Any]:
    """Verify the causal integrity of the JSONL evidence under a scan path. The conclusion layer folds this in.

    Returns { verdict: intact|broken, checked: N, sources: {name: {...}}, broken: [...], stalled: [...] }."""
    root = Path(scan_path)
    seen: set[Path] = set()
    files: list[Path] = []
    for name in _KNOWN_CHAINED:
        p = root / name
        if p.is_file():
            files.append(p); seen.add(p.resolve())
    if root.is_dir():
        for p in sorted(root.rglob("*.jsonl")):
            rp = p.resolve()
            if rp in seen:
                continue
            files.append(p); seen.add(rp)
            if len(files) >= max_files:
                break
    sources: dict[str, Any] = {}
    broken: list[dict[str, Any]] = []
    stalled: list[dict[str, Any]] = []
    for p in files:
        chk = verify_file(p)
        if not chk:
            continue
        key = str(p.relative_to(root)) if root in p.parents or root == p.parent else p.name
        sources[key] = chk
        if chk["kind"] == "chain" and not chk["intact"]:
            broken.append({"source": key, "break_at": chk["break_at"]})
        if chk.get("open_tail"):
            stalled.append({"source": key, **chk["open_tail"]})
    verdict = "broken" if broken else "intact"
    return {"verdict": verdict, "checked": len(sources), "sources": sources, "broken": broken, "stalled": stalled}


# ── selftest (offline; parity with the box koepel pol vectors) ──
def _selftest() -> int:
    import tempfile, os
    d = Path(tempfile.mkdtemp(prefix="causal-integrity-"))

    def chain(name, events):
        prev = ""; lines = []
        for ev in events:
            t = dict(ev); t["prev"] = prev
            line = json.dumps(t) + "\n"
            lines.append(line); prev = hashlib.sha256(line.encode()).hexdigest()
        (d / name).write_text("".join(lines))

    ok = 0

    def check(n, c):
        nonlocal ok
        print(("  ✓ " if c else "  ✗ FAIL ") + n); assert c, n; ok += 1

    chain("trail.jsonl", [{"kind": "up", "note": "a"}, {"kind": "reach", "note": "0x4000"}, {"kind": "seal", "note": "sealed 0x4000"}])
    chain("continuityd-audit.jsonl", [{"kind": "request", "note": "welcome vertex startup"}, {"kind": "offer", "note": "awaiting enroll-confirm"}])
    rep = scan_causal_integrity(d)
    check("CI-V01 intact chain verifies", rep["verdict"] == "intact" and rep["sources"]["trail.jsonl"]["intact"])
    check("CI-V02 open tail (Pol'n) flagged", any(s["source"] == "continuityd-audit.jsonl" for s in rep["stalled"]))
    ls = (d / "trail.jsonl").read_text().splitlines(keepends=True)
    ls[1] = ls[1].replace("0x4000", "TAMPERED")
    (d / "trail.jsonl").write_text("".join(ls))
    rep2 = scan_causal_integrity(d)
    check("CI-V03 tamper → broken @rec 2", rep2["verdict"] == "broken"
          and any(b["source"] == "trail.jsonl" and b["break_at"] == 2 for b in rep2["broken"]))
    print("\n  ALL GREEN — causal_integrity: 3/3 (%d checks)." % ok)
    return 0


if __name__ == "__main__":
    raise SystemExit(_selftest())
