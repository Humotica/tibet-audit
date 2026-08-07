"""red_specter.py — regression guards for the NIGHTFALL red-team findings (gap #22).

    ┌───────────────────────────────────────────────────────────────────────────┐
    │  CREDIT — these guards exist because of a real adversary who did it right.   │
    │                                                                             │
    │  Red Specter · richard.specter.aint                                         │
    │  NIGHTFALL engagement, 2026-08-06 (RS2026-002).                             │
    │                                                                             │
    │  Richard found that the TIBET ledger was forgeable (T143) and that tool     │
    │  manifests were unsigned and injectable (T152), and flagged that tombstoned │
    │  identities could still be accepted as callers (MED). Every finding below   │
    │  is his. Turning them into permanent regression guards is the most durable  │
    │  thanks we can give: his work now defends the box forever. — the AInternet  │
    │  family                                                                     │
    └───────────────────────────────────────────────────────────────────────────┘

A red-team finding fixed once can silently return. These checks assert each NIGHTFALL fix still holds — where
possible they are *self-proving*: they reproduce the original attack and require the defence to catch it, so if
the defence ever regresses, the guard turns EXPOSED. Read-only against real evidence; synthetic repros run in a
temp dir. tibet-audit is MIT — these guards are open, verifiable, and Richard is credited in the open.
"""
from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path
from typing import Any

CREDIT = "Red Specter · richard.specter.aint · NIGHTFALL RS2026-002 (2026-08-06)"
# Richard publishes his research in the open (Zenodo). tibet-audit is MIT — these guards are open too, and the
# repo is his to try: github.com/Humotica/tibet-audit  ·  "try for yourself".
CREDIT_LINKS = ["https://zenodo.org/records/21834333", "https://zenodo.org/records/21834202"]


def _check_c1_ledger_tampering(scan_path: Path) -> dict[str, Any]:
    """T143 — ledger erase/corrupt. Fix C1: verify-on-read (prev=sha256(previous line)). Self-proving:
    reproduce a tamper, require the detector to catch it; then scan the real ledger for live tampering."""
    from .causal_integrity import scan_causal_integrity

    # 1) self-proof — the defence must still catch a tampered chain (guards the detector against regressing)
    tmp = Path(tempfile.mkdtemp(prefix="rsv-c1-"))
    prev = ""; lines = []
    for ev in ({"kind": "up", "note": "a"}, {"kind": "reach", "note": "b"}, {"kind": "seal", "note": "c"}):
        t = dict(ev); t["prev"] = prev
        ln = json.dumps(t) + "\n"; lines.append(ln); prev = hashlib.sha256(ln.encode()).hexdigest()
    lines[1] = lines[1].replace('"b"', '"b-TAMPERED"')          # Richard's T143, in miniature
    (tmp / "trail.jsonl").write_text("".join(lines))
    detector_catches = scan_causal_integrity(tmp)["verdict"] == "broken"

    # 2) live scan — the real ledger under the scan path must itself be intact
    live = scan_causal_integrity(scan_path)
    live_broken = live["broken"]

    if not detector_catches:
        return {"status": "EXPOSED", "detail": "C1 defence regressed: causal-integrity no longer catches a "
                "tampered ledger (the T143 attack would succeed)."}
    if live_broken:
        first = live_broken[0]
        return {"status": "EXPOSED", "detail": f"live ledger tampering: {first['source']} @rec {first['break_at']} "
                "(T143 reproduced against real evidence)."}
    return {"status": "guarded", "detail": f"verify-on-read active; {live['checked']} source(s) intact."}


def _iter_waint_manifests(scan_path: Path, limit: int = 200):
    seen: set[Path] = set()
    if scan_path.is_dir():
        for p in sorted(scan_path.rglob("*.waint.json")):   # one rooted walk; dedup by resolved path
            rp = p.resolve()
            if rp in seen:
                continue
            seen.add(rp)
            yield p
            if len(seen) >= limit:
                return


def _check_c2_manifest_injection(scan_path: Path) -> dict[str, Any]:
    """T152 — unsigned .waint.json tool-manifest injection (persistence). Fix C2: sign + admit on read.
    Any executable tool manifest without a signature is the exact exposure Richard planted a backdoor through."""
    unsigned = []
    total = 0
    for p in _iter_waint_manifests(scan_path):
        total += 1
        try:
            d = json.loads(p.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            unsigned.append((p.name, "unparseable"))
            continue
        if not isinstance(d, dict):
            continue
        has_sig = any(k in d for k in ("signature", "sig", "sealed", "sha256", "manifest_sig"))
        executable = any(k in d for k in ("exec", "command", "cmd", "entrypoint"))
        if executable and not has_sig:
            unsigned.append((p.name, "executable, no signature"))
    if unsigned:
        return {"status": "EXPOSED", "detail": f"{len(unsigned)} unsigned executable tool manifest(s) "
                f"(T152): {', '.join(n for n, _ in unsigned[:5])}"}
    if total == 0:
        return {"status": "not-observed", "detail": "no .waint.json tool manifests under scan path."}
    return {"status": "guarded", "detail": f"{total} tool manifest(s), all signed."}


def _check_med_caller_freshness(scan_path: Path) -> dict[str, Any]:
    """MED — a tombstoned identity accepted as a caller. Fix: caller_freshness (verify + tombstone + freshness).
    Evidence check: a tombstoned id must never appear as an ACCEPTED caller; a refusal is the defence working."""
    tombstoned: set[str] = set()
    accepted_tombstoned: list[str] = []
    refusals = 0
    for p in list(scan_path.rglob("*.jsonl"))[:80]:
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for line in text.splitlines():
            line = line.strip()
            if not line or "tombstone" not in line.lower() and "caller" not in line.lower():
                continue
            try:
                d = json.loads(line)
            except Exception:
                continue
            if not isinstance(d, dict):
                continue
            blob = json.dumps(d).lower()
            who = d.get("aint") or d.get("from_aint") or d.get("caller") or ""
            if "tombston" in blob and d.get("event") in ("tombstone", "revoke") or d.get("kind") == "tombstone":
                if who:
                    tombstoned.add(who)
            if "0x0000" in blob and "tombston" in blob:
                refusals += 1
            accepted = d.get("accepted") is True or d.get("decision") == "accept" or "0x4000" in blob
            if accepted and who and who in tombstoned and "tombston" in blob:
                accepted_tombstoned.append(who)
    if accepted_tombstoned:
        return {"status": "EXPOSED", "detail": f"tombstoned identity accepted as caller (MED): "
                f"{', '.join(sorted(set(accepted_tombstoned))[:5])}"}
    if refusals:
        return {"status": "guarded", "detail": f"caller_freshness observed refusing {refusals} tombstoned caller(s)."}
    return {"status": "not-observed", "detail": "no tombstone/caller evidence in scope; enforced at accept sites (box #54)."}


RSV_FINDINGS = [
    {"id": "RSV-C1", "tibet_id": "T143", "title": "TIBET ledger tampering (erase/corrupt)",
     "fix": "C1 verify-on-read", "check": _check_c1_ledger_tampering},
    {"id": "RSV-C2", "tibet_id": "T152", "title": "Unsigned .waint.json manifest injection (persistence)",
     "fix": "C2 manifest-admission", "check": _check_c2_manifest_injection},
    {"id": "RSV-MED", "tibet_id": "MED", "title": "Tombstoned identity accepted as caller",
     "fix": "MED caller_freshness", "check": _check_med_caller_freshness},
]


def run_regression(scan_path: str | Path) -> dict[str, Any]:
    """Run every NIGHTFALL red-team finding as a regression guard. exposed>0 = a fixed vuln has returned."""
    root = Path(scan_path)
    results = []
    for f in RSV_FINDINGS:
        try:
            outcome = f["check"](root)
        except Exception as exc:
            outcome = {"status": "error", "detail": str(exc)}
        results.append({"id": f["id"], "tibet_id": f["tibet_id"], "title": f["title"],
                        "fix": f["fix"], **outcome})
    exposed = [r for r in results if r["status"] == "EXPOSED"]
    verdict = "regression" if exposed else "guarded"
    return {"kind": "org.ainternet.tibet-audit.red-specter.v1", "credit": CREDIT, "credit_links": CREDIT_LINKS,
            "verdict": verdict, "exposed": len(exposed), "findings": results}


# ── selftest RSV-V01..V03 (offline) ──
def _selftest() -> int:
    ok = 0

    def check(n, c):
        nonlocal ok
        print(("  ✓ " if c else "  ✗ FAIL ") + n); assert c, n; ok += 1

    # clean box: C1 detector proves itself, no unsigned manifests, no tombstone abuse → all guarded/not-observed
    clean = Path(tempfile.mkdtemp(prefix="rsv-clean-"))
    prev = ""; L = []
    for ev in ({"kind": "up", "note": "a"}, {"kind": "seal", "note": "b"}):
        t = dict(ev); t["prev"] = prev; ln = json.dumps(t) + "\n"; L.append(ln); prev = hashlib.sha256(ln.encode()).hexdigest()
    (clean / "trail.jsonl").write_text("".join(L))
    rep = run_regression(clean)
    check("RSV-V01 clean box → guarded (no regression)", rep["verdict"] == "guarded" and rep["exposed"] == 0)

    # T152 reproduced: an unsigned executable tool manifest must be caught
    box = Path(tempfile.mkdtemp(prefix="rsv-t152-"))
    (box / "manifests" / "tools").mkdir(parents=True)
    (box / "manifests" / "tools" / "backdoor.waint.json").write_text(
        json.dumps({"name": "backdoor.waint", "version": "1.0", "exec": "/bin/bash -c evil"}))
    rep2 = run_regression(box)
    c2 = next(r for r in rep2["findings"] if r["id"] == "RSV-C2")
    check("RSV-V02 T152 unsigned manifest → EXPOSED", c2["status"] == "EXPOSED" and rep2["verdict"] == "regression")

    # T143 reproduced: a tampered real ledger must be caught by C1
    box2 = Path(tempfile.mkdtemp(prefix="rsv-t143-"))
    prev = ""; L = []
    for ev in ({"kind": "up", "note": "a"}, {"kind": "reach", "note": "b"}, {"kind": "seal", "note": "c"}):
        t = dict(ev); t["prev"] = prev; ln = json.dumps(t) + "\n"; L.append(ln); prev = hashlib.sha256(ln.encode()).hexdigest()
    L[1] = L[1].replace('"b"', '"b-EVIL"'); (box2 / "trail.jsonl").write_text("".join(L))
    c1 = next(r for r in run_regression(box2)["findings"] if r["id"] == "RSV-C1")
    check("RSV-V03 T143 live ledger tamper → EXPOSED", c1["status"] == "EXPOSED")

    print("\n  ALL GREEN — red_specter: 3/3 (%d checks).  Credit: %s" % (ok, CREDIT))
    return 0


if __name__ == "__main__":
    raise SystemExit(_selftest())
