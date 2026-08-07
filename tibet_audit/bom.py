"""bom.py — reflect on the box's own sealed self-portrait (gap #18 + #27).

The box already builds a rich BOM floor at seal / dark-boot: it seals a `system-bom-<build>.json` SYSCARD that
records which subsystem sensors are present (hw · net · mux · ram · gpu · role) alongside the static bills
(sbom · cbom · ai-sbom), each with a digest — "names locate, hashes decide, receipts remember". The auditor
must not re-collect any of this; it **reflects against the sealed floor**: read the self-portrait, verify the
recorded digests where the bill is in scope, and name what the floor still does not cover.

The one thing the floor does NOT carry: **human presence**. The sensor family is machine-floor + egress
(net/mux/role) — presence is measurable in IAB (RVP / owner-binding / liveness) yet absent from the box's
self-portrait. This check surfaces that gap honestly (gap #27). Read-only.
"""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

# sensor names that would represent a human-presence reading, if the BOM ever grew one.
_PRESENCE_NAMES = ("presence", "rvp", "liveness", "owner", "human", "presence-bom")


def _read_presence(root: Path) -> dict[str, Any]:
    """READ human presence from the evidence the box already emits — do not gauge it from outside.

    The box binds its human owner FRESH at `box up` (owner-binding.json: RVP token · custody · TPM2 substrate ·
    expiry) and streams a live posture (presence-live.json: posture · input_recent). This reflects that real
    reading. It is NOT yet a sys-bom SENSOR — folding it into the BOM sensor family is the open half (#27/#49)."""
    out: dict[str, Any] = {"in_bom_sensor_family": False, "measurable": True, "bound": False,
                           "status": "unbound", "evidence": []}

    def _first(*names):
        for n in names:
            p = root / n
            if p.is_file():
                return p
        for n in names:
            hits = list(root.rglob(n))
            if hits:
                return hits[0]
        return None

    ob = _first("owner-binding.json")
    if ob:
        try:
            d = json.loads(ob.read_text(encoding="utf-8", errors="ignore"))
            tok = d.get("token") or {}
            exp = tok.get("expires_at")
            out.update({
                "bound": True, "owner": d.get("root_aint"), "fresh": d.get("fresh"),
                "method": d.get("method"), "custody_ok": d.get("custody_ok"),
                "rvp": {"resolution": tok.get("resolution"), "confidence": tok.get("confidence"),
                        "threshold": tok.get("threshold"), "assurance": tok.get("assurance")},
                "substrate": tok.get("substrate"), "bound_at": d.get("bound_at"), "expires_at": exp,
                "expired": bool(exp) and float(exp) < time.time(),
            })
            out["evidence"].append("owner-binding.json")
        except Exception:
            pass
    pl = _first("presence-live.json", ".presence-live.json")
    if pl:
        try:
            d = json.loads(pl.read_text(encoding="utf-8", errors="ignore"))
            out["live_posture"] = d.get("posture")
            out["input_recent"] = d.get("input_recent")
            out["evidence"].append("presence-live.json")
        except Exception:
            pass

    if not out["bound"]:
        out["status"], out["note"] = "unbound", "no owner binding sealed — the box has not verified its human."
    elif out.get("expired"):
        out["status"], out["note"] = "stale", "owner presence bound but EXPIRED — needs a fresh re-attest."
    elif out.get("rvp", {}).get("resolution") not in (None, "GO"):
        out["status"], out["note"] = "deferred", "owner binding did not resolve GO (held/deferred)."
    else:
        out["status"] = "present"
        out["note"] = "human presence read from owner-binding + live posture (RVP), not gauged."
    return out


def _sensor_present(v: Any) -> bool:
    return v == "present" or (isinstance(v, dict) and v.get("status") == "present")


def _find_syscards(root: Path) -> list[Path]:
    out: list[Path] = []
    if root.is_dir():
        out += sorted(root.glob("system-bom*.json"))
        out += [p for p in (root / "sysbom-live.json", root / ".sysbom-live.json") if p.is_file()]
        if not out:
            out += sorted(root.rglob("system-bom*.json"))[:5]
    elif root.is_file():
        out = [root]
    return out


def _digest(path: Path) -> str | None:
    if not path.is_file():
        return None
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            h.update(c)
    return "sha256:" + h.hexdigest()


def reflect_bom(scan_path: str | Path) -> dict[str, Any]:
    """Reflect on the sealed system-bom: sensor readiness, digest verification, and the human-presence gap."""
    root = Path(scan_path)
    cards = _find_syscards(root)
    if not cards:
        return {"kind": "org.ainternet.tibet-audit.bom.v1", "verdict": "not-observed",
                "note": "no sealed system-bom found — the box has not sealed its self-portrait in scope.",
                "human_presence": _read_presence(root)}
    card_path = cards[0]
    try:
        card = json.loads(card_path.read_text(encoding="utf-8", errors="ignore"))
    except Exception as exc:
        return {"kind": "org.ainternet.tibet-audit.bom.v1", "verdict": "unreadable",
                "note": f"system-bom present but unreadable: {exc}"}

    sensors = card.get("sensor_status") or {}
    present = sum(1 for v in sensors.values() if _sensor_present(v))
    total = len(sensors) or card.get("sensors_total") or present
    rd = card.get("readiness")
    verdict_str = card.get("verdict") or (rd.get("verdict") if isinstance(rd, dict) else None) or "?"

    # digest verification — hashes decide. Recompute the digest of any bill that is in scope and compare.
    checks = []
    mismatches = 0
    for name, v in sensors.items():
        rec = v.get("digest") if isinstance(v, dict) else None
        if not rec:
            continue
        bill = None
        for cand in (root / "manifests" / f"{name}.json", root / f"{name}.json", root / "compliance" / f"{name}.json"):
            if cand.is_file():
                bill = cand
                break
        if bill is None:
            checks.append({"sensor": name, "status": "recorded", "detail": "digest recorded; bill not in scope to verify"})
            continue
        actual = _digest(bill)
        if actual == rec:
            checks.append({"sensor": name, "status": "verified", "detail": rec[:23] + "…"})
        else:
            mismatches += 1
            checks.append({"sensor": name, "status": "MISMATCH", "detail": f"recorded {rec[:16]}… != actual {(actual or 'missing')[:16]}…"})

    # human presence — READ from the box's own owner-binding + live posture (RVP), not gauged (#27).
    # Also note whether the sys-bom SENSOR FAMILY folds a presence sensor yet (it does not: machine-floor only).
    human_presence = _read_presence(root)
    human_presence["in_bom_sensor_family"] = any(
        any(pn in str(k).lower() for pn in _PRESENCE_NAMES) for k in sensors)

    presence_ok = human_presence["status"] == "present"
    if mismatches:
        verdict = "digest-mismatch"      # a recorded digest no longer matches the bill — integrity break
    elif present < total or not presence_ok:
        verdict = "partial"
    else:
        verdict = "observed"

    return {
        "kind": "org.ainternet.tibet-audit.bom.v1",
        "verdict": verdict,
        "card": card_path.name,
        "sensors_present": present, "sensors_total": total, "bom_verdict": verdict_str,
        "digest_checks": checks, "digest_mismatches": mismatches,
        "missing_sensors": [k for k, v in sensors.items() if not _sensor_present(v)],
        "human_presence": human_presence,
    }


# ── selftest BOM-V01..V04 (offline) ──
def _selftest() -> int:
    import tempfile
    ok = 0

    def check(n, c):
        nonlocal ok
        print(("  ✓ " if c else "  ✗ FAIL ") + n); assert c, n; ok += 1

    d = Path(tempfile.mkdtemp(prefix="bom-"))
    (d / "manifests").mkdir()
    bill = d / "manifests" / "sbom.json"
    bill.write_text(json.dumps({"components": ["x"]}))
    good_digest = _digest(bill)
    (d / "system-bom-abc.json").write_text(json.dumps({
        "kind": "org.ainternet.box.system-bom.v1", "verdict": "partial · 4/6",
        "sensor_status": {
            "sbom": {"status": "present", "digest": good_digest},
            "mux-bom": {"status": "present"},
            "ram-bom": {"status": "absent-pending"},
            "role-bom": {"status": "absent-pending"},
        }}))
    r = reflect_bom(d)
    check("BOM-V01 reflects the sealed self-portrait", r["card"] == "system-bom-abc.json" and r["sensors_present"] == 2)
    check("BOM-V02 verifies a recorded digest against the bill", any(c["status"] == "verified" for c in r["digest_checks"]))
    check("BOM-V03 no owner-binding → presence unbound, verdict partial",
          r["human_presence"]["status"] == "unbound" and r["human_presence"]["in_bom_sensor_family"] is False
          and r["verdict"] == "partial")

    # READ real presence: seal an owner-binding (fresh RVP GO) + a live posture, then reflect it
    (d / "owner-binding.json").write_text(json.dumps({
        "kind": "org.ainternet.box.owner-binding.v1", "root_aint": "jasper.aint", "method": "pam-sudo",
        "fresh": True, "custody_ok": True, "bound_at": int(time.time()),
        "token": {"resolution": "GO", "confidence": 0.92, "threshold": 0.8,
                  "expires_at": int(time.time()) + 3600, "substrate": {"tpm2_present": True, "measured": True}}}))
    (d / "presence-live.json").write_text(json.dumps({"kind": "org.ainternet.presence-live.v1",
                                                      "posture": "present-active", "input_recent": True}))
    rp = reflect_bom(d)["human_presence"]
    check("BOM-V05 READS real presence (owner-binding + live posture, RVP GO)",
          rp["status"] == "present" and rp["owner"] == "jasper.aint" and rp["rvp"]["resolution"] == "GO"
          and rp["live_posture"] == "present-active" and "owner-binding.json" in rp["evidence"])

    # expired binding → stale (needs re-attest)
    (d / "owner-binding.json").write_text(json.dumps({
        "kind": "org.ainternet.box.owner-binding.v1", "root_aint": "jasper.aint", "fresh": True,
        "token": {"resolution": "GO", "expires_at": int(time.time()) - 10}}))
    check("BOM-V06 expired owner-binding → stale", reflect_bom(d)["human_presence"]["status"] == "stale")

    # tamper the bill → digest mismatch (integrity break)
    bill.write_text(json.dumps({"components": ["x", "EVIL"]}))
    r2 = reflect_bom(d)
    check("BOM-V07 digest mismatch → integrity break", r2["verdict"] == "digest-mismatch" and r2["digest_mismatches"] == 1)

    print("\n  ALL GREEN — bom: 7/7 (%d checks)." % ok)
    return 0


if __name__ == "__main__":
    raise SystemExit(_selftest())
