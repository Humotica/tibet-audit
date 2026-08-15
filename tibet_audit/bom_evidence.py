"""BOM evidence family — tibet-audit reads, mirrors, and grades a box's bills of materials as an EVIDENCE family.

The point (Codex BOM-EVIDENCE #2): tibet-audit does not *own* the BOMs and never assumes they are PyPI packages.
A BOM is an evidence ARTIFACT, not a distribution form. So we detect by artifact-name + schema (not "is package
installed"), mirror what is present, and grade a read-only posture. It is TOLERANT: a missing BOM is a posture, never
a hard failure. This lets the audit say not only *what happened*, but *what the machine, runtime, route and workload
were built from* when it happened.

Layer 1 (this module): detect + posture. Layer 3 (later, with the box): correlate can_carry↔sys-bom,
MUX-posture↔mux-bom, AI-workload↔ai-sbom, carrier/continuity↔cbom, release↔SBOM/hash/signature.
"""

from __future__ import annotations

import json
import os
from typing import Any

# The BOM family we recognise. `aka` = filename substrings (any match), `kind` = known schema kind(s), `of` = the
# plain-language subject the BOM attests. New members are additive — an unknown BOM-looking artifact is still counted
# under "other" rather than dropped.
BOM_FAMILY: list[dict[str, Any]] = [
    {"key": "system-bom", "aka": ["system-bom", "sys-bom", "sysbom"],
     "kinds": ["org.ainternet.box.system-bom.v1"], "of": "the machine floor it ran on"},
    {"key": "sbom", "aka": ["sbom", "software-bom", "cyclonedx", "spdx"],
     "kinds": ["org.ainternet.iab.sbom.v1"], "of": "the software components"},
    {"key": "ai-sbom", "aka": ["ai-sbom", "aisbom", "ai_sbom", "model-bom"],
     "kinds": ["org.ainternet.iab.ai-sbom.v1"], "of": "the AI models and workload"},
    {"key": "cbom", "aka": ["cbom", "crypto-bom", "cryptography-bom"],
     "kinds": ["org.ainternet.iab.cbom.v1"], "of": "the cryptographic materials"},
    {"key": "mux-bom", "aka": ["mux-bom", "muxbom", "mux_bom"],
     "kinds": ["org.ainternet.box.mux-bom.v1", "org.ainternet.iab.mux-bom.v1"], "of": "the routing / MUX posture"},
    {"key": "source-reproducible", "aka": ["source-reproducible", "reproducible", "source-repro"],
     "kinds": ["org.ainternet.iab.source-reproducible.v1"], "of": "reproducible-build provenance"},
    {"key": "hash-manifest", "aka": ["hash-manifest", "hash_manifest"],
     "kinds": ["org.ainternet.iab.hash-manifest.v1"], "of": "the release file hashes"},
    {"key": "release-signature", "aka": ["release-signature", "release_signature", "release-sig"],
     "kinds": ["org.ainternet.iab.release-signature.v1"], "of": "the release signatures"},
]

_COUNT_KEYS = ("components", "packages", "sensors", "entries", "artifacts", "items", "modules", "crates",
               "libraries", "algorithms", "models", "files", "primary_components", "kernel_components",
               "signatures")
_LINK_KEYS = ("box_id", "raint", "runtime", "runtime_id", "node", "node_id", "host", "chain_id")
_SIG_KEYS = ("signature", "signatures", "sig", "signed", "attestation", "cosign", "pgp")
_TS_KEYS = ("timestamp", "ts", "generated_at", "created", "created_at", "time")
_VER_KEYS = ("version", "spec_version", "schema_version", "bom_version")
_GEN_KEYS = ("generator", "tool", "producer", "created_by", "generated_by")


def _first_key(d: dict[str, Any], keys) -> Any:
    for k in keys:
        if k in d and d[k] not in (None, "", []):
            return d[k]
    return None


def _has_hash(d: dict[str, Any]) -> bool:
    for k, v in d.items():
        kl = str(k).lower()
        if v and (kl.endswith("_sha256") or kl.endswith("_hash") or kl.endswith("_digest")
                  or kl in ("hash", "digest", "sha256", "checksum", "checksums", "hashes", "files", "payload")):
            return True
    # a hash-manifest is, by definition, hashes
    return "hash" in str(d.get("kind") or "").lower()


def _has_signature(d: dict[str, Any]) -> bool:
    if any(bool(d.get(k)) for k in _SIG_KEYS):
        return True
    return "signature" in str(d.get("kind") or "").lower()


def _component_count(d: dict[str, Any]) -> int | None:
    for k in _COUNT_KEYS:
        v = d.get(k)
        if isinstance(v, list):
            return len(v)
        if isinstance(v, dict):
            return len(v)
    for k in ("component_count", "package_count", "kernel_component_count", "kernel_shipped_count",
              "tracked_file_count", "count", "n"):
        if isinstance(d.get(k), int):
            return d[k]
    return None


def _is_linked(d: dict[str, Any]) -> bool:
    return any(bool(d.get(k)) for k in _LINK_KEYS)


def _to_int(v: Any) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _posture(present: bool, has_evidence: bool, linked: bool, stale: bool) -> str:
    """complete / partial / missing / stale / unlinked — a tolerant read, never a hard fail."""
    if not present:
        return "missing"
    if stale:
        return "stale"
    if not has_evidence:
        return "partial"        # present but thin — no hash/signature to stand on
    if not linked:
        return "unlinked"       # real BOM, but not tied to a runtime/node — can't be placed in the chain
    return "complete"


def _scan_files(run: str) -> list[str]:
    hits: list[str] = []
    root = os.fspath(run)
    if not os.path.isdir(root):
        return hits
    for dirpath, _dirs, files in os.walk(root):
        if dirpath[len(root):].count(os.sep) > 4:
            continue
        for f in files:
            fl = f.lower()
            if not (fl.endswith(".json") or fl.endswith(".jsonl")):
                continue
            if any(tag in fl for tag in ("bom", "reproducible", "release", "manifest")):
                hits.append(os.path.join(dirpath, f))
    return hits


def _load(path: str) -> dict[str, Any] | None:
    try:
        with open(path, encoding="utf-8") as fh:
            first = fh.read()
        data = json.loads(first)
        if isinstance(data, dict):
            return data
        if isinstance(data, list) and data and isinstance(data[-1], dict):
            return data[-1]
    except Exception:
        # a jsonl file — take the last well-formed object
        try:
            last = None
            for line in open(path, encoding="utf-8"):
                line = line.strip()
                if line:
                    try:
                        obj = json.loads(line)
                        if isinstance(obj, dict):
                            last = obj
                    except Exception:
                        continue
            return last
        except Exception:
            return None
    return None


def _match_member(path: str, doc: dict[str, Any] | None) -> dict[str, Any] | None:
    name = os.path.basename(path).lower()
    kind = str((doc or {}).get("kind") or "").lower()
    # pass 1 — KIND is authoritative (the sealed schema, not a filename): ai-sbom.v1 must never fall to the sbom
    # member just because "sbom" is a substring of "ai-sbom".
    if kind:
        for member in BOM_FAMILY:
            if kind in [k.lower() for k in member["kinds"]]:
                return member
    # pass 2 — filename aka, MOST-SPECIFIC first so a longer token ("ai-sbom") beats a shorter one ("sbom").
    best, best_len = None, 0
    for member in BOM_FAMILY:
        for tag in member["aka"]:
            if tag in name and len(tag) > best_len:
                best, best_len = member, len(tag)
    return best


def build_bom_evidence(run: str, extra_roots=(), now_ts: int | None = None,
                       stale_after_s: int = 30 * 24 * 3600) -> dict[str, Any]:
    """Detect the BOM family under `run` (+ any `extra_roots`, e.g. the box's shipped `manifests/` dir), grade each,
    and summarise. Read-only, tolerant. On a REVIVED box (reseeded / recovered from an ungraceful death) the same
    family member can appear several times — we keep the newest as the headline but count the `instances` so the mess
    is stated, not hidden.

    `now_ts` (optional) = a reference time (e.g. the newest evidence tick) to judge staleness against; when omitted,
    nothing is marked stale (layer-1 stays conservative rather than guess a clock)."""
    found: dict[str, dict[str, Any]] = {}
    other: list[dict[str, Any]] = []
    instances: dict[str, int] = {}
    roots = [run] + [r for r in extra_roots if r]
    seen_paths: set[str] = set()
    for root in roots:
        for path in _scan_files(root):
            if path in seen_paths:
                continue
            seen_paths.add(path)
            doc = _load(path)
            member = _match_member(path, doc)
            d = doc or {}
            ts = _to_int(_first_key(d, _TS_KEYS))
            stale = bool(now_ts and ts and (now_ts - ts) > stale_after_s)
            has_evidence = _has_hash(d) or _has_signature(d)
            linked = _is_linked(d)
            entry = {
                "present": True,
                "path": os.path.basename(path),
                "kind": d.get("kind"),
                "timestamp": ts,
                "version": _first_key(d, _VER_KEYS),
                "generator": _first_key(d, _GEN_KEYS),
                "component_count": _component_count(d),
                "has_hash": _has_hash(d),
                "has_signature": _has_signature(d),
                "linked": linked,
                "posture": _posture(True, has_evidence, linked, stale),
            }
            if member:
                instances[member["key"]] = instances.get(member["key"], 0) + 1
                entry["of"] = member["of"]
                # keep the richest/newest instance as the headline if a member appears more than once (revived box)
                prev = found.get(member["key"])
                if not prev or (entry["timestamp"] or 0) >= (prev.get("timestamp") or 0):
                    entry["key"] = member["key"]
                    found[member["key"]] = entry
            else:
                entry["key"] = "other"
                other.append(entry)
    for key, entry in found.items():
        entry["instances"] = instances.get(key, 1)

    family: list[dict[str, Any]] = []
    for member in BOM_FAMILY:
        if member["key"] in found:
            family.append(found[member["key"]])
        else:
            family.append({
                "key": member["key"], "present": False, "of": member["of"],
                "posture": "missing", "path": None, "kind": None, "timestamp": None,
                "version": None, "generator": None, "component_count": None,
                "has_hash": False, "has_signature": False, "linked": False,
            })
    family.extend(other)

    counts = {"complete": 0, "partial": 0, "missing": 0, "stale": 0, "unlinked": 0}
    for e in family:
        counts[e["posture"]] = counts.get(e["posture"], 0) + 1
    present = sum(1 for e in family if e["present"])
    # koepel posture: complete only if every KNOWN member is complete; else partial; missing if none present
    known = [e for e in family if e["key"] != "other"]
    if present == 0:
        koepel = "missing"
    elif all(e["posture"] == "complete" for e in known if e["present"]) and counts["missing"] == 0:
        koepel = "complete"
    else:
        koepel = "partial"

    return {
        "kind": "org.ainternet.audit.bom-evidence.v1",
        "family": family,
        "summary": {
            "present": present,
            "total": len(family),
            "posture": koepel,
            "posture_counts": counts,
        },
    }


# ── renderers (self-contained so the report layer only calls, never re-implements) ──────────────────────────────

def render_bom_markdown(bom: dict[str, Any]) -> list[str]:
    if not bom or not bom.get("family"):
        return []
    s = bom.get("summary", {})
    lines = [
        "",
        "## BOM Evidence Family",
        "",
        f"- Koepel posture: **{s.get('posture', 'missing')}** "
        f"({s.get('present', 0)}/{s.get('total', 0)} present)",
    ]
    for e in bom.get("family", []):
        bits = []
        if e["present"]:
            if e.get("component_count") is not None:
                bits.append(f"{e['component_count']} components")
            if e.get("has_hash"):
                bits.append("hash")
            if e.get("has_signature"):
                bits.append("signed")
            if e.get("version"):
                bits.append(f"v{e['version']}")
            if (e.get("instances") or 1) > 1:
                bits.append(f"{e['instances']}× found (revived)")
        detail = (" — " + ", ".join(bits)) if bits else ""
        lines.append(f"- `{e['key']}` ({e.get('of', '')}): **{e['posture']}**{detail}")
    lines.append("")
    return lines


def _esc(v: Any) -> str:
    return (str(v).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")) if v is not None else ""


def render_bom_html(bom: dict[str, Any]) -> str:
    if not bom or not bom.get("family"):
        return ""
    s = bom.get("summary", {})
    rows = []
    for e in bom.get("family", []):
        bits = []
        if e["present"]:
            if e.get("component_count") is not None:
                bits.append(f"{e['component_count']} components")
            if e.get("has_hash"):
                bits.append("hash")
            if e.get("has_signature"):
                bits.append("signed")
            if e.get("version"):
                bits.append(f"v{_esc(e['version'])}")
            if (e.get("instances") or 1) > 1:
                bits.append(f"{e['instances']}× found (revived)")
        rows.append(
            f"<tr><td>{_esc(e['key'])}</td><td>{_esc(e.get('of', ''))}</td>"
            f"<td>{_esc(e['posture'])}</td><td>{_esc(', '.join(bits))}</td></tr>"
        )
    return (
        "<section><h2>BOM Evidence Family</h2>"
        f"<p>Koepel posture: <strong>{_esc(s.get('posture', 'missing'))}</strong> "
        f"({_esc(s.get('present', 0))}/{_esc(s.get('total', 0))} present) — read-only, tolerant: a missing BOM is a "
        "posture, never a hard failure.</p>"
        "<table><thead><tr><th>BOM</th><th>Attests</th><th>Posture</th><th>Evidence</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table></section>"
    )
