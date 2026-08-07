"""pqc.py — flag Harvest-Now-Decrypt-Later / quantum-forgeable provenance (gap #7).

    Credit: Red Specter · richard.specter.aint — HNDL research, published open on Zenodo (2026-08-07):
      https://zenodo.org/records/21834333  ·  https://zenodo.org/records/21834202

Richard's point: classical signatures (Ed25519 / ECDSA / RSA) and RFC3161-style timestamps are **retroactively
forgeable** once a cryptographically-relevant quantum computer exists. An audit trail is long-lived provenance
— exactly the thing an adversary would harvest now to forge later. tibet-audit's `tls` check looks at transport
ciphers; it never flagged this. This check does: it reads the crypto posture from the evidence and warns when
long-lived provenance is signed classical-only, recommending the hybrid response (Ed25519 + ML-DSA-65).

This is an AUDIT posture check + advisory — it does not implement PQC in the box (that is the box-side task).
Read-only; honest about what it actually observed.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

CREDIT = "Red Specter · richard.specter.aint · HNDL research (Zenodo, 2026-08-07)"
CREDIT_LINKS = ["https://zenodo.org/records/21834333", "https://zenodo.org/records/21834202"]
RECOMMENDATION = "hybrid Ed25519 + ML-DSA-65 for identity signatures and long-lived audit timestamps"

# classical signature schemes — forgeable by a CRQC (Shor); a threat to LONG-LIVED signed provenance.
_CLASSICAL_SIG = re.compile(r"ed25519|ecdsa|secp256[rk]1|\bp-?256\b|\bp-?384\b|\brsa\b|\bdsa\b|sha256withrsa", re.I)
# classical key-exchange — the confidentiality half of HNDL (harvest ciphertext now, decrypt later).
_CLASSICAL_KEX = re.compile(r"\becdh\b|x25519|x448|\bdh\b|rsa-?oaep|rsa-?kem", re.I)
# post-quantum schemes — the mitigation.
_PQC = re.compile(r"ml-?dsa|dilithium|slh-?dsa|sphincs|falcon|ml-?kem|kyber", re.I)
# classical timestamp anchoring — retroactively forgeable alongside the signature.
_TS = re.compile(r"rfc ?3161|timestamp|tsa\b", re.I)
# evidence that is LONG-LIVED provenance — the crown jewel HNDL targets.
_LONG_LIVED = ("ledger", "trail", "audit", "history", "release", "genesis", "signature", "provenance")


def scan_pqc_posture(scan_path: str | Path, max_files: int = 120) -> dict[str, Any]:
    """Read the crypto posture from evidence and classify HNDL exposure. Honest about what was observed."""
    root = Path(scan_path)
    hits = {"classical_sig": 0, "classical_kex": 0, "pqc": 0, "timestamp": 0}
    sources_classical: set[str] = set()
    sources_pqc: set[str] = set()
    long_lived_classical: set[str] = set()
    files: list[Path] = []
    if root.is_dir():
        for pat in ("*.jsonl", "*.json", "*.pem", "*.toml", "*.cfg"):
            files.extend(sorted(root.rglob(pat)))
    elif root.is_file():
        files = [root]
    for p in files[:max_files]:
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        name = p.name
        c_sig, c_kex, pqc, ts = (_CLASSICAL_SIG.search(text), _CLASSICAL_KEX.search(text),
                                 _PQC.search(text), _TS.search(text))
        if c_sig:
            hits["classical_sig"] += 1; sources_classical.add(name)
        if c_kex:
            hits["classical_kex"] += 1
        if pqc:
            hits["pqc"] += 1; sources_pqc.add(name)
        if ts:
            hits["timestamp"] += 1
        # long-lived provenance signed classical-only, no PQC in the same file → the HNDL crown-jewel exposure
        if c_sig and not pqc and any(k in name.lower() for k in _LONG_LIVED):
            long_lived_classical.add(name)

    if hits["pqc"] and hits["classical_sig"]:
        verdict, note = "hybrid", "post-quantum schemes present alongside classical — the recommended posture."
    elif hits["pqc"]:
        verdict, note = "pqc", "post-quantum schemes observed."
    elif hits["classical_sig"]:
        verdict = "hndl-exposed"
        note = ("long-lived provenance signed classical-only — retroactively forgeable once a CRQC exists "
                "(harvest-now-decrypt-later).")
    else:
        verdict, note = "not-observed", "no signature/crypto algorithm identifiers found in scope."

    return {
        "kind": "org.ainternet.tibet-audit.pqc-hndl.v1",
        "credit": CREDIT, "credit_links": CREDIT_LINKS,
        "verdict": verdict, "note": note,
        "hits": hits,
        "classical_sources": sorted(sources_classical)[:10],
        "pqc_sources": sorted(sources_pqc)[:10],
        "long_lived_exposed": sorted(long_lived_classical)[:10],
        "recommendation": RECOMMENDATION,
    }


# ── selftest PQC-V01..V03 (offline) ──
def _selftest() -> int:
    import tempfile
    ok = 0

    def check(n, c):
        nonlocal ok
        print(("  ✓ " if c else "  ✗ FAIL ") + n); assert c, n; ok += 1

    d = Path(tempfile.mkdtemp(prefix="pqc-"))
    # classical-only long-lived provenance → hndl-exposed
    (d / "trail.jsonl").write_text(json.dumps({"kind": "seal", "sig_alg": "Ed25519", "ts": 1}) + "\n")
    (d / "release-signature.json").write_text(json.dumps({"algorithm": "ecdsa-p256", "rfc3161": True}))
    r1 = scan_pqc_posture(d)
    check("PQC-V01 classical-only long-lived → hndl-exposed",
          r1["verdict"] == "hndl-exposed" and "trail.jsonl" in r1["long_lived_exposed"])
    check("PQC-V02 recommendation names the hybrid response", "ML-DSA-65" in r1["recommendation"])

    # add a PQC signature → hybrid
    (d / "identity.json").write_text(json.dumps({"sig_alg": "ML-DSA-65", "classic": "Ed25519"}))
    r2 = scan_pqc_posture(d)
    check("PQC-V03 PQC alongside classical → hybrid", r2["verdict"] == "hybrid" and r2["hits"]["pqc"] >= 1)

    print("\n  ALL GREEN — pqc: 3/3 (%d checks).  Credit: %s" % (ok, CREDIT))
    return 0


if __name__ == "__main__":
    raise SystemExit(_selftest())
