"""T-1 genesis / pre-grant audit assessment.

The genesis layer does not grant capabilities. It audits whether a candidate
tool can safely become T0-ready.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from typing import Any


GENESIS_CONTRACT_VERSION = "tibet.genesis.t-1.v1"

GENESIS_REQUIRED_FIELDS = (
    "tool_id",
    "schema_hash",
    "description_hash",
    "allowed_tools_hash",
    "endpoint_hash",
    "registry_source",
    "retrieved_at",
    "retriever_identity",
    "magic_bytes",
    "tibet_token",
    "jis_claim",
    "airlock_verdict",
    "fork_id",
    "merge_to_t0_verdict",
)


@dataclass(frozen=True)
class GenesisAssessment:
    status: str
    summary: str
    candidate_count: int
    ready_count: int
    blocked_count: int
    forked_count: int
    events: tuple[dict[str, Any], ...]
    findings: tuple[dict[str, Any], ...]
    contract: dict[str, Any]
    content_hash: str


def _canonical_json(value: dict[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha256(value: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _event_type(record: dict[str, Any]) -> str:
    return str(record.get("event") or record.get("event_type") or record.get("phase") or "")


def is_genesis_event(record: dict[str, Any]) -> bool:
    kind = str(record.get("kind") or "")
    event = _event_type(record)
    return (
        kind.startswith("tibet.genesis.")
        or event.startswith("t-1.")
        or "merge_to_t0_verdict" in record
        or "genesis_candidate_id" in record
    )


def _contract_check(records: list[dict[str, Any]]) -> dict[str, Any]:
    capture_records = [
        record for record in records
        if _event_type(record) in {"t-1.capture", "t-1.clean-slate-attestation", "t-1.merge-to-t0"}
        or "merge_to_t0_verdict" in record
    ]
    missing: dict[str, int] = {}
    for record in capture_records:
        for field_name in GENESIS_REQUIRED_FIELDS:
            if field_name not in record or record.get(field_name) in (None, ""):
                missing[field_name] = missing.get(field_name, 0) + 1

    if not capture_records:
        status = "unknown"
    elif missing:
        status = "fail"
    else:
        status = "pass"

    return {
        "name": GENESIS_CONTRACT_VERSION,
        "status": status,
        "records_checked": len(capture_records),
        "required_fields": list(GENESIS_REQUIRED_FIELDS),
        "missing_required": missing,
    }


def assess_genesis_events(records: list[dict[str, Any]]) -> dict[str, Any]:
    genesis_records = [record for record in records if is_genesis_event(record)]
    findings: list[dict[str, Any]] = []
    ready_count = 0
    blocked_count = 0
    forked_count = 0

    for record in genesis_records:
        event = _event_type(record)
        verdict = str(record.get("airlock_verdict") or record.get("merge_to_t0_verdict") or record.get("verdict") or "")
        reason = str(record.get("reason") or record.get("m4_variant") or "")
        tool_id = str(record.get("tool_id") or record.get("genesis_candidate_id") or "unknown")

        if verdict in {"ready", "clean", "merge-ok", "allow"} or record.get("merge_to_t0_verdict") == "ready":
            ready_count += 1
            findings.append({"severity": "ok", "tool_id": tool_id, "event": event, "message": "candidate can merge to T0"})
        elif verdict in {"poisoned", "blocked", "fail", "reject", "no-grant"}:
            blocked_count += 1
            findings.append({"severity": "warning", "tool_id": tool_id, "event": event, "message": f"candidate blocked: {reason or verdict}"})
        elif verdict in {"fork", "forked", "mutation-before-merge"} or event == "t-1.fork":
            forked_count += 1
            findings.append({"severity": "warning", "tool_id": tool_id, "event": event, "message": f"candidate forked: {reason or verdict}"})

    contract = _contract_check(genesis_records)
    if blocked_count or forked_count:
        status = "attention"
    elif ready_count:
        status = "ready"
    elif genesis_records:
        status = "observed"
    else:
        status = "absent"

    assessment_without_hash = {
        "kind": "tibet.genesis.assessment.v1",
        "status": status,
        "candidate_count": len(genesis_records),
        "ready_count": ready_count,
        "blocked_count": blocked_count,
        "forked_count": forked_count,
        "findings": findings,
        "contract": contract,
    }
    assessment = GenesisAssessment(
        status=status,
        summary=(
            f"{len(genesis_records)} T-1 events, {ready_count} ready, "
            f"{blocked_count} blocked, {forked_count} forked"
        ),
        candidate_count=len(genesis_records),
        ready_count=ready_count,
        blocked_count=blocked_count,
        forked_count=forked_count,
        events=tuple(genesis_records),
        findings=tuple(findings),
        contract=contract,
        content_hash=_sha256(assessment_without_hash),
    )
    return asdict(assessment)
