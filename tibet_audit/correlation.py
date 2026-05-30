"""Evidence correlation for operator-readable incident chains."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class ChainStep:
    subsystem: str
    action: str
    summary: str
    ts: str | None
    source: str
    severity: str


@dataclass(frozen=True)
class EvidenceChain:
    chain_id: str
    title: str
    status: str
    severity: str
    steps: tuple[ChainStep, ...]
    missing_links: tuple[str, ...]


def _ts(record: dict[str, Any]) -> str | None:
    value = record.get("ts") or record.get("timestamp") or record.get("time") or record.get("created_at")
    return str(value) if value is not None else None


def _source(record: dict[str, Any]) -> str:
    return str(record.get("_source") or "unknown")


def _is_external_ai_context(record: dict[str, Any]) -> bool:
    text = " ".join(str(value) for value in record.values())
    return "external_ai" in text or "external-ai" in text or "external ai" in text.lower()


def _find_first(records: list[dict[str, Any]], predicate) -> dict[str, Any] | None:
    for record in records:
        if predicate(record):
            return record
    return None


def _step(subsystem: str, action: str, summary: str, record: dict[str, Any], severity: str = "info") -> ChainStep:
    return ChainStep(subsystem, action, summary, _ts(record), _source(record), severity)


def _severity_for_missing(missing: list[str], steps: list[ChainStep]) -> str:
    if any(step.severity == "warning" for step in steps):
        return "warning"
    if missing:
        return "partial"
    return "ok"


def _status_for_missing(missing: list[str]) -> str:
    return "complete" if not missing else "partial"


def build_evidence_chains(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    chains: list[EvidenceChain] = []

    posture = _find_first(
        events,
        lambda record: "posture" in str(record.get("intent", ""))
        and (
            "deny_external_ai_inbound" in str(record.get("switches_changed", ""))
            or _is_external_ai_context(record)
        ),
    )
    snaft_deny = _find_first(
        events,
        lambda record: (record.get("engine") == "snaft" or "snaft" in _source(record))
        and str(record.get("verdict") or record.get("action")).lower() in {"deny", "block", "quarantine"},
    )
    continuity_quarantine = _find_first(
        events,
        lambda record: str(record.get("disposition_hint") or "") in {"quarantine", "triage-disguised", "reject"},
    )
    gateway_deny = _find_first(
        events,
        lambda record: ("gateway" in _source(record) or record.get("observation_layer") == "tibet-gateway")
        and ("deny" in str(record.get("lane_collision_policy", "")) or _is_external_ai_context(record)),
    )
    pol_block = _find_first(
        events,
        lambda record: (record.get("operator") == "tibet-pol" or "pol-verdict" in _source(record))
        and str(record.get("approval_state") or record.get("decision")).lower() in {"blocked", "deny", "rejected"},
    )
    cmail_notice = _find_first(
        events,
        lambda record: ("cmail" in _source(record) or str(record.get("kind", "")).startswith("cmail."))
        and (_is_external_ai_context(record) or str(record.get("message_type")) in {"command", "opdracht"}),
    )
    cortex_deny = _find_first(
        events,
        lambda record: ("cortex" in _source(record) or record.get("system") == "tibet-cortex")
        and ("deny" in str(record.get("action", "")) or _is_external_ai_context(record)),
    )

    if any([posture, snaft_deny, continuity_quarantine, gateway_deny, pol_block, cmail_notice, cortex_deny]):
        steps: list[ChainStep] = []
        missing: list[str] = []
        if posture:
            steps.append(_step(
                "cap-bus",
                "posture-transition",
                f"{posture.get('from_posture', 'unknown')} -> {posture.get('to_posture', posture.get('posture', 'unknown'))}",
                posture,
            ))
        else:
            missing.append("cap-bus posture transition")

        if snaft_deny:
            steps.append(_step("snaft", "precheck", str(snaft_deny.get("reason") or "deny verdict"), snaft_deny, "warning"))
        else:
            missing.append("SNAFT deny verdict")

        if continuity_quarantine:
            steps.append(_step(
                "continuityd",
                "intake",
                f"{continuity_quarantine.get('name', 'object')} -> {continuity_quarantine.get('disposition_hint')}",
                continuity_quarantine,
                "warning",
            ))
        else:
            missing.append("continuityd quarantine/reject event")

        if gateway_deny:
            steps.append(_step(
                "gateway",
                "lane-policy",
                f"{gateway_deny.get('lane_class', 'lane')} -> {gateway_deny.get('lane_collision_policy', 'observed')}",
                gateway_deny,
            ))
        else:
            missing.append("gateway lane policy event")

        if pol_block:
            steps.append(_step(
                "tibet-pol",
                "operator-policy",
                f"{pol_block.get('subject', 'subject')} -> {pol_block.get('approval_state') or pol_block.get('decision')}",
                pol_block,
            ))
        else:
            missing.append("tibet-pol block/approval event")

        if cmail_notice:
            steps.append(_step(
                "cmail",
                "operator-notice",
                str(cmail_notice.get("subject") or cmail_notice.get("kind") or "cmail notification"),
                cmail_notice,
            ))
        else:
            missing.append("cmail operator notice")

        if cortex_deny:
            steps.append(_step(
                "tibet-cortex",
                "context-policy",
                f"{cortex_deny.get('cortex_level', cortex_deny.get('trust_level', 'level'))}: {cortex_deny.get('subject', '-')}",
                cortex_deny,
            ))
        else:
            missing.append("tibet-cortex context event")

        chains.append(EvidenceChain(
            chain_id="chain_external_ai_containment",
            title="External AI containment chain",
            status=_status_for_missing(missing),
            severity=_severity_for_missing(missing, steps),
            steps=tuple(steps),
            missing_links=tuple(missing),
        ))

    cmail_send = _find_first(
        events,
        lambda record: ("cmail" in _source(record) or str(record.get("kind", "")).startswith("cmail."))
        and bool(record.get("content_hash")),
    )
    pol_approve = _find_first(
        events,
        lambda record: (record.get("operator") == "tibet-pol" or "pol-verdict" in _source(record))
        and str(record.get("approval_state") or record.get("decision")).lower() in {"approved", "allow", "accepted"},
    )
    if cmail_send or pol_approve:
        steps = []
        missing = []
        if cmail_send:
            steps.append(_step(
                "cmail",
                "sealed-message",
                f"{cmail_send.get('from', '?')} -> {cmail_send.get('to', '?')}: {cmail_send.get('subject', '-')}",
                cmail_send,
            ))
        else:
            missing.append("cmail hashed/sealed message")
        if pol_approve:
            steps.append(_step(
                "tibet-pol",
                "operator-approval",
                f"{pol_approve.get('subject', 'subject')} -> {pol_approve.get('approval_state') or pol_approve.get('decision')}",
                pol_approve,
            ))
        else:
            missing.append("tibet-pol approval")
        chains.append(EvidenceChain(
            chain_id="chain_cmail_operator_send",
            title="Cmail operator send chain",
            status=_status_for_missing(missing),
            severity=_severity_for_missing(missing, steps),
            steps=tuple(steps),
            missing_links=tuple(missing),
        ))

    return [asdict(chain) for chain in chains]
