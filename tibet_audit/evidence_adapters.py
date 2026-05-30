"""Typed evidence adapters for TIBET operational audit sources."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class AdapterAssessment:
    adapter: str
    source: str
    status: str
    records: int
    summary: str
    signals: dict[str, Any]


class EvidenceAdapter:
    name = "generic"

    def matches(self, source_name: str, record: dict[str, Any]) -> bool:
        return False

    def assess(self, source_name: str, records: list[dict[str, Any]]) -> AdapterAssessment:
        return AdapterAssessment(self.name, source_name, "unknown", len(records), "No adapter assessment", {})


class ContinuitydAdapter(EvidenceAdapter):
    name = "continuityd"

    def matches(self, source_name: str, record: dict[str, Any]) -> bool:
        return "continuityd" in source_name or "continuity_id" in record or record.get("stage") == "sniff"

    def assess(self, source_name: str, records: list[dict[str, Any]]) -> AdapterAssessment:
        by_disposition: dict[str, int] = {}
        by_intake: dict[str, int] = {}
        quarantine = 0
        for record in records:
            disposition = str(record.get("disposition_hint") or "unknown")
            intake = str(record.get("intake_class") or "unknown")
            by_disposition[disposition] = by_disposition.get(disposition, 0) + 1
            by_intake[intake] = by_intake.get(intake, 0) + 1
            if disposition in {"quarantine", "reject", "triage-disguised"}:
                quarantine += 1
        status = "attention" if quarantine else "observed"
        return AdapterAssessment(
            self.name,
            source_name,
            status,
            len(records),
            f"{len(records)} intake events, {quarantine} require attention",
            {"by_disposition": by_disposition, "by_intake": by_intake, "attention_events": quarantine},
        )


class CapBusAdapter(EvidenceAdapter):
    name = "cap-bus"

    def matches(self, source_name: str, record: dict[str, Any]) -> bool:
        return "cap-bus" in source_name or "posture" in str(record.get("intent", "")) or "switches_changed" in record

    def assess(self, source_name: str, records: list[dict[str, Any]]) -> AdapterAssessment:
        transitions = 0
        switches: set[str] = set()
        last_posture = "unknown"
        for record in records:
            if "posture" in str(record.get("intent", "")):
                transitions += 1
                last_posture = str(record.get("to_posture") or record.get("posture") or last_posture)
            changed = record.get("switches_changed") or []
            if not isinstance(changed, list):
                changed = [changed]
            switches.update(str(item) for item in changed)
        status = "active" if transitions else "observed"
        return AdapterAssessment(
            self.name,
            source_name,
            status,
            len(records),
            f"{transitions} posture transitions, {len(switches)} switches observed",
            {"transitions": transitions, "last_posture": last_posture, "switches": sorted(switches)},
        )


class SnaftAdapter(EvidenceAdapter):
    name = "snaft"

    def matches(self, source_name: str, record: dict[str, Any]) -> bool:
        text = source_name.lower()
        return "snaft" in text or record.get("engine") == "snaft" or "policy" in record or "verdict" in record

    def assess(self, source_name: str, records: list[dict[str, Any]]) -> AdapterAssessment:
        verdicts: dict[str, int] = {}
        fail_closed = False
        for record in records:
            verdict = str(record.get("verdict") or record.get("action") or "unknown")
            verdicts[verdict] = verdicts.get(verdict, 0) + 1
            fail_closed = fail_closed or record.get("fail_mode") == "closed" or record.get("default_policy") == "deny"
        status = "ready" if fail_closed else "observed"
        return AdapterAssessment(
            self.name,
            source_name,
            status,
            len(records),
            f"{len(records)} policy/verdict events, fail-closed={fail_closed}",
            {"verdicts": verdicts, "fail_closed": fail_closed},
        )


class TibetPolAdapter(EvidenceAdapter):
    name = "tibet-pol"

    def matches(self, source_name: str, record: dict[str, Any]) -> bool:
        text = source_name.lower()
        return "pol" in text or record.get("operator") == "tibet-pol" or "approval_state" in record

    def assess(self, source_name: str, records: list[dict[str, Any]]) -> AdapterAssessment:
        approvals: dict[str, int] = {}
        for record in records:
            state = str(record.get("approval_state") or record.get("state") or record.get("decision") or "unknown")
            approvals[state] = approvals.get(state, 0) + 1
        status = "active" if approvals else "observed"
        return AdapterAssessment(
            self.name,
            source_name,
            status,
            len(records),
            f"{len(records)} operator policy events",
            {"approvals": approvals},
        )


class GatewayAdapter(EvidenceAdapter):
    name = "gateway"

    def matches(self, source_name: str, record: dict[str, Any]) -> bool:
        return "gateway" in source_name or record.get("observation_layer") == "tibet-gateway" or "lane_class" in record

    def assess(self, source_name: str, records: list[dict[str, Any]]) -> AdapterAssessment:
        lanes: dict[str, int] = {}
        emitters: dict[str, int] = {}
        for record in records:
            lane = str(record.get("lane_class") or "unknown")
            emitter = str(record.get("_emitter") or record.get("emitter") or "unknown")
            lanes[lane] = lanes.get(lane, 0) + 1
            emitters[emitter] = emitters.get(emitter, 0) + 1
        return AdapterAssessment(
            self.name,
            source_name,
            "observed",
            len(records),
            f"{len(records)} gateway lane events",
            {"lanes": lanes, "emitters": emitters},
        )


class CmailAdapter(EvidenceAdapter):
    name = "cmail"

    def matches(self, source_name: str, record: dict[str, Any]) -> bool:
        text = source_name.lower()
        return "cmail" in text or str(record.get("kind", "")).startswith("cmail.") or "content_hash" in record

    def assess(self, source_name: str, records: list[dict[str, Any]]) -> AdapterAssessment:
        sealed = 0
        command = 0
        for record in records:
            sealed += int(bool(record.get("sealed") or record.get("content_hash")))
            command += int(record.get("message_type") in {"command", "opdracht"} or record.get("intent") == "command")
        status = "ready" if sealed else "observed"
        return AdapterAssessment(
            self.name,
            source_name,
            status,
            len(records),
            f"{sealed} hashed/sealed messages, {command} command messages",
            {"sealed_or_hashed": sealed, "commands": command},
        )


class CortexAdapter(EvidenceAdapter):
    name = "tibet-cortex"

    def matches(self, source_name: str, record: dict[str, Any]) -> bool:
        text = source_name.lower()
        return "cortex" in text or "trust_level" in record or "l0_l4" in record or "cortex_level" in record

    def assess(self, source_name: str, records: list[dict[str, Any]]) -> AdapterAssessment:
        levels: dict[str, int] = {}
        for record in records:
            level = str(record.get("trust_level") or record.get("cortex_level") or record.get("l0_l4") or "unknown")
            levels[level] = levels.get(level, 0) + 1
        status = "observed" if levels else "unknown"
        return AdapterAssessment(
            self.name,
            source_name,
            status,
            len(records),
            f"{len(records)} cortex management events",
            {"levels": levels},
        )


ADAPTERS: tuple[EvidenceAdapter, ...] = (
    ContinuitydAdapter(),
    CapBusAdapter(),
    SnaftAdapter(),
    TibetPolAdapter(),
    GatewayAdapter(),
    CmailAdapter(),
    CortexAdapter(),
)


def assess_sources(source_records: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    assessments: list[AdapterAssessment] = []
    for source_name, records in sorted(source_records.items()):
        if not records:
            continue
        matched = False
        for adapter in ADAPTERS:
            if any(adapter.matches(source_name, record) for record in records):
                assessments.append(adapter.assess(source_name, records))
                matched = True
                break
        if not matched:
            assessments.append(AdapterAssessment(
                "generic-jsonl",
                source_name,
                "observed",
                len(records),
                f"{len(records)} JSONL records with no specialized adapter",
                {},
            ))
    return [asdict(item) for item in assessments]
