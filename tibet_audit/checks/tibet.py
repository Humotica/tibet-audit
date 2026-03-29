"""TIBET Provenance checks — IETF draft-vandemeent-tibet-provenance-01.

Validates compliance with TIBET (Traceable Intent-Based Event Tokens):
- ERIN (what), ERAAN (dependencies), EROMHEEN (context), ERACHTER (intent)
- Token chain integrity
- Provenance storage and retention policy
- Cryptographic verification (HMAC-SHA256)

References:
    https://datatracker.ietf.org/doc/draft-vandemeent-tibet-provenance/
"""

import json
from pathlib import Path
from typing import List

from .base import BaseCheck, CheckResult, Status, Severity, FixAction


def _find_files(scan_path: Path, names: List[str]) -> List[Path]:
    hits = []
    for name in names:
        for path in scan_path.rglob(name):
            if path.is_file():
                hits.append(path)
            if len(hits) >= 10:
                return hits
    return hits


def _read_text(path: Path, max_bytes: int = 200_000) -> str:
    try:
        data = path.read_bytes()[:max_bytes]
        return data.decode("utf-8", errors="ignore")
    except Exception:
        return ""


def _scan_code_for_patterns(scan_path: Path, patterns: List[str], extensions: List[str] = None) -> List[str]:
    """Scan code files for pattern matches. Returns matched patterns."""
    if extensions is None:
        extensions = ["*.py", "*.rs", "*.ts", "*.js", "*.go", "*.java"]
    found = []
    files_checked = 0
    for ext in extensions:
        for code_file in scan_path.rglob(ext):
            if files_checked >= 80:
                return found
            try:
                content = code_file.read_bytes()[:100_000].decode("utf-8", errors="ignore").lower()
                for pat in patterns:
                    if pat.lower() in content and pat not in found:
                        found.append(pat)
                files_checked += 1
            except Exception:
                continue
    return found


class TIBETTokenStructureCheck(BaseCheck):
    """Check for TIBET token creation with ERIN/ERAAN/EROMHEEN/ERACHTER fields."""
    check_id = "TIBET-001"
    name = "TIBET token structure (4-field)"
    description = "Checks that TIBET tokens include all four provenance fields: ERIN, ERAAN, EROMHEEN, ERACHTER."
    severity = Severity.HIGH
    category = "tibet"
    score_weight = 12

    def run(self, context: dict) -> CheckResult:
        scan_path = context["scan_path"]
        fields = ["erin", "eraan", "eromheen", "erachter"]
        found = _scan_code_for_patterns(scan_path, fields)

        if len(found) == 4:
            return CheckResult(
                check_id=self.check_id,
                name=self.name,
                status=Status.PASSED,
                severity=self.severity,
                message="All four TIBET fields found: ERIN, ERAAN, EROMHEEN, ERACHTER",
                references=["draft-vandemeent-tibet-provenance-01 §3"],
                score_impact=0,
            )
        elif found:
            missing = [f for f in fields if f not in [x.lower() for x in found]]
            return CheckResult(
                check_id=self.check_id,
                name=self.name,
                status=Status.WARNING,
                severity=self.severity,
                message=f"Partial TIBET fields: {', '.join(found)}. Missing: {', '.join(missing)}",
                recommendation="Implement all four TIBET fields per draft-vandemeent-tibet-provenance §3.",
                references=["draft-vandemeent-tibet-provenance-01 §3"],
                score_impact=self.score_weight // 2,
            )

        return CheckResult(
            check_id=self.check_id,
            name=self.name,
            status=Status.FAILED,
            severity=self.severity,
            message="No TIBET token structure (ERIN/ERAAN/EROMHEEN/ERACHTER) found in codebase.",
            recommendation="Implement TIBET tokens. See: draft-vandemeent-tibet-provenance §3.",
            references=["draft-vandemeent-tibet-provenance-01 §3"],
            score_impact=self.score_weight,
        )


class TIBETTokenChainCheck(BaseCheck):
    """Check for TIBET token chaining (parent_id linkage)."""
    check_id = "TIBET-002"
    name = "TIBET token chain integrity"
    description = "Checks that tokens are chained via parent references for audit trails."
    severity = Severity.HIGH
    category = "tibet"
    score_weight = 10

    def run(self, context: dict) -> CheckResult:
        scan_path = context["scan_path"]
        chain_patterns = ["parent_id", "parent_token", "token_chain", "chain_id", "previous_token"]
        found = _scan_code_for_patterns(scan_path, chain_patterns)

        # Also check for .tibet.json or token storage files
        token_files = _find_files(scan_path, ["*.tibet.json", "tibet_tokens.json", "tokens.jsonl", ".tibet/*"])

        if found or token_files:
            return CheckResult(
                check_id=self.check_id,
                name=self.name,
                status=Status.PASSED,
                severity=self.severity,
                message=f"Token chain linkage detected: {', '.join(found) if found else 'token files found'}",
                references=["draft-vandemeent-tibet-provenance-01 §3.5"],
                score_impact=0,
            )

        return CheckResult(
            check_id=self.check_id,
            name=self.name,
            status=Status.WARNING,
            severity=self.severity,
            message="No token chaining detected. TIBET requires linked provenance chains.",
            recommendation="Implement parent_id references between tokens per §3.5.",
            references=["draft-vandemeent-tibet-provenance-01 §3.5"],
            score_impact=self.score_weight // 2,
        )


class TIBETCryptoVerificationCheck(BaseCheck):
    """Check for HMAC-SHA256 or equivalent cryptographic token verification."""
    check_id = "TIBET-003"
    name = "TIBET cryptographic verification"
    description = "Checks for HMAC-SHA256 or equivalent integrity verification on TIBET tokens."
    severity = Severity.HIGH
    category = "tibet"
    score_weight = 10

    def run(self, context: dict) -> CheckResult:
        scan_path = context["scan_path"]
        crypto_patterns = [
            "hmac", "sha256", "sha-256", "hashlib", "crypto.createhmac",
            "ring::hmac", "hmac_sha256", "verify_signature", "token_hash"
        ]
        found = _scan_code_for_patterns(scan_path, crypto_patterns)

        if found:
            return CheckResult(
                check_id=self.check_id,
                name=self.name,
                status=Status.PASSED,
                severity=self.severity,
                message=f"Cryptographic verification found: {', '.join(found[:3])}",
                references=["draft-vandemeent-tibet-provenance-01 §4"],
                score_impact=0,
            )

        return CheckResult(
            check_id=self.check_id,
            name=self.name,
            status=Status.FAILED,
            severity=self.severity,
            message="No cryptographic token verification detected.",
            recommendation="Implement HMAC-SHA256 verification per TIBET §4 (Security).",
            references=["draft-vandemeent-tibet-provenance-01 §4"],
            score_impact=self.score_weight,
        )


class TIBETRetentionPolicyCheck(BaseCheck):
    """Check for token retention/lifecycle policy."""
    check_id = "TIBET-004"
    name = "TIBET token retention policy"
    description = "Checks for documented token retention and lifecycle management."
    severity = Severity.MEDIUM
    category = "tibet"
    score_weight = 6

    def run(self, context: dict) -> CheckResult:
        scan_path = context["scan_path"]
        policy_files = _find_files(scan_path, [
            "*retention*", "*lifecycle*", "*policy*.md", "*policy*.txt",
            "docs/*policy*", "SECURITY.md", "COMPLIANCE.md"
        ])

        keywords = ["retention", "lifecycle", "token expir", "archive", "purge"]
        for path in policy_files:
            text = _read_text(path).lower()
            if any(k in text for k in keywords):
                return CheckResult(
                    check_id=self.check_id,
                    name=self.name,
                    status=Status.PASSED,
                    severity=self.severity,
                    message=f"Retention/lifecycle policy found: {path.name}",
                    references=["draft-vandemeent-tibet-provenance-01 §3.7"],
                    score_impact=0,
                )

        return CheckResult(
            check_id=self.check_id,
            name=self.name,
            status=Status.WARNING,
            severity=self.severity,
            message="No token retention or lifecycle policy documentation found.",
            recommendation="Document token retention periods per TIBET §3.7.",
            references=["draft-vandemeent-tibet-provenance-01 §3.7"],
            score_impact=self.score_weight,
        )


class TIBETStateTransitionCheck(BaseCheck):
    """Check for TIBET state machine (CREATED→DETECTED→CLASSIFIED→MITIGATED→RESOLVED)."""
    check_id = "TIBET-005"
    name = "TIBET state transitions"
    description = "Checks for implementation of the TIBET token state machine."
    severity = Severity.MEDIUM
    category = "tibet"
    score_weight = 6

    def run(self, context: dict) -> CheckResult:
        scan_path = context["scan_path"]
        states = ["created", "detected", "classified", "mitigated", "resolved"]
        found = _scan_code_for_patterns(scan_path, states)

        # Need at least 3 of 5 states for meaningful state machine
        if len(found) >= 3:
            return CheckResult(
                check_id=self.check_id,
                name=self.name,
                status=Status.PASSED,
                severity=self.severity,
                message=f"TIBET state transitions found: {', '.join(found)}",
                references=["draft-vandemeent-tibet-provenance-01 §3.3"],
                score_impact=0,
            )
        elif found:
            return CheckResult(
                check_id=self.check_id,
                name=self.name,
                status=Status.WARNING,
                severity=self.severity,
                message=f"Partial state machine: {', '.join(found)} ({len(found)}/5)",
                recommendation="Implement full TIBET state machine: CREATED→DETECTED→CLASSIFIED→MITIGATED→RESOLVED.",
                references=["draft-vandemeent-tibet-provenance-01 §3.3"],
                score_impact=self.score_weight // 2,
            )

        return CheckResult(
            check_id=self.check_id,
            name=self.name,
            status=Status.WARNING,
            severity=self.severity,
            message="No TIBET state transitions detected.",
            recommendation="Implement token state machine per TIBET §3.3.",
            references=["draft-vandemeent-tibet-provenance-01 §3.3"],
            score_impact=self.score_weight,
        )


TIBET_CHECKS = [
    TIBETTokenStructureCheck(),
    TIBETTokenChainCheck(),
    TIBETCryptoVerificationCheck(),
    TIBETRetentionPolicyCheck(),
    TIBETStateTransitionCheck(),
]
