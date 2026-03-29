"""JIS Identity checks — IETF draft-vandemeent-jis-identity-01.

Validates compliance with JIS (JTel Identity Service):
- Identity file with jis: URI scheme
- Bilateral consent (handshake) before communication
- Intent declaration per action
- Key rotation policy
- Consent hash verification

References:
    https://datatracker.ietf.org/doc/draft-vandemeent-jis-identity/
"""

from pathlib import Path
from typing import List

from .base import BaseCheck, CheckResult, Status, Severity


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


class JISIdentityFileCheck(BaseCheck):
    check_id = "JIS-001"
    name = "JIS identity file present"
    description = "Looks for a JIS identity or metadata file."
    severity = Severity.HIGH
    category = "jis"
    score_weight = 10

    def run(self, context: dict) -> CheckResult:
        scan_path = context["scan_path"]
        names = ["jis.json", "jis.yaml", "identity.json", "identity.yaml", "jis_identity.json"]
        hits = _find_files(scan_path, names)
        if hits:
            return CheckResult(
                check_id=self.check_id,
                name=self.name,
                status=Status.PASSED,
                severity=self.severity,
                message=f"Found identity file(s): {', '.join(str(h) for h in hits[:3])}",
                score_impact=0,
            )
        return CheckResult(
            check_id=self.check_id,
            name=self.name,
            status=Status.FAILED,
            severity=self.severity,
            message="No JIS identity file found (expected jis.json/identity.json).",
            recommendation="Create a JIS identity file with owner/scope/environment.",
            score_impact=self.score_weight,
        )


class JISMetadataCheck(BaseCheck):
    check_id = "JIS-002"
    name = "JIS identity metadata completeness"
    description = "Checks for owner/scope/environment fields in identity data."
    severity = Severity.MEDIUM
    category = "jis"
    score_weight = 6

    def run(self, context: dict) -> CheckResult:
        scan_path = context["scan_path"]
        hits = _find_files(scan_path, ["jis.json", "identity.json", "identity.yaml", "jis.yaml"])
        if not hits:
            return CheckResult(
                check_id=self.check_id,
                name=self.name,
                status=Status.SKIPPED,
                severity=self.severity,
                message="No identity file found to validate metadata.",
                score_impact=0,
            )

        text = _read_text(hits[0]).lower()
        missing = [k for k in ("owner", "scope", "environment") if k not in text]
        if not missing:
            return CheckResult(
                check_id=self.check_id,
                name=self.name,
                status=Status.PASSED,
                severity=self.severity,
                message="Identity metadata includes owner/scope/environment.",
                score_impact=0,
            )

        return CheckResult(
            check_id=self.check_id,
            name=self.name,
            status=Status.WARNING,
            severity=self.severity,
            message=f"Identity metadata missing fields: {', '.join(missing)}",
            recommendation="Add missing identity metadata fields.",
            score_impact=self.score_weight,
        )


class JISKeyRotationPolicyCheck(BaseCheck):
    check_id = "JIS-003"
    name = "Key rotation policy present"
    description = "Checks for documentation of key rotation policy."
    severity = Severity.MEDIUM
    category = "jis"
    score_weight = 6

    def run(self, context: dict) -> CheckResult:
        scan_path = context["scan_path"]
        policy_files = _find_files(scan_path, ["*policy*.md", "*policy*.txt", "*security*.md", "*security*.txt"])
        keywords = ["key rotation", "rotate keys", "rotation policy"]
        for path in policy_files:
            text = _read_text(path).lower()
            if any(k in text for k in keywords):
                return CheckResult(
                    check_id=self.check_id,
                    name=self.name,
                    status=Status.PASSED,
                    severity=self.severity,
                    message=f"Key rotation policy found in {path}.",
                    score_impact=0,
                )

        return CheckResult(
            check_id=self.check_id,
            name=self.name,
            status=Status.WARNING,
            severity=self.severity,
            message="No explicit key rotation policy found.",
            recommendation="Document key rotation frequency and procedure.",
            score_impact=self.score_weight,
        )


def _scan_code_for_patterns(scan_path: Path, patterns: List[str]) -> List[str]:
    found = []
    files_checked = 0
    for ext in ["*.py", "*.rs", "*.ts", "*.js", "*.go", "*.java"]:
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


class JISBilateralConsentCheck(BaseCheck):
    """Check for bilateral consent (handshake before communication)."""
    check_id = "JIS-004"
    name = "Bilateral consent (handshake)"
    description = "Checks for JIS bilateral consent — both parties must agree before data exchange."
    severity = Severity.HIGH
    category = "jis"
    score_weight = 10

    def run(self, context: dict) -> CheckResult:
        scan_path = context["scan_path"]
        consent_patterns = [
            "bilateral_consent", "handshake", "consent_hash",
            "mutual_auth", "jis_handshake", "consent_token",
            "sign_off", "signoff", "jis_consent"
        ]
        found = _scan_code_for_patterns(scan_path, consent_patterns)

        if found:
            return CheckResult(
                check_id=self.check_id,
                name=self.name,
                status=Status.PASSED,
                severity=self.severity,
                message=f"Bilateral consent found: {', '.join(found[:3])}",
                references=["draft-vandemeent-jis-identity-01 §3.2"],
                score_impact=0,
            )

        return CheckResult(
            check_id=self.check_id,
            name=self.name,
            status=Status.FAILED,
            severity=self.severity,
            message="No bilateral consent mechanism found.",
            recommendation="Implement JIS bilateral consent (handshake) per §3.2.",
            references=["draft-vandemeent-jis-identity-01 §3.2"],
            score_impact=self.score_weight,
        )


class JISIntentDeclarationCheck(BaseCheck):
    """Check for intent declaration per action."""
    check_id = "JIS-005"
    name = "Intent declaration per action"
    description = "Checks that actions include declared intent (why this action is taken)."
    severity = Severity.MEDIUM
    category = "jis"
    score_weight = 8

    def run(self, context: dict) -> CheckResult:
        scan_path = context["scan_path"]
        intent_patterns = [
            "intent", "erachter", "purpose", "action_reason",
            "declared_intent", "intent_type", "jis_intent"
        ]
        found = _scan_code_for_patterns(scan_path, intent_patterns)

        if found:
            return CheckResult(
                check_id=self.check_id,
                name=self.name,
                status=Status.PASSED,
                severity=self.severity,
                message=f"Intent declaration found: {', '.join(found[:3])}",
                references=["draft-vandemeent-jis-identity-01 §3.3"],
                score_impact=0,
            )

        return CheckResult(
            check_id=self.check_id,
            name=self.name,
            status=Status.WARNING,
            severity=self.severity,
            message="No intent declaration detected in codebase.",
            recommendation="Declare intent per action — JIS requires stating 'why' for each operation.",
            references=["draft-vandemeent-jis-identity-01 §3.3"],
            score_impact=self.score_weight,
        )


class JISURISchemeCheck(BaseCheck):
    """Check for jis: URI scheme usage (not did:)."""
    check_id = "JIS-006"
    name = "JIS URI scheme (jis:)"
    description = "Checks for jis: URI scheme usage for identity references."
    severity = Severity.MEDIUM
    category = "jis"
    score_weight = 4

    def run(self, context: dict) -> CheckResult:
        scan_path = context["scan_path"]
        jis_uri_found = _scan_code_for_patterns(scan_path, ["jis:"])
        did_found = _scan_code_for_patterns(scan_path, ["did:jtel"])

        if jis_uri_found and not did_found:
            return CheckResult(
                check_id=self.check_id,
                name=self.name,
                status=Status.PASSED,
                severity=self.severity,
                message="Uses jis: URI scheme correctly.",
                references=["draft-vandemeent-jis-identity-01 §3.1"],
                score_impact=0,
            )
        elif did_found:
            return CheckResult(
                check_id=self.check_id,
                name=self.name,
                status=Status.WARNING,
                severity=self.severity,
                message="Found deprecated did:jtel references — use jis: URI scheme instead.",
                recommendation="Migrate from did:jtel: to jis: URI scheme per JIS -01.",
                references=["draft-vandemeent-jis-identity-01 §3.1"],
                score_impact=self.score_weight,
            )

        # If neither found, skip — identity may use different mechanism
        identity_files = _find_files(scan_path, ["jis.json", "identity.json", "jis.yaml"])
        if identity_files:
            return CheckResult(
                check_id=self.check_id,
                name=self.name,
                status=Status.WARNING,
                severity=self.severity,
                message="Identity files found but no jis: URI references detected.",
                recommendation="Use jis: URI scheme for identity references.",
                references=["draft-vandemeent-jis-identity-01 §3.1"],
                score_impact=self.score_weight // 2,
            )

        return CheckResult(
            check_id=self.check_id,
            name=self.name,
            status=Status.SKIPPED,
            severity=self.severity,
            message="No JIS identity context detected — skipping URI check.",
            score_impact=0,
        )


JIS_CHECKS = [
    JISIdentityFileCheck(),
    JISMetadataCheck(),
    JISKeyRotationPolicyCheck(),
    JISBilateralConsentCheck(),
    JISIntentDeclarationCheck(),
    JISURISchemeCheck(),
]
