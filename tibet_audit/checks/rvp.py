"""RVP Continuous Verification checks — IETF draft-vandemeent-rvp-continuous-verification-01.

Validates compliance with RVP (Resilience Verification Protocol):
- Trust levels (L0 TOKEN → L1 DEVICE → L2 BIOMETRIC → L3 PHYSICAL)
- Continuous verification (not just login-time auth)
- Drift detection and re-verification triggers
- FIR/A trust scoring

References:
    https://datatracker.ietf.org/doc/draft-vandemeent-rvp-continuous-verification/
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


def _scan_code_for_patterns(scan_path: Path, patterns: List[str]) -> List[str]:
    found = []
    files_checked = 0
    for ext in ["*.py", "*.rs", "*.ts", "*.js", "*.go", "*.java", "*.yaml", "*.yml"]:
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


class RVPTrustLevelsCheck(BaseCheck):
    """Check for multi-level trust implementation (L0-L3)."""
    check_id = "RVP-001"
    name = "RVP trust levels (L0-L3)"
    description = "Checks for graduated trust levels: L0 TOKEN, L1 DEVICE, L2 BIOMETRIC, L3 PHYSICAL."
    severity = Severity.HIGH
    category = "rvp"
    score_weight = 10

    def run(self, context: dict) -> CheckResult:
        scan_path = context["scan_path"]

        trust_patterns = [
            "trust_level", "trust_score", "trust_tier",
            "l0_token", "l1_device", "l2_biometric", "l3_physical",
            "fira_score", "fir_a", "trust_escalation"
        ]
        found = _scan_code_for_patterns(scan_path, trust_patterns)

        if found:
            return CheckResult(
                check_id=self.check_id,
                name=self.name,
                status=Status.PASSED,
                severity=self.severity,
                message=f"Trust level implementation found: {', '.join(found[:4])}",
                references=["draft-vandemeent-rvp-continuous-verification-01 §3"],
                score_impact=0,
            )

        # Check for any multi-factor or role-based access
        auth_patterns = ["mfa", "multi_factor", "role_based", "rbac", "authorization_level", "access_level"]
        auth_found = _scan_code_for_patterns(scan_path, auth_patterns)

        if auth_found:
            return CheckResult(
                check_id=self.check_id,
                name=self.name,
                status=Status.WARNING,
                severity=self.severity,
                message=f"Basic access control found ({', '.join(auth_found[:2])}), but no RVP trust levels.",
                recommendation="Map existing auth levels to RVP L0-L3 trust tiers per §3.",
                references=["draft-vandemeent-rvp-continuous-verification-01 §3"],
                score_impact=self.score_weight // 2,
            )

        return CheckResult(
            check_id=self.check_id,
            name=self.name,
            status=Status.FAILED,
            severity=self.severity,
            message="No graduated trust levels or access control tiers found.",
            recommendation="Implement RVP trust levels: L0 TOKEN → L1 DEVICE → L2 BIOMETRIC → L3 PHYSICAL.",
            references=["draft-vandemeent-rvp-continuous-verification-01 §3"],
            score_impact=self.score_weight,
        )


class RVPContinuousVerificationCheck(BaseCheck):
    """Check for continuous verification (not just login-time auth)."""
    check_id = "RVP-002"
    name = "Continuous verification"
    description = "Checks that verification is ongoing, not only at authentication time."
    severity = Severity.HIGH
    category = "rvp"
    score_weight = 10

    def run(self, context: dict) -> CheckResult:
        scan_path = context["scan_path"]

        cv_patterns = [
            "continuous_verif", "session_check", "revalidat",
            "periodic_auth", "heartbeat_check", "trust_decay",
            "re_verify", "reverif", "session_monitor",
            "activity_monitor", "anomaly_detect"
        ]
        found = _scan_code_for_patterns(scan_path, cv_patterns)

        if found:
            return CheckResult(
                check_id=self.check_id,
                name=self.name,
                status=Status.PASSED,
                severity=self.severity,
                message=f"Continuous verification patterns found: {', '.join(found[:3])}",
                references=["draft-vandemeent-rvp-continuous-verification-01 §3.2"],
                score_impact=0,
            )

        # Check for session management at minimum
        session_patterns = ["session_timeout", "token_expir", "jwt_expir", "refresh_token", "session_ttl"]
        session_found = _scan_code_for_patterns(scan_path, session_patterns)

        if session_found:
            return CheckResult(
                check_id=self.check_id,
                name=self.name,
                status=Status.WARNING,
                severity=self.severity,
                message=f"Session management found ({', '.join(session_found[:2])}), but no continuous verification.",
                recommendation="Add continuous verification beyond session management per RVP §3.2.",
                references=["draft-vandemeent-rvp-continuous-verification-01 §3.2"],
                score_impact=self.score_weight // 2,
            )

        return CheckResult(
            check_id=self.check_id,
            name=self.name,
            status=Status.FAILED,
            severity=self.severity,
            message="No continuous verification or session revalidation detected.",
            recommendation="Implement continuous verification — RVP requires ongoing trust, not one-time auth.",
            references=["draft-vandemeent-rvp-continuous-verification-01 §3.2"],
            score_impact=self.score_weight,
        )


class RVPDriftDetectionCheck(BaseCheck):
    """Check for drift detection / anomaly monitoring."""
    check_id = "RVP-003"
    name = "Drift detection"
    description = "Checks for behavioral drift detection or anomaly monitoring."
    severity = Severity.MEDIUM
    category = "rvp"
    score_weight = 8

    def run(self, context: dict) -> CheckResult:
        scan_path = context["scan_path"]

        drift_patterns = [
            "drift_detect", "anomaly", "baseline_compare",
            "behavior_monitor", "deviation", "expected_state",
            "config_drift", "state_drift", "integrity_check"
        ]
        found = _scan_code_for_patterns(scan_path, drift_patterns)

        if found:
            return CheckResult(
                check_id=self.check_id,
                name=self.name,
                status=Status.PASSED,
                severity=self.severity,
                message=f"Drift/anomaly detection found: {', '.join(found[:3])}",
                references=["draft-vandemeent-rvp-continuous-verification-01 §3.4"],
                score_impact=0,
            )

        return CheckResult(
            check_id=self.check_id,
            name=self.name,
            status=Status.WARNING,
            severity=self.severity,
            message="No drift detection or anomaly monitoring found.",
            recommendation="Implement drift detection per RVP §3.4 — detect when state deviates from baseline.",
            references=["draft-vandemeent-rvp-continuous-verification-01 §3.4"],
            score_impact=self.score_weight,
        )


class RVPIncidentResponseCheck(BaseCheck):
    """Check for incident response / trust recovery procedures."""
    check_id = "RVP-004"
    name = "Incident response & trust recovery"
    description = "Checks for documented incident response and trust recovery procedures."
    severity = Severity.MEDIUM
    category = "rvp"
    score_weight = 6

    def run(self, context: dict) -> CheckResult:
        scan_path = context["scan_path"]
        policy_files = _find_files(scan_path, [
            "*incident*", "*response*", "*recovery*",
            "SECURITY.md", "RUNBOOK.md", "docs/*incident*",
            "*playbook*", "*escalation*"
        ])

        keywords = ["incident", "response", "recovery", "escalat", "runbook", "playbook"]
        for path in policy_files:
            text = _read_text(path).lower()
            if any(k in text for k in keywords):
                return CheckResult(
                    check_id=self.check_id,
                    name=self.name,
                    status=Status.PASSED,
                    severity=self.severity,
                    message=f"Incident response documentation found: {path.name}",
                    references=["draft-vandemeent-rvp-continuous-verification-01 §4"],
                    score_impact=0,
                )

        return CheckResult(
            check_id=self.check_id,
            name=self.name,
            status=Status.WARNING,
            severity=self.severity,
            message="No incident response or trust recovery documentation found.",
            recommendation="Document incident response and trust recovery per RVP §4.",
            references=["draft-vandemeent-rvp-continuous-verification-01 §4"],
            score_impact=self.score_weight,
        )


RVP_CHECKS = [
    RVPTrustLevelsCheck(),
    RVPContinuousVerificationCheck(),
    RVPDriftDetectionCheck(),
    RVPIncidentResponseCheck(),
]
