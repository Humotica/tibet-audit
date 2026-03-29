"""AINS Discovery checks — IETF draft-vandemeent-ains-discovery-01.

Validates compliance with AINS (AInternet Name Service):
- Agent identity registration (.aint domains)
- Capability advertisement
- Trust-aware discovery
- Rate limiting by trust tier

References:
    https://datatracker.ietf.org/doc/draft-vandemeent-ains-discovery/
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
    for ext in ["*.py", "*.rs", "*.ts", "*.js", "*.go", "*.java", "*.yaml", "*.yml", "*.json"]:
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


class AINSAgentRegistrationCheck(BaseCheck):
    """Check for agent identity registration (AINS record / .aint domain)."""
    check_id = "AINS-001"
    name = "Agent identity registration"
    description = "Checks for AINS agent registration, .aint domain, or agent identity config."
    severity = Severity.HIGH
    category = "ains"
    score_weight = 10

    def run(self, context: dict) -> CheckResult:
        scan_path = context["scan_path"]

        # Look for AINS config files
        ains_files = _find_files(scan_path, [
            "ains.json", "ains.yaml", "ains_registry*",
            "agent_identity*", "agent.json", "agent.yaml",
            ".aint", "ains_config*"
        ])

        # Look for .aint domain references in code
        aint_patterns = [".aint", "ains_register", "ains_resolve", "agent_registry", "ains_domain"]
        found = _scan_code_for_patterns(scan_path, aint_patterns)

        if ains_files:
            return CheckResult(
                check_id=self.check_id,
                name=self.name,
                status=Status.PASSED,
                severity=self.severity,
                message=f"AINS registration found: {', '.join(f.name for f in ains_files[:3])}",
                references=["draft-vandemeent-ains-discovery-01 §3"],
                score_impact=0,
            )
        elif found:
            return CheckResult(
                check_id=self.check_id,
                name=self.name,
                status=Status.PASSED,
                severity=self.severity,
                message=f"AINS references in code: {', '.join(found[:3])}",
                references=["draft-vandemeent-ains-discovery-01 §3"],
                score_impact=0,
            )

        return CheckResult(
            check_id=self.check_id,
            name=self.name,
            status=Status.FAILED,
            severity=self.severity,
            message="No AINS agent registration or .aint domain configuration found.",
            recommendation="Register agent identity via AINS. See draft-vandemeent-ains-discovery §3.",
            references=["draft-vandemeent-ains-discovery-01 §3"],
            score_impact=self.score_weight,
        )


class AINSCapabilityAdvertisementCheck(BaseCheck):
    """Check for capability advertisement (what can the agent do?)."""
    check_id = "AINS-002"
    name = "Capability advertisement"
    description = "Checks that agents advertise their capabilities per AINS records."
    severity = Severity.MEDIUM
    category = "ains"
    score_weight = 6

    def run(self, context: dict) -> CheckResult:
        scan_path = context["scan_path"]

        cap_patterns = [
            "capabilities", "agent_capabilities", "can_do",
            "supported_operations", "tools_available", "mcp_tools",
            "service_description", "capability_list"
        ]
        found = _scan_code_for_patterns(scan_path, cap_patterns)

        # Check for OpenAPI / service description
        api_files = _find_files(scan_path, [
            "openapi.json", "openapi.yaml", "swagger.json", "swagger.yaml",
            "api-spec*", "service.json", "manifest.json"
        ])

        if found or api_files:
            detail = ', '.join(found[:2]) if found else ', '.join(f.name for f in api_files[:2])
            return CheckResult(
                check_id=self.check_id,
                name=self.name,
                status=Status.PASSED,
                severity=self.severity,
                message=f"Capability advertisement found: {detail}",
                references=["draft-vandemeent-ains-discovery-01 §3.2"],
                score_impact=0,
            )

        return CheckResult(
            check_id=self.check_id,
            name=self.name,
            status=Status.WARNING,
            severity=self.severity,
            message="No capability advertisement found.",
            recommendation="Advertise agent capabilities for AINS discovery per §3.2.",
            references=["draft-vandemeent-ains-discovery-01 §3.2"],
            score_impact=self.score_weight,
        )


class AINSTrustTierRateLimitCheck(BaseCheck):
    """Check for trust-based rate limiting per AINS tier."""
    check_id = "AINS-003"
    name = "Trust-tier rate limiting"
    description = "Checks for rate limiting that respects trust tiers (AINS §3.4)."
    severity = Severity.MEDIUM
    category = "ains"
    score_weight = 6

    def run(self, context: dict) -> CheckResult:
        scan_path = context["scan_path"]

        rate_patterns = [
            "rate_limit", "ratelimit", "throttl",
            "trust_tier", "tier_limit", "quota",
            "requests_per_hour", "msg_per_hour"
        ]
        found = _scan_code_for_patterns(scan_path, rate_patterns)

        if found:
            return CheckResult(
                check_id=self.check_id,
                name=self.name,
                status=Status.PASSED,
                severity=self.severity,
                message=f"Rate limiting found: {', '.join(found[:3])}",
                references=["draft-vandemeent-ains-discovery-01 §3.4"],
                score_impact=0,
            )

        return CheckResult(
            check_id=self.check_id,
            name=self.name,
            status=Status.WARNING,
            severity=self.severity,
            message="No trust-tier rate limiting detected.",
            recommendation="Implement rate limits based on trust tiers per AINS §3.4.",
            references=["draft-vandemeent-ains-discovery-01 §3.4"],
            score_impact=self.score_weight,
        )


class AINSDiscoveryEndpointCheck(BaseCheck):
    """Check for an AINS-compatible discovery endpoint."""
    check_id = "AINS-004"
    name = "Discovery endpoint"
    description = "Checks for a resolvable discovery endpoint (resolve, lookup, or well-known)."
    severity = Severity.MEDIUM
    category = "ains"
    score_weight = 6

    def run(self, context: dict) -> CheckResult:
        scan_path = context["scan_path"]

        endpoint_patterns = [
            "ains/resolve", "ains/lookup", ".well-known/ains",
            "agent/resolve", "discovery_endpoint", "resolve_agent",
            "/resolve/", "/discover/"
        ]
        found = _scan_code_for_patterns(scan_path, endpoint_patterns)

        # Check for well-known directory
        wellknown = scan_path / ".well-known"
        has_wellknown = wellknown.exists() and wellknown.is_dir()

        if found:
            return CheckResult(
                check_id=self.check_id,
                name=self.name,
                status=Status.PASSED,
                severity=self.severity,
                message=f"Discovery endpoint found: {', '.join(found[:2])}",
                references=["draft-vandemeent-ains-discovery-01 §3.1"],
                score_impact=0,
            )
        elif has_wellknown:
            return CheckResult(
                check_id=self.check_id,
                name=self.name,
                status=Status.WARNING,
                severity=self.severity,
                message=".well-known directory exists but no AINS endpoint detected.",
                recommendation="Add AINS discovery to .well-known/ per §3.1.",
                references=["draft-vandemeent-ains-discovery-01 §3.1"],
                score_impact=self.score_weight // 2,
            )

        return CheckResult(
            check_id=self.check_id,
            name=self.name,
            status=Status.WARNING,
            severity=self.severity,
            message="No discovery endpoint detected.",
            recommendation="Implement AINS resolve/lookup endpoint per §3.1.",
            references=["draft-vandemeent-ains-discovery-01 §3.1"],
            score_impact=self.score_weight,
        )


AINS_CHECKS = [
    AINSAgentRegistrationCheck(),
    AINSCapabilityAdvertisementCheck(),
    AINSTrustTierRateLimitCheck(),
    AINSDiscoveryEndpointCheck(),
]
