"""UPIP Process Integrity checks — IETF draft-vandemeent-upip-process-integrity-01.

Validates compliance with UPIP (Unified Process Integrity Protocol):
- 5-layer integrity stack: STATE, DEPS, PROCESS, RESULT, VERIFY
- Reproducibility evidence
- Process signing and verification
- SBOM/dependency manifest

References:
    https://datatracker.ietf.org/doc/draft-vandemeent-upip-process-integrity/
"""

import json
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


class UPIPLayerStackCheck(BaseCheck):
    """Check for UPIP 5-layer integrity stack implementation."""
    check_id = "UPIP-001"
    name = "UPIP 5-layer integrity stack"
    description = "Checks for the 5 UPIP layers: L1 STATE, L2 DEPS, L3 PROCESS, L4 RESULT, L5 VERIFY."
    severity = Severity.HIGH
    category = "upip"
    score_weight = 12

    def run(self, context: dict) -> CheckResult:
        scan_path = context["scan_path"]

        # Check for UPIP bundle files
        upip_files = _find_files(scan_path, [
            "*.upip.json", "upip_bundle*", "process_integrity*",
            ".upip/*", "upip.json", "upip.yaml"
        ])

        # Check for layer references in code
        layer_patterns = [
            "l1_state", "l2_deps", "l3_process", "l4_result", "l5_verify",
            "layer_state", "layer_deps", "layer_process", "layer_result", "layer_verify",
            "upip_layer", "integrity_layer"
        ]
        found = _scan_code_for_patterns(scan_path, layer_patterns)

        if upip_files:
            return CheckResult(
                check_id=self.check_id,
                name=self.name,
                status=Status.PASSED,
                severity=self.severity,
                message=f"UPIP bundle(s) found: {', '.join(f.name for f in upip_files[:3])}",
                references=["draft-vandemeent-upip-process-integrity-01 §3"],
                score_impact=0,
            )
        elif found:
            return CheckResult(
                check_id=self.check_id,
                name=self.name,
                status=Status.PASSED,
                severity=self.severity,
                message=f"UPIP layer references in code: {', '.join(found[:4])}",
                references=["draft-vandemeent-upip-process-integrity-01 §3"],
                score_impact=0,
            )

        return CheckResult(
            check_id=self.check_id,
            name=self.name,
            status=Status.FAILED,
            severity=self.severity,
            message="No UPIP 5-layer integrity stack detected.",
            recommendation="Implement UPIP layers: STATE→DEPS→PROCESS→RESULT→VERIFY. See UPIP §3.",
            references=["draft-vandemeent-upip-process-integrity-01 §3"],
            score_impact=self.score_weight,
        )


class UPIPDependencyManifestCheck(BaseCheck):
    """Check for dependency manifest / SBOM (UPIP L2 DEPS)."""
    check_id = "UPIP-002"
    name = "Dependency manifest (UPIP L2)"
    description = "Checks for dependency manifest, lock file, or SBOM for reproducibility."
    severity = Severity.HIGH
    category = "upip"
    score_weight = 10

    def run(self, context: dict) -> CheckResult:
        scan_path = context["scan_path"]
        manifest_files = _find_files(scan_path, [
            "requirements.txt", "Pipfile.lock", "poetry.lock", "uv.lock",
            "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
            "Cargo.lock", "go.sum", "Gemfile.lock",
            "sbom.json", "sbom.spdx.json", "sbom.cyclonedx.json",
            "bom.json", "*.sbom",
        ])

        if manifest_files:
            return CheckResult(
                check_id=self.check_id,
                name=self.name,
                status=Status.PASSED,
                severity=self.severity,
                message=f"Dependency manifest found: {', '.join(f.name for f in manifest_files[:3])}",
                references=["draft-vandemeent-upip-process-integrity-01 §3.2"],
                score_impact=0,
            )

        return CheckResult(
            check_id=self.check_id,
            name=self.name,
            status=Status.FAILED,
            severity=self.severity,
            message="No dependency manifest or lock file found.",
            recommendation="Create lock file or SBOM for reproducible builds (UPIP L2 DEPS).",
            references=["draft-vandemeent-upip-process-integrity-01 §3.2"],
            score_impact=self.score_weight,
        )


class UPIPGitStateCheck(BaseCheck):
    """Check for version control state capture (UPIP L1 STATE)."""
    check_id = "UPIP-003"
    name = "Version control state (UPIP L1)"
    description = "Checks for git or version control to capture L1 STATE layer."
    severity = Severity.MEDIUM
    category = "upip"
    score_weight = 6

    def run(self, context: dict) -> CheckResult:
        scan_path = context["scan_path"]
        git_dir = scan_path / ".git"
        if git_dir.exists():
            return CheckResult(
                check_id=self.check_id,
                name=self.name,
                status=Status.PASSED,
                severity=self.severity,
                message="Git repository detected — L1 STATE layer available.",
                references=["draft-vandemeent-upip-process-integrity-01 §3.1"],
                score_impact=0,
            )

        # Check parent directories
        current = scan_path.parent
        for _ in range(5):
            if (current / ".git").exists():
                return CheckResult(
                    check_id=self.check_id,
                    name=self.name,
                    status=Status.PASSED,
                    severity=self.severity,
                    message=f"Git repository found in parent: {current}",
                    references=["draft-vandemeent-upip-process-integrity-01 §3.1"],
                    score_impact=0,
                )
            current = current.parent

        return CheckResult(
            check_id=self.check_id,
            name=self.name,
            status=Status.WARNING,
            severity=self.severity,
            message="No version control found. UPIP L1 STATE requires reproducible state.",
            recommendation="Initialize git or equivalent VCS for state tracking.",
            references=["draft-vandemeent-upip-process-integrity-01 §3.1"],
            score_impact=self.score_weight,
        )


class UPIPProcessSigningCheck(BaseCheck):
    """Check for process output signing or verification (UPIP L5 VERIFY)."""
    check_id = "UPIP-004"
    name = "Process verification (UPIP L5)"
    description = "Checks for process output signing, hashing, or attestation."
    severity = Severity.MEDIUM
    category = "upip"
    score_weight = 8

    def run(self, context: dict) -> CheckResult:
        scan_path = context["scan_path"]

        # Check for signing/attestation files
        verify_files = _find_files(scan_path, [
            "*.sig", "*.asc", "CHECKSUMS", "SHA256SUMS",
            "*.intoto.jsonl", "*.attestation", "cosign.*",
            "provenance*.json", "slsa-*.json"
        ])

        if verify_files:
            return CheckResult(
                check_id=self.check_id,
                name=self.name,
                status=Status.PASSED,
                severity=self.severity,
                message=f"Verification artifacts found: {', '.join(f.name for f in verify_files[:3])}",
                references=["draft-vandemeent-upip-process-integrity-01 §3.5"],
                score_impact=0,
            )

        # Check for signing in CI
        ci_files = _find_files(scan_path, [
            ".github/workflows/*.yml", ".github/workflows/*.yaml",
            ".gitlab-ci.yml", "Jenkinsfile", ".circleci/config.yml"
        ])
        for ci in ci_files:
            content = _read_text(ci).lower()
            if any(k in content for k in ["sign", "attest", "cosign", "checksum", "sha256sum", "slsa"]):
                return CheckResult(
                    check_id=self.check_id,
                    name=self.name,
                    status=Status.PASSED,
                    severity=self.severity,
                    message=f"Build signing/attestation found in CI: {ci.name}",
                    references=["draft-vandemeent-upip-process-integrity-01 §3.5"],
                    score_impact=0,
                )

        return CheckResult(
            check_id=self.check_id,
            name=self.name,
            status=Status.WARNING,
            severity=self.severity,
            message="No process output signing or verification detected.",
            recommendation="Add build signing or hash attestation (UPIP L5 VERIFY).",
            references=["draft-vandemeent-upip-process-integrity-01 §3.5"],
            score_impact=self.score_weight,
        )


class UPIPReproducibilityCheck(BaseCheck):
    """Check for reproducibility evidence (CI, Dockerfile, build scripts)."""
    check_id = "UPIP-005"
    name = "Build reproducibility (UPIP L3)"
    description = "Checks for reproducible build configuration (Dockerfile, CI, Makefile)."
    severity = Severity.MEDIUM
    category = "upip"
    score_weight = 6

    def run(self, context: dict) -> CheckResult:
        scan_path = context["scan_path"]
        build_files = _find_files(scan_path, [
            "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
            "Makefile", "justfile", "Taskfile.yml",
            ".github/workflows/*.yml", ".gitlab-ci.yml",
            "nix/flake.nix", "flake.nix", "shell.nix",
            "BUILD", "BUILD.bazel", "WORKSPACE",
        ])

        if build_files:
            return CheckResult(
                check_id=self.check_id,
                name=self.name,
                status=Status.PASSED,
                severity=self.severity,
                message=f"Reproducible build config found: {', '.join(f.name for f in build_files[:3])}",
                references=["draft-vandemeent-upip-process-integrity-01 §3.3"],
                score_impact=0,
            )

        return CheckResult(
            check_id=self.check_id,
            name=self.name,
            status=Status.WARNING,
            severity=self.severity,
            message="No reproducible build configuration found.",
            recommendation="Add Dockerfile, CI pipeline, or Makefile for reproducible builds (UPIP L3).",
            references=["draft-vandemeent-upip-process-integrity-01 §3.3"],
            score_impact=self.score_weight,
        )


UPIP_CHECKS = [
    UPIPLayerStackCheck(),
    UPIPDependencyManifestCheck(),
    UPIPGitStateCheck(),
    UPIPProcessSigningCheck(),
    UPIPReproducibilityCheck(),
]
