"""TIBET Audit Scanner - The core scanning engine."""

from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Optional, Callable
from datetime import datetime
import uuid
import os
import importlib.metadata

from .checks import ALL_CHECKS, CheckResult, Status


# Lynis-style status labels with colors (for Rich console)
STATUS_LABELS = {
    Status.PASSED: ("[green]", "OK"),
    Status.WARNING: ("[yellow]", "WARNING"),
    Status.FAILED: ("[red]", "FAILED"),
    Status.SKIPPED: ("[dim]", "SKIPPED"),
}

# Category display names and emojis
CATEGORY_NAMES = {
    "humotica": ("🏛️ Humotica Three Pillars (A-Grade Gate)", "humotica"),
    "health": ("💚 System Health & Energy", "health"),
    "tibet": ("📜 TIBET Provenance (IETF Draft)", "tibet"),
    "jis": ("🧭 JIS Identity (IETF Draft)", "jis"),
    "upip": ("🔒 UPIP Process Integrity (IETF Draft)", "upip"),
    "rvp": ("🔄 RVP Continuous Verification (IETF Draft)", "rvp"),
    "ains": ("🌐 AINS Agent Discovery (IETF Draft)", "ains"),
    "gdpr": ("🇪🇺 GDPR (EU Privacy)", "gdpr"),
    "ai_act": ("🤖 EU AI Act", "ai_act"),
    "sovereignty": ("🛰️ Sovereignty & Residency", "sovereignty"),
    "provider": ("🛡️ Provider Security", "provider"),
    "nis2": ("🛡️ NIS2 Directive", "nis2"),
    "ucp": ("🛒 UCP Commerce", "ucp"),
    "pipa": ("🇰🇷 PIPA (Korea)", "pipa"),
    "appi": ("🇯🇵 APPI (Japan)", "appi"),
    "pdpa": ("🇸🇬 PDPA (Singapore)", "pdpa"),
    "au_privacy": ("🇦🇺 Privacy Act (Australia)", "au_privacy"),
    "lgpd": ("🇧🇷 LGPD (Brazil)", "lgpd"),
    "gulf": ("🇸🇦 Gulf PDPL", "gulf"),
    "ndpr": ("🇳🇬 NDPR (Nigeria)", "ndpr"),
    "penguin": ("🐧 Penguin Act (Antarctica)", "penguin"),
}


@dataclass
class ScanResult:
    """Complete scan result."""
    timestamp: datetime
    scan_path: str
    score: int
    grade: str
    passed: int
    warnings: int
    failed: int
    skipped: int
    results: List[CheckResult]
    duration_seconds: float
    scan_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])

    @property
    def fixable_count(self) -> int:
        """Count of issues that can be auto-fixed."""
        return sum(1 for r in self.results if r.can_auto_fix and r.status != Status.PASSED)


class TIBETAudit:
    """
    TIBET Audit Scanner

    The Diaper Protocol™ - One command, hands free, compliance done.

    Usage:
        audit = TIBETAudit()
        result = audit.scan("/path/to/project")
        print(f"Score: {result.score}/100 (Grade: {result.grade})")

    For Lynis-style live output:
        result = audit.scan("/path/to/project", live_mode=True)

    For sovereign mode (no cloud APIs):
        audit = TIBETAudit(sovereign_mode=True)
        result = audit.scan("/path/to/project")
    """

    def __init__(self, checks: Optional[List] = None, sovereign_mode: bool = False):
        """Initialize scanner with checks.

        Args:
            checks: Optional list of checks to run
            sovereign_mode: If True, skip any checks that require cloud APIs
        """
        self.checks = checks or ALL_CHECKS
        self.sovereign_mode = sovereign_mode

    def scan(
        self,
        path: str = ".",
        categories: Optional[List[str]] = None,
        live_mode: bool = False,
        output_callback: Optional[Callable[[str], None]] = None,
        extra_context: Optional[dict] = None,
    ) -> ScanResult:
        """
        Run all compliance checks on the given path.

        Args:
            path: Directory to scan
            categories: Optional list of categories to check (e.g., ["gdpr", "ai_act"])
            live_mode: If True, print Lynis-style live output
            output_callback: Optional callback for live output (default: print to rich console)

        Returns:
            ScanResult with score and all check results
        """
        import time
        start_time = time.time()

        scan_path = Path(path).resolve()

        # Build context for checks
        context = {
            "scan_path": scan_path,
            "tibet_available": self._check_tibet_available(),
            "installed_packages": self._installed_packages(),
            "sovereign_mode": self.sovereign_mode,
        }
        context.update(self._load_tibet_provenance(scan_path))
        if extra_context:
            context.update(extra_context)

        # Get console for live mode output
        console = None
        if live_mode:
            try:
                from rich.console import Console
                console = Console()
            except ImportError:
                live_mode = False

        # Group checks by category for Lynis-style output
        checks_by_category = {}
        for check in self.checks:
            if categories and check.category not in categories:
                continue
            cat = check.category or "general"
            if cat not in checks_by_category:
                checks_by_category[cat] = []
            checks_by_category[cat].append(check)

        # Run checks
        results = []
        current_category = None

        for category, category_checks in checks_by_category.items():
            # Print category header in live mode
            if live_mode and console:
                cat_name, _ = CATEGORY_NAMES.get(category, (f"📋 {category.upper()}", category))
                console.print(f"\n[bold cyan][+] {cat_name}[/]")
                console.print("[cyan]" + "-" * 40 + "[/]")

            for check in category_checks:
                try:
                    result = check.run(context)
                    # Ensure category is set from the check class
                    if result.category is None:
                        result.category = check.category
                    results.append(result)

                    # Print live status
                    if live_mode and console:
                        self._print_check_result(console, result)

                except Exception as e:
                    # Check failed to run - skip it
                    result = CheckResult(
                        check_id=check.check_id,
                        name=check.name,
                        status=Status.SKIPPED,
                        severity=check.severity,
                        category=check.category,
                        message=f"Check failed to run: {str(e)}",
                        score_impact=0
                    )
                    results.append(result)

                    if live_mode and console:
                        self._print_check_result(console, result)

        # Calculate score
        score, grade = self._calculate_score(results)

        # Count by status
        passed = sum(1 for r in results if r.status == Status.PASSED)
        warnings = sum(1 for r in results if r.status == Status.WARNING)
        failed = sum(1 for r in results if r.status == Status.FAILED)
        skipped = sum(1 for r in results if r.status == Status.SKIPPED)

        duration = time.time() - start_time

        return ScanResult(
            timestamp=datetime.now(),
            scan_path=str(scan_path),
            score=score,
            grade=grade,
            passed=passed,
            warnings=warnings,
            failed=failed,
            skipped=skipped,
            results=results,
            duration_seconds=round(duration, 2)
        )

    def _print_check_result(self, console, result: CheckResult):
        """Print a single check result in Lynis style."""
        color, label = STATUS_LABELS.get(result.status, ("[white]", "UNKNOWN"))

        # Truncate name if too long
        name = result.name[:45] if len(result.name) > 45 else result.name

        # Format: "  - Check name                             [ STATUS ]"
        padding = 50 - len(name)
        if padding < 2:
            padding = 2

        console.print(f"  - {name}" + " " * padding + f"{color}[ {label:^8} ][/]")

        # Show details for non-passed checks
        if result.status == Status.WARNING:
            if result.message:
                msg = result.message[:60] if len(result.message) > 60 else result.message
                console.print(f"    [dim]{msg}[/]")
        elif result.status == Status.FAILED:
            if result.message:
                msg = result.message[:60] if len(result.message) > 60 else result.message
                console.print(f"    [red]{msg}[/]")
            if result.recommendation:
                rec = result.recommendation[:55] if len(result.recommendation) > 55 else result.recommendation
                console.print(f"    [green]→ {rec}[/]")

        # Show TIBET recommendation for failed/warning checks
        if result.status in (Status.FAILED, Status.WARNING):
            self._print_tibet_recommendation(console, result)

    def _print_tibet_recommendation(self, console, result: CheckResult):
        """Print TIBET stack recommendation for a failed check."""
        try:
            from .tibet_recommendations import get_recommendation
            rec = get_recommendation(result.check_id, getattr(result, "category", ""))
            if rec:
                pkgs = ", ".join(rec.get("packages", []))
                console.print(f"    [cyan]TIBET: {rec.get('title', '')}[/]")
                console.print(f"    [dim cyan]{rec.get('install', '')}[/]")
        except Exception:
            pass  # tibet_recommendations not available

    def _load_tibet_provenance(self, scan_path: Path) -> dict:
        """Load the shared TIBET JSONL token store for provenance checks."""
        candidates = []
        env_store = os.getenv("TIBET_TOKEN_STORE")
        if env_store:
            candidates.append(Path(env_store).expanduser())
        candidates.extend([
            scan_path / ".tibet" / "provenance" / "tokens.jsonl",
            Path.home() / ".tibet" / "provenance" / "tokens.jsonl",
        ])

        seen = set()
        unique_candidates = []
        for candidate in candidates:
            resolved = str(candidate)
            if resolved not in seen:
                seen.add(resolved)
                unique_candidates.append(candidate)

        for token_path in unique_candidates:
            if not token_path.exists():
                continue
            try:
                from tibet_core import FileStore

                store = FileStore(str(token_path))
                tokens = [t.to_dict() for t in store.all()]
                integrity = store.verify_file()
                return {
                    "tibet_token_store": token_path,
                    "tibet_tokens": tokens,
                    "tibet_token_count": len(tokens),
                    "tibet_token_integrity": integrity,
                }
            except Exception as exc:
                return {
                    "tibet_token_store": token_path,
                    "tibet_tokens": [],
                    "tibet_token_count": 0,
                    "tibet_token_load_error": str(exc),
                }

        return {
            "tibet_token_store": None,
            "tibet_tokens": [],
            "tibet_token_count": 0,
        }

    def _calculate_score(self, results: List[CheckResult]) -> tuple:
        """Calculate compliance score from results."""
        max_score = 100
        deductions = 0

        for result in results:
            if result.status == Status.FAILED:
                deductions += result.score_impact
            elif result.status == Status.WARNING:
                deductions += result.score_impact * 0.5  # Half penalty

        score = max(0, int(max_score - deductions))

        # Calculate grade
        if score >= 90:
            grade = "A"
        elif score >= 80:
            grade = "B"
        elif score >= 70:
            grade = "C"
        elif score >= 60:
            grade = "D"
        else:
            grade = "F"

        return score, grade

    def _check_tibet_available(self) -> bool:
        """Check if the TIBET provenance substrate is installed."""
        return self._package_available("tibet-core") or self._package_available("tibet-vault")

    def _package_available(self, package_name: str) -> bool:
        try:
            importlib.metadata.version(package_name)
            return True
        except importlib.metadata.PackageNotFoundError:
            return False

    def _installed_packages(self) -> dict:
        watched = [
            "tibet",
            "tibet-core",
            "jis-core",
            "snaft",
            "tibet-snaft",
            "tibet-audit",
            "tibet-cmail",
            "tibet-continuityd",
            "tibet-cap-bus",
            "tibet-home-agent",
            "ainternet",
            "ipoll",
            "tibet-mux",
            "tibet-overlay",
            "tibet-triage",
            "tibet-airlock",
        ]
        installed = {}
        for package_name in watched:
            try:
                installed[package_name] = importlib.metadata.version(package_name)
            except importlib.metadata.PackageNotFoundError:
                pass
        return installed

    def get_fixable_issues(self, results: List[CheckResult]) -> List[CheckResult]:
        """Get list of issues that can be auto-fixed."""
        return [r for r in results if r.can_auto_fix and r.status != Status.PASSED]
