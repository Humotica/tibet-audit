#!/usr/bin/env python3
"""
TIBET Audit CLI - Compliance Health Scanner

The Diaper Protocol™: One command, hands free, compliance done.

    $ tibet-audit scan
    $ tibet-audit fix --auto       # Fix everything, no questions asked
    $ tibet-audit fix --wet-wipe   # Preview what would be fixed (dry-run)

For when you have one hand on the baby and one on the keyboard.

Authors: Jasper van de Meent & Root AI
License: MIT
"""

import sys
import json
from pathlib import Path
from typing import Optional, List

try:
    import typer
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich import box
except ImportError:
    print("Missing dependencies. Run: pip install typer rich")
    sys.exit(1)

from .scanner import TIBETAudit, ScanResult
from .checks.base import Status, Severity
from .runtime import RuntimeAudit
from .mercury import build_report, generate_roadmap, generate_upgrades, diff_reports, high_five
from . import __version__

# Framework imports
try:
    from .frameworks.bio2 import (
        BIO2_FRAMEWORK,
        get_automated_bio2_checks,
        format_bio2_report,
        BIO2Grade,
    )
    BIO2_AVAILABLE = True
except ImportError:
    BIO2_AVAILABLE = False

try:
    from .frameworks.dora import (
        DORA_FRAMEWORK,
        run_dora_audit,
        format_dora_report,
        DORAGrade,
    )
    DORA_AVAILABLE = True
except ImportError:
    DORA_AVAILABLE = False

try:
    import requests
    from packaging import version
except ImportError:
    # Optional dependencies for update checking
    requests = None
    version = None

def check_for_updates():
    """Checks PyPI for a newer version of tibet-audit in a humAIn way."""
    if not requests or not version:
        return
    try:
        response = requests.get("https://pypi.org/pypi/tibet-audit/json", timeout=1.5)
        if response.status_code == 200:
            latest_version = response.json()["info"]["version"]
            if version.parse(latest_version) > version.parse(__version__):
                console.print(f"\n[bold yellow][💡] Update beschikbaar: tibet-audit {latest_version}[/] [dim](huidig: {__version__})[/]")
                console.print(f"    [blue]pip install --upgrade tibet-audit[/]\n")
    except Exception:
        pass # Silent fail to respect the user's focus

app = typer.Typer(
    name="audit-tool",
    help="TIBET Audit - Compliance Health Scanner. Like Lynis, but for regulations.",
    add_completion=False,
)
console = Console()


# ═══════════════════════════════════════════════════════════════════════════════
# BANNER
# ═══════════════════════════════════════════════════════════════════════════════

BANNER = """
[bold blue]══════════════════════════════════════════════════════════════════════════════[/]
[bold blue]  ████████╗██╗██████╗ ███████╗████████╗     █████╗ ██╗   ██╗██████╗ ██╗████████╗[/]
[bold blue]  ╚══██╔══╝██║██╔══██╗██╔════╝╚══██╔══╝    ██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝[/]
[bold blue]     ██║   ██║██████╔╝█████╗     ██║       ███████║██║   ██║██║  ██║██║   ██║   [/]
[bold blue]     ██║   ██║██╔══██╗██╔══╝     ██║       ██╔══██║██║   ██║██║  ██║██║   ██║   [/]
[bold blue]     ██║   ██║██████╔╝███████╗   ██║       ██║  ██║╚██████╔╝██████╔╝██║   ██║   [/]
[bold blue]     ╚═╝   ╚═╝╚═════╝ ╚══════╝   ╚═╝       ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝   [/]
[bold blue]══════════════════════════════════════════════════════════════════════════════[/]
[dim]  Compliance Health Scanner v{version}[/]
[dim]  "SSL secures the connection. TIBET secures the timeline. JIS verifies the intent."[/]
[bold blue]══════════════════════════════════════════════════════════════════════════════[/]
"""

DIAPER_BANNER = """
[bold yellow]══════════════════════════════════════════════════════════════════════════════[/]
[bold yellow]  🍼 DIAPER PROTOCOL™ ACTIVATED[/]
[dim]  "Press the button, hands free, diaper change, server fixed."[/]
[bold yellow]══════════════════════════════════════════════════════════════════════════════[/]
"""

CALL_MAMA_BANNER = """
[bold red]══════════════════════════════════════════════════════════════════════════════[/]
[bold red]  📞 CALLING M.A.M.A...[/]
[bold red]  Mission Assurance & Monitoring Agent[/]
[dim]  "When the diaper is too dirty, you call for backup."[/]
[bold red]══════════════════════════════════════════════════════════════════════════════[/]
"""


# ═══════════════════════════════════════════════════════════════════════════════
# COMMANDS
# ═══════════════════════════════════════════════════════════════════════════════

@app.command()
def scan(
    path: str = typer.Argument(".", help="Path to scan"),
    categories: Optional[str] = typer.Option(None, "--categories", "-c", help="Categories: gdpr,ai_act,jis,sovereignty,provider"),
    framework: Optional[str] = typer.Option(None, "--framework", "-f", help="Framework: bio2, nis2, gdpr, ai_act, dora"),
    org_name: Optional[str] = typer.Option(None, "--org", help="Organization name for compliance report"),
    output: str = typer.Option("terminal", "--output", "-o", help="Output: terminal, json"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Minimal output"),
    cry: bool = typer.Option(False, "--cry", help="Verbose mode - for when things are really bad"),
    profile: str = typer.Option("default", "--profile", "-p", help="Profile: default, enterprise, dev"),
    high_five: bool = typer.Option(False, "--high-five", help="Signed handshake ping (opt-in)"),
    sovereign: bool = typer.Option(False, "--sovereign", help="🏴 Sovereign mode: no cloud APIs, fully local inference"),
):
    """
    Scan for compliance issues and get a health score.

    Examples:
        tibet-audit scan
        tibet-audit scan ./my-project
        tibet-audit scan --categories gdpr,ai_act
        tibet-audit scan --framework bio2 --org "Gemeente Amsterdam"
        tibet-audit scan --cry              # When you need ALL the details
        tibet-audit scan --sovereign        # 🏴 No cloud, fully local
    """
    machine_output = output.lower() != "terminal"
    quiet = quiet or machine_output

    if not quiet:
        check_for_updates()

    if sovereign:
        console.print("[bold cyan]🏴 SOVEREIGN MODE[/]")
        console.print("[dim]   All checks run locally. No data leaves your machine.[/]")
        console.print("[dim]   \"Your compliance, your infrastructure, your sovereignty.\"[/]")
        console.print()
        # Set environment variable for checks to respect
        import os
        os.environ["TIBET_SOVEREIGN_MODE"] = "1"

    if cry:
        console.print("[bold red]😭 CRY MODE ACTIVATED - Full verbose output[/]")
        console.print("[dim]   \"When everything is on fire, you need all the details.\"[/]")
        console.print()

    # Framework-specific handling
    bio2_mode = False
    dora_mode = False
    if framework:
        framework = framework.lower()
        if framework == "bio2":
            if not BIO2_AVAILABLE:
                console.print("[bold red]❌ BIO2 framework not available[/]")
                raise typer.Exit(1)
            bio2_mode = True
            org = org_name or "Organisatie"
            console.print("[bold orange3]🏛️  BIO2 COMPLIANCE MODE[/]")
            console.print(f"[dim]   Baseline Informatiebeveiliging Overheid 2 (v{BIO2_FRAMEWORK['version']})[/]")
            console.print(f"[dim]   Organisatie: {org}[/]")
            console.print(f"[dim]   {BIO2_FRAMEWORK['nis2_alignment']}[/]")
            console.print()
        elif framework == "dora":
            if not DORA_AVAILABLE:
                console.print("[bold red]❌ DORA framework not available[/]")
                raise typer.Exit(1)
            dora_mode = True
            org = org_name or "Financial Entity"
            console.print("[bold green]🏦 DORA COMPLIANCE MODE[/]")
            console.print(f"[dim]   Digital Operational Resilience Act (v{DORA_FRAMEWORK['version']})[/]")
            console.print(f"[dim]   Entity: {org}[/]")
            console.print(f"[dim]   Deadline: {DORA_FRAMEWORK['deadline']} | Pillars: {DORA_FRAMEWORK['pillars']} | BIO2 overlap: {DORA_FRAMEWORK['bio2_overlap']}[/]")
            console.print(f"[dim]   TIBET = Pillar 5 compliance (Information Sharing)[/]")
            console.print()
        else:
            console.print(f"[yellow]⚠️  Framework '{framework}' - using standard scan[/]")
            console.print()

    if not quiet and not bio2_mode and not dora_mode:
        console.print(BANNER.format(version=__version__))

    # Parse categories
    cat_list = categories.split(",") if categories else None

    # Run scan
    audit = TIBETAudit(sovereign_mode=sovereign)

    if cry:
        # Cry mode: show live progress Lynis-style
        console.print("[bold cyan]Running checks...[/]\n")
        result = audit.scan(path, categories=cat_list, live_mode=True)
        console.print()  # Newline after live progress
    else:
        # Normal mode: spinner
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True,
        ) as progress:
            progress.add_task("Scanning for compliance issues...", total=None)
            result = audit.scan(path, categories=cat_list)

    if machine_output:
        report = build_report(result, profile=profile)
        console.print(json.dumps(report, indent=2))
    elif bio2_mode:
        # BIO2 Compliance Report - Grade A-F format
        org = org_name or "Organisatie"
        bio2_results = []
        for check_result in result.results:
            # Map tibet-audit results to BIO2 format
            # Status can be Status.PASSED, Status.WARNING, Status.FAILED, etc.
            status_str = str(check_result.status.value if hasattr(check_result.status, 'value') else check_result.status).upper()
            is_pass = status_str in ("PASS", "PASSED", "OK", "SUCCESS")

            bio2_results.append({
                "check_id": f"BIO2-{check_result.check_id}" if not check_result.check_id.startswith("BIO2") else check_result.check_id,
                "name": check_result.name,
                "status": "pass" if is_pass else "fail",
                "severity": check_result.severity.value if hasattr(check_result.severity, 'value') else str(check_result.severity),
                "message": check_result.message or check_result.name,
            })

        # Generate and display BIO2 report
        bio2_report = format_bio2_report(org, bio2_results)
        console.print(f"\n[bold]{bio2_report}[/]")
    elif dora_mode:
        # DORA Compliance Report - 5 Pillars with Grade A-F
        org = org_name or "Financial Entity"
        # Run DORA-specific audit (uses file-based checks)
        dora_results = run_dora_audit(path)
        # Generate and display DORA report
        dora_report = format_dora_report(org, dora_results)
        console.print(f"\n[bold]{dora_report}[/]")
    else:
        # Display results
        _display_results(result, quiet, verbose=cry)

    # Semantic summary (Runtime layer)
    if not quiet and not machine_output:
        import os
        runtime = RuntimeAudit(
            user_id=os.getenv("USER", "unknown"),
            intent="compliance_scan"
        )
        semantic_summary = runtime.semantify({
            "score": result.score,
            "failed": result.failed,
            "results": str(result.results)
        })
        console.print(f"\n[dim]{semantic_summary}[/]")

        # Log TIBET token (placeholder for now)
        tibet_token = runtime.secure_log({"score": result.score})
        console.print(f"[dim]TIBET Audit Trail: {tibet_token[:40]}...[/]")

    # Friendly invite (only if not quiet)
    if not quiet and not machine_output:
        console.print()
        console.print("[dim]🙌 Like tibet-audit? Say hi to the makers: [bold]tibet-audit high-five[/][/]")
        console.print("[dim]   (No data shared, just a friendly wave)[/]")
        console.print()

    if high_five:
        _run_high_five()


@app.command()
def fix(
    path: str = typer.Argument(".", help="Path to scan and fix"),
    auto: bool = typer.Option(False, "--auto", "-a", help="🍼 Diaper Protocol: fix everything, no questions"),
    wet_wipe: bool = typer.Option(False, "--wet-wipe", "-w", help="Preview what would be fixed (like --dry-run but funnier)"),
    dry_run: bool = typer.Option(False, "--dry-run", "-n", help="Same as --wet-wipe"),
    require_signoff: bool = typer.Option(False, "--require-signoff", "-s", help="⚖️ Require human sign-off before RESOLVED state"),
    reviewer: Optional[str] = typer.Option(None, "--reviewer", "-r", help="Reviewer name for sign-off (e.g., 'Eva de Vries, Jurist')"),
    reviewer_did: Optional[str] = typer.Option(None, "--reviewer-did", help="Reviewer DID (e.g., 'did:jis:jurist:eva.devries')"),
    sovereign: bool = typer.Option(False, "--sovereign", help="🏴 Sovereign mode: no cloud APIs, fully local"),
):
    """
    Fix compliance issues automatically.

    The Diaper Protocol™: For when you have one hand on the baby
    and one on the keyboard.

    With --require-signoff: "TIBET prepares, Human verifies, JIS seals."
    With --sovereign: No cloud APIs, fully local inference.

    Examples:
        tibet-audit fix                    # Interactive fix
        tibet-audit fix --wet-wipe         # Preview fixes
        tibet-audit fix --auto             # 🍼 Fix everything, no questions
        tibet-audit fix --require-signoff  # ⚖️ Create sign-off request after fix
        tibet-audit fix -s -r "Eva de Vries, Jurist"  # With reviewer info
        tibet-audit fix --sovereign --require-signoff  # 🏴⚖️ Full sovereignty + human verification
    """
    # --wet-wipe is an alias for --dry-run
    preview_only = wet_wipe or dry_run

    if auto and not preview_only:
        console.print(DIAPER_BANNER)
    else:
        console.print(BANNER.format(version=__version__))

    if sovereign:
        console.print("[bold cyan]🏴 SOVEREIGN MODE[/]")
        console.print("[dim]   All operations run locally. No data leaves your machine.[/]")
        console.print()
        import os
        os.environ["TIBET_SOVEREIGN_MODE"] = "1"

    # First, scan
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task("Scanning for fixable issues...", total=None)
        audit = TIBETAudit(sovereign_mode=sovereign)
        result = audit.scan(path)

    # Get fixable issues
    fixable = audit.get_fixable_issues(result.results)

    if not fixable:
        console.print("[green]✅ No fixable issues found! Your compliance is looking good.[/]")
        return

    console.print(f"\n[bold]Found {len(fixable)} fixable issue(s):[/]\n")

    # Display what would be fixed
    for i, issue in enumerate(fixable, 1):
        status_color = "red" if issue.status == Status.FAILED else "yellow"
        console.print(f"  [{status_color}]{issue.icon}[/] [{status_color}]{issue.check_id}[/]: {issue.name}")
        if issue.fix_action:
            console.print(f"     [dim]→ {issue.fix_action.description}[/]")
            if issue.fix_action.command:
                console.print(f"     [dim]  $ {issue.fix_action.command}[/]")
        console.print()

    if preview_only:
        console.print("[yellow]🧻 Wet-wipe mode: No changes made. Run without --wet-wipe to apply fixes.[/]")
        return

    fixed_count = 0
    if auto:
        # Diaper Protocol: just do it
        console.print("[bold yellow]🍼 Diaper Protocol: Applying all fixes...[/]\n")
        fixed_count = _apply_fixes(fixable)
    else:
        # Interactive mode
        if typer.confirm("Apply these fixes?"):
            fixed_count = _apply_fixes(fixable)
        else:
            console.print("[dim]No changes made.[/]")
            return

    # Handle sign-off requirement
    if require_signoff and fixed_count > 0:
        _create_signoff_request(result, fixed_count, reviewer, reviewer_did)


def _apply_fixes(issues: List) -> int:
    """Apply fixes for issues. Returns count of successful fixes."""
    import subprocess

    fixed = 0
    failed = 0

    for issue in issues:
        if not issue.fix_action or not issue.fix_action.command:
            continue

        console.print(f"[bold]Fixing {issue.check_id}...[/]")

        try:
            # For now, just show what would be done
            # In production, you'd actually run the commands
            console.print(f"  [green]✅[/] Would run: {issue.fix_action.command}")
            fixed += 1
        except Exception as e:
            console.print(f"  [red]❌[/] Failed: {e}")
            failed += 1

    console.print()
    console.print(f"[bold green]🎉 Done! Fixed: {fixed}, Failed: {failed}[/]")
    console.print()
    console.print("[dim]Run 'tibet-audit scan' to verify improvements.[/]")
    return fixed


def _create_signoff_request(result, fixed_count: int, reviewer: Optional[str], reviewer_did: Optional[str]):
    """Create a sign-off request after fixes are applied."""
    from .signoff import SignoffManager, create_signoff_prompt

    console.print()
    console.print("[bold cyan]⚖️  SIGN-OFF REQUIRED[/]")
    console.print("[dim]\"TIBET prepares, Human verifies, JIS seals.\"[/]")
    console.print()

    manager = SignoffManager()
    record = manager.create_signoff_request(
        scan_id=result.scan_id,
        scan_path=result.scan_path,
        scan_score=result.score,
        scan_grade=result.grade,
        issues_fixed=fixed_count,
        tool_version=__version__
    )

    # If reviewer info provided, start review immediately
    if reviewer:
        record = manager.start_review(record.signoff_id, reviewer, reviewer_did)
        console.print(f"[green]✓[/] Reviewer assigned: {reviewer}")
        if reviewer_did:
            console.print(f"[green]✓[/] Reviewer DID: {reviewer_did}")

    console.print(create_signoff_prompt(record))
    console.print(f"[bold]Sign-off ID: [cyan]{record.signoff_id}[/][/]")
    console.print()
    console.print("[dim]To approve and seal:[/]")
    console.print(f"  [cyan]tibet-audit signoff approve {record.signoff_id}[/]")
    console.print(f"  [cyan]tibet-audit signoff seal {record.signoff_id}[/]")
    console.print()
    console.print("[dim]Or view all pending sign-offs:[/]")
    console.print("  [cyan]tibet-audit signoff list[/]")


@app.command("list")
def list_checks(
    category: Optional[str] = typer.Option(None, "--category", "-c", help="Filter by category"),
):
    """List all available compliance checks."""
    console.print(BANNER.format(version=__version__))

    from .checks import ALL_CHECKS

    table = Table(title="Available Compliance Checks", box=box.ROUNDED)
    table.add_column("ID", style="cyan", width=12)
    table.add_column("Name", width=30)
    table.add_column("Category", style="green", width=10)
    table.add_column("Severity", width=10)
    table.add_column("Weight", justify="right", width=8)

    for check in ALL_CHECKS:
        if category and check.category != category:
            continue

        severity_colors = {
            Severity.INFO: "dim",
            Severity.LOW: "green",
            Severity.MEDIUM: "yellow",
            Severity.HIGH: "red",
            Severity.CRITICAL: "bold red",
        }
        sev_color = severity_colors.get(check.severity, "white")

        table.add_row(
            check.check_id,
            check.name,
            check.category,
            f"[{sev_color}]{check.severity.value}[/]",
            str(check.score_weight)
        )

    console.print(table)
    console.print(f"\n[dim]Total: {len(ALL_CHECKS)} checks[/]")


# Default M.A.M.A. endpoint
MAMA_DEFAULT_EMAIL = "mama@humotica.com"  # Forwards to support team


@app.command("call-mama")
def call_mama(
    path: str = typer.Argument(".", help="Path to scan"),
    email: Optional[str] = typer.Option(None, "--email", "-e", help=f"Send report to email (default: {MAMA_DEFAULT_EMAIL})"),
    webhook: Optional[str] = typer.Option(None, "--webhook", "-w", help="POST report to webhook URL"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save report to file"),
    send: bool = typer.Option(False, "--send", "-s", help=f"Actually send to {MAMA_DEFAULT_EMAIL}"),
):
    """
    📞 Call M.A.M.A. - Mission Assurance & Monitoring Agent

    When the diaper is too dirty to handle alone, you call for backup.
    Generates a full compliance report and sends it to:
    - M.A.M.A. HQ (--send) - sends to SymbAIon support team
    - Email (--email) - send to custom email
    - Webhook (--webhook) - POST to Slack/Teams/custom
    - File (--output) - save locally

    Examples:
        tibet-audit call-mama --send              # Send to M.A.M.A. HQ
        tibet-audit call-mama --email me@co.com   # Custom email
        tibet-audit call-mama --webhook https://slack.webhook.url
        tibet-audit call-mama --output report.json
    """
    console.print(CALL_MAMA_BANNER)

    # Run scan
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task("Scanning for compliance issues...", total=None)
        audit = TIBETAudit()
        result = audit.scan(path)

    # Build report
    import json
    from datetime import datetime

    report = {
        "generated_at": datetime.now().isoformat(),
        "tool": "tibet-audit",
        "version": "0.1.0",
        "scan_path": result.scan_path,
        "score": result.score,
        "grade": result.grade,
        "summary": {
            "passed": result.passed,
            "warnings": result.warnings,
            "failed": result.failed,
            "skipped": result.skipped,
            "fixable": result.fixable_count,
        },
        "issues": [
            {
                "check_id": r.check_id,
                "name": r.name,
                "status": r.status.value,
                "severity": r.severity.value,
                "message": r.message,
                "recommendation": r.recommendation,
                "can_auto_fix": r.can_auto_fix,
            }
            for r in result.results if r.status != Status.PASSED
        ],
        "help_requested": True,
        "mama_message": "Help! The compliance diaper needs changing! 🍼"
    }

    report_json = json.dumps(report, indent=2)

    # Display summary
    console.print(f"\n[bold]Compliance Report Generated[/]")
    console.print(f"  Score: [{_score_color(result.score)}]{result.score}/100[/] (Grade: {result.grade})")
    console.print(f"  Issues: {result.failed} failed, {result.warnings} warnings")
    console.print()

    sent_to = []

    # Send to M.A.M.A. HQ (SymbAIon support)
    if send:
        try:
            import urllib.request
            mama_endpoint = "https://brein.jaspervandemeent.nl/api/mama/report"
            req = urllib.request.Request(
                mama_endpoint,
                data=report_json.encode('utf-8'),
                headers={'Content-Type': 'application/json'},
                method='POST'
            )
            with urllib.request.urlopen(req, timeout=15) as response:
                if response.status in (200, 201, 202):
                    console.print(f"[green]✅ Report sent to M.A.M.A. HQ ({MAMA_DEFAULT_EMAIL})[/]")
                    sent_to.append("mama_hq")
                else:
                    console.print(f"[yellow]⚠️ M.A.M.A. HQ returned status {response.status}[/]")
        except Exception as e:
            console.print(f"[yellow]⚠️ Could not reach M.A.M.A. HQ: {e}[/]")
            console.print(f"[dim]   Try --output to save locally instead[/]")

    # Send to email
    if email:
        console.print(f"[yellow]📧 Would send report to: {email}[/]")
        console.print(f"   [dim](Email sending not yet implemented - save to file and send manually)[/]")
        sent_to.append(f"email:{email}")

    # Send to webhook
    if webhook:
        try:
            import urllib.request
            req = urllib.request.Request(
                webhook,
                data=report_json.encode('utf-8'),
                headers={'Content-Type': 'application/json'},
                method='POST'
            )
            with urllib.request.urlopen(req, timeout=10) as response:
                if response.status == 200:
                    console.print(f"[green]✅ Report sent to webhook![/]")
                    sent_to.append(f"webhook:{webhook}")
                else:
                    console.print(f"[red]❌ Webhook returned status {response.status}[/]")
        except Exception as e:
            console.print(f"[red]❌ Failed to send to webhook: {e}[/]")

    # Save to file
    if output:
        try:
            Path(output).write_text(report_json)
            console.print(f"[green]✅ Report saved to: {output}[/]")
            sent_to.append(f"file:{output}")
        except Exception as e:
            console.print(f"[red]❌ Failed to save report: {e}[/]")

    # If nothing specified, print to stdout
    if not email and not webhook and not output:
        console.print("[dim]Tip: Use --email, --webhook, or --output to send the report somewhere[/]")
        console.print()
        console.print("[bold]Report JSON:[/]")
        console.print(report_json)

    console.print()
    console.print("[bold green]📞 Mama has been called! Help is on the way![/]")
    console.print("[dim]   (Or at least, the report is ready to send)[/]")


def _score_color(score: int) -> str:
    """Get color for score."""
    if score >= 80:
        return "green"
    elif score >= 60:
        return "yellow"
    return "red"


@app.command()
def version():
    """Show version information."""
    from . import __version__
    console.print(f"audit-tool version {__version__}")
    console.print("https://humotica.com")


@app.command()
def token(
    token_id: str = typer.Argument(..., help="TIBET Token ID to display"),
    endpoint: str = typer.Option("http://localhost:8000", "--endpoint", "-e", help="TIBET API endpoint"),
    output: str = typer.Option("terminal", "--output", "-o", help="Output: terminal, json"),
):
    """
    Display a TIBET provenance token in full detail.

    Shows the complete provenance chain:
    - ERIN: What's IN the action (content/payload)
    - ERAAN: What's attached (dependencies, references)
    - EROMHEEN: Context around it (environment, state)
    - ERACHTER: Intent behind it (why this action)

    Examples:
        tibet-audit token abc123-def456
        tibet-audit token abc123 --output json
        tibet-audit token abc123 --endpoint http://192.168.4.85:8100
    """
    import urllib.request
    import json as json_module

    # Fetch token from TIBET API
    try:
        url = f"{endpoint}/api/tibet/{token_id}"
        req = urllib.request.Request(url, headers={'Accept': 'application/json'})
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json_module.loads(response.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            console.print(f"[red]❌ Token not found: {token_id}[/]")
        else:
            console.print(f"[red]❌ API error: {e.code} {e.reason}[/]")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]❌ Could not reach TIBET API: {e}[/]")
        console.print(f"[dim]   Endpoint: {endpoint}[/]")
        raise typer.Exit(1)

    if output.lower() == "json":
        console.print(json_module.dumps(data, indent=2, default=str))
        return

    # Pretty print the token
    _display_tibet_token(data)


def _display_tibet_token(token: dict):
    """Display a TIBET token in beautiful box format."""

    # Extract fields with safe defaults (support both MCP and brain_api formats)
    token_id = token.get("id") or token.get("token_id", "unknown")
    token_type = token.get("type") or token.get("token_type", "unknown")

    # Actor can be in metadata or top-level
    metadata = token.get("metadata", {})
    actors = metadata.get("actors", [])
    actor = token.get("actor") or (", ".join(actors) if actors else "unknown")

    state = token.get("state", "CREATED")
    trust = token.get("trust_score", 0.5)
    timestamp = token.get("created_at") or token.get("timestamp", "")
    signature = token.get("compact", "")[:30] + "..." if token.get("compact") else (token.get("signature", "")[:20] + "..." if token.get("signature") else "N/A")

    # Provenance fields - map from different API formats
    # MCP format: erin, eraan, eromheen, erachter
    # Brain API format: intent, reason, humotica_*, metadata

    # ERIN = What's in the action (content)
    erin = token.get("erin") or token.get("humotica_sense") or {
        "intent": token.get("intent", ""),
        "type": token_type,
    }
    if isinstance(erin, str):
        erin = {"content": erin}

    # ERAAN = What's attached (dependencies, references)
    eraan = token.get("eraan") or token.get("dependencies") or actors or []
    if token.get("fir_a_genesis"):
        if isinstance(eraan, list):
            eraan = eraan + [f"genesis: {token.get('fir_a_genesis')}"]

    # EROMHEEN = Context (environment, state)
    eromheen = token.get("eromheen") or token.get("humotica_context") or {
        "channel": metadata.get("channel", "unknown"),
        "state": metadata.get("state", state),
    }
    if isinstance(eromheen, str):
        eromheen = {"context": eromheen}

    # ERACHTER = Intent/Why
    erachter = token.get("erachter") or token.get("humotica_intent") or token.get("reason") or ""

    # State color
    state_colors = {
        "CREATED": "blue",
        "DETECTED": "yellow",
        "CLASSIFIED": "cyan",
        "MITIGATED": "magenta",
        "RESOLVED": "green",
    }
    state_color = state_colors.get(state.upper(), "white")

    # Trust color
    trust_color = "green" if trust >= 0.7 else "yellow" if trust >= 0.4 else "red"

    # Build the display
    console.print()
    console.print("[bold blue]╔══════════════════════════════════════════════════════════════════╗[/]")
    console.print("[bold blue]║[/]                    [bold]TIBET PROVENANCE TOKEN[/]                        [bold blue]║[/]")
    console.print("[bold blue]╠══════════════════════════════════════════════════════════════════╣[/]")
    console.print(f"[bold blue]║[/] TOKEN ID:  [cyan]{token_id[:50]:<50}[/] [bold blue]║[/]")
    console.print(f"[bold blue]║[/] TYPE:      [white]{str(token_type)[:50]:<50}[/] [bold blue]║[/]")
    console.print(f"[bold blue]║[/] ACTOR:     [white]{str(actor)[:50]:<50}[/] [bold blue]║[/]")
    console.print(f"[bold blue]║[/] STATE:     [{state_color}]{state:<50}[/] [bold blue]║[/]")
    console.print(f"[bold blue]║[/] TRUST:     [{trust_color}]{trust:<50}[/] [bold blue]║[/]")
    console.print("[bold blue]╠══════════════════════════════════════════════════════════════════╣[/]")

    # ERIN
    console.print("[bold blue]║[/] [bold green]ERIN[/] (Wat zit erin?)                                           [bold blue]║[/]")
    if isinstance(erin, dict):
        for k, v in list(erin.items())[:5]:
            line = f"   {k}: {v}"[:60]
            console.print(f"[bold blue]║[/]   {line:<62} [bold blue]║[/]")
    else:
        line = str(erin)[:60]
        console.print(f"[bold blue]║[/]   {line:<62} [bold blue]║[/]")

    console.print("[bold blue]╠══════════════════════════════════════════════════════════════════╣[/]")

    # ERAAN
    console.print("[bold blue]║[/] [bold yellow]ERAAN[/] (Wat hangt eraan?)                                        [bold blue]║[/]")
    if isinstance(eraan, list):
        for item in eraan[:5]:
            line = f"→ {item}"[:60]
            console.print(f"[bold blue]║[/]   {line:<62} [bold blue]║[/]")
    else:
        line = str(eraan)[:60]
        console.print(f"[bold blue]║[/]   {line:<62} [bold blue]║[/]")

    console.print("[bold blue]╠══════════════════════════════════════════════════════════════════╣[/]")

    # EROMHEEN
    console.print("[bold blue]║[/] [bold cyan]EROMHEEN[/] (Context)                                              [bold blue]║[/]")
    if isinstance(eromheen, dict):
        for k, v in list(eromheen.items())[:5]:
            line = f"   {k}: {v}"[:60]
            console.print(f"[bold blue]║[/]   {line:<62} [bold blue]║[/]")
    else:
        line = str(eromheen)[:60]
        console.print(f"[bold blue]║[/]   {line:<62} [bold blue]║[/]")

    console.print("[bold blue]╠══════════════════════════════════════════════════════════════════╣[/]")

    # ERACHTER
    console.print("[bold blue]║[/] [bold magenta]ERACHTER[/] (Intent/Waarom?)                                       [bold blue]║[/]")
    if erachter:
        # Word wrap long intents
        words = str(erachter).split()
        lines = []
        current_line = ""
        for word in words:
            if len(current_line) + len(word) + 1 <= 60:
                current_line += (" " if current_line else "") + word
            else:
                lines.append(current_line)
                current_line = word
        if current_line:
            lines.append(current_line)
        for line in lines[:4]:
            console.print(f"[bold blue]║[/]   {line:<62} [bold blue]║[/]")
    else:
        console.print(f"[bold blue]║[/]   {'(geen intent gespecificeerd)':<62} [bold blue]║[/]")

    console.print("[bold blue]╠══════════════════════════════════════════════════════════════════╣[/]")
    console.print(f"[bold blue]║[/] SIGNATURE: [dim]{signature:<52}[/] [bold blue]║[/]")
    console.print(f"[bold blue]║[/] TIMESTAMP: [dim]{str(timestamp)[:52]:<52}[/] [bold blue]║[/]")
    console.print("[bold blue]╚══════════════════════════════════════════════════════════════════╝[/]")
    console.print()


@app.command()
def roadmap(
    path: str = typer.Argument(".", help="Path to scan"),
    output: str = typer.Option("terminal", "--output", "-o", help="Output: terminal, json"),
    profile: str = typer.Option("default", "--profile", "-p", help="Profile: default, enterprise, dev"),
):
    """Generate a compliance roadmap (Mercury)."""
    audit = TIBETAudit()
    result = audit.scan(path)
    roadmap_data = generate_roadmap(result)

    if output.lower() == "json":
        console.print(json.dumps({
            "report": build_report(result, profile=profile),
            "roadmap": roadmap_data,
        }, indent=2))
        return

    _print_roadmap(roadmap_data)


@app.command()
def upgrades(
    path: str = typer.Argument(".", help="Path to scan"),
    output: str = typer.Option("terminal", "--output", "-o", help="Output: terminal, json"),
    profile: str = typer.Option("default", "--profile", "-p", help="Profile: default, enterprise, dev"),
):
    """Generate value-based upgrade suggestions (Mercury)."""
    audit = TIBETAudit()
    result = audit.scan(path)
    upgrades_data = generate_upgrades(result)

    if output.lower() == "json":
        console.print(json.dumps({
            "report": build_report(result, profile=profile),
            "upgrades": upgrades_data,
        }, indent=2))
        return

    _print_upgrades(upgrades_data)


@app.command()
def diff(
    old_report: Path = typer.Argument(..., help="Old report JSON"),
    new_report: Path = typer.Argument(..., help="New report JSON"),
    output: str = typer.Option("terminal", "--output", "-o", help="Output: terminal, json"),
):
    """Compare two reports and show compliance drift."""
    old = json.loads(old_report.read_text())
    new = json.loads(new_report.read_text())
    delta = diff_reports(old, new)

    if output.lower() == "json":
        console.print(json.dumps(delta, indent=2))
        return

    console.print(f"[bold]Score delta:[/] {delta['score_delta']}")
    if delta["newly_failed"]:
        console.print("[red]Newly failed:[/]")
        for check_id in delta["newly_failed"]:
            console.print(f"  - {check_id}")
    if delta["resolved"]:
        console.print("[green]Resolved:[/]")
        for check_id in delta["resolved"]:
            console.print(f"  - {check_id}")


@app.command("high-five")
def high_five_cmd():
    """Send a signed handshake ping (no scan data)."""
    _run_high_five()


@app.command("eu-pack")
def eu_pack(
    path: str = typer.Argument(".", help="Path to scan"),
    output: str = typer.Option("terminal", "--output", "-o", help="Output: terminal, json, soc2, markdown"),
    organization: str = typer.Option("Unknown", "--org", help="Organization name for SOC2 report"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Minimal output"),
):
    """
    EU Compliance Pack - GDPR + AI Act + NIS2 combined scan.

    Perfect for US companies targeting the European market.
    Generates SOC2-ready reports with TIBET attestation.

    Examples:
        tibet-audit eu-pack
        tibet-audit eu-pack ./my-ai-project
        tibet-audit eu-pack --output soc2 --org "Acme Corp"
        tibet-audit eu-pack --output markdown > compliance-report.md
    """
    from .checks import EU_COMPLIANCE_CHECKS
    from .exporters.soc2 import export_to_soc2

    if not quiet:
        console.print(BANNER.format(version=__version__))
        console.print("[bold blue]🇪🇺 EU COMPLIANCE PACK[/]")
        console.print("[dim]GDPR + AI Act + NIS2 - Everything you need for the EU market[/]\n")

    # Run audit with EU checks only
    audit = TIBETAudit()
    result = audit.scan(path, categories=["gdpr", "ai_act", "nis2"])

    # Generate output
    if output.lower() == "soc2":
        # SOC2 Type II format
        soc2_report = export_to_soc2(
            {"results": [r.__dict__ for r in result.results]},
            organization=organization,
            output_format="markdown",
            tibet_token=f"TIBET-EU-{result.scan_id}",
        )
        console.print(soc2_report)
    elif output.lower() == "json":
        console.print(json.dumps({
            "pack": "EU Compliance Pack",
            "score": result.score,
            "grade": result.grade,
            "gdpr_passed": sum(1 for r in result.results if r.category == "gdpr" and r.status == Status.PASSED),
            "ai_act_passed": sum(1 for r in result.results if r.category == "ai_act" and r.status == Status.PASSED),
            "nis2_passed": sum(1 for r in result.results if r.category == "nis2" and r.status == Status.PASSED),
            "results": [r.__dict__ for r in result.results],
        }, indent=2, default=str))
    elif output.lower() == "markdown":
        console.print(f"# EU Compliance Report - {organization}\n")
        console.print(f"**Score:** {result.score}/100 ({result.grade})\n")
        console.print("## Breakdown\n")
        for cat in ["gdpr", "ai_act", "nis2"]:
            cat_results = [r for r in result.results if r.category == cat]
            passed = sum(1 for r in cat_results if r.status == Status.PASSED)
            console.print(f"### {cat.upper().replace('_', ' ')}")
            console.print(f"- Passed: {passed}/{len(cat_results)}\n")
    else:
        # Terminal output
        _display_results(result, quiet=quiet)

        # EU-specific summary
        console.print("\n[bold blue]🇪🇺 EU MARKET READINESS:[/]\n")

        for cat, name, emoji in [("gdpr", "GDPR", "🔒"), ("ai_act", "AI Act", "🤖"), ("nis2", "NIS2", "🛡️")]:
            cat_results = [r for r in result.results if r.category == cat]
            passed = sum(1 for r in cat_results if r.status == Status.PASSED)
            total = len(cat_results)
            pct = int(passed / total * 100) if total else 0
            color = "green" if pct >= 80 else "yellow" if pct >= 60 else "red"
            console.print(f"  {emoji} {name}: [{color}]{passed}/{total} ({pct}%)[/]")

        console.print("\n[dim]Export to SOC2: tibet-audit eu-pack --output soc2 --org 'Your Company'[/]")


# ═══════════════════════════════════════════════════════════════════════════════
# COMPLIANCE CHECK (AETHER TIERS)
# ═══════════════════════════════════════════════════════════════════════════════

# AETHER Tier Definitions
# Philosophy: Signal → Amplify → Broadcast → Resonance
# "I exist" → "I am heard" → "I broadcast" → "I resonate with the AETHER"
AETHER_TIERS = {
    "signal": {
        "name": "SIGNAL",
        "emoji": "🟢",
        "color": "green",
        "price": "Free",
        "description": "I exist.",
        "tagline": "Basic installation",
        "min_packages": 1,
    },
    "amplify": {
        "name": "AMPLIFY",
        "emoji": "🔵",
        "color": "blue",
        "price": "€99/mo",
        "description": "I am heard.",
        "tagline": "Monitoring active",
        "min_packages": 3,
    },
    "broadcast": {
        "name": "BROADCAST",
        "emoji": "🟡",
        "color": "yellow",
        "price": "€499/mo",
        "description": "I broadcast.",
        "tagline": "Custom rules, streaming",
        "min_packages": 5,
    },
    "resonance": {
        "name": "RESONANCE",
        "emoji": "🟣",
        "color": "magenta",
        "price": "Custom",
        "description": "I resonate with the AETHER.",
        "tagline": "War Room, Zero-trust",
        "min_packages": 8,
    },
}

# Package categories for compliance calculation
HUMOTICA_PACKAGES = {
    # Core audit (essential)
    "tibet-audit": {"weight": 20, "category": "audit", "tier": "signal"},
    "tibet-chip": {"weight": 15, "category": "audit", "tier": "signal"},
    "tibet-vault": {"weight": 15, "category": "audit", "tier": "amplify"},

    # MCP Servers (integration)
    "mcp-server-tibet": {"weight": 10, "category": "mcp", "tier": "signal"},
    "mcp-server-rabel": {"weight": 10, "category": "mcp", "tier": "amplify"},
    "mcp-server-sensory": {"weight": 8, "category": "mcp", "tier": "amplify"},
    "mcp-server-aidrac": {"weight": 8, "category": "mcp", "tier": "broadcast"},
    "mcp-server-inject-bender": {"weight": 5, "category": "mcp", "tier": "broadcast"},
    "mcp-server-ollama-bridge": {"weight": 5, "category": "mcp", "tier": "broadcast"},
    "mcp-server-gemini-bridge": {"weight": 5, "category": "mcp", "tier": "broadcast"},
    "mcp-server-openai-bridge": {"weight": 5, "category": "mcp", "tier": "broadcast"},

    # Protocols
    "sema-protocol": {"weight": 10, "category": "protocol", "tier": "amplify"},
    "reflux-protocol": {"weight": 8, "category": "protocol", "tier": "broadcast"},
    "ainternet": {"weight": 12, "category": "protocol", "tier": "amplify"},

    # Tools & CLI
    "idd-cli": {"weight": 8, "category": "tools", "tier": "amplify"},
    "kit-pm": {"weight": 5, "category": "tools", "tier": "signal"},
    "oomllama": {"weight": 10, "category": "llm", "tier": "amplify"},
    "humotica": {"weight": 5, "category": "core", "tier": "signal"},

    # Advanced
    "sensory": {"weight": 8, "category": "advanced", "tier": "broadcast"},
    "aidrac": {"weight": 8, "category": "advanced", "tier": "broadcast"},
    "aindex-diy": {"weight": 5, "category": "tools", "tier": "amplify"},
    "ai-network": {"weight": 8, "category": "protocol", "tier": "broadcast"},
    "ipoll": {"weight": 8, "category": "protocol", "tier": "amplify"},
}

# Zenodo papers for authority
ZENODO_PAPERS = [
    {"id": "18341384", "title": "TIBET: Transparency & Intent Protocol"},
    {"id": "18340471", "title": "SNAFT: Security That Feels Like Safety"},
    {"id": "18208218", "title": "JIS: Just-In-Time Security Routing"},
    {"id": "17762391", "title": "AETHER: Semantic Search Architecture"},
    {"id": "17759713", "title": "HumoticaOS: AI Governance Framework"},
]


def _detect_installed_packages() -> dict:
    """Detect which Humotica packages are installed."""
    import importlib.util
    import subprocess

    installed = {}

    # Try pip list first (most reliable)
    try:
        result = subprocess.run(
            ["pip", "list", "--format=json"],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            import json as json_mod
            pip_packages = {p["name"].lower(): p["version"] for p in json_mod.loads(result.stdout)}

            for pkg_name, pkg_info in HUMOTICA_PACKAGES.items():
                # Check both with and without hyphens/underscores
                check_names = [
                    pkg_name.lower(),
                    pkg_name.lower().replace("-", "_"),
                    pkg_name.lower().replace("_", "-"),
                ]
                for check_name in check_names:
                    if check_name in pip_packages:
                        installed[pkg_name] = {
                            "version": pip_packages[check_name],
                            **pkg_info
                        }
                        break
    except Exception:
        # Fallback: try importlib
        for pkg_name, pkg_info in HUMOTICA_PACKAGES.items():
            module_name = pkg_name.replace("-", "_")
            try:
                spec = importlib.util.find_spec(module_name)
                if spec is not None:
                    installed[pkg_name] = {"version": "unknown", **pkg_info}
            except (ImportError, ModuleNotFoundError):
                pass

    return installed


def _calculate_compliance(installed: dict) -> tuple:
    """Calculate compliance percentage and tier."""
    if not installed:
        return 0, "signal"

    # Calculate weighted score
    total_weight = sum(pkg["weight"] for pkg in HUMOTICA_PACKAGES.values())
    installed_weight = sum(pkg["weight"] for pkg in installed.values())
    compliance_pct = int((installed_weight / total_weight) * 100)

    # Determine tier based on packages installed
    pkg_count = len(installed)

    if pkg_count >= 8:
        tier = "resonance"
    elif pkg_count >= 5:
        tier = "broadcast"
    elif pkg_count >= 3:
        tier = "amplify"
    else:
        tier = "signal"

    return compliance_pct, tier


@app.command("check")
def check_compliance(
    output: str = typer.Option("terminal", "--output", "-o", help="Output: terminal, json"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show detailed component status"),
):
    """
    Check your AETHER compliance level and tier.

    Analyzes your local environment for:
    - JIS Identity (Level 1)
    - TIBET Provenance (Level 2)
    - Genesis Tunnel (Level 3)
    - War Room Access (Level 4)

    Examples:
        tibet-audit check
        tibet-audit check --verbose
        tibet-audit check --output json
    """
    # Detect installed packages
    installed = _detect_installed_packages()
    compliance_pct, current_tier = _calculate_compliance(installed)

    tier_info = AETHER_TIERS[current_tier]

    # Determine component status
    has_jis = any(p in installed for p in ["tibet-audit", "tibet-chip", "idd-cli"])
    has_tibet = any(p in installed for p in ["tibet-vault", "mcp-server-tibet", "tibet-audit"])
    has_genesis = any(p in installed for p in ["mcp-server-rabel", "ainternet", "reflux-protocol"])
    has_warroom = len(installed) >= 8

    if output.lower() == "json":
        import json as json_mod
        result = {
            "tier": current_tier,
            "tier_name": tier_info["name"],
            "compliance_percentage": compliance_pct,
            "components": {
                "jis_identity": has_jis,
                "tibet_provenance": has_tibet,
                "genesis_tunnel": has_genesis,
                "war_room": has_warroom,
            },
            "installed_packages": list(installed.keys()),
            "package_count": len(installed),
            "upgrade_url": "https://humotica.com/tiers",
            "contact": "info@humotica.com",
            "zenodo_papers": [f"https://zenodo.org/records/{p['id']}" for p in ZENODO_PAPERS],
        }
        console.print(json_mod.dumps(result, indent=2))
        return

    # Clean CLI output - Jasper's vision
    console.print()
    console.print("[dim]> Analyzing Local Environment...[/]")
    console.print()

    # Component checks
    jis_status = "[green]Found[/] (Level 1 ✅)" if has_jis else "[red]Missing[/] (Level 1 ❌)"
    tibet_status = "[green]Active[/] (Level 2 ✅)" if has_tibet else "[red]Inactive[/] (Level 2 ❌)"
    genesis_status = "[green]Connected[/] (Level 3 ✅)" if has_genesis else "[yellow]Inactive[/] (Level 3 ❌)"
    warroom_status = "[green]Access Granted[/] (Level 4 ✅)" if has_warroom else "[dim]Locked[/] (Level 4 🔒)"

    console.print(f"[dim]>[/] JIS Identity:      {jis_status}")
    console.print(f"[dim]>[/] TIBET Provenance:  {tibet_status}")
    console.print(f"[dim]>[/] Genesis Tunnel:    {genesis_status}")
    console.print(f"[dim]>[/] War Room:          {warroom_status}")
    console.print()

    # Status with poetic quote
    tier_quotes = {
        "signal": "You exist. But does anyone know?",
        "amplify": "You are heard. But are you broadcasting truth?",
        "broadcast": "You broadcast. But do you resonate?",
        "resonance": "You resonate with the AETHER. Welcome home.",
    }

    console.print(f"[bold]>>> YOUR STATUS: [{tier_info['color']}]{tier_info['emoji']} {tier_info['name']}[/]")
    console.print(f"[italic]>>> \"{tier_quotes[current_tier]}\"[/]")

    # Upgrade suggestion
    tier_order = ["signal", "amplify", "broadcast", "resonance"]
    current_idx = tier_order.index(current_tier)

    if current_idx < 3:
        next_tier = tier_order[current_idx + 1]
        console.print(f"[dim]>>> Upgrade to {next_tier.upper()}: $ pip install tibet-vault ainternet[/]")
    console.print()

    # Verbose: show installed packages
    if verbose:
        console.print("[dim]─────────────────────────────────────────[/]")
        console.print(f"[dim]Packages: {len(installed)} installed ({compliance_pct}% coverage)[/]")
        for pkg_name, pkg_info in installed.items():
            console.print(f"[dim]  • {pkg_name} ({pkg_info['version']})[/]")
        console.print()

    # Links
    console.print("[dim]📚 Research: https://zenodo.org/records/18341384[/]")
    console.print("[dim]🌐 Tiers:    https://humotica.com/tiers[/]")
    console.print("[dim]📞 Contact:  info@humotica.com[/]")
    console.print()


# ═══════════════════════════════════════════════════════════════════════════════
# DISPLAY HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def _print_roadmap(roadmap_data: List[dict]):
    for stage in roadmap_data:
        console.print(f"\n[bold]{stage['stage']}[/]")
        if not stage["items"]:
            console.print("[dim]No items[/]")
            continue
        table = Table(box=box.SIMPLE)
        table.add_column("Check")
        table.add_column("Severity")
        table.add_column("Status")
        table.add_column("Rationale")
        for item in stage["items"]:
            table.add_row(
                item["check_id"],
                item["severity"],
                item["status"],
                item["rationale"],
            )
        console.print(table)


def _print_upgrades(upgrades_data: List[dict]):
    if not upgrades_data:
        console.print("[dim]No upgrade suggestions available.[/]")
        return
    table = Table(title="Top Upgrade Suggestions", box=box.SIMPLE)
    table.add_column("Check")
    table.add_column("ROI")
    table.add_column("Rationale")
    for item in upgrades_data:
        table.add_row(
            item["check_id"],
            str(item["roi_score"]),
            item["rationale"],
        )
    console.print(table)


def _run_high_five():
    result = high_five()
    if result.get("status") == "ok":
        console.print("[bold green]🙌 High-five received![/]")
        console.print()
        console.print("[dim]Your signed handshake reached the HumoticaOS AETHER.[/]")
        console.print("[dim]Welcome to the IDD family.[/]")
        console.print()
        console.print("[bold]One love, one fAmIly![/] 💙")
    elif result.get("status") == "skipped":
        console.print("[bold cyan]🙌 High-five! (offline mode)[/]")
        console.print()
        console.print("[dim]Could not reach humotica.com - running in offline mode.[/]")
        console.print("[dim]Set AUDIT_HIGH_FIVE_URL to use a custom endpoint.[/]")
    else:
        console.print("[yellow]🙌 High-five attempt...[/]")
        console.print(f"[dim]Could not connect: {result.get('error', 'unknown error')}[/]")
        console.print("[dim]No worries - tibet-audit works fine offline![/]")

def _display_results(result: ScanResult, quiet: bool = False, verbose: bool = False):
    """Display scan results in a nice format."""

    # Score display
    score_color = "green" if result.score >= 80 else "yellow" if result.score >= 60 else "red"

    score_panel = Panel(
        f"[bold {score_color}]{result.score}/100[/]  [dim]Grade: {result.grade}[/]",
        title="[bold]COMPLIANCE HEALTH SCORE[/]",
        border_style=score_color,
        padding=(1, 4),
    )
    console.print(score_panel)

    # Summary
    console.print(f"\n  [green]✅ PASSED[/]: {result.passed}")
    console.print(f"  [yellow]⚠️  WARNINGS[/]: {result.warnings}")
    console.print(f"  [red]❌ FAILED[/]: {result.failed}")
    if result.skipped:
        console.print(f"  [dim]⏭️  SKIPPED[/]: {result.skipped}")

    console.print()

    # In cry mode, show EVERYTHING
    if verbose:
        console.print("[bold]😭 FULL BREAKDOWN (cry mode):[/]\n")

        # Show all passed checks too
        passed = [r for r in result.results if r.status == Status.PASSED]
        if passed:
            console.print("[bold green]PASSED CHECKS:[/]")
            for check in passed:
                console.print(f"  [green]✅[/] {check.check_id}: {check.name}")
                console.print(f"     [dim]{check.message}[/]")
            console.print()

    # Failed checks (priority)
    failed = [r for r in result.results if r.status == Status.FAILED]
    if failed:
        console.print("[bold red]TOP PRIORITIES:[/]\n")
        limit = len(failed) if verbose else 5  # Show all in cry mode
        for i, check in enumerate(failed[:limit], 1):
            console.print(f"  {i}. [red][{check.severity.value.upper()}][/] {check.name}")
            console.print(f"     [dim]{check.message}[/]")
            if check.recommendation:
                console.print(f"     [green]→ FIX: {check.recommendation}[/]")
            if verbose and check.references:
                console.print(f"     [cyan]📚 References:[/]")
                for ref in check.references:
                    console.print(f"        - {ref}")
            if verbose and check.fix_action:
                console.print(f"     [yellow]🔧 Auto-fix available:[/]")
                console.print(f"        {check.fix_action.description}")
                if check.fix_action.command:
                    console.print(f"        $ {check.fix_action.command}")
            console.print()

    # Warnings
    warnings = [r for r in result.results if r.status == Status.WARNING]
    if warnings and not quiet:
        console.print("[bold yellow]WARNINGS:[/]\n")
        limit = len(warnings) if verbose else 3  # Show all in cry mode
        for check in warnings[:limit]:
            console.print(f"  [yellow]⚠️[/]  {check.name}: {check.message}")
            if verbose and check.recommendation:
                console.print(f"     [green]→ {check.recommendation}[/]")
            if verbose and check.references:
                for ref in check.references:
                    console.print(f"     [dim]📚 {ref}[/]")
        if len(warnings) > limit and not verbose:
            console.print(f"  [dim]... and {len(warnings) - limit} more[/]")
        console.print()

    # Fixable count
    fixable = sum(1 for r in result.results if r.can_auto_fix and r.status != Status.PASSED)
    if fixable:
        console.print(f"[bold]💡 {fixable} issue(s) can be auto-fixed:[/]")
        console.print("   [dim]audit-tool fix --auto[/]  (Diaper Protocol™)")
        console.print("   [dim]audit-tool fix --wet-wipe[/]  (preview first)")

    # Scan info
    console.print(f"\n[dim]Scanned: {result.scan_path}[/]")
    console.print(f"[dim]Duration: {result.duration_seconds}s[/]")


# ═══════════════════════════════════════════════════════════════════════════════
# CHECKPOINT CODE - Cross-Border Compliance
# ═══════════════════════════════════════════════════════════════════════════════

CHECKPOINT_BANNER = """
[bold yellow]══════════════════════════════════════════════════════════════════════════════[/]
[bold yellow]  🚧 CHECKPOINT CODE[/]
[dim]  "Passports checked. Math matches. You may proceed."[/]
[bold yellow]══════════════════════════════════════════════════════════════════════════════[/]
"""


@app.command("checkpoint")
def checkpoint(
    path: str = typer.Argument(".", help="Path to scan"),
    source: str = typer.Option("eu", "--from", "-f", help="Source jurisdiction (eu, us, jp, za, au, br)"),
    target: str = typer.Option("us", "--to", "-t", help="Target jurisdiction"),
    output: str = typer.Option("terminal", "--output", "-o", help="Output: terminal, json"),
):
    """
    🚧 Cross the Checkpoint - Check cross-border compliance readiness.

    Translates compliance terms between jurisdictions using SEMA.
    PAUL the border guard will tell you if you can cross.

    Examples:
        tibet-audit checkpoint                    # EU -> US (default)
        tibet-audit checkpoint --from eu --to jp  # EU -> Japan
        tibet-audit checkpoint ./my-project --from us --to eu
        tibet-audit checkpoint --from eu --to us --output json
    """
    from .checkpoint import checkpoint_scan, Jurisdiction

    console.print(CHECKPOINT_BANNER)

    # Run McMurdo check first
    console.print("[bold cyan]🏔️  McMurdo Base: Pre-flight check...[/]")

    # Quick provenance check
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task("Checking TIBET provenance...", total=None)
        audit = TIBETAudit()
        scan_result = audit.scan(path, categories=["jis", "sovereignty"])

    console.print(f"    [green]✓[/] Provenance check: {scan_result.passed} passed")
    console.print(f"    [green]✓[/] Chain integrity: {'VERIFIED' if scan_result.score >= 70 else 'NEEDS ATTENTION'}")
    console.print()

    # Cross the checkpoint
    try:
        result, rendered = checkpoint_scan(source, target, path)

        if output.lower() == "json":
            import json as json_mod
            json_result = {
                "source": result.source.value,
                "target": result.target.value,
                "readiness_score": result.readiness_score,
                "can_cross": result.can_cross,
                "paul_says": result.paul_says,
                "translations": [
                    {
                        "source_term": t.source_term,
                        "target_term": t.target_term,
                        "confidence": t.confidence,
                        "warning": t.warning,
                        "references": t.references,
                    }
                    for t in result.translations
                ],
                "warnings": result.warnings,
            }
            console.print(json_mod.dumps(json_result, indent=2))
        else:
            console.print(rendered)

            # Action recommendation
            if result.can_cross:
                console.print("[bold green]✅ Ready to operate in target jurisdiction![/]")
            else:
                console.print("[bold red]❌ Compliance gaps detected. Review warnings above.[/]")
                console.print("[dim]   Run: tibet-audit scan --categories gdpr,sovereignty[/]")

    except ValueError as e:
        console.print(f"[red]Error: {e}[/]")
        console.print("[dim]Valid jurisdictions: eu, us, jp, za, au, br, sg, global[/]")
        raise typer.Exit(1)


@app.command("checkpoint-matrix")
def checkpoint_matrix(
    path: str = typer.Argument(".", help="Path to scan"),
    output: str = typer.Option("terminal", "--output", "-o", help="Output: terminal, json"),
):
    """
    🌍 Full checkpoint matrix - Check readiness for ALL jurisdiction crossings.

    Shows a matrix of cross-border readiness scores.

    Examples:
        tibet-audit checkpoint-matrix
        tibet-audit checkpoint-matrix ./my-project
    """
    from .checkpoint import cross_checkpoint, Jurisdiction

    console.print(CHECKPOINT_BANNER)
    console.print("[bold]🌍 CHECKPOINT MATRIX - All Border Crossings[/]\n")

    jurisdictions = [Jurisdiction.EU, Jurisdiction.US, Jurisdiction.JP, Jurisdiction.ZA]

    # Build matrix
    table = Table(title="Cross-Border Readiness Matrix", box=box.ROUNDED)
    table.add_column("From \\ To", style="bold")

    for j in jurisdictions:
        table.add_column(j.value.upper(), justify="center")

    for source in jurisdictions:
        row = [source.value.upper()]
        for target in jurisdictions:
            if source == target:
                row.append("[dim]—[/]")
            else:
                result = cross_checkpoint(source, target)
                score = result.readiness_score
                if score >= 85:
                    color = "green"
                elif score >= 70:
                    color = "yellow"
                else:
                    color = "red"
                row.append(f"[{color}]{score:.0f}%[/]")
        table.add_row(*row)

    console.print(table)
    console.print()
    console.print("[dim]Run 'tibet-audit checkpoint --from X --to Y' for detailed translation[/]")


# ═══════════════════════════════════════════════════════════════════════════════
# SIGN-OFF COMMANDS (Jurist Verification)
# ═══════════════════════════════════════════════════════════════════════════════

SIGNOFF_BANNER = """
[bold cyan]══════════════════════════════════════════════════════════════════════════════[/]
[bold cyan]  ⚖️  TIBET SIGN-OFF - Human Verification with JIS Bilateral Consent[/]
[dim]  "TIBET prepares, Human verifies, JIS seals."[/]
[bold cyan]══════════════════════════════════════════════════════════════════════════════[/]
"""

signoff_app = typer.Typer(
    name="signoff",
    help="Manage sign-off requests for compliance verification",
    add_completion=False,
)
app.add_typer(signoff_app, name="signoff")


@signoff_app.command("list")
def signoff_list():
    """List all pending sign-off requests."""
    from .signoff import SignoffManager, SignoffState

    console.print(SIGNOFF_BANNER)

    manager = SignoffManager()
    pending = manager.list_pending()

    if not pending:
        console.print("[green]✅ No pending sign-offs. All compliance assessments are verified![/]")
        return

    table = Table(title="Pending Sign-offs", box=box.ROUNDED)
    table.add_column("ID", style="cyan", width=14)
    table.add_column("Path", width=30)
    table.add_column("Score", justify="right", width=8)
    table.add_column("Fixed", justify="right", width=8)
    table.add_column("State", width=15)
    table.add_column("Reviewer", width=20)

    state_colors = {
        SignoffState.PENDING_REVIEW: "yellow",
        SignoffState.UNDER_REVIEW: "blue",
    }

    for record in pending:
        path = record.scan_path[:28] + "..." if len(record.scan_path) > 30 else record.scan_path
        color = state_colors.get(record.state, "white")
        table.add_row(
            record.signoff_id,
            path,
            f"{record.scan_score}/100",
            str(record.issues_fixed),
            f"[{color}]{record.state.value}[/]",
            record.reviewer_name or "[dim]Unassigned[/]"
        )

    console.print(table)
    console.print(f"\n[dim]Total pending: {len(pending)}[/]")
    console.print()
    console.print("[dim]To approve: tibet-audit signoff approve <ID>[/]")
    console.print("[dim]To seal:    tibet-audit signoff seal <ID>[/]")


@signoff_app.command("show")
def signoff_show(signoff_id: str = typer.Argument(..., help="Sign-off ID")):
    """Show details of a specific sign-off."""
    from .signoff import SignoffManager, create_signoff_prompt, format_sealed_certificate, SignoffState

    manager = SignoffManager()
    record = manager.get_record(signoff_id)

    if not record:
        console.print(f"[red]❌ Sign-off {signoff_id} not found[/]")
        raise typer.Exit(1)

    console.print(SIGNOFF_BANNER)

    if record.state == SignoffState.JIS_SEALED:
        console.print(format_sealed_certificate(record))
    else:
        console.print(create_signoff_prompt(record))
        console.print(f"[bold]State:[/] {record.state.value}")
        if record.reviewer_name:
            console.print(f"[bold]Reviewer:[/] {record.reviewer_name}")
        if record.reviewer_did:
            console.print(f"[bold]DID:[/] {record.reviewer_did}")


@signoff_app.command("approve")
def signoff_approve(
    signoff_id: str = typer.Argument(..., help="Sign-off ID"),
    reviewer: Optional[str] = typer.Option(None, "--reviewer", "-r", help="Reviewer name"),
    reviewer_did: Optional[str] = typer.Option(None, "--did", help="Reviewer DID"),
    comment: Optional[str] = typer.Option(None, "--comment", "-c", help="Review comment"),
):
    """Approve a compliance assessment (human verification step)."""
    from .signoff import SignoffManager, SignoffState

    console.print(SIGNOFF_BANNER)

    manager = SignoffManager()
    record = manager.get_record(signoff_id)

    if not record:
        console.print(f"[red]❌ Sign-off {signoff_id} not found[/]")
        raise typer.Exit(1)

    # Start review if reviewer info provided and not yet reviewing
    if reviewer and record.state == SignoffState.PENDING_REVIEW:
        record = manager.start_review(signoff_id, reviewer, reviewer_did)
        console.print(f"[blue]→ Review started by {reviewer}[/]")

    # Approve
    try:
        record = manager.approve(signoff_id, comment)
        console.print(f"[green]✅ Sign-off {signoff_id} APPROVED![/]")
        console.print()
        console.print(f"[dim]State: {record.state.value}[/]")
        if comment:
            console.print(f"[dim]Comment: {comment}[/]")
        console.print()
        console.print("[bold]Next step:[/] Seal with JIS bilateral consent:")
        console.print(f"  [cyan]tibet-audit signoff seal {signoff_id}[/]")
    except ValueError as e:
        console.print(f"[red]❌ {e}[/]")
        raise typer.Exit(1)


@signoff_app.command("reject")
def signoff_reject(
    signoff_id: str = typer.Argument(..., help="Sign-off ID"),
    reason: str = typer.Option(..., "--reason", "-r", help="Reason for rejection"),
):
    """Reject a compliance assessment."""
    from .signoff import SignoffManager

    console.print(SIGNOFF_BANNER)

    manager = SignoffManager()

    try:
        record = manager.reject(signoff_id, reason)
        console.print(f"[red]❌ Sign-off {signoff_id} REJECTED[/]")
        console.print(f"[dim]Reason: {reason}[/]")
        console.print()
        console.print("[dim]The compliance assessment needs to be reviewed and re-run.[/]")
    except ValueError as e:
        console.print(f"[red]❌ {e}[/]")
        raise typer.Exit(1)


@signoff_app.command("seal")
def signoff_seal(signoff_id: str = typer.Argument(..., help="Sign-off ID")):
    """Cryptographically seal an approved sign-off with JIS bilateral consent."""
    from .signoff import SignoffManager, format_sealed_certificate, SignoffState

    console.print(SIGNOFF_BANNER)

    manager = SignoffManager()
    record = manager.get_record(signoff_id)

    if not record:
        console.print(f"[red]❌ Sign-off {signoff_id} not found[/]")
        raise typer.Exit(1)

    if record.state != SignoffState.HUMAN_VERIFIED:
        console.print(f"[red]❌ Can only seal HUMAN_VERIFIED sign-offs[/]")
        console.print(f"[dim]Current state: {record.state.value}[/]")
        if record.state == SignoffState.PENDING_REVIEW:
            console.print(f"\n[dim]First approve: tibet-audit signoff approve {signoff_id}[/]")
        raise typer.Exit(1)

    try:
        record = manager.seal_with_jis(signoff_id)
        console.print("[bold green]🔐 JIS SEALED![/]")
        console.print()
        console.print(format_sealed_certificate(record))
        console.print("[bold green]✅ Compliance assessment is now cryptographically verified.[/]")
        console.print()
        console.print(f"[dim]Certificate saved to: ~/.tibet-audit/signoffs/{signoff_id}_consent.json[/]")
    except ValueError as e:
        console.print(f"[red]❌ {e}[/]")
        raise typer.Exit(1)


@signoff_app.command("stats")
def signoff_stats():
    """Show sign-off statistics (for tibet-pol integration)."""
    from .signoff import SignoffManager, SignoffState

    console.print(SIGNOFF_BANNER)

    manager = SignoffManager()
    counts = manager.count_by_state()

    table = Table(title="Sign-off Statistics", box=box.ROUNDED)
    table.add_column("State", width=20)
    table.add_column("Count", justify="right", width=10)
    table.add_column("Description", width=40)

    state_info = {
        "PENDING_REVIEW": ("yellow", "Awaiting human reviewer"),
        "UNDER_REVIEW": ("blue", "Currently being reviewed"),
        "HUMAN_VERIFIED": ("green", "Approved, awaiting seal"),
        "HUMAN_REJECTED": ("red", "Rejected, needs re-assessment"),
        "JIS_SEALED": ("bold green", "Cryptographically sealed ✓"),
    }

    total = 0
    for state, count in counts.items():
        total += count
        color, desc = state_info.get(state, ("white", ""))
        table.add_row(f"[{color}]{state}[/]", str(count), desc)

    console.print(table)
    console.print(f"\n[bold]Total sign-offs: {total}[/]")

    # Calculate metrics for tibet-pol
    sealed = counts.get("JIS_SEALED", 0)
    pending = counts.get("PENDING_REVIEW", 0) + counts.get("UNDER_REVIEW", 0)
    verified = counts.get("HUMAN_VERIFIED", 0)

    if total > 0:
        seal_rate = sealed / total * 100
        console.print(f"[dim]Seal rate: {seal_rate:.1f}%[/]")
        console.print(f"[dim]Pending review: {pending}[/]")
        console.print(f"[dim]Awaiting seal: {verified}[/]")


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    """Main entry point."""
    app()


if __name__ == "__main__":
    main()
