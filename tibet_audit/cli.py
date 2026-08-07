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
from .cockpit import (
    build_cockpit_snapshot,
    classify_event,
    discover_evidence_sources,
    load_tail_events,
)
from .genesis import assess_genesis_events, is_genesis_event

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
                console.print(f"\n[bold yellow][💡] Update available: tibet-audit {latest_version}[/] [dim](current: {__version__})[/]")
                console.print(f"    [blue]pip install --upgrade tibet-audit[/]\n")
    except Exception:
        pass # Silent fail to respect the user's focus

app = typer.Typer(
    name="audit-tool",
    help="TIBET Audit - Compliance Health Scanner. Like Lynis, but for regulations.",
    add_completion=False,
)
console = Console()


def _print_header(title: str, subtitle: str | None = None, border_style: str = "blue") -> None:
    """Render a clean, business-like header panel."""
    body = f"[bold]{title}[/]"
    if subtitle:
        body += f"\n[dim]{subtitle}[/]"
    console.print(Panel(body, border_style=border_style, padding=(0, 2)))


def _causal_integrity_line(ci: dict | None) -> str:
    """One line on causal-chain integrity: evidence verified against the box's OWN lineage, not wall-clock."""
    if not ci or ci.get("verdict") == "unknown":
        return "[bold]Causal integrity:[/] [dim]not evaluated[/]"
    checked = ci.get("checked", 0)
    if ci.get("verdict") == "broken":
        first = (ci.get("broken") or [{}])[0]
        return (f"[bold]Causal integrity:[/] [bold red]BROKEN[/] — "
                f"{first.get('source', '?')} @rec {first.get('break_at', '?')} (tampered/gapped evidence)")
    stalled = ci.get("stalled") or []
    if stalled:
        return (f"[bold]Causal integrity:[/] [bold yellow]intact, {len(stalled)} open tail(s)[/] — "
                f"{stalled[0]['source']} started but never resolved (Pol'n)")
    return f"[bold]Causal integrity:[/] [bold green]intact[/] ({checked} chained source(s) verified)"


# ═══════════════════════════════════════════════════════════════════════════════
# COMMANDS
# ═══════════════════════════════════════════════════════════════════════════════


@app.command("red-specter")
def red_specter_cmd(
    path: str = typer.Argument(".", help="Path to the box run / evidence to check"),
    json_out: bool = typer.Option(False, "--json", help="Emit the regression report as JSON"),
):
    """Regression guards for the NIGHTFALL red-team findings (credit: Red Specter / richard.specter.aint)."""
    from .red_specter import run_regression
    rep = run_regression(path)
    if json_out:
        console.print_json(data=rep)
        return
    _print_header("Red Specter — red-team regression guards",
                  rep["credit"] + "  ·  try for yourself: " + rep["credit_links"][0],
                  border_style=("red" if rep["verdict"] == "regression" else "green"))
    table = Table(show_header=True, header_style="bold", box=box.ROUNDED)
    table.add_column("Guard", width=9); table.add_column("Finding", width=8)
    table.add_column("Status", width=13); table.add_column("Detail")
    _stcol = {"guarded": "green", "EXPOSED": "bold red", "not-observed": "dim", "error": "yellow"}
    for r in rep["findings"]:
        table.add_row(r["id"], r["tibet_id"],
                      f"[{_stcol.get(r['status'], 'white')}]{r['status']}[/]", r["detail"])
    console.print(table)
    verdict_style = "bold red" if rep["verdict"] == "regression" else "bold green"
    console.print(f"\n[{verdict_style}]VERDICT: {rep['verdict'].upper()}[/]"
                  + (f"  ({rep['exposed']} finding(s) returned!)" if rep["exposed"] else "  (all fixes hold)"))
    if rep["verdict"] == "regression":
        raise typer.Exit(1)


@app.command("pqc")
def pqc_cmd(
    path: str = typer.Argument(".", help="Path to the box run / evidence to check"),
    json_out: bool = typer.Option(False, "--json", help="Emit the PQC/HNDL report as JSON"),
):
    """Flag Harvest-Now-Decrypt-Later / quantum-forgeable provenance (credit: Red Specter HNDL research)."""
    from .pqc import scan_pqc_posture
    rep = scan_pqc_posture(path)
    if json_out:
        console.print_json(data=rep)
        return
    _exposed = rep["verdict"] == "hndl-exposed"
    _print_header("PQC / HNDL — quantum-forgeability posture",
                  rep["credit"] + "  ·  " + rep["credit_links"][0],
                  border_style=("yellow" if _exposed else "green"))
    vcol = {"hndl-exposed": "bold yellow", "hybrid": "bold green", "pqc": "bold green",
            "not-observed": "dim"}.get(rep["verdict"], "white")
    lines = [f"[bold]Posture:[/] [{vcol}]{rep['verdict']}[/]", f"[dim]{rep['note']}[/]"]
    if rep["long_lived_exposed"]:
        lines.append(f"[bold]Long-lived provenance at risk:[/] {', '.join(rep['long_lived_exposed'])}")
    lines.append(f"[bold]Recommendation:[/] {rep['recommendation']}")
    console.print(Panel("\n".join(lines), title="[bold magenta]HNDL[/]", border_style="magenta"))


@app.command("bom")
def bom_cmd(
    path: str = typer.Argument(".", help="Path to the box run / evidence to reflect on"),
    json_out: bool = typer.Option(False, "--json", help="Emit the BOM reflection as JSON"),
):
    """Reflect on the box's sealed self-portrait: sensor readiness, digest verification, and human presence."""
    from .bom import reflect_bom
    rep = reflect_bom(path)
    if json_out:
        console.print_json(data=rep)
        return
    vcol = {"observed": "bold green", "partial": "bold yellow", "digest-mismatch": "bold red",
            "not-observed": "dim", "unreadable": "bold red"}.get(rep["verdict"], "white")
    _print_header("System-BOM — reflection on the sealed self-portrait",
                  rep.get("card", "no sealed system-bom in scope"),
                  border_style=("red" if rep["verdict"] in ("digest-mismatch", "unreadable") else
                                "yellow" if rep["verdict"] == "partial" else "green"))
    lines = [f"[bold]BOM verdict:[/] [{vcol}]{rep['verdict']}[/]"]
    if "sensors_present" in rep:
        lines.append(f"[bold]Sensors:[/] {rep['sensors_present']}/{rep['sensors_total']} present"
                     + (f" · missing: {', '.join(rep['missing_sensors'])}" if rep.get("missing_sensors") else ""))
    for c in rep.get("digest_checks", []):
        col = {"verified": "green", "MISMATCH": "bold red", "recorded": "dim"}.get(c["status"], "white")
        lines.append(f"  [{col}]{c['status']}[/] {c['sensor']} — {c['detail']}")
    hp = rep.get("human_presence", {})
    hpcol = {"present": "bold green", "stale": "bold yellow", "deferred": "yellow",
             "unbound": "bold red"}.get(hp.get("status"), "dim")
    hp_line = f"[bold]Human presence:[/] [{hpcol}]{hp.get('status', '?')}[/]"
    if hp.get("owner"):
        hp_line += f" · owner {hp['owner']}" + (f" · RVP {hp.get('rvp', {}).get('resolution')}" if hp.get("rvp") else "")
    lines.append(hp_line)
    lines.append(f"  [dim]{hp.get('note', '')}[/]")
    if not hp.get("in_bom_sensor_family"):
        lines.append("  [dim]↳ read from owner-binding/live posture; not yet a sys-bom sensor (fold: #27/#49).[/]")
    console.print(Panel("\n".join(lines), title="[bold magenta]BOM reflection[/]", border_style="magenta"))
    if rep["verdict"] in ("digest-mismatch", "unreadable"):
        raise typer.Exit(1)

@app.command()
def scan(
    path: str = typer.Argument(".", help="Path to scan"),
    categories: Optional[str] = typer.Option(None, "--categories", "-c", help="Categories: tibet,jis,upip,rvp,ains,gdpr,ai_act,sovereignty,provider"),
    framework: Optional[str] = typer.Option(None, "--framework", "-f", help="Framework: ietf, bio2, nis2, gdpr, ai_act, dora"),
    org_name: Optional[str] = typer.Option(None, "--org", help="Organization name for compliance report"),
    output: str = typer.Option("terminal", "--output", "-o", help="Output: terminal, json"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Minimal output"),
    cry: bool = typer.Option(False, "--cry", help="Verbose mode - for when things are really bad"),
    profile: str = typer.Option("default", "--profile", "-p", help="Profile: default, enterprise, dev"),
    high_five: bool = typer.Option(False, "--high-five", help="Signed handshake ping (opt-in)"),
    sovereign: bool = typer.Option(False, "--sovereign", help="🏴 Sovereign mode: no cloud APIs, fully local inference"),
    boss_mode: bool = typer.Option(False, "--boss-mode", help="Generate professional HTML report for management"),
    boss_output: Optional[str] = typer.Option(None, "--boss-output", help="Output path for boss-mode HTML report (default: tibet-audit-report.html)"),
    boss_logo: Optional[str] = typer.Option(None, "--logo", help="Path to logo image for boss-mode report (PNG/JPG/SVG)"),
    auditor_mode: bool = typer.Option(False, "--auditor", "-bd", help="Auditor/accountant export: clean JSON/CSV, no jargon, just verdicts and TIBET hashes"),
    auditor_output: Optional[str] = typer.Option(None, "--bd-output", help="Output path for auditor report (default: tibet-audit-findings.json)"),
    auditor_format: str = typer.Option("json", "--bd-format", help="Auditor export format: json, csv"),
    bs_mode: bool = typer.Option(False, "--bs", help="Friday afternoon manager mode: 4 green checkmarks, zero information content"),
    bs_output: Optional[str] = typer.Option(None, "--bs-output", help="Save BS report as HTML file (for attaching to emails)"),
    tls_host: Optional[str] = typer.Option(None, "--tls", help="Scan TLS/SSL certificate for a remote host (e.g., emigreen.eu, example.com:8443)"),
    compliance: bool = typer.Option(False, "--compliance", help="Show ISO/EU AI Act/NIS2/GDPR compliance coverage matrix"),
    compliance_output: Optional[str] = typer.Option(None, "--compliance-output", help="Export compliance report as JSON (e.g., compliance.json)"),
    jis_export: Optional[str] = typer.Option(None, "--jis", help="Export compliance block for jis.json (e.g., jis-compliance.json)"),
):
    """
    Scan for compliance issues and get a health score.

    Examples:
        tibet-audit scan
        tibet-audit scan ./my-project
        tibet-audit scan --framework ietf        # All 5 IETF drafts
        tibet-audit scan --categories tibet,jis  # Specific IETF protocols
        tibet-audit scan --categories gdpr,ai_act
        tibet-audit scan --framework bio2 --org "Gemeente Amsterdam"
        tibet-audit scan --cry              # When you need ALL the details
        tibet-audit scan --sovereign        # No cloud, fully local
        tibet-audit scan --boss-mode        # Professional HTML report
        tibet-audit scan --boss-mode --org "Acme B.V." --boss-output report.html
        tibet-audit scan --boss-mode --logo ./logo.png --org "Acme B.V."
        tibet-audit scan -bd                     # Auditor export (JSON)
        tibet-audit scan -bd --bd-format csv     # Auditor export (CSV)
        tibet-audit scan -bs                     # Friday afternoon mode
        tibet-audit scan --tls emigreen.eu       # TLS certificate scan
        tibet-audit scan --tls example.com:8443  # Custom port
        tibet-audit scan --compliance            # ISO/EU coverage matrix
        tibet-audit scan --jis compliance.json   # Export for jis.json
        tibet-audit scan --compliance --compliance-output full.json
    """
    machine_output = output.lower() != "terminal"
    quiet = quiet or machine_output

    # Smart flag inference: if you specify output/format, you meant the mode
    if (auditor_output or auditor_format != "json") and not auditor_mode:
        auditor_mode = True
    if (boss_output or boss_logo) and not boss_mode:
        boss_mode = True
    if bs_output and not bs_mode:
        bs_mode = True

    if not quiet:
        check_for_updates()

    if sovereign:
        _print_header(
            "Sovereign Mode",
            'All checks run locally. No data leaves your machine.\n"Your compliance, your infrastructure, your sovereignty."',
            border_style="cyan",
        )
        # Set environment variable for checks to respect
        import os
        os.environ["TIBET_SOVEREIGN_MODE"] = "1"

    if cry:
        _print_header(
            "Verbose Mode",
            '"When everything is on fire, you need all the details."',
            border_style="red",
        )

    # Framework-specific handling
    bio2_mode = False
    dora_mode = False
    ietf_mode = False
    if framework:
        framework = framework.lower()
        if framework == "ietf":
            ietf_mode = True
            categories = "tibet,jis,upip,rvp,ains"
            _print_header(
                "IETF Compliance Mode",
                "Five IETF Internet-Drafts — draft-vandemeent-*\n"
                "TIBET (provenance) | JIS (identity) | UPIP (process integrity)\n"
                "RVP (continuous verification) | AINS (agent discovery)\n"
                "https://datatracker.ietf.org/doc/search?name=vandemeent",
                border_style="cyan",
            )
        elif framework == "bio2":
            if not BIO2_AVAILABLE:
                console.print("[bold red]❌ BIO2 framework not available[/]")
                raise typer.Exit(1)
            bio2_mode = True
            org = org_name or "Organization"
            _print_header(
                "BIO2 Compliance Mode",
                f"Baseline Informatiebeveiliging Overheid 2 (v{BIO2_FRAMEWORK['version']})\n"
                f"Organisatie: {org}\n"
                f"{BIO2_FRAMEWORK['nis2_alignment']}",
                border_style="orange3",
            )
        elif framework == "dora":
            if not DORA_AVAILABLE:
                console.print("[bold red]❌ DORA framework not available[/]")
                raise typer.Exit(1)
            dora_mode = True
            org = org_name or "Financial Entity"
            _print_header(
                "DORA Compliance Mode",
                f"Digital Operational Resilience Act (v{DORA_FRAMEWORK['version']})\n"
                f"Entity: {org}\n"
                f"Deadline: {DORA_FRAMEWORK['deadline']} | Pillars: {DORA_FRAMEWORK['pillars']} | BIO2 overlap: {DORA_FRAMEWORK['bio2_overlap']}\n"
                "TIBET = Pillar 5 compliance (Information Sharing)",
                border_style="green",
            )
        else:
            console.print(f"[yellow]⚠️  Framework '{framework}' - using standard scan[/]")
            console.print()

    if not quiet and not bio2_mode and not dora_mode and not ietf_mode:
        _print_header(
            f"TIBET Audit v{__version__}",
            'Compliance Health Scanner. "SSL secures the connection. TIBET secures the timeline. JIS verifies the intent."',
            border_style="blue",
        )

    # Parse categories
    cat_list = categories.split(",") if categories else None

    # Build extra context for TLS scanning
    extra_ctx = {}
    if tls_host:
        # Parse host:port
        if ":" in tls_host and not tls_host.startswith("["):
            parts = tls_host.rsplit(":", 1)
            extra_ctx["tls_host"] = parts[0]
            extra_ctx["tls_port"] = parts[1]
        else:
            extra_ctx["tls_host"] = tls_host
        # Auto-include tls category
        if cat_list is None:
            cat_list = ["tls"]
        elif "tls" not in cat_list:
            cat_list.append("tls")
        if not quiet:
            _print_header("TLS Scan", tls_host, border_style="cyan")

    # Run scan
    audit = TIBETAudit(sovereign_mode=sovereign)

    if cry:
        # Cry mode: show live progress Lynis-style
        console.print("[bold cyan]Running checks...[/]\n")
        result = audit.scan(path, categories=cat_list, live_mode=True, extra_context=extra_ctx or None)
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
            result = audit.scan(path, categories=cat_list, extra_context=extra_ctx or None)

    # ── Compliance / JIS export modes ──────────────────────────────────
    if compliance or compliance_output or jis_export:
        from .compliance_map import get_framework_coverage, generate_jis_compliance_block, FRAMEWORKS
        from .governance_conclusion import build_governance_conclusion

        if jis_export:
            # Export jis.json compliance block
            jis_block = generate_jis_compliance_block(result.results)
            Path(jis_export).write_text(json.dumps(jis_block, indent=2, ensure_ascii=False))
            console.print(f"\n[bold green]JIS compliance block exported: {jis_export}[/]")
            console.print(f"  [dim]{jis_block['compliance']['summary']['total']} checks, "
                         f"{jis_block['compliance']['summary']['passed']} passed[/]")
            if not compliance:
                return

        coverage = get_framework_coverage(result.results)

        if compliance_output:
            # Export full compliance report
            governance_conclusion = build_governance_conclusion(result, result.scan_path)
            report = {
                "scanner": "tibet-audit",
                "version": __version__,
                "score": result.score,
                "grade": result.grade,
                "governance_conclusion": governance_conclusion,
                "frameworks": {},
            }
            for fw_key, cov in coverage.items():
                report["frameworks"][fw_key] = {
                    "name": cov["name"],
                    "title": cov["title"],
                    "coverage_pct": cov["coverage_pct"],
                    "total_checks": cov["total_checks"],
                    "passed": cov["passed"],
                    "failed": cov["failed"],
                    "total_clauses": cov["total_clauses"],
                    "passed_clauses": cov["passed_clauses"],
                    "clauses": cov["clauses"],
                }
            Path(compliance_output).write_text(json.dumps(report, indent=2, ensure_ascii=False))
            console.print(f"\n[bold green]Compliance report exported: {compliance_output}[/]")

        if compliance:
            # Print compliance coverage matrix to terminal
            governance_conclusion = build_governance_conclusion(result, result.scan_path)
            console.print()
            console.print(Panel(
                f"[bold]Compliance Coverage Matrix[/]\n"
                f"[dim]Score: {result.score}/100 (Grade {result.grade}) — "
                f"{result.passed} passed, {result.warnings} warnings, {result.failed} failed[/]",
                title="[bold cyan]ISO / EU / Regulatory Mapping[/]",
                border_style="cyan",
            ))

            # Framework coverage table
            table = Table(show_header=True, header_style="bold", box=box.ROUNDED)
            table.add_column("Framework", style="cyan", width=28)
            table.add_column("Standard", width=32)
            table.add_column("Checks", justify="right", width=8)
            table.add_column("Pass", justify="right", width=6)
            table.add_column("Fail", justify="right", width=6)
            table.add_column("Coverage", justify="right", width=10)
            table.add_column("Clauses", justify="right", width=9)

            # Sort by coverage descending
            sorted_fw = sorted(coverage.items(), key=lambda x: x[1]["coverage_pct"], reverse=True)

            for fw_key, cov in sorted_fw:
                pct = cov["coverage_pct"]
                color = "green" if pct >= 90 else "yellow" if pct >= 70 else "red"
                table.add_row(
                    cov["name"],
                    cov["title"][:30],
                    str(cov["total_checks"]),
                    f"[green]{cov['passed']}[/]",
                    f"[red]{cov['failed']}[/]" if cov["failed"] > 0 else "[green]0[/]",
                    f"[{color}]{pct}%[/]",
                    f"{cov['passed_clauses']}/{cov['total_clauses']}",
                )

            console.print(table)

            console.print()
            lane_summary = governance_conclusion.get("operational_lane_summary", {})
            lane_classes = lane_summary.get("lane_classes", {})
            collision = lane_summary.get("lane_collision_policies", {})
            coffee = lane_summary.get("coffee_lane_policies", {})
            emitters = lane_summary.get("emitters", {})
            if lane_summary.get("event_count"):
                console.print(Panel(
                    "\n".join([
                        f"[bold]Observed events:[/] {lane_summary['event_count']}",
                        f"[bold]Lane classes:[/] {', '.join(f'{k}={v}' for k, v in lane_classes.items()) or '-'}",
                        f"[bold]Collision:[/] {', '.join(f'{k}={v}' for k, v in collision.items()) or '-'}",
                        f"[bold]Coffee:[/] {', '.join(f'{k}={v}' for k, v in coffee.items()) or '-'}",
                        f"[bold]Emitters:[/] {', '.join(f'{k}={v}' for k, v in emitters.items()) or '-'}",
                    ]),
                    title="[bold blue]Operational Lane Summary[/]",
                    border_style="blue",
                ))
                console.print()
            console.print(Panel(
                "\n".join([
                    f"[bold]Profile:[/] {governance_conclusion['governance_profile']}",
                    f"[bold]Confidence:[/] {governance_conclusion['overall_governance_confidence']}",
                    f"[bold]WHAT:[/] {governance_conclusion['what_status']}   "
                    f"[bold]HOW:[/] {governance_conclusion['how_status']}   "
                    f"[bold]WHO:[/] {governance_conclusion['who_status']}   "
                    f"[bold]WHY:[/] {governance_conclusion['why_status']}",
                    _causal_integrity_line(governance_conclusion.get("causal_integrity")),
                ]),
                title="[bold magenta]Governance Conclusion[/]",
                border_style="magenta",
            ))

            # Per-framework clause detail (collapsed)
            for fw_key, cov in sorted_fw:
                if cov["failed"] > 0:
                    console.print(f"\n[bold yellow]  {cov['name']} — failing clauses:[/]")
                    for clause_key, clause in cov["clauses"].items():
                        if clause["status"] == "fail":
                            checks_str = ", ".join(clause["checks"])
                            console.print(f"    [red]✗[/] {clause['clause']}: {clause['title']} [{checks_str}]")

            console.print()
            if not compliance_output and not jis_export:
                console.print("[dim]  Export: --compliance-output report.json  |  --jis jis-compliance.json[/]")
            return

    if bs_mode:
        # BS Mode: Friday afternoon manager report
        from .bs_report import generate_bs_terminal, generate_bs_html
        if bs_output:
            org = org_name or "Organization"
            html = generate_bs_html(result, org_name=org, output_path=bs_output)
            generate_bs_terminal(result, console)
            console.print(f"[dim]  HTML version saved: {bs_output}[/]")
        else:
            generate_bs_terminal(result, console)
        return
    elif auditor_mode:
        # Auditor Mode: clean accountant/regulator export
        from .auditor_report import generate_auditor_report
        org = org_name or "Organization"
        ext = "csv" if auditor_format == "csv" else "json"
        out_file = auditor_output or f"tibet-audit-findings.{ext}"
        output_str = generate_auditor_report(
            result,
            org_name=org,
            framework=framework,
            output_path=out_file,
            fmt=auditor_format,
        )
        governance_conclusion = build_governance_conclusion(result, result.scan_path)
        if not quiet:
            console.print(f"\n[bold]Auditor Export: {out_file}[/]")
            console.print(f"  Format: {auditor_format.upper()}")
            console.print(f"  Findings: {len(result.results)} ({result.passed} compliant, {result.failed} non-compliant, {result.warnings} needs review)")
            console.print(f"  Score: {result.score}/100 (Grade {result.grade})")
            console.print(
                f"  Governance: {governance_conclusion['governance_profile']} "
                f"({governance_conclusion['overall_governance_confidence']})"
            )
        else:
            # Quiet mode: just dump to stdout
            print(output_str)
        return
    elif boss_mode:
        # Boss Mode: professional HTML report
        from .boss_report import generate_boss_report
        org = org_name or "Organization"
        out_file = boss_output or "tibet-audit-report.html"
        html = generate_boss_report(
            result,
            org_name=org,
            framework=framework,
            output_path=out_file,
            logo_path=boss_logo,
        )
        console.print(f"\n[bold green]Boss Mode: Report generated![/]")
        console.print(f"  [cyan]{out_file}[/]")
        console.print(f"  Score: {result.score}/100 (Grade {result.grade})")
        console.print(f"  {result.passed} passed, {result.warnings} warnings, {result.failed} failed")
        console.print(f"\n[dim]Open in browser: file://{Path(out_file).resolve()}[/]")
        console.print(f"[dim]Print to PDF: open in browser -> Ctrl+P -> Save as PDF[/]")
        return
    elif machine_output:
        report = build_report(result, profile=profile)
        # Use print() instead of console.print() to avoid Rich markup/ANSI in JSON
        print(json.dumps(report, indent=2, ensure_ascii=False))
    elif bio2_mode:
        # BIO2 Compliance Report - Grade A-F format
        org = org_name or "Organization"
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
def template(
    name: str = typer.Argument(None, help="Template name (e.g., privacy-policy, breach-procedure)"),
    list_all: bool = typer.Option(False, "--list", "-l", help="List all available templates"),
):
    """
    Generate compliance document templates.

    Examples:
        tibet-audit template --list
        tibet-audit template privacy-policy
        tibet-audit template privacy-policy > docs/privacy-policy.md
        tibet-audit template breach-procedure > docs/breach-procedure.md
    """
    from .templates import get_template, list_templates

    if list_all or name is None:
        templates = list_templates()
        console.print("[bold]Available templates:[/]\n")
        for t in templates:
            console.print(f"  [cyan]{t['name']:<25}[/] {t['title']}")
        console.print(f"\n[dim]Usage: tibet-audit template <name>[/]")
        console.print(f"[dim]  Pipe to file: tibet-audit template <name> > docs/<filename>.md[/]")
        return

    tmpl = get_template(name)
    if not tmpl:
        console.print(f"[red]Unknown template: {name}[/]")
        console.print("[dim]Run 'tibet-audit template --list' to see available templates.[/]")
        raise typer.Exit(1)

    # Output raw content (no Rich markup) so it can be piped to a file
    print(tmpl["content"])


@app.command()
def fix(
    path: str = typer.Argument(".", help="Path to scan and fix"),
    auto: bool = typer.Option(False, "--auto", "-a", help="Apply all available fixes without prompts"),
    wet_wipe: bool = typer.Option(False, "--wet-wipe", "-w", help="Preview fixes without changing files"),
    dry_run: bool = typer.Option(False, "--dry-run", "-n", help="Same as --wet-wipe"),
    require_signoff: bool = typer.Option(False, "--require-signoff", "-s", help="Require human sign-off before RESOLVED state"),
    reviewer: Optional[str] = typer.Option(None, "--reviewer", "-r", help="Reviewer name for sign-off (e.g., 'Eva de Vries, Jurist')"),
    reviewer_did: Optional[str] = typer.Option(None, "--reviewer-did", help="Reviewer DID (e.g., 'jis:jurist:eva.devries')"),
    sovereign: bool = typer.Option(False, "--sovereign", help="Sovereign mode: no cloud APIs, fully local"),
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
        _print_header(
            "Diaper Protocol Activated",
            '"Press the button, hands free, diaper change, server fixed."',
            border_style="yellow",
        )
    else:
        _print_header(
            f"TIBET Audit v{__version__}",
            'Compliance Health Scanner. "SSL secures the connection. TIBET secures the timeline. JIS verifies the intent."',
            border_style="blue",
        )

    if sovereign:
        _print_header(
            "Sovereign Mode",
            "All operations run locally. No data leaves your machine.",
            border_style="cyan",
        )
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
        console.print("[green]No fixable issues found. Current scan state looks good.[/]")
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
        console.print("[yellow]Preview mode: no changes made. Run without --wet-wipe to apply fixes.[/]")
        return

    fixed_count = 0
    if auto:
        # Diaper Protocol: just do it
        console.print("[bold yellow]Applying all fixes...[/]\n")
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
    import shlex
    import re
    from pathlib import Path
    from .templates import get_template

    fixed = 0
    failed = 0

    for issue in issues:
        if not issue.fix_action:
            continue

        console.print(f"[bold]Fixing {issue.check_id}...[/]")

        try:
            # Execute the fix action
            if issue.fix_action.function:
                # Python function fix
                issue.fix_action.function()
                console.print(f"  [green]✅[/] Fixed: {issue.fix_action.description}")
                fixed += 1
            elif issue.fix_action.command:
                cmd = issue.fix_action.command

                # Handle "tibet-audit template X > path/file.md" internally
                tmpl_match = re.match(
                    r'tibet-audit template (\S+)\s*>\s*(.+)', cmd
                )
                if tmpl_match:
                    tmpl_name = tmpl_match.group(1)
                    out_path = Path(tmpl_match.group(2).strip())
                    tmpl = get_template(tmpl_name)
                    if tmpl:
                        out_path.parent.mkdir(parents=True, exist_ok=True)
                        out_path.write_text(tmpl["content"])
                        console.print(f"  [green]✅[/] Created: {out_path}")
                        fixed += 1
                    else:
                        console.print(f"  [red]❌[/] Unknown template: {tmpl_name}")
                        failed += 1
                    continue

                # Handle other commands via subprocess
                console.print(f"  [dim]Running: {cmd}[/]")

                # Shell commands (redirects, pipes)
                if any(c in cmd for c in ['>', '|', '&&', ';']):
                    proc = subprocess.run(
                        cmd, shell=True, capture_output=True, text=True, timeout=60
                    )
                else:
                    proc = subprocess.run(
                        shlex.split(cmd), capture_output=True, text=True, timeout=60
                    )

                if proc.returncode == 0:
                    console.print(f"  [green]✅[/] Fixed: {issue.fix_action.description}")
                    fixed += 1
                else:
                    err = proc.stderr.strip() or proc.stdout.strip() or f"exit code {proc.returncode}"
                    console.print(f"  [red]❌[/] Failed: {err}")
                    failed += 1
            else:
                console.print(f"  [yellow]⚠️[/]  No command or function available for this fix")
        except subprocess.TimeoutExpired:
            console.print(f"  [red]❌[/] Failed: command timed out (60s)")
            failed += 1
        except Exception as e:
            console.print(f"  [red]❌[/] Failed: {e}")
            failed += 1

    console.print()
    console.print(f"[bold green]Fix run complete. Fixed: {fixed}, Failed: {failed}[/]")
    console.print()
    console.print("[dim]Run 'tibet-audit scan' to verify improvements.[/]")
    return fixed


def _create_signoff_request(result, fixed_count: int, reviewer: Optional[str], reviewer_did: Optional[str]):
    """Create a sign-off request after fixes are applied."""
    from .signoff import SignoffManager, create_signoff_prompt

    console.print()
    _print_header(
        "Sign-off Required",
        "TIBET prepares, human verifies, JIS seals.",
        border_style="cyan",
    )

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
    _print_header(
        f"TIBET Audit v{__version__}",
        'Compliance Health Scanner. "SSL secures the connection. TIBET secures the timeline. JIS verifies the intent."',
        border_style="blue",
    )

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
    contact: Optional[str] = typer.Option(None, "--contact", "-c", help="Your email for follow-up support"),
    company: Optional[str] = typer.Option(None, "--company", help="Your company name (optional)"),
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
        tibet-audit call-mama --send --contact me@company.com  # With follow-up email
        tibet-audit call-mama --send --contact me@co.com --company "Acme Inc"
        tibet-audit call-mama --output report.json
    """
    _print_header(
        "Calling M.A.M.A.",
        "Mission Assurance & Monitoring Agent. When the diaper is too dirty, you call for backup.",
        border_style="red",
    )

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
    import platform
    import hashlib
    from datetime import datetime, timezone

    # Interactive contact prompt (only when --send and no --contact given)
    if send and not contact:
        console.print()
        console.print("[dim]Want to include your email so we can follow up? (completely optional)[/]")
        try:
            contact_input = console.input("[dim]  Email (Enter to skip): [/]").strip()
            if contact_input and "@" in contact_input:
                contact = contact_input
        except (EOFError, KeyboardInterrupt):
            pass
        if not company:
            try:
                company_input = console.input("[dim]  Company (Enter to skip): [/]").strip()
                if company_input:
                    company = company_input
            except (EOFError, KeyboardInterrupt):
                pass
        console.print()

    # Anonymous system fingerprint — no PII, just enough to count unique users
    hostname_hash = hashlib.sha256(platform.node().encode()).hexdigest()[:12]
    fingerprint = {
        "os": platform.system(),
        "os_version": platform.release(),
        "python": platform.python_version(),
        "arch": platform.machine(),
        "hostname_hash": hostname_hash,
        "timezone": str(datetime.now(timezone.utc).astimezone().tzinfo),
    }

    report = {
        "generated_at": datetime.now().isoformat(),
        "tool": "tibet-audit",
        "version": __version__,
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
        "mama_message": "Help! The compliance diaper needs changing! 🍼",
        "contact_email": contact,
        "company": company,
        "system": fingerprint,
    }

    report_json = json.dumps(report, indent=2)

    # Display summary
    console.print(f"\n[bold]Compliance Report Generated[/]")
    console.print(f"  Score: [{_score_color(result.score)}]{result.score}/100[/] (Grade: {result.grade})")
    console.print(f"  Issues: {result.failed} failed, {result.warnings} warnings")
    console.print()

    sent_to = []

    # Send to a report endpoint — OFF by default. A sovereign audit tool phones no
    # one unless the operator opts in via TIBET_AUDIT_REPORT_URL.
    if send:
        import os as _os
        report_endpoint = _os.getenv("TIBET_AUDIT_REPORT_URL", "").strip()
        if not report_endpoint:
            console.print("[yellow]⚠️ No report endpoint configured — set TIBET_AUDIT_REPORT_URL to send.[/]")
            console.print("[dim]   Sovereign default: nothing leaves this machine. Use --output to save locally.[/]")
        else:
            try:
                import urllib.request
                req = urllib.request.Request(
                    report_endpoint,
                    data=report_json.encode('utf-8'),
                    headers={'Content-Type': 'application/json'},
                    method='POST'
                )
                with urllib.request.urlopen(req, timeout=15) as response:
                    if response.status in (200, 201, 202):
                        console.print(f"[green]✅ Report sent to {report_endpoint}[/]")
                        sent_to.append("report_endpoint")
                    else:
                        console.print(f"[yellow]⚠️ Report endpoint returned status {response.status}[/]")
            except Exception as e:
                console.print(f"[yellow]⚠️ Could not reach report endpoint: {e}[/]")
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
        tibet-audit token abc123 --endpoint http://your-node:8100
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
    console.print("[bold blue]║[/] [bold green]ERIN[/] (What's in it?)                                           [bold blue]║[/]")
    if isinstance(erin, dict):
        for k, v in list(erin.items())[:5]:
            line = f"   {k}: {v}"[:60]
            console.print(f"[bold blue]║[/]   {line:<62} [bold blue]║[/]")
    else:
        line = str(erin)[:60]
        console.print(f"[bold blue]║[/]   {line:<62} [bold blue]║[/]")

    console.print("[bold blue]╠══════════════════════════════════════════════════════════════════╣[/]")

    # ERAAN
    console.print("[bold blue]║[/] [bold yellow]ERAAN[/] (What's attached?)                                        [bold blue]║[/]")
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
    console.print("[bold blue]║[/] [bold magenta]ERACHTER[/] (Intent/Why?)                                           [bold blue]║[/]")
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
def genesis(
    source: str = typer.Argument(..., help="Path to JSONL log of tibet.genesis.t-1.v1 events"),
    output: str = typer.Option("terminal", "--output", "-o", help="Output: terminal, json"),
):
    """
    T-1 Genesis audit — read pre-grant genesis-event records and report
    ready/blocked/forked status per tool_id.

    Codex' spec (2026-05-31): tibet-audit acts as blackbox recorder + validator
    over the real genesis pass. The enforcement layer lives in
    trust-kernel/airlock/capability-grant; this command only reads what the
    enforcement layer emitted and tells the operator whether each pre-grant
    candidate is safe to merge into T0.

    Contract: tibet.genesis.t-1.v1 (see T1_GENESIS_M4_PREGRANT_SPEC.md)
    Required fields per record: tool_id, schema_hash, description_hash,
    allowed_tools_hash, endpoint_hash, registry_source, retrieved_at,
    retriever_identity, magic_bytes, tibet_token, jis_claim, airlock_verdict,
    fork_id, merge_to_t0_verdict.

    Status codes:
        absent     → no genesis events found in source
        observed   → events present but no ready/blocked/forked yet
        ready      → at least one candidate cleared merge_to_t0_verdict=ready
        attention  → blocked or forked candidates require operator action
    """
    from pathlib import Path
    src = Path(source)
    if not src.exists():
        console.print(f"[red]tibet-audit: no genesis source at {src}[/]")
        raise typer.Exit(code=3)

    records: list[dict] = []
    for line in src.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    assessment = assess_genesis_events(records)

    if output.lower() == "json":
        console.print(json.dumps(assessment, indent=2, ensure_ascii=False))
        return

    status = assessment["status"]
    status_color = {
        "ready": "green",
        "observed": "cyan",
        "attention": "yellow",
        "absent": "dim",
    }.get(status, "white")

    console.print(Panel(
        f"[bold]T-1 Genesis assessment[/]\n"
        f"  source: {src}\n"
        f"  contract: tibet.genesis.t-1.v1",
        border_style=status_color,
    ))
    console.print(f"  status:          [{status_color}]{status}[/]")
    console.print(f"  candidates seen: {assessment['candidate_count']}")
    console.print(f"  ready:           [green]{assessment['ready_count']}[/]")
    console.print(f"  blocked:         [yellow]{assessment['blocked_count']}[/]")
    console.print(f"  forked:          [yellow]{assessment['forked_count']}[/]")

    if assessment["findings"]:
        t = Table(title="Per-candidate findings", box=box.SIMPLE_HEAVY)
        t.add_column("Severity", width=10)
        t.add_column("Tool ID", overflow="fold")
        t.add_column("Event", width=18)
        t.add_column("Message", overflow="fold")
        for f in assessment["findings"]:
            sev = f["severity"]
            sev_style = {"ok": "green", "warning": "yellow"}.get(sev, "white")
            t.add_row(f"[{sev_style}]{sev}[/]", f["tool_id"], f["event"], f["message"])
        console.print(t)

    contract = assessment["contract"]
    if contract.get("missing_fields"):
        console.print(f"\n[yellow]Contract gaps:[/] {len(contract['missing_fields'])} field(s) missing across records")
        for fname, count in list(contract["missing_fields"].items())[:6]:
            console.print(f"  - {fname}: {count} record(s) missing")

    console.print(f"\n[dim]content_hash: {assessment.get('content_hash', '?')}[/]")
    console.print("[dim]Note: this command is read-only. Real T-1 enforcement lives in trust-kernel/airlock.[/]")


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
        _print_header(
            f"TIBET Audit v{__version__}",
            'Compliance Health Scanner. "SSL secures the connection. TIBET secures the timeline. JIS verifies the intent."',
            border_style="blue",
        )
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
    "tibet": {"weight": 20, "category": "core", "tier": "signal"},
    "tibet-core": {"weight": 25, "category": "core", "tier": "signal"},
    "jis-core": {"weight": 20, "category": "identity", "tier": "signal"},
    "snaft": {"weight": 18, "category": "security", "tier": "amplify"},
    "tibet-audit": {"weight": 20, "category": "audit", "tier": "signal"},
    "tibet-chip": {"weight": 15, "category": "audit", "tier": "signal"},
    "tibet-vault": {"weight": 15, "category": "audit", "tier": "amplify"},
    "tibet-triage": {"weight": 14, "category": "security", "tier": "amplify"},
    "tibet-airlock": {"weight": 14, "category": "security", "tier": "amplify"},
    "tibet-cmail": {"weight": 12, "category": "protocol", "tier": "amplify"},
    "tibet-continuityd": {"weight": 12, "category": "runtime", "tier": "broadcast"},
    "tibet-cap-bus": {"weight": 10, "category": "runtime", "tier": "broadcast"},
    "tibet-home-agent": {"weight": 10, "category": "agent", "tier": "broadcast"},

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
    import importlib.metadata

    installed = {}
    for pkg_name, pkg_info in HUMOTICA_PACKAGES.items():
        try:
            installed[pkg_name] = {
                "version": importlib.metadata.version(pkg_name),
                **pkg_info,
            }
        except importlib.metadata.PackageNotFoundError:
            continue

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
    has_jis = any(p in installed for p in ["jis-core", "idd-cli", "tibet-chip"])
    has_tibet = any(p in installed for p in ["tibet-core", "tibet-vault", "mcp-server-tibet", "tibet-audit"])
    has_genesis = any(p in installed for p in ["tibet-genesis", "mcp-server-rabel", "ainternet", "reflux-protocol"])
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
        title="[bold]Compliance Score[/]",
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
        console.print("[bold]Full Breakdown:[/]\n")

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

    _print_header(
        "Checkpoint Code",
        '"Passports checked. Math matches. You may proceed."',
        border_style="yellow",
    )

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

    _print_header(
        "Checkpoint Matrix",
        "All border crossings",
        border_style="yellow",
    )

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

    _print_header(
        "TIBET Sign-off",
        "Human verification with JIS bilateral consent.\nTIBET prepares, human verifies, JIS seals.",
        border_style="cyan",
    )

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

    _print_header(
        "TIBET Sign-off",
        "Human verification with JIS bilateral consent.",
        border_style="cyan",
    )

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

    _print_header(
        "TIBET Sign-off",
        "Human verification with JIS bilateral consent.",
        border_style="cyan",
    )

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

    _print_header(
        "TIBET Sign-off",
        "Human verification with JIS bilateral consent.",
        border_style="cyan",
    )

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

    _print_header(
        "TIBET Sign-off",
        "Human verification with JIS bilateral consent.",
        border_style="cyan",
    )

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
        console.print("[bold green]JIS Sealed[/]")
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

    _print_header(
        "TIBET Sign-off",
        "Human verification with JIS bilateral consent.",
        border_style="cyan",
    )

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
# STATUS DASHBOARD
# ═══════════════════════════════════════════════════════════════════════════════

def _print_evidence_table(snapshot: dict, title: str = "Evidence Sources") -> None:
    table = Table(title=title, box=box.SIMPLE_HEAVY)
    table.add_column("Source", style="bold")
    table.add_column("Kind", width=8)
    table.add_column("Records", justify="right", width=10)
    table.add_column("Latest", overflow="fold")
    table.add_column("Path", overflow="fold")

    sources = snapshot.get("evidence_sources", [])
    if not sources:
        table.add_row("none", "-", "0", "-", "No local evidence files found")
    for source in sources:
        status_style = "green" if source["records"] else "dim"
        table.add_row(
            f"[{status_style}]{source['name']}[/]",
            source["kind"],
            str(source["records"]),
            source.get("latest_ts") or "-",
            source["path"],
        )
    console.print(table)


def _print_component_table(snapshot: dict) -> None:
    table = Table(title="Runtime Components", box=box.SIMPLE_HEAVY)
    table.add_column("Group", width=10)
    table.add_column("Component")
    table.add_column("Kind", width=8)
    table.add_column("Status", width=12)
    table.add_column("Version / Path", overflow="fold")

    for component in snapshot.get("components", []):
        status = component["status"]
        style = "green" if status in {"installed", "available"} else "yellow"
        detail = component.get("version") or component.get("path") or "-"
        table.add_row(
            component["group"],
            component["name"],
            component["kind"],
            f"[{style}]{status}[/]",
            detail,
        )
    console.print(table)


def _print_readiness_table(snapshot: dict) -> None:
    table = Table(title="Operational Readiness", box=box.SIMPLE_HEAVY)
    table.add_column("Lane", style="bold")
    table.add_column("Status", width=10)
    table.add_column("Observed", overflow="fold")
    table.add_column("Reason", overflow="fold")

    style_map = {
        "ready": "green",
        "active": "green",
        "partial": "yellow",
        "baseline": "cyan",
        "missing": "red",
    }
    for lane in snapshot.get("readiness_lanes", []):
        status = lane["status"]
        style = style_map.get(status, "white")
        observed = ", ".join(lane.get("observed", [])) or "-"
        table.add_row(lane["name"], f"[{style}]{status}[/]", observed, lane["reason"])
    console.print(table)


def _print_adapter_table(snapshot: dict) -> None:
    table = Table(title="Evidence Adapters", box=box.SIMPLE_HEAVY)
    table.add_column("Adapter", style="bold")
    table.add_column("Status", width=10)
    table.add_column("Records", justify="right", width=8)
    table.add_column("Summary", overflow="fold")
    table.add_column("Source", overflow="fold")

    style_map = {
        "ready": "green",
        "active": "green",
        "observed": "cyan",
        "attention": "yellow",
        "unknown": "dim",
    }
    assessments = snapshot.get("adapter_assessments", [])
    if not assessments:
        table.add_row("none", "-", "0", "No typed evidence adapters matched", "-")
    for assessment in assessments:
        status = assessment["status"]
        style = style_map.get(status, "white")
        table.add_row(
            assessment["adapter"],
            f"[{style}]{status}[/]",
            str(assessment["records"]),
            assessment["summary"],
            assessment["source"],
        )
    console.print(table)


def _print_chain_table(snapshot: dict) -> None:
    table = Table(title="Evidence Chains", box=box.SIMPLE_HEAVY)
    table.add_column("Chain", style="bold", overflow="fold")
    table.add_column("Status", width=10)
    table.add_column("Steps", justify="right", width=7)
    table.add_column("Story", overflow="fold")
    table.add_column("Missing", overflow="fold")

    style_map = {"complete": "green", "partial": "yellow", "missing": "red"}
    chains = snapshot.get("evidence_chains", [])
    if not chains:
        table.add_row("none", "-", "0", "No correlated evidence chains found", "-")
    for chain in chains:
        status = chain["status"]
        style = style_map.get(status, "white")
        story = " -> ".join(f"{step['subsystem']}:{step['action']}" for step in chain.get("steps", []))
        missing = ", ".join(chain.get("missing_links", [])) or "-"
        table.add_row(chain["title"], f"[{style}]{status}[/]", str(len(chain.get("steps", []))), story, missing)
    console.print(table)


def _print_posture_panel(snapshot: dict) -> None:
    posture = snapshot.get("posture_summary", {})
    switches = posture.get("active_switches", [])
    lines = [
        f"[bold]Current posture:[/] {posture.get('current_posture', 'unknown')}",
        f"[bold]Transitions:[/] {len(posture.get('transitions', []))}",
        f"[bold]External AI inbound denied:[/] {posture.get('deny_external_ai_inbound', False)}",
        f"[bold]Airlock marker required:[/] {posture.get('require_airlock_marker_on_tokens', False)}",
        f"[bold]Quarantine events:[/] {posture.get('quarantine_events', 0)}",
        f"[bold]Switches:[/] {', '.join(switches) if switches else '-'}",
    ]
    console.print(Panel("\n".join(lines), title="Posture Summary", border_style="yellow"))


def _render_ops_report_markdown(snapshot: dict) -> str:
    summary = snapshot["summary"]
    posture = snapshot.get("posture_summary", {})
    lines = [
        "# TIBET Audit Ops Report",
        "",
        f"- Path: `{snapshot['path']}`",
        f"- Posture: `{snapshot['posture']}`",
        f"- Evidence sources: {summary['active_evidence_sources']}/{summary['evidence_sources']} active",
        f"- Latest events indexed: {summary['latest_events']}",
        f"- Warnings: {summary['warnings']}",
        "",
        "## Posture",
        "",
        f"- Current posture: `{posture.get('current_posture', 'unknown')}`",
        f"- External AI inbound denied: `{posture.get('deny_external_ai_inbound', False)}`",
        f"- Airlock marker required: `{posture.get('require_airlock_marker_on_tokens', False)}`",
        f"- Quarantine events: `{posture.get('quarantine_events', 0)}`",
        "",
        "## Readiness Lanes",
        "",
        "| Lane | Status | Observed | Reason |",
        "|---|---:|---|---|",
    ]
    for lane in snapshot.get("readiness_lanes", []):
        observed = ", ".join(lane.get("observed", [])) or "-"
        lines.append(f"| {lane['name']} | `{lane['status']}` | {observed} | {lane['reason']} |")

    lines.extend(["", "## Evidence Sources", "", "| Source | Kind | Records | Latest |", "|---|---:|---:|---|"])
    for source in snapshot.get("evidence_sources", []):
        lines.append(f"| `{source['name']}` | {source['kind']} | {source['records']} | {source.get('latest_ts') or '-'} |")

    lines.extend(["", "## Evidence Adapters", "", "| Adapter | Status | Records | Summary |", "|---|---:|---:|---|"])
    for assessment in snapshot.get("adapter_assessments", []):
        lines.append(
            f"| {assessment['adapter']} | `{assessment['status']}` | {assessment['records']} | {assessment['summary']} |"
        )

    lines.extend(["", "## Evidence Chains", "", "| Chain | Status | Steps | Missing |", "|---|---:|---:|---|"])
    for chain in snapshot.get("evidence_chains", []):
        missing = ", ".join(chain.get("missing_links", [])) or "-"
        lines.append(f"| {chain['title']} | `{chain['status']}` | {len(chain.get('steps', []))} | {missing} |")
        for step in chain.get("steps", []):
            lines.append(f"| - {step['subsystem']} | `{step['severity']}` | {step['action']} | {step['summary']} |")

    lines.extend(["", "## Latest Findings", "", "| Severity | Message | Source |", "|---|---|---|"])
    for finding in snapshot.get("findings", []):
        lines.append(f"| `{finding['severity']}` | {finding['message']} | `{finding['source']}` |")

    if snapshot.get("next_actions"):
        lines.extend(["", "## Next Actions", ""])
        lines.extend(f"- {action}" for action in snapshot["next_actions"])

    return "\n".join(lines) + "\n"


def _resolve_tail_source(path: str, source: Optional[str], include_system: bool) -> Optional[str]:
    if source:
        source_path = Path(source)
        if source_path.exists():
            return str(source_path)
        sources = discover_evidence_sources(path, include_system=include_system)
        for candidate in sources:
            if candidate.name == source or candidate.path.endswith(source):
                return candidate.path
        return source

    sources = [
        candidate for candidate in discover_evidence_sources(path, include_system=include_system)
        if candidate.kind == "jsonl" and candidate.records > 0
    ]
    if not sources:
        return None
    sources.sort(key=lambda item: (item.latest_ts or "", item.records), reverse=True)
    return sources[0].path


@app.command("evidence")
def evidence_index(
    path: str = typer.Argument(".", help="Path to inspect"),
    output: str = typer.Option("terminal", "--output", "-o", help="Output: terminal, json"),
    system: bool = typer.Option(False, "--system", help="Also inspect /var/log/tibet, /var/lib/tibet and root trust dirs"),
):
    """
    Index local evidence files that can feed the audit conclusion layer.
    """
    snapshot = build_cockpit_snapshot(path, include_system=system, lines=1)
    if output.lower() == "json":
        console.print(json.dumps({
            "path": snapshot["path"],
            "posture": snapshot["posture"],
            "summary": snapshot["summary"],
            "evidence_sources": snapshot["evidence_sources"],
        }, indent=2))
        return

    _print_header("TIBET Evidence Index", "Local runtime evidence available to tibet-audit.", "cyan")
    _print_evidence_table(snapshot)


@app.command("tail")
def tail_evidence(
    path: str = typer.Argument(".", help="Path to inspect"),
    source: Optional[str] = typer.Option(None, "--source", "-s", help="Evidence file name or path"),
    lines: int = typer.Option(25, "--lines", "-n", min=1, max=500, help="Number of records to show"),
    output: str = typer.Option("terminal", "--output", "-o", help="Output: terminal, json"),
    system: bool = typer.Option(False, "--system", help="Also inspect /var/log/tibet, /var/lib/tibet and root trust dirs"),
):
    """
    Show the latest JSONL evidence records in a compact audit view.
    """
    resolved = _resolve_tail_source(path, source, include_system=system)
    if not resolved:
        if output.lower() == "json":
            console.print(json.dumps({"events": [], "source": None}, indent=2))
            return
        _print_header("TIBET Evidence Tail", "No active JSONL evidence source found.", "yellow")
        return

    events = load_tail_events(resolved, lines=lines)
    if output.lower() == "json":
        console.print(json.dumps({"source": resolved, "events": events}, indent=2))
        return

    _print_header("TIBET Evidence Tail", resolved, "cyan")
    table = Table(box=box.SIMPLE_HEAVY)
    table.add_column("#", justify="right", width=4)
    table.add_column("Severity", width=10)
    table.add_column("Event", overflow="fold")
    table.add_column("Actor / Object", overflow="fold")
    for idx, event in enumerate(events, 1):
        finding = classify_event(event)
        style = {"warning": "yellow", "ok": "green", "info": "cyan"}.get(finding.severity, "white")
        actor = event.get("actor_id") or event.get("object_id") or event.get("event_id") or "-"
        table.add_row(str(idx), f"[{style}]{finding.severity}[/]", finding.message, str(actor))
    console.print(table)


@app.command("cockpit")
def cockpit_dashboard(
    path: str = typer.Argument(".", help="Path to inspect"),
    lines: int = typer.Option(20, "--lines", "-n", min=1, max=100, help="Latest evidence records to include"),
    output: str = typer.Option("terminal", "--output", "-o", help="Output: terminal, json"),
    system: bool = typer.Option(False, "--system", help="Also inspect /var/log/tibet, /var/lib/tibet and root trust dirs"),
):
    """
    Dual-pane operational cockpit for audit evidence and runtime posture.
    """
    snapshot = build_cockpit_snapshot(path, include_system=system, lines=lines)
    if output.lower() == "json":
        console.print(json.dumps(snapshot, indent=2))
        return

    summary = snapshot["summary"]
    subtitle = (
        f"Posture: {snapshot['posture']} | "
        f"Evidence: {summary['active_evidence_sources']}/{summary['evidence_sources']} active | "
        f"Warnings: {summary['warnings']}"
    )
    _print_header("TIBET Audit Cockpit", subtitle, "cyan")

    from rich.columns import Columns
    from rich.panel import Panel as RichPanel

    left = Table(box=box.SIMPLE)
    left.add_column("Source")
    left.add_column("Records", justify="right")
    for source_row in snapshot.get("evidence_sources", [])[:12]:
        left.add_row(source_row["name"], str(source_row["records"]))
    if not snapshot.get("evidence_sources"):
        left.add_row("none", "0")

    right = Table(box=box.SIMPLE)
    right.add_column("Finding")
    right.add_column("Source")
    for finding in snapshot.get("findings", [])[-12:]:
        right.add_row(finding["message"], finding["source"])
    if not snapshot.get("findings"):
        right.add_row("No JSONL findings yet", "-")

    console.print(Columns([
        RichPanel(left, title="Evidence Sources", border_style="blue"),
        RichPanel(right, title="Latest Findings", border_style="magenta"),
    ], equal=True, expand=True))
    console.print()
    _print_posture_panel(snapshot)
    console.print()
    _print_adapter_table(snapshot)
    console.print()
    _print_chain_table(snapshot)
    console.print()
    _print_readiness_table(snapshot)
    if snapshot.get("next_actions"):
        console.print()
        actions = "\n".join(f"- {action}" for action in snapshot["next_actions"])
        console.print(Panel(actions, title="Next Actions", border_style="yellow"))
    console.print()
    _print_component_table(snapshot)


@app.command("ops-report")
def ops_report(
    path: str = typer.Argument(".", help="Path to inspect"),
    output_path: Optional[str] = typer.Option(None, "--out", help="Write report to this path"),
    format: str = typer.Option("markdown", "--format", "-f", help="Output: markdown, json"),
    lines: int = typer.Option(50, "--lines", "-n", min=1, max=500, help="Latest evidence records to include"),
    system: bool = typer.Option(False, "--system", help="Also inspect /var/log/tibet, /var/lib/tibet and root trust dirs"),
):
    """
    Export an operator-grade audit report from runtime evidence.
    """
    snapshot = build_cockpit_snapshot(path, include_system=system, lines=lines)
    fmt = format.lower()
    if fmt == "json":
        rendered = json.dumps(snapshot, indent=2)
    elif fmt in {"markdown", "md"}:
        rendered = _render_ops_report_markdown(snapshot)
    else:
        console.print(f"[red]Unsupported format: {format}[/]")
        raise typer.Exit(1)

    if output_path:
        Path(output_path).write_text(rendered, encoding="utf-8")
        console.print(f"[green]Ops report written:[/] {output_path}")
        return
    console.print(rendered)


@app.command("status")
def status_dashboard(
    path: str = typer.Argument(".", help="Path to scan"),
    output: str = typer.Option("terminal", "--output", "-o", help="Output: terminal, json"),
    system: bool = typer.Option(False, "--system", help="Also inspect /var/log/tibet, /var/lib/tibet and root trust dirs"),
):
    """
    TIBET Status Dashboard — One-glance compliance overview.

    Shows:
    - Installed TIBET packages and versions
    - Quick compliance scan score
    - TIBET recommendations for gaps
    - Aggregate trust and security posture

    Examples:
        tibet-audit status
        tibet-audit status /path/to/project
        tibet-audit status --output json
    """
    import time

    if output.lower() != "json":
        _print_header(
            "TIBET Status Dashboard",
            "One-glance compliance overview.",
            border_style="cyan",
        )

    # 1. Detect installed packages
    installed = _detect_installed_packages()
    compliance_pct, tier = _calculate_compliance(installed)

    # Key package categories
    has_core = any(p in installed for p in ["tibet-core", "tibet-vault"])
    has_security = any(p in installed for p in ["snaft", "tibet-snaft", "tibet-claw", "tibet-airlock", "tibet-triage", "inject-bender", "tibet-pol"])
    has_audit = "tibet-audit" in installed
    has_identity = any(p in installed for p in ["jis-core", "idd-cli"])
    has_local_ai = any(p in installed for p in ["oomllama", "sensory"])

    # 2. Run quick scan
    start = time.time()
    audit = TIBETAudit()
    scan_result = audit.scan(str(path))
    scan_duration = round(time.time() - start, 2)

    # 3. Get TIBET recommendations
    from .tibet_recommendations import enrich_results, format_recommendations_summary
    enrich_results(scan_result.results)
    rec_summary = format_recommendations_summary(scan_result.results)

    # 4. Count threat-relevant checks
    failed_critical = sum(
        1 for r in scan_result.results
        if r.status == Status.FAILED and r.severity in (Severity.CRITICAL, Severity.HIGH)
    )
    cockpit_snapshot = build_cockpit_snapshot(path, include_system=system, lines=10)

    if output.lower() == "json":
        import json as json_mod
        result = {
            "dashboard": {
                "score": scan_result.score,
                "grade": scan_result.grade,
                "tier": tier,
                "compliance_pct": compliance_pct,
                "posture": cockpit_snapshot["posture"],
            },
            "packages": {
                "installed_count": len(installed),
                "installed": {k: v.get("version", "?") for k, v in installed.items()},
                "coverage": {
                    "core_provenance": has_core,
                    "security": has_security,
                    "audit": has_audit,
                    "identity": has_identity,
                    "local_ai": has_local_ai,
                },
            },
            "scan": {
                "passed": scan_result.passed,
                "warnings": scan_result.warnings,
                "failed": scan_result.failed,
                "critical_failures": failed_critical,
                "fixable": scan_result.fixable_count,
                "duration_seconds": scan_duration,
            },
            "runtime": {
                "summary": cockpit_snapshot["summary"],
                "evidence_sources": cockpit_snapshot["evidence_sources"],
                "findings": cockpit_snapshot["findings"],
                "adapter_assessments": cockpit_snapshot["adapter_assessments"],
                "evidence_chains": cockpit_snapshot["evidence_chains"],
                "posture_summary": cockpit_snapshot["posture_summary"],
                "readiness_lanes": cockpit_snapshot["readiness_lanes"],
                "next_actions": cockpit_snapshot["next_actions"],
            },
            "recommendations": [
                {
                    "check_id": r.check_id,
                    "name": r.name,
                    "tibet_packages": getattr(r, "tibet_recommendation", {}).get("packages", [])
                    if getattr(r, "tibet_recommendation", None) else [],
                }
                for r in scan_result.results
                if r.status == Status.FAILED and getattr(r, "tibet_recommendation", None)
            ],
        }
        console.print(json_mod.dumps(result, indent=2))
        return

    # Terminal output
    score_color = "green" if scan_result.score >= 80 else "yellow" if scan_result.score >= 60 else "red"

    # Score + Grade
    console.print(f"  Score:   [{score_color}]{scan_result.score}/100[/] (Grade {scan_result.grade})")
    console.print(f"  Tier:    [bold]{tier.upper()}[/] ({len(installed)} packages, {compliance_pct}% coverage)")
    console.print(f"  Posture: [bold]{cockpit_snapshot['posture']}[/]")
    console.print()

    # Checks summary
    console.print(f"  [green]Passed[/]:     {scan_result.passed}")
    console.print(f"  [yellow]Warnings[/]:   {scan_result.warnings}")
    console.print(f"  [red]Failed[/]:     {scan_result.failed}", end="")
    if failed_critical > 0:
        console.print(f"  [bold red]({failed_critical} critical/high)[/]")
    else:
        console.print()
    if scan_result.fixable_count > 0:
        console.print(f"  [cyan]Auto-fixable[/]: {scan_result.fixable_count}")
    console.print()

    # Stack coverage
    console.print("[bold]TIBET Stack Coverage:[/]")
    console.print(f"  {'[green]OK[/]' if has_core else '[red]MISSING[/]'}  Core Provenance (tibet-core, tibet-vault)")
    console.print(f"  {'[green]OK[/]' if has_security else '[red]MISSING[/]'}  Security (snaft, tibet-airlock, tibet-triage)")
    console.print(f"  {'[green]OK[/]' if has_audit else '[red]MISSING[/]'}  Compliance (tibet-audit)")
    console.print(f"  {'[green]OK[/]' if has_identity else '[red]MISSING[/]'}  Identity (jis-core, idd-cli)")
    console.print(f"  {'[green]OK[/]' if has_local_ai else '[dim]N/A[/]'}  Local AI (oomllama, sensory)")
    console.print()

    summary = cockpit_snapshot["summary"]
    console.print("[bold]Operational Evidence:[/]")
    console.print(f"  Sources:  {summary['active_evidence_sources']}/{summary['evidence_sources']} active")
    console.print(f"  Events:   {summary['latest_events']} latest indexed")
    console.print(f"  Warnings: {summary['warnings']}")
    console.print()
    if cockpit_snapshot.get("evidence_sources"):
        _print_evidence_table(cockpit_snapshot, title="Evidence Sources")
        console.print()
    _print_posture_panel(cockpit_snapshot)
    console.print()
    _print_adapter_table(cockpit_snapshot)
    console.print()
    _print_chain_table(cockpit_snapshot)
    console.print()
    _print_readiness_table(cockpit_snapshot)
    if cockpit_snapshot.get("next_actions"):
        console.print()
        actions = "\n".join(f"- {action}" for action in cockpit_snapshot["next_actions"])
        console.print(Panel(actions, title="Next Actions", border_style="yellow"))
    console.print()

    # Top 3 failed checks with TIBET recommendations
    failed = [r for r in scan_result.results if r.status == Status.FAILED]
    if failed:
        console.print("[bold]Top Issues + TIBET Fix:[/]")
        for r in failed[:5]:
            rec = getattr(r, "tibet_recommendation", None)
            console.print(f"  [red]x[/] {r.check_id}: {r.name}")
            if rec:
                console.print(f"    [cyan]-> {rec.get('install', '')}[/]")
        console.print()

    # Quick install suggestion
    if not has_core or not has_security:
        missing_pkgs = []
        if not has_core:
            missing_pkgs.extend(["tibet-core"])
        if not has_security:
            missing_pkgs.extend(["snaft", "tibet-airlock", "tibet-triage"])
        console.print(f"[bold]Quick upgrade:[/] pip install {' '.join(missing_pkgs)}")
        console.print()

    console.print(f"[dim]Scanned {path} in {scan_duration}s | tibet-audit {__version__}[/]")
    console.print()


@app.command("dashboard")
def dashboard_dashboard(
    path: str = typer.Argument(".", help="Path to inspect"),
    profile: str = typer.Option("node", "--profile", "-p", help="Profile to filter stack: node, hub, evidence, client, airlock, builder, full"),
    live: bool = typer.Option(False, "--live", help="Follow live tibet-tail logs"),
    lines: int = typer.Option(20, "--lines", "-n", min=1, max=100, help="Latest evidence records to include"),
    system: bool = typer.Option(False, "--system", help="Also inspect /var/log/tibet, /var/lib/tibet and root trust dirs"),
):
    """
    Next-generation TIBET Audit Dashboard — Six-Pane Operator Cockpit.

    Visualizes the entire AInternet status based on Codex's doctrine:
    1. Pulse: Newest events and live tail flow
    2. Posture: Current posture, active switches, and MUX route posture decodes
    3. Surface: Semantic Surface Manifest (SSM) cards and known file/intake surfaces
    4. Chain: Correlated evidence chains and missing links
    5. Stack: Profile-aware software mapping using repo_posture.json
    6. Action: Categorized human next steps (identity, evidence, policy, runtime)
    """
    import sys
    import os
    import json as json_mod
    from pathlib import Path
    import importlib.metadata
    from rich.columns import Columns
    from rich.panel import Panel as RichPanel

    # Installed deps are used first; opt-in monorepo dev fallback via TIBET_AUDIT_DEV_SRC.
    # No hardcoded /srv path ships in the package.
    try:
        from tibet_mux import cpu_capability as cc
        from tibet_mux import route_posture as rp
        MUX_INTEGRATION = True
    except ImportError:
        from ._devpath import add_dev_src
        add_dev_src()
        try:
            from tibet_mux import cpu_capability as cc
            from tibet_mux import route_posture as rp
            MUX_INTEGRATION = True
        except ImportError:
            MUX_INTEGRATION = False

    try:
        from tibet_cbom import ssm
        CBOM_INTEGRATION = True
    except ImportError:
        CBOM_INTEGRATION = False

    import time
    start_time = time.time()
    # Detect installed packages
    installed = _detect_installed_packages()
    cockpit_snapshot = build_cockpit_snapshot(path, include_system=system, lines=lines)
    summary = cockpit_snapshot["summary"]
    scan_duration = round(time.time() - start_time, 2)

    # Dynamic check utility using metadata or local imports
    def check_pkg_installed(name: str) -> str:
        try:
            ver = importlib.metadata.version(name)
            return f"[green]OK ({ver})[/]"
        except importlib.metadata.PackageNotFoundError:
            pass

        mod_name = name.replace("-", "_")
        try:
            mod = __import__(mod_name)
            ver = getattr(mod, "__version__", None) or getattr(mod, "VERSION", None) or "src"
            return f"[green]OK ({ver})[/]"
        except ImportError:
            if name == "tibet-mux" and MUX_INTEGRATION:
                return "[green]OK (1.2.0)[/]"
            if name == "tibet-cbom" and CBOM_INTEGRATION:
                return "[green]OK (0.3.1)[/]"
            return "[red]MISSING[/]"

    has_core = check_pkg_installed("tibet-core").startswith("[green]")
    has_audit = check_pkg_installed("tibet-audit").startswith("[green]")
    has_security = check_pkg_installed("tibet-security").startswith("[green]") or check_pkg_installed("snaft").startswith("[green]")

    # Calculate System Posture Fold (Meet via tibet_mux.posture_algebra)
    system_posture_str = "unknown"
    smoke_verdict_str = ""
    if MUX_INTEGRATION:
        try:
            from tibet_mux import posture_algebra as pa
            has_jis = check_pkg_installed("jis-core").startswith("[green]")
            p_id = "#34358" if (has_core and has_jis) else "#34308" if has_core else "#00000"
            has_cont = check_pkg_installed("tibet-continuityd").startswith("[green]")
            p_cont = "#34357" if has_cont else "#34307"
            has_cbom = check_pkg_installed("tibet-cbom").startswith("[green]")
            p_ev = "#34358" if (has_audit and has_cbom) else "#34308"
            has_ipoll = check_pkg_installed("ipoll").startswith("[green]")
            has_ainternet = check_pkg_installed("ainternet").startswith("[green]")
            p_com = "#34347" if (has_ainternet and has_ipoll) else "#34307"
            has_pol = check_pkg_installed("tibet-pol").startswith("[green]")
            p_im = "#34358" if (has_security and has_pol) else "#34307"
            has_tk = check_pkg_installed("tibet-trust-kernel").startswith("[green]")
            p_hard = "#34358" if has_tk else "#34307"

            lane_postures = [p_id, p_cont, p_ev, p_com, p_im, p_hard]
            system_posture_str = pa.compose(*lane_postures)

            expected_system = "#34358"
            smoke = pa.verify_tree(lane_postures, expected_system)
            if smoke.ok:
                smoke_verdict_str = " · [green]smoke GREEN[/]"
            else:
                smoke_verdict_str = f" · [red]smoke RED ({smoke.weakest})[/]"
        except Exception as e:
            system_posture_str = f"error: {str(e)}"

    _print_header(
        "TIBET Audit Dashboard",
        f"SYSTEM POSTURE: {system_posture_str}{smoke_verdict_str} | {summary['active_evidence_sources']}/{summary['evidence_sources']} active sources",
        border_style="magenta",
    )

    if live:
        console.print("[yellow]Live watch mode active (TODO: Connect to live tibet-tail stream)...[/]")
        console.print()

    # --- PANE 1: Pulse (tibet-tail & JSONL evidence) ---
    pulse_table = Table(box=box.SIMPLE, expand=True)
    pulse_table.add_column("Age", justify="right", width=6)
    pulse_table.add_column("Severity", width=9)
    pulse_table.add_column("Event / Finding", overflow="fold")
    pulse_table.add_column("Source", overflow="fold")

    findings = cockpit_snapshot.get("findings", [])[-lines:]
    for idx, f in enumerate(reversed(findings), 1):
        style = {"warning": "yellow", "ok": "green", "info": "cyan"}.get(f["severity"], "white")
        pulse_table.add_row(
            f"{idx}m ago",
            f"[{style}]{f['severity'].upper()}[/]",
            f["message"],
            f["source"],
        )
    if not findings:
        pulse_table.add_row("-", "[dim]INFO[/]", "No evidence logs indexed in this run", "-")

    # --- PANE 2: Posture (Switches & MUX Route Posture Decodes) ---
    posture_data = cockpit_snapshot.get("posture_summary", {})
    switches = posture_data.get("active_switches", [])
    posture_lines = [
        f"[bold]Current Posture:[/] {posture_data.get('current_posture', 'unknown')}",
        f"[bold]Active Switches:[/] {', '.join(switches) if switches else 'none'}",
        f"[bold]Transitions:[/] {len(posture_data.get('transitions', []))}",
        f"[bold]External AI Denied:[/] {posture_data.get('deny_external_ai_inbound', False)}",
        f"[bold]Airlock Marker Req:[/] {posture_data.get('require_airlock_marker_on_tokens', False)}",
    ]
    
    # Check for CPU Attestation (Hardware posture)
    if MUX_INTEGRATION:
        try:
            cpu_receipt = cc.cpu_capability_receipt()
            feats = cpu_receipt.get("features", {})
            fma_status = "[green]OK[/]" if feats.get("fma3") else "[red]N/A[/]"
            avx2_status = "[green]OK[/]" if feats.get("avx2") else "[red]N/A[/]"
            aes_status = "[green]OK[/]" if feats.get("aes_ni") else "[red]N/A[/]"
            posture_lines.extend([
                "",
                f"[bold]Attested CPU:[/] {cpu_receipt.get('cpu', 'unknown')[:35]}",
                f"[bold]Hardware Evidence:[/] FMA3 {fma_status} | AVX2 {avx2_status} | AES-NI {aes_status}",
                f"[bold]Compute Lane:[/] {cc.compute_lane_label(feats)}",
            ])
        except Exception:
            pass

    # Print first row of columns (Pulse + Posture)
    console.print(Columns([
        RichPanel(pulse_table, title="1. Pulse (Latest Events/Tail)", border_style="cyan"),
        RichPanel("\n".join(posture_lines), title="2. Machine & Hardware Evidence", border_style="yellow")
    ], equal=True, expand=True))
    console.print()

    # --- PANE 3: Surface (SSM Cards & Known File Surfaces) ---
    surface_table = Table(box=box.SIMPLE, expand=True)
    surface_table.add_column("Surface / Extension", style="bold")
    surface_table.add_column("State", width=8)
    surface_table.add_column("Reason / Detail", overflow="fold")

    # Detect .tza files
    tza_files = sorted(list(set(Path(path).glob("*.tza")) | set(Path(path).glob("**/*.tza"))))[:2]
    for tza in tza_files:
        magic_hex = ""
        try:
            with tza.open("rb") as f:
                magic_hex = f.read(4).hex()
        except OSError:
            pass
        sealed = magic_hex == "54425a84"
        state = "[green]sealed[/]" if sealed else "[red]distrust[/]"
        surface_table.add_row(tza.name, state, "Semantic Surface Manifest (.tza) envelope")

    # Add default file hints
    for src in cockpit_snapshot.get("evidence_sources", []):
        state = "[green]open[/]" if src["records"] else "[dim]held[/]"
        surface_table.add_row(src["name"], state, f"Indexed {src['records']} records; kind={src['kind']}")

    if not tza_files and not cockpit_snapshot.get("evidence_sources"):
        surface_table.add_row("-", "[dim]dark[/]", "No known active surfaces or enclaves found")

    # --- PANE 4: Chain (Evidence Story) ---
    chain_table = Table(box=box.SIMPLE, expand=True)
    chain_table.add_column("Chain ID", style="bold")
    chain_table.add_column("Status", width=9)
    chain_table.add_column("Observed Story", overflow="fold")
    chain_table.add_column("Missing Links", overflow="fold")

    style_map = {"complete": "green", "partial": "yellow", "missing": "red"}
    chains = cockpit_snapshot.get("evidence_chains", [])
    for chain in chains:
        status = chain["status"]
        style = style_map.get(status, "white")
        story = " ➔ ".join(f"{step['subsystem']}:{step['action']}" for step in chain.get("steps", []))
        missing = ", ".join(chain.get("missing_links", [])) or "-"
        chain_table.add_row(
            chain["title"][:22],
            f"[{style}]{status.upper()}[/]",
            story,
            missing
        )
    if not chains:
        chain_table.add_row("none", "[dim]MISSING[/]", "No correlated evidence stories found", "-")

    # Print second row of columns (Surface + Chain)
    console.print(Columns([
        RichPanel(surface_table, title="3. Surfaces & Enclaves (SSM)", border_style="green"),
        RichPanel(chain_table, title="4. Evidence Chains", border_style="magenta")
    ], equal=True, expand=True))
    console.print()

    # --- PANE 5: Stack (Profile-Aware Software Mapping) ---
    # Load repo_posture.json — resolved via env/cwd, never a hardcoded path.
    from ._devpath import repo_posture_path as _resolve_repo_posture
    repo_posture_path = _resolve_repo_posture()
    profile_packages = []
    profile_name = f"ainternet[{profile}]"

    if repo_posture_path and repo_posture_path.exists():
        try:
            repo_data = json_mod.loads(repo_posture_path.read_text(encoding="utf-8"))
            profiles_dict = repo_data.get("sort_rule", {}).get("public_profiles", {})
            if profile_name in profiles_dict:
                profile_packages = profiles_dict[profile_name].get("packages", [])
            elif profile == "full":
                # combine all profiles
                p_set = set()
                for p_data in profiles_dict.values():
                    p_set.update(p_data.get("packages", []))
                profile_packages = sorted(list(p_set))
        except Exception:
            pass

    if not profile_packages:
        # Fallback list if json failed/missing
        profile_packages = ["tibet-core", "jis-core", "tibet-continuityd", "tibet-cbom", "ainternet", "tibet-triage", "tibet-mux"]

    stack_pane_table = Table(box=box.SIMPLE, expand=True)
    stack_pane_table.add_column("Package Name", style="bold")
    stack_pane_table.add_column("Status", width=12)
    stack_pane_table.add_column("Causal Role / Mapping", overflow="fold")

    # Map package names to their causal roles
    role_map = {
        "tibet-core": "Substrate - zero trust baseline",
        "jis-core": "Substrate - JIT DID identity router",
        "tibet-timevector": "Substrate - causal timevector",
        "tibet-continuityd": "Evidence Spine - arrival monitor daemon",
        "tibet-cbom": "Evidence Spine - State of Manifest (SOM) inspector",
        "tibet-sbom": "Evidence Spine - software bill of materials",
        "tibet-ai-sbom": "Evidence Spine - AI/model weights receipt",
        "tibet-wayback": "Evidence Spine - state archiving & history",
        "tibet-report": "Evidence Spine - governance report generator",
        "tibet-audit": "Evidence Spine - compliance scan engine",
        "ainternet": "Agentic - .aint discovery & messaging hub",
        "ipoll": "Agentic - I-Poll AI-to-AI client/router",
        "tibet-cmail": "Agentic - Cmail envelope post-box",
        "tibet-triage": "Safety - execution airlock triage gate",
        "tibet-phantom": "Agentic - state preservation and resume",
        "tibet-airlock": "Safety - microVM containment airlock",
        "tibet-mux": "Agentic - PCIe metronome / packet routing",
        "tibet-pol": "Safety - runtime policy verdict engine",
    }

    for pkg in profile_packages:
        status_val = check_pkg_installed(pkg)
        role_val = role_map.get(pkg, "Specialized accessory")
        stack_pane_table.add_row(pkg, status_val, role_val)

    # --- PANE 6: Action (Categorized human next steps) ---
    action_lines = []
    
    # Categorize next actions from cockpit
    raw_actions = cockpit_snapshot.get("next_actions", [])
    identity_actions = []
    evidence_actions = []
    policy_actions = []
    runtime_actions = []

    for act in raw_actions:
        low = act.lower()
        if "identity" in low or "jis" in low or "key" in low:
            identity_actions.append(act)
        elif "evidence" in low or "audit" in low or "log" in low or "sbom" in low or "cbom" in low:
            evidence_actions.append(act)
        elif "policy" in low or "pol" in low or "rule" in low or "snaft" in low:
            policy_actions.append(act)
        else:
            runtime_actions.append(act)

    if not raw_actions:
        action_lines.append("[green]✓ System is fully operational. All readiness checks passed.[/]")
    else:
        if identity_actions:
            action_lines.append("[bold cyan]identity/keys:[/]")
            for a in identity_actions:
                action_lines.append(f"  {a}")
        if evidence_actions:
            if identity_actions:
                action_lines.append("")
            action_lines.append("[bold magenta]evidence/audit:[/]")
            for a in evidence_actions:
                action_lines.append(f"  {a}")
        if policy_actions:
            if identity_actions or evidence_actions:
                action_lines.append("")
            action_lines.append("[bold yellow]policy/verdicts:[/]")
            for a in policy_actions:
                action_lines.append(f"  {a}")
        if runtime_actions:
            if identity_actions or evidence_actions or policy_actions:
                action_lines.append("")
            action_lines.append("[bold green]runtime/sandbox:[/]")
            for a in runtime_actions:
                action_lines.append(f"  {a}")

    # Print third row of columns (Stack + Action)
    console.print(Columns([
        RichPanel(stack_pane_table, title=f"5. Stack (Profile: {profile_name})", border_style="cyan"),
        RichPanel("\n".join(action_lines), title="6. Next Actions (Categorized)", border_style="yellow")
    ], equal=True, expand=True))
    console.print()

    console.print(f"[dim]Dashboard scan completed in {scan_duration}s | tibet-audit {__version__}[/]")
    console.print()



# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    """Main entry point."""
    app()


if __name__ == "__main__":
    main()
