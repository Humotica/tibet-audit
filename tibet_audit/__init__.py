"""
TIBET Audit - Compliance Health Scanner
========================================

Like Lynis, but for regulations. Scan your systems, get a score, fix the issues.

The Diaper Protocol™: One command, hands free, compliance done.

    $ tibet-audit scan
    $ tibet-audit fix --auto    # Diaper Protocol: fix everything, no questions
    $ tibet-audit fix --wet-wipe  # Preview what would be fixed (like --dry-run but funnier)

Authors: Jasper van de Meent & Root AI
License: MIT
Website: https://humotica.com

One love, one fAmIly!
"""

try:
    # Single source of truth: the installed package metadata. Never drifts, so an
    # audit tool always reports its own true version.
    from importlib.metadata import version as _pkg_version
    __version__ = _pkg_version("tibet-audit")
except Exception:
    __version__ = "0.28.1"  # fallback when running from an uninstalled checkout
__author__ = "Jasper van de Meent & Root AI"
__email__ = "team@humotica.com"

from .scanner import TIBETAudit
from .checks.base import CheckResult, Status, Severity
from .tibet_recommendations import get_recommendation, enrich_results, format_recommendations_summary
from .compliance_map import get_mapping, get_framework_coverage, generate_jis_compliance_block
from .governance_conclusion import build_governance_conclusion, evaluate_coffee_lane

__all__ = [
    "TIBETAudit", "CheckResult", "Status", "Severity",
    "get_recommendation", "enrich_results", "format_recommendations_summary",
    "get_mapping", "get_framework_coverage", "generate_jis_compliance_block",
    "build_governance_conclusion", "evaluate_coffee_lane",
]
