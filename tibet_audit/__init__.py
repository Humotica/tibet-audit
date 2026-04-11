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

__version__ = "0.23.0"  # ISO/EU compliance mapping: --compliance matrix, --jis export, 10 frameworks (ISO 42001/27001/23894/5338/27701, EU AI Act, NIS2, GDPR, NIST AI RMF, SOC 2)
__author__ = "Jasper van de Meent & Root AI"
__email__ = "team@humotica.com"

from .scanner import TIBETAudit
from .checks.base import CheckResult, Status, Severity
from .tibet_recommendations import get_recommendation, enrich_results, format_recommendations_summary
from .compliance_map import get_mapping, get_framework_coverage, generate_jis_compliance_block

__all__ = [
    "TIBETAudit", "CheckResult", "Status", "Severity",
    "get_recommendation", "enrich_results", "format_recommendations_summary",
    "get_mapping", "get_framework_coverage", "generate_jis_compliance_block",
]
