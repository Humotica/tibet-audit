"""
BIO2 - Baseline Informatiebeveiliging Overheid 2 Framework
============================================================

Nederlandse overheid security baseline (MinBZK/CIP/VNG-IBD)
Gebaseerd op ISO 27001/27002:2022 structuur

Controls: 5.xx (Organisatorisch), 6.xx (Personeel), 7.xx (Fysiek), 8.xx (Technisch)

Bron: https://github.com/MinBZK/Baseline-Informatiebeveiliging-Overheid
Versie: BIO2 v1.2

tibet-audit integration by Humotica - https://humotica.com
"""

from typing import Dict, List, Any
from enum import Enum


class Severity(str, Enum):
    """Check severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

# =============================================================================
# BIO2 CONTROL CATEGORIES
# =============================================================================

BIO2_CATEGORIES = {
    "basishygiene": "Basishygiëne - Fundamentele beveiligingsmaatregelen",
    "ketenhygiene": "Ketenhygiëne - Supply chain en keten beveiliging",
    "overheidsrisico": "Overheidsrisico - Specifieke overheidsmaatregelen",
}

# =============================================================================
# BIO2 AUTOMATED CHECKS - Chapter 5 (Organisatorisch)
# =============================================================================

BIO2_CHECKS_CH5 = [
    {
        "id": "BIO2-5.14.01",
        "name": "Forum Standaardisatie Compliance",
        "description": "Internetfacing-informatiesystemen en e-mail moeten voldoen aan verplichte standaarden (HTTPS, DNSSEC, DMARC, etc.)",
        "category": "basishygiene",
        "severity": "HIGH",
        "automated": True,
        "iac_resources": ["aws_cloudfront_distribution", "aws_alb", "azurerm_cdn_endpoint"],
        "checks": [
            "tls_version >= 1.2",
            "https_only = true",
            "hsts_enabled = true"
        ]
    },
    {
        "id": "BIO2-5.14.02",
        "name": "TLS Certificaat Validatie",
        "description": "Gebruik van OV-certificaten voor gevoelige gegevens",
        "category": "basishygiene",
        "severity": "MEDIUM",
        "automated": True,
        "iac_resources": ["aws_acm_certificate", "azurerm_app_service_certificate"],
        "checks": [
            "certificate_type in ['OV', 'EV']",
            "certificate_valid = true"
        ]
    },
    {
        "id": "BIO2-5.15.01",
        "name": "Toegangsbeveiliging Beleid",
        "description": "Regels voor fysieke en logische toegang tot informatie",
        "category": "basishygiene",
        "severity": "HIGH",
        "automated": True,
        "iac_resources": ["aws_iam_policy", "azurerm_role_definition", "google_iam_policy"],
        "checks": [
            "least_privilege_enforced = true",
            "deny_by_default = true"
        ]
    },
    {
        "id": "BIO2-5.17.01",
        "name": "Wachtwoordeisen Automatisch Afgedwongen",
        "description": "Eisen aan wachtwoorden moeten geautomatiseerd worden afgedwongen",
        "category": "basishygiene",
        "severity": "HIGH",
        "automated": True,
        "iac_resources": ["aws_iam_account_password_policy", "azuread_conditional_access_policy"],
        "checks": [
            "min_password_length >= 12",
            "require_uppercase = true",
            "require_numbers = true",
            "require_symbols = true",
            "password_expiry_days <= 90"
        ]
    },
    {
        "id": "BIO2-5.23.01",
        "name": "Clouddiensten Beveiliging",
        "description": "Processen voor aanschaffen, gebruiken, beheren en beëindigen van clouddiensten",
        "category": "basishygiene",
        "severity": "HIGH",
        "automated": True,
        "iac_resources": ["aws_s3_bucket", "azurerm_storage_account", "google_storage_bucket"],
        "checks": [
            "encryption_at_rest = true",
            "public_access = false",
            "logging_enabled = true"
        ]
    },
]

# =============================================================================
# BIO2 AUTOMATED CHECKS - Chapter 8 (Technisch)
# =============================================================================

BIO2_CHECKS_CH8 = [
    {
        "id": "BIO2-8.01.01",
        "name": "Mobile Device Encryption",
        "description": "Mobiele apparatuur met versleuteling en wissen op afstand",
        "category": "basishygiene",
        "severity": "HIGH",
        "automated": True,
        "iac_resources": ["aws_workspaces_workspace", "azurerm_virtual_desktop_host_pool"],
        "checks": [
            "encryption_enabled = true",
            "remote_wipe_capable = true"
        ]
    },
    {
        "id": "BIO2-8.02.01",
        "name": "Privileged Access Review",
        "description": "Speciale bevoegdheden worden minimaal ieder kwartaal beoordeeld",
        "category": "basishygiene",
        "severity": "HIGH",
        "automated": True,
        "iac_resources": ["aws_iam_role", "azurerm_role_assignment"],
        "checks": [
            "admin_roles_documented = true",
            "mfa_required_for_admin = true"
        ]
    },
    {
        "id": "BIO2-8.03.01",
        "name": "Informatie Isolatie",
        "description": "Fysiek en/of logisch isoleren van informatie met specifiek belang",
        "category": "basishygiene",
        "severity": "MEDIUM",
        "automated": True,
        "iac_resources": ["aws_vpc", "azurerm_virtual_network", "google_compute_network"],
        "checks": [
            "network_segmentation = true",
            "private_subnets_used = true"
        ]
    },
    {
        "id": "BIO2-8.05.01",
        "name": "Externe Leverancier Toegang",
        "description": "Risicoafweging voor netwerktoegang externe leveranciers",
        "category": "basishygiene",
        "severity": "HIGH",
        "automated": True,
        "iac_resources": ["aws_vpn_connection", "azurerm_virtual_network_gateway"],
        "checks": [
            "vendor_access_logged = true",
            "time_limited_access = true"
        ]
    },
    {
        "id": "BIO2-8.07.01",
        "name": "Antimalware Downloads",
        "description": "Antimalware-software beoordeelt alle downloads",
        "category": "basishygiene",
        "severity": "HIGH",
        "automated": True,
        "iac_resources": ["aws_guardduty_detector", "azurerm_security_center_subscription_pricing"],
        "checks": [
            "malware_scanning_enabled = true",
            "realtime_protection = true"
        ]
    },
    {
        "id": "BIO2-8.08.04",
        "name": "Vulnerability Assessment",
        "description": "Jaarlijkse controle op technische naleving beveiligingsnormen",
        "category": "basishygiene",
        "severity": "HIGH",
        "automated": True,
        "iac_resources": ["aws_inspector_assessment_target", "azurerm_security_center_assessment"],
        "checks": [
            "vulnerability_scanning_enabled = true",
            "automated_scanning = true"
        ]
    },
    {
        "id": "BIO2-8.09.01",
        "name": "Configuration Management",
        "description": "Configuraties zijn gedocumenteerd en gecontroleerd",
        "category": "basishygiene",
        "severity": "MEDIUM",
        "automated": True,
        "iac_resources": ["aws_config_configuration_recorder", "azurerm_policy_definition"],
        "checks": [
            "config_tracking_enabled = true",
            "drift_detection = true"
        ]
    },
    {
        "id": "BIO2-8.13.01",
        "name": "Backup Procedures",
        "description": "Back-up van informatie, software en systemen",
        "category": "basishygiene",
        "severity": "HIGH",
        "automated": True,
        "iac_resources": ["aws_backup_plan", "azurerm_backup_policy_vm", "google_compute_resource_policy"],
        "checks": [
            "backup_enabled = true",
            "backup_encrypted = true",
            "backup_tested = true"
        ]
    },
    {
        "id": "BIO2-8.15.01",
        "name": "Logging",
        "description": "Activiteiten worden geregistreerd en beschermd",
        "category": "basishygiene",
        "severity": "HIGH",
        "automated": True,
        "iac_resources": ["aws_cloudtrail", "azurerm_monitor_diagnostic_setting", "google_logging_project_sink"],
        "checks": [
            "audit_logging_enabled = true",
            "log_retention_days >= 365",
            "log_encryption = true"
        ]
    },
    {
        "id": "BIO2-8.20.01",
        "name": "Network Security",
        "description": "Netwerken en netwerkapparaten worden beveiligd en beheerd",
        "category": "basishygiene",
        "severity": "HIGH",
        "automated": True,
        "iac_resources": ["aws_security_group", "azurerm_network_security_group", "google_compute_firewall"],
        "checks": [
            "default_deny_ingress = true",
            "no_unrestricted_ssh = true",
            "no_unrestricted_rdp = true"
        ]
    },
    {
        "id": "BIO2-8.22.01",
        "name": "Network Segregation",
        "description": "Groepen informatiediensten, gebruikers en informatiesystemen gescheiden",
        "category": "basishygiene",
        "severity": "MEDIUM",
        "automated": True,
        "iac_resources": ["aws_subnet", "azurerm_subnet", "google_compute_subnetwork"],
        "checks": [
            "private_subnet_isolated = true",
            "nacl_configured = true"
        ]
    },
    {
        "id": "BIO2-8.24.01",
        "name": "Cryptografie",
        "description": "Effectief gebruik van cryptografie",
        "category": "basishygiene",
        "severity": "HIGH",
        "automated": True,
        "iac_resources": ["aws_kms_key", "azurerm_key_vault", "google_kms_crypto_key"],
        "checks": [
            "encryption_at_rest = true",
            "encryption_in_transit = true",
            "key_rotation_enabled = true"
        ]
    },
]

# =============================================================================
# ALL BIO2 CHECKS
# =============================================================================

BIO2_CHECKS = BIO2_CHECKS_CH5 + BIO2_CHECKS_CH8


def get_bio2_checks() -> List[Dict[str, Any]]:
    """Return all BIO2 checks"""
    return BIO2_CHECKS


def get_bio2_check_by_id(check_id: str) -> Dict[str, Any]:
    """Get a specific BIO2 check by ID"""
    for check in BIO2_CHECKS:
        if check["id"] == check_id:
            return check
    return None


def get_automated_bio2_checks() -> List[Dict[str, Any]]:
    """Return only automated BIO2 checks"""
    return [c for c in BIO2_CHECKS if c.get("automated", False)]


def get_bio2_checks_by_category(category: str) -> List[Dict[str, Any]]:
    """Return BIO2 checks filtered by category"""
    return [c for c in BIO2_CHECKS if c.get("category") == category]


# =============================================================================
# BIO2 FRAMEWORK METADATA
# =============================================================================

BIO2_FRAMEWORK = {
    "id": "bio2",
    "name": "Baseline Informatiebeveiliging Overheid 2",
    "version": "1.2",
    "source": "https://github.com/MinBZK/Baseline-Informatiebeveiliging-Overheid",
    "authority": "MinBZK / CIP / VNG-IBD",
    "scope": ["Gemeenten", "Provincies", "Waterschappen", "Rijksoverheid"],
    "iso_alignment": "ISO 27001:2022, ISO 27002:2022",
    "nis2_alignment": "BIO2 + ISO 27001 = NIS2 zorgplicht invulling",
    "total_controls": 160,
    "automated_checks": len(get_automated_bio2_checks()),
    "categories": BIO2_CATEGORIES,
}


# =============================================================================
# BIO2 COMPLIANCE GRADING
# =============================================================================

class BIO2Grade:
    """BIO2 Compliance Grade (A-F scale)"""
    A = ("A", "✅", "Volledig compliant")
    B = ("B", "🟢", "Grotendeels compliant, kleine verbeterpunten")
    C = ("C", "⚠️", "Deels compliant, actie vereist")
    D = ("D", "🟠", "Onvoldoende, significante gaps")
    F = ("F", "❌", "Niet compliant, kritieke issues")


def calculate_bio2_grade(passed: int, failed: int, critical_failures: int = 0) -> tuple:
    """
    Calculate BIO2 compliance grade based on check results

    Returns: (grade_letter, emoji, description)
    """
    if critical_failures > 0:
        return BIO2Grade.F

    total = passed + failed
    if total == 0:
        return BIO2Grade.C

    score = passed / total

    if score >= 0.95:
        return BIO2Grade.A
    elif score >= 0.80:
        return BIO2Grade.B
    elif score >= 0.60:
        return BIO2Grade.C
    elif score >= 0.40:
        return BIO2Grade.D
    else:
        return BIO2Grade.F


def format_bio2_report(org_name: str, results: List[Dict[str, Any]]) -> str:
    """
    Generate BIO2 Compliance Report in Gemini-style format

    Example output:
    BIO2 COMPLIANCE REPORT - KIESRAAD v1.0

    [8.24] Cryptografie: ⚠️ GRADE C (Sleutelbeheer in US-KMS gedetecteerd)
    [5.21] Leverancier: ❌ GRADE F (Geen sovereign-agreement met Cloud Provider)
    [8.01] Access: ✅ GRADE A (JIS-protocol geïmplementeerd - Intent-based)
    """
    lines = [
        f"BIO2 COMPLIANCE REPORT - {org_name.upper()} v1.0",
        "=" * 50,
        ""
    ]

    passed = 0
    failed = 0
    critical = 0

    for result in results:
        check_id = result.get("check_id", "")
        status = result.get("status", "unknown")
        message = result.get("message", "")
        severity = result.get("severity", "MEDIUM")

        # Extract control number (e.g., "8.24" from "BIO2-8.24.01")
        control_num = check_id.replace("BIO2-", "").rsplit(".", 1)[0] if check_id.startswith("BIO2-") else check_id

        if status == "pass":
            passed += 1
            grade = BIO2Grade.A
        elif severity == "CRITICAL":
            critical += 1
            failed += 1
            grade = BIO2Grade.F
        elif severity == "HIGH":
            failed += 1
            grade = BIO2Grade.D
        else:
            failed += 1
            grade = BIO2Grade.C

        lines.append(f"[{control_num}] {result.get('name', 'Check')}: {grade[1]} GRADE {grade[0]} ({message})")

    # Overall grade
    overall = calculate_bio2_grade(passed, failed, critical)

    lines.extend([
        "",
        "-" * 50,
        f"OVERALL: {overall[1]} GRADE {overall[0]} - {overall[2]}",
        f"Passed: {passed}/{passed+failed} checks",
        "",
        "Powered by tibet-audit | https://humotica.com"
    ])

    return "\n".join(lines)
