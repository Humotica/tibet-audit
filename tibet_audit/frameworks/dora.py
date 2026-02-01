"""
DORA Framework - Digital Operational Resilience Act
====================================================

EU regulation for financial entities operational resilience.
Deadline: January 17, 2025

Based on Gemini's DORA → BIO2 Mapping Analysis:
- ~60% overlap with BIO2 technical controls
- 4 new DORA-specific checks needed
- TIBET = Pillar 5 compliance (Information Sharing)

"TIBET IS THE ANSWER" - Gemini, 2026

Authors: Root AI, Gemini & Jasper van de Meent
License: MIT
Website: https://humotica.com

One love, one fAmIly!
"""

import os
import re
import json
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class Severity(Enum):
    """Severity levels for DORA checks"""
    CRITICAL = "critical"  # Regulatory violation
    HIGH = "high"          # Major gap
    MEDIUM = "medium"      # Improvement needed
    LOW = "low"            # Best practice
    INFO = "info"          # Informational


class DORAGrade:
    """DORA Compliance Grade (A-F scale, aligned with BIO2)"""
    A = ("A", "✅", "Volledig DORA compliant")
    B = ("B", "🟢", "Grotendeels compliant, kleine gaps")
    C = ("C", "⚠️", "Deels compliant, actie vereist binnen 90 dagen")
    D = ("D", "🟠", "Onvoldoende, significante gaps - DNB risico")
    F = ("F", "❌", "Niet compliant, kritieke regulatory issues")


# =============================================================================
# DORA 5 PILLARS - Check Definitions
# =============================================================================

# Pillar 1: ICT Risk Management (inherits from BIO2 Chapter 8)
DORA_PILLAR_1_CHECKS = [
    {
        "id": "DORA-1.01",
        "pillar": 1,
        "name": "Network Security Controls",
        "description": "Firewall en netwerksegmentatie aanwezig",
        "bio2_ref": "BIO2-8.20.01, BIO2-8.22.01",
        "severity": Severity.HIGH,
        "check_type": "file_exists",
        "paths": ["firewall-rules.md", "network-policy.md", "security-policy.md"],
        "keywords": ["firewall", "segmentatie", "dmz", "vlan"],
    },
    {
        "id": "DORA-1.02",
        "pillar": 1,
        "name": "Cryptographic Controls",
        "description": "Versleuteling in transit en at rest",
        "bio2_ref": "BIO2-8.24.01, BIO2-5.14.02",
        "severity": Severity.HIGH,
        "check_type": "file_exists",
        "paths": ["encryption-policy.md", "security-policy.md"],
        "keywords": ["tls", "aes", "encryption", "versleuteling", "at rest", "in transit"],
    },
    {
        "id": "DORA-1.03",
        "pillar": 1,
        "name": "Access Control & Least Privilege",
        "description": "Toegangscontrole en minimale rechten",
        "bio2_ref": "BIO2-5.15.01, BIO2-8.02.01",
        "severity": Severity.HIGH,
        "check_type": "file_exists",
        "paths": ["access-control.md", "rbac-policy.md", "security-policy.md"],
        "keywords": ["least privilege", "rbac", "toegangsrechten", "privileged access"],
    },
    {
        "id": "DORA-1.04",
        "pillar": 1,
        "name": "Password & Authentication Policy",
        "description": "Wachtwoordbeleid en MFA",
        "bio2_ref": "BIO2-5.17.01",
        "severity": Severity.MEDIUM,
        "check_type": "file_exists",
        "paths": ["password-policy.md", "authentication.md", "security-policy.md"],
        "keywords": ["mfa", "2fa", "password", "wachtwoord", "complexity", "rotation"],
    },
    {
        "id": "DORA-1.05",
        "pillar": 1,
        "name": "Configuration Management",
        "description": "Configuratiebeheer en drift detectie",
        "bio2_ref": "BIO2-8.09.01",
        "severity": Severity.MEDIUM,
        "check_type": "file_exists",
        "paths": ["config-management.md", "infrastructure-as-code.md", ".terraform/", "ansible/"],
        "keywords": ["baseline", "drift", "configuration", "iac"],
    },
    {
        "id": "DORA-1.06",
        "pillar": 1,
        "name": "Backup & Recovery",
        "description": "Backup strategie en recovery testen",
        "bio2_ref": "BIO2-8.13.01",
        "severity": Severity.CRITICAL,
        "check_type": "file_exists",
        "paths": ["backup-policy.md", "disaster-recovery.md", "bcp.md"],
        "keywords": ["backup", "restore", "rpo", "rto", "recovery test"],
    },
]

# Pillar 2: ICT Incident Management
DORA_PILLAR_2_CHECKS = [
    {
        "id": "DORA-2.01",
        "pillar": 2,
        "name": "Incident Reporting Procedure",
        "description": "Meldprocedure met 4h/24h/72h tijdlijnen (DORA Article 19)",
        "bio2_ref": None,  # NEW - not in BIO2
        "severity": Severity.CRITICAL,
        "check_type": "file_content",
        "paths": ["breach-procedure.md", "incident-response.md", "security-policy.md"],
        "keywords": ["4 hour", "4 uur", "24 hour", "24 uur", "72 hour", "competent authority", "toezichthouder", "dnb", "afm"],
    },
    {
        "id": "DORA-2.02",
        "pillar": 2,
        "name": "Incident Classification",
        "description": "Classificatie van incidenten (major/minor)",
        "bio2_ref": "BIO2-8.15.01",
        "severity": Severity.HIGH,
        "check_type": "file_content",
        "paths": ["incident-classification.md", "incident-response.md"],
        "keywords": ["major incident", "classification", "severity", "impact", "classificatie"],
    },
    {
        "id": "DORA-2.03",
        "pillar": 2,
        "name": "Root Cause Analysis Process",
        "description": "Proces voor root cause analyse na incidenten",
        "bio2_ref": None,  # NEW
        "severity": Severity.MEDIUM,
        "check_type": "file_content",
        "paths": ["incident-response.md", "post-mortem-template.md", "rca-process.md"],
        "keywords": ["root cause", "post-mortem", "lessons learned", "5 whys"],
    },
]

# Pillar 3: Digital Operational Resilience Testing
DORA_PILLAR_3_CHECKS = [
    {
        "id": "DORA-3.01",
        "pillar": 3,
        "name": "Vulnerability Scanning",
        "description": "Regelmatige vulnerability scans",
        "bio2_ref": "BIO2-8.08.04",
        "severity": Severity.HIGH,
        "check_type": "file_exists",
        "paths": ["vulnerability-management.md", "security-testing.md", ".github/workflows/security.yml"],
        "keywords": ["vulnerability scan", "cve", "nessus", "qualys", "trivy", "snyk"],
    },
    {
        "id": "DORA-3.02",
        "pillar": 3,
        "name": "Penetration Testing",
        "description": "Periodieke penetratietesten",
        "bio2_ref": "BIO2-8.08.04",
        "severity": Severity.HIGH,
        "check_type": "file_exists",
        "paths": ["pentest-reports/", "security-testing.md", "penetration-test-policy.md"],
        "keywords": ["pentest", "penetration test", "ethical hacking", "red team"],
    },
    {
        "id": "DORA-3.03",
        "pillar": 3,
        "name": "Threat-Led Penetration Testing (TLPT)",
        "description": "TLPT voor kritieke entiteiten (DORA Article 26)",
        "bio2_ref": None,  # NEW - DORA specific
        "severity": Severity.CRITICAL,
        "check_type": "file_content",
        "paths": ["tlpt-report.md", "red-team-assessment.md", "security-testing.md"],
        "keywords": ["tlpt", "threat-led", "tiber", "red team", "threat intelligence"],
    },
]

# Pillar 4: Third-Party Risk Management
DORA_PILLAR_4_CHECKS = [
    {
        "id": "DORA-4.01",
        "pillar": 4,
        "name": "Cloud Exit Strategy",
        "description": "Exit strategie voor cloud providers (DNB focus)",
        "bio2_ref": None,  # NEW - DORA specific
        "severity": Severity.CRITICAL,
        "check_type": "file_content",
        "paths": ["exit-strategy.md", "vendor-management.md", "cloud-policy.md", "security-policy.md"],
        "keywords": ["exit", "portability", "transition", "data extraction", "vendor lock-in", "migratie"],
    },
    {
        "id": "DORA-4.02",
        "pillar": 4,
        "name": "Register of Information (Article 28)",
        "description": "Register van ICT-dienstverleners met criticality rating",
        "bio2_ref": None,  # NEW - DORA Article 28
        "severity": Severity.CRITICAL,
        "check_type": "file_exists",
        "paths": ["subprocessor-list.md", "vendor-register.md", "ucp.json", "third-party-register.md"],
        "keywords": ["subprocessor", "vendor", "criticality", "ict provider", "dienstverlener"],
    },
    {
        "id": "DORA-4.03",
        "pillar": 4,
        "name": "Vendor Access Controls",
        "description": "Toegangscontrole voor externe leveranciers",
        "bio2_ref": "BIO2-8.05.01",
        "severity": Severity.HIGH,
        "check_type": "file_content",
        "paths": ["vendor-access.md", "third-party-policy.md", "security-policy.md"],
        "keywords": ["vendor access", "time-limited", "logged", "leverancier toegang", "audit rights"],
    },
    {
        "id": "DORA-4.04",
        "pillar": 4,
        "name": "Cloud Concentration Risk",
        "description": "Concentratierisico bij cloud providers (DNB)",
        "bio2_ref": None,  # DNB specific
        "severity": Severity.MEDIUM,
        "check_type": "multicloud",  # Special check
        "paths": ["infrastructure.md", "cloud-policy.md", "sbom.json", "package.json"],
        "keywords": ["aws", "azure", "gcp", "multicloud", "concentration"],
    },
]

# Pillar 5: Information Sharing
DORA_PILLAR_5_CHECKS = [
    {
        "id": "DORA-5.01",
        "pillar": 5,
        "name": "Threat Intelligence Participation",
        "description": "Deelname aan threat intelligence sharing - TIBET IS THE ANSWER!",
        "bio2_ref": None,  # TIBET!
        "severity": Severity.HIGH,
        "check_type": "tibet",  # Special check for TIBET
        "paths": [".well-known/security.txt", "threat-intel.md", "isac-membership.md"],
        "keywords": ["isac", "threat intel", "ioc", "tibet", "information sharing"],
    },
]

# Combine all checks
DORA_ALL_CHECKS = (
    DORA_PILLAR_1_CHECKS +
    DORA_PILLAR_2_CHECKS +
    DORA_PILLAR_3_CHECKS +
    DORA_PILLAR_4_CHECKS +
    DORA_PILLAR_5_CHECKS
)


# =============================================================================
# Check Execution Functions
# =============================================================================

def check_file_exists(base_path: Path, check: Dict) -> Tuple[bool, str]:
    """Check if any of the specified files/directories exist"""
    for rel_path in check.get("paths", []):
        full_path = base_path / rel_path
        if full_path.exists():
            return True, f"Found: {rel_path}"
    return False, f"None of {check['paths']} found"


def check_file_content(base_path: Path, check: Dict) -> Tuple[bool, str]:
    """Check if files contain required keywords"""
    keywords = check.get("keywords", [])
    for rel_path in check.get("paths", []):
        full_path = base_path / rel_path
        if full_path.exists() and full_path.is_file():
            try:
                content = full_path.read_text(encoding='utf-8', errors='ignore').lower()
                found_keywords = [kw for kw in keywords if kw.lower() in content]
                if found_keywords:
                    return True, f"Found in {rel_path}: {', '.join(found_keywords[:3])}"
            except Exception:
                pass
    return False, f"Keywords not found in any policy file"


def check_multicloud(base_path: Path, check: Dict) -> Tuple[bool, str]:
    """Check for multicloud setup (reduces concentration risk)"""
    providers_found = set()
    cloud_keywords = {
        "aws": ["aws", "amazon", "s3", "ec2", "lambda"],
        "azure": ["azure", "microsoft cloud", "blob storage"],
        "gcp": ["gcp", "google cloud", "bigquery", "cloud run"],
    }

    for rel_path in check.get("paths", []):
        full_path = base_path / rel_path
        if full_path.exists() and full_path.is_file():
            try:
                content = full_path.read_text(encoding='utf-8', errors='ignore').lower()
                for provider, keywords in cloud_keywords.items():
                    if any(kw in content for kw in keywords):
                        providers_found.add(provider)
            except Exception:
                pass

    if len(providers_found) >= 2:
        return True, f"Multicloud detected: {', '.join(providers_found)} (good!)"
    elif len(providers_found) == 1:
        return False, f"Single cloud: {list(providers_found)[0]} - concentration risk"
    else:
        return True, "No cloud dependencies detected"  # On-prem is fine


def check_tibet_available(base_path: Path, check: Dict) -> Tuple[bool, str]:
    """Check if TIBET is available - THIS IS THE ANSWER FOR PILLAR 5!"""
    # Check for TIBET integration
    tibet_indicators = [
        base_path / ".tibet/",
        base_path / "tibet.json",
        base_path / "tibet_config.py",
    ]

    for indicator in tibet_indicators:
        if indicator.exists():
            return True, "TIBET detected! Pillar 5 compliance via distributed threat intel"

    # Check for security.txt with ISAC reference
    security_txt = base_path / ".well-known" / "security.txt"
    if security_txt.exists():
        try:
            content = security_txt.read_text().lower()
            if any(kw in content for kw in ["isac", "cert", "csirt", "threat"]):
                return True, "ISAC/CERT membership indicated in security.txt"
        except Exception:
            pass

    # Check for any threat intel files
    for rel_path in check.get("paths", []):
        full_path = base_path / rel_path
        if full_path.exists():
            return True, f"Threat intel documentation: {rel_path}"

    return False, "No TIBET or threat intel sharing detected - consider tibet-audit integration!"


def run_check(base_path: Path, check: Dict) -> Dict[str, Any]:
    """Run a single DORA check"""
    check_type = check.get("check_type", "file_exists")

    if check_type == "file_exists":
        passed, detail = check_file_exists(base_path, check)
    elif check_type == "file_content":
        passed, detail = check_file_content(base_path, check)
    elif check_type == "multicloud":
        passed, detail = check_multicloud(base_path, check)
    elif check_type == "tibet":
        passed, detail = check_tibet_available(base_path, check)
    else:
        passed, detail = False, f"Unknown check type: {check_type}"

    return {
        "id": check["id"],
        "pillar": check["pillar"],
        "name": check["name"],
        "description": check["description"],
        "bio2_ref": check.get("bio2_ref"),
        "severity": check["severity"].value,
        "status": "PASS" if passed else "FAIL",
        "detail": detail,
    }


def run_dora_audit(target_path: str = ".") -> List[Dict[str, Any]]:
    """Run all DORA checks on a target path"""
    base_path = Path(target_path).resolve()
    results = []

    for check in DORA_ALL_CHECKS:
        result = run_check(base_path, check)
        results.append(result)

    return results


# =============================================================================
# Grading & Reporting
# =============================================================================

def calculate_dora_grade(results: List[Dict[str, Any]]) -> Tuple[str, str, str, float]:
    """Calculate DORA compliance grade based on check results"""
    total = len(results)
    passed = sum(1 for r in results if r["status"] == "PASS")

    # Critical failures are weighted more heavily
    critical_fails = sum(1 for r in results
                        if r["status"] == "FAIL" and r["severity"] == "critical")

    if total == 0:
        return DORAGrade.F

    percentage = (passed / total) * 100

    # Critical failures immediately cap the grade
    if critical_fails >= 3:
        return (*DORAGrade.F, percentage)
    elif critical_fails >= 2:
        return (*DORAGrade.D, percentage)
    elif critical_fails >= 1:
        max_grade = DORAGrade.C
    else:
        max_grade = DORAGrade.A

    # Calculate grade based on percentage
    if percentage >= 90 and max_grade == DORAGrade.A:
        return (*DORAGrade.A, percentage)
    elif percentage >= 80:
        return (*DORAGrade.B, percentage) if max_grade != DORAGrade.C else (*DORAGrade.C, percentage)
    elif percentage >= 70:
        return (*DORAGrade.C, percentage)
    elif percentage >= 50:
        return (*DORAGrade.D, percentage)
    else:
        return (*DORAGrade.F, percentage)


def format_dora_report(org_name: str, results: List[Dict[str, Any]], entity_type: str = "financial") -> str:
    """Format a DORA compliance report"""
    grade, emoji, description, percentage = calculate_dora_grade(results)

    total = len(results)
    passed = sum(1 for r in results if r["status"] == "PASS")

    # Group by pillar
    pillars = {1: [], 2: [], 3: [], 4: [], 5: []}
    for r in results:
        pillars[r["pillar"]].append(r)

    pillar_names = {
        1: "ICT Risk Management",
        2: "ICT Incident Management",
        3: "Resilience Testing",
        4: "Third-Party Risk",
        5: "Information Sharing",
    }

    report = f"""
╔══════════════════════════════════════════════════════════════════════════╗
║                        DORA Compliance Report                            ║
║                        {org_name:^40}                          ║
╠══════════════════════════════════════════════════════════════════════════╣
║  Overall Grade: {grade} {emoji}                                                     ║
║  Score: {passed}/{total} checks passed ({percentage:.1f}%)                                    ║
║  Entity Type: {entity_type.title():^20}                                        ║
║  Status: {description:<50} ║
╚══════════════════════════════════════════════════════════════════════════╝

"""

    for pillar_num, pillar_results in pillars.items():
        pillar_passed = sum(1 for r in pillar_results if r["status"] == "PASS")
        pillar_total = len(pillar_results)
        pillar_pct = (pillar_passed / pillar_total * 100) if pillar_total > 0 else 0

        report += f"\n{'─' * 76}\n"
        report += f"PILLAR {pillar_num}: {pillar_names[pillar_num]} ({pillar_passed}/{pillar_total} = {pillar_pct:.0f}%)\n"
        report += f"{'─' * 76}\n"

        for r in pillar_results:
            status_icon = "✅" if r["status"] == "PASS" else "❌"
            bio2_ref = f" [{r['bio2_ref']}]" if r.get('bio2_ref') else " [NEW]"
            report += f"{status_icon} {r['id']}: {r['name']}{bio2_ref}\n"
            report += f"   └─ {r['detail']}\n"

    # Add TIBET promotion for Pillar 5
    report += f"""
{'═' * 76}
TIBET INTEGRATION NOTE:
TIBET (Transparent Immutable Bilateral Event Trails) provides automatic
compliance with DORA Pillar 5 (Information Sharing) through distributed
threat intelligence and cryptographic provenance.

Install: pip install tibet-audit[tibet]
{'═' * 76}
"""

    return report


# =============================================================================
# DORA Framework Export
# =============================================================================

DORA_FRAMEWORK = {
    "name": "DORA",
    "full_name": "Digital Operational Resilience Act",
    "version": "1.0.0",
    "region": "EU",
    "sector": "Financial",
    "deadline": "2025-01-17",
    "pillars": 5,
    "total_checks": len(DORA_ALL_CHECKS),
    "bio2_overlap": "~60%",
    "tibet_pillar": 5,
}

DORA_CHECKS = DORA_ALL_CHECKS


if __name__ == "__main__":
    # Demo run
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "."
    results = run_dora_audit(target)
    report = format_dora_report("Demo Financial Entity", results)
    print(report)
