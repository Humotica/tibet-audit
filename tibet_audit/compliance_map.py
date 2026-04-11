"""
Compliance Mapping — ISO/EU/Regulation cross-reference for every check.
========================================================================

Maps each tibet-audit check ID to:
- ISO standards (42001, 27001, 23894, 5338, 27701)
- EU AI Act articles
- NIS2 Directive articles
- GDPR articles
- Other frameworks (NIST AI RMF, SOC 2, etc.)

This mapping enables:
1. jis.json compliance blocks — machine-readable trustworthiness
2. tibet-sbom --compliance — aggregate coverage per framework
3. Enterprise reports — "which ISO clauses does my stack cover?"
4. Service agreements — attach compliance evidence to contracts

Usage:
    from tibet_audit.compliance_map import get_mapping, get_framework_coverage
    mapping = get_mapping("GDPR-001")
    coverage = get_framework_coverage(scan_results)
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional

# ══════════════════════════════════════════════════════════════════════
# Framework definitions — what we map to
# ══════════════════════════════════════════════════════════════════════

FRAMEWORKS = {
    "iso_42001": {
        "name": "ISO/IEC 42001:2023",
        "title": "AI Management System",
        "scope": "Any organization developing, providing, or using AI systems",
    },
    "iso_27001": {
        "name": "ISO/IEC 27001:2022",
        "title": "Information Security Management",
        "scope": "Information security controls and risk management",
    },
    "iso_23894": {
        "name": "ISO/IEC 23894:2023",
        "title": "AI Risk Management",
        "scope": "Risk identification, assessment, treatment for AI systems",
    },
    "iso_5338": {
        "name": "ISO/IEC 5338:2023",
        "title": "AI System Lifecycle",
        "scope": "Lifecycle processes for AI systems (Rob van der Veer's standard)",
    },
    "iso_27701": {
        "name": "ISO/IEC 27701:2019",
        "title": "Privacy Information Management",
        "scope": "Privacy extension to ISO 27001/27002",
    },
    "eu_ai_act": {
        "name": "EU AI Act",
        "title": "Regulation (EU) 2024/1689",
        "scope": "AI systems placed on EU market or affecting EU persons",
    },
    "nis2": {
        "name": "NIS2 Directive",
        "title": "Directive (EU) 2022/2555",
        "scope": "Essential and important entities — cybersecurity measures",
    },
    "gdpr": {
        "name": "GDPR",
        "title": "Regulation (EU) 2016/679",
        "scope": "Processing of personal data in the EU",
    },
    "nist_ai_rmf": {
        "name": "NIST AI RMF 1.0",
        "title": "AI Risk Management Framework",
        "scope": "US voluntary framework for AI risk management",
    },
    "soc2": {
        "name": "SOC 2",
        "title": "Service Organization Control 2",
        "scope": "Trust service criteria: security, availability, processing integrity, confidentiality, privacy",
    },
}


@dataclass
class ComplianceRef:
    """A single regulation/standard reference."""
    framework: str       # Key into FRAMEWORKS
    clause: str          # e.g. "§6.1.2", "Art.13", "A.5.16"
    title: str           # Human-readable clause title
    relevance: str = "direct"  # direct, supporting, partial


@dataclass
class CheckMapping:
    """Full compliance mapping for a single check."""
    check_id: str
    refs: List[ComplianceRef] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Export for jis.json."""
        return {
            "check_id": self.check_id,
            "mappings": {
                r.framework: {"clause": r.clause, "title": r.title, "relevance": r.relevance}
                for r in self.refs
            }
        }

    def frameworks(self) -> List[str]:
        return list(set(r.framework for r in self.refs))


# ══════════════════════════════════════════════════════════════════════
# The Master Mapping Table
# ══════════════════════════════════════════════════════════════════════
# Every tibet-audit check → which regulation clauses it satisfies

_R = ComplianceRef  # shorthand

COMPLIANCE_MAP: Dict[str, CheckMapping] = {}


def _m(check_id: str, *refs: ComplianceRef):
    """Register a mapping."""
    COMPLIANCE_MAP[check_id] = CheckMapping(check_id=check_id, refs=list(refs))


# ── Humotica Pillars ─────────────────────────────────────────────────

_m("HP-001",  # Trust pillar
   _R("iso_42001", "§6.1.2", "AI risk assessment — trust evaluation"),
   _R("iso_27001", "§A.5.1", "Policies for information security"),
   _R("eu_ai_act", "Art.9", "Risk management system"),
   _R("nist_ai_rmf", "GOVERN 1.1", "Legal and regulatory requirements"),
)
_m("HP-002",  # Transparency pillar
   _R("iso_42001", "§6.1.3", "AI system transparency requirements"),
   _R("eu_ai_act", "Art.13", "Transparency obligations for high-risk AI"),
   _R("iso_5338", "§7.2", "AI system documentation"),
   _R("nist_ai_rmf", "GOVERN 1.5", "Organizational transparency"),
)
_m("HP-003",  # Safety pillar
   _R("iso_42001", "§8.4", "AI system operation and monitoring"),
   _R("iso_23894", "§6.3", "AI risk treatment"),
   _R("eu_ai_act", "Art.15", "Accuracy, robustness, cybersecurity"),
   _R("nis2", "Art.21(2)(a)", "Risk analysis and information system security"),
)

# ── Health Checks ────────────────────────────────────────────────────

_m("HEALTH-001",  # Disk space
   _R("iso_27001", "§A.8.6", "Capacity management"),
   _R("nis2", "Art.21(2)(c)", "Business continuity and crisis management"),
   _R("soc2", "A1.1", "Availability — capacity planning"),
)
_m("HEALTH-002",  # Memory usage
   _R("iso_27001", "§A.8.6", "Capacity management"),
   _R("nis2", "Art.21(2)(c)", "Business continuity"),
   _R("soc2", "A1.1", "Availability — resource monitoring"),
)
_m("HEALTH-003",  # CPU usage
   _R("iso_27001", "§A.8.6", "Capacity management"),
   _R("soc2", "A1.1", "Availability — performance monitoring"),
)
_m("HEALTH-004",  # System uptime
   _R("nis2", "Art.21(2)(c)", "Business continuity"),
   _R("soc2", "A1.2", "Availability — recovery objectives"),
)
_m("HEALTH-005",  # Python version
   _R("iso_27001", "§A.8.8", "Management of technical vulnerabilities"),
   _R("nis2", "Art.21(2)(e)", "Vulnerability handling and disclosure"),
)

# ── TIBET Provenance (IETF Draft) ────────────────────────────────────

_m("TIBET-001",  # Provenance chain exists
   _R("iso_42001", "§6.1.2", "AI risk assessment — provenance tracking"),
   _R("iso_5338", "§7.3.2", "AI data management — lineage"),
   _R("eu_ai_act", "Art.12", "Record-keeping for high-risk AI"),
   _R("eu_ai_act", "Art.13", "Transparency — traceability"),
   _R("nist_ai_rmf", "MAP 3.4", "AI system provenance tracking"),
)
_m("TIBET-002",  # Token integrity
   _R("iso_42001", "§8.4", "AI system integrity monitoring"),
   _R("iso_27001", "§A.8.24", "Use of cryptography"),
   _R("eu_ai_act", "Art.15(4)", "Cybersecurity — integrity protection"),
   _R("soc2", "PI1.1", "Processing integrity — completeness and accuracy"),
)
_m("TIBET-003",  # Chain continuity
   _R("iso_5338", "§7.3.2", "AI lifecycle traceability"),
   _R("eu_ai_act", "Art.12(2)", "Automatic recording of events"),
   _R("nis2", "Art.21(2)(g)", "Audit trail and logging"),
)
_m("TIBET-004",  # Vault configured
   _R("iso_27001", "§A.8.24", "Cryptographic key management"),
   _R("iso_27001", "§A.5.33", "Protection of records"),
   _R("nis2", "Art.21(2)(h)", "Cryptography and encryption policies"),
)
_m("TIBET-005",  # Immutability
   _R("iso_42001", "§9.1", "Monitoring, measurement, analysis"),
   _R("eu_ai_act", "Art.12(1)", "Record-keeping — automatic logging"),
   _R("soc2", "CC7.2", "Security — audit logging"),
)

# ── JIS Identity (IETF Draft) ───────────────────────────────────────

_m("JIS-001",  # Agent identity exists
   _R("iso_27001", "§A.5.16", "Identity management"),
   _R("iso_42001", "§7.3", "AI system stakeholder identification"),
   _R("eu_ai_act", "Art.14(4)(c)", "Human oversight — identify AI system"),
   _R("nist_ai_rmf", "GOVERN 2.1", "Roles and responsibilities"),
)
_m("JIS-002",  # Cryptographic keys
   _R("iso_27001", "§A.8.24", "Use of cryptography"),
   _R("iso_27001", "§A.5.17", "Authentication information"),
   _R("nis2", "Art.21(2)(h)", "Cryptography and encryption"),
   _R("soc2", "CC6.1", "Logical access security"),
)
_m("JIS-003",  # Identity verified
   _R("iso_27001", "§A.5.16", "Identity management — verification"),
   _R("eu_ai_act", "Art.16(j)", "Provider — registration in EU database"),
   _R("gdpr", "Art.5(1)(d)", "Accuracy of personal data"),
)
_m("JIS-004",  # Sovereign binding
   _R("iso_42001", "§6.1.4", "AI system context and boundaries"),
   _R("iso_27001", "§A.5.23", "Cloud service security"),
   _R("eu_ai_act", "Art.25", "Obligations of distributors"),
)

# ── UPIP Process Integrity (IETF Draft) ─────────────────────────────

_m("UPIP-001",  # Process integrity policy
   _R("iso_42001", "§8.2", "AI development process requirements"),
   _R("iso_23894", "§6.2", "AI risk assessment process"),
   _R("eu_ai_act", "Art.9(2)(a)", "Risk management — identify and analyze risks"),
   _R("soc2", "PI1.2", "Processing integrity — accuracy of processing"),
)
_m("UPIP-002",  # Evaporation policy
   _R("iso_27701", "§7.4.5", "Data minimization"),
   _R("gdpr", "Art.5(1)(e)", "Storage limitation"),
   _R("gdpr", "Art.17", "Right to erasure"),
   _R("nist_ai_rmf", "GOVERN 1.6", "Data governance"),
)
_m("UPIP-003",  # Bilateral consent
   _R("iso_27701", "§7.2.3", "Determining lawful basis"),
   _R("gdpr", "Art.6", "Lawfulness of processing"),
   _R("gdpr", "Art.7", "Conditions for consent"),
   _R("eu_ai_act", "Art.14(3)(d)", "Human oversight — consent mechanisms"),
)
_m("UPIP-004",  # Step attestation
   _R("iso_42001", "§8.4", "AI system operation verification"),
   _R("iso_5338", "§7.2.5", "Verification and validation"),
   _R("soc2", "PI1.3", "Processing integrity — timeliness"),
)

# ── RVP Continuous Verification (IETF Draft) ────────────────────────

_m("RVP-001",  # Heartbeat active
   _R("iso_42001", "§9.1", "Monitoring and measurement"),
   _R("iso_27001", "§A.8.16", "Monitoring activities"),
   _R("nis2", "Art.21(2)(b)", "Incident handling"),
   _R("soc2", "CC7.1", "Security — monitoring"),
)
_m("RVP-002",  # Drift detection
   _R("iso_42001", "§9.1.2", "AI performance monitoring"),
   _R("iso_23894", "§6.5", "AI risk monitoring and review"),
   _R("eu_ai_act", "Art.9(2)(b)", "Risk management — continuous monitoring"),
   _R("nist_ai_rmf", "MEASURE 1.1", "AI system performance measurement"),
)
_m("RVP-003",  # Verification schedule
   _R("iso_27001", "§9.2", "Internal audit"),
   _R("nis2", "Art.21(2)(f)", "Assessment of cybersecurity measures"),
   _R("soc2", "CC4.1", "Monitoring — ongoing evaluations"),
)

# ── AINS Agent Discovery (IETF Draft) ───────────────────────────────

_m("AINS-001",  # Agent registered
   _R("iso_42001", "§7.3", "AI system registration"),
   _R("eu_ai_act", "Art.49", "Registration in EU database"),
   _R("eu_ai_act", "Art.16(j)", "Provider registration obligations"),
)
_m("AINS-002",  # Discovery endpoint
   _R("iso_27001", "§A.5.23", "Cloud/service discovery security"),
   _R("iso_42001", "§7.5", "Documented information — accessibility"),
)
_m("AINS-003",  # Capability declaration
   _R("iso_42001", "§6.1.3", "AI system capability documentation"),
   _R("eu_ai_act", "Art.13(3)(b)(i)", "Transparency — capabilities and limitations"),
   _R("nist_ai_rmf", "MAP 2.1", "AI system capabilities specification"),
)

# ── GDPR ─────────────────────────────────────────────────────────────

_m("GDPR-001",  # Privacy policy
   _R("gdpr", "Art.13", "Information to data subject"),
   _R("gdpr", "Art.14", "Information — indirect collection"),
   _R("iso_27701", "§7.3.2", "Privacy notice"),
   _R("eu_ai_act", "Art.13", "Transparency — user information"),
)
_m("GDPR-002",  # Data processing records
   _R("gdpr", "Art.30", "Records of processing activities"),
   _R("iso_27701", "§7.2.8", "Records related to processing PII"),
   _R("soc2", "P1.1", "Privacy — notice and communication"),
)
_m("GDPR-003",  # Consent mechanism
   _R("gdpr", "Art.7", "Conditions for consent"),
   _R("gdpr", "Art.8", "Child's consent"),
   _R("iso_27701", "§7.2.3", "Determining lawful basis"),
)
_m("GDPR-004",  # Data retention
   _R("gdpr", "Art.5(1)(e)", "Storage limitation"),
   _R("gdpr", "Art.17", "Right to erasure"),
   _R("iso_27701", "§7.4.7", "Data retention and disposal"),
)
_m("GDPR-005",  # Breach notification
   _R("gdpr", "Art.33", "Notification to supervisory authority"),
   _R("gdpr", "Art.34", "Communication to data subject"),
   _R("nis2", "Art.23", "Incident reporting obligations"),
   _R("iso_27001", "§A.5.26", "Response to information security incidents"),
)
_m("GDPR-006",  # DPO designation
   _R("gdpr", "Art.37", "Designation of DPO"),
   _R("iso_27701", "§6.3", "Organization roles"),
)
_m("GDPR-007",  # Cross-border transfer
   _R("gdpr", "Art.44-49", "International data transfers"),
   _R("iso_27701", "§7.5", "PII sharing, transfer, and disclosure"),
)
_m("GDPR-008",  # DPIA
   _R("gdpr", "Art.35", "Data protection impact assessment"),
   _R("iso_27701", "§7.2.5", "Privacy impact assessment"),
   _R("eu_ai_act", "Art.9(5)", "FRIA — fundamental rights impact assessment"),
)

# ── EU AI Act ────────────────────────────────────────────────────────

_m("AIACT-001",  # AI decision audit trail
   _R("eu_ai_act", "Art.12", "Record-keeping"),
   _R("eu_ai_act", "Art.13", "Transparency"),
   _R("iso_42001", "§9.1", "Monitoring and measurement"),
   _R("iso_5338", "§7.3.2", "AI traceability"),
)
_m("AIACT-002",  # Human oversight mechanism
   _R("eu_ai_act", "Art.14", "Human oversight"),
   _R("iso_42001", "§8.4.2", "Human-AI interaction controls"),
   _R("nist_ai_rmf", "GOVERN 3.2", "Human-AI teaming"),
)
_m("AIACT-003",  # Risk classification
   _R("eu_ai_act", "Art.6", "Classification rules — high-risk"),
   _R("eu_ai_act", "Art.9", "Risk management system"),
   _R("iso_23894", "§6.2", "AI risk assessment"),
   _R("nist_ai_rmf", "MAP 1.1", "AI system risk identification"),
)
_m("AIACT-004",  # Technical documentation
   _R("eu_ai_act", "Art.11", "Technical documentation"),
   _R("eu_ai_act", "Annex IV", "Technical documentation content"),
   _R("iso_42001", "§7.5", "Documented information"),
   _R("iso_5338", "§7.2", "AI system documentation"),
)
_m("AIACT-005",  # Data governance
   _R("eu_ai_act", "Art.10", "Data and data governance"),
   _R("iso_42001", "§8.3", "AI data management"),
   _R("nist_ai_rmf", "MAP 2.3", "AI data requirements"),
)
_m("AIACT-006",  # Model robustness
   _R("eu_ai_act", "Art.15", "Accuracy, robustness, cybersecurity"),
   _R("iso_42001", "§8.4", "AI system robustness requirements"),
   _R("iso_23894", "§6.3", "AI risk treatment — robustness"),
)
_m("AIACT-007",  # Bias detection
   _R("eu_ai_act", "Art.10(2)(f)", "Data governance — bias examination"),
   _R("iso_42001", "§8.3.3", "AI fairness and bias management"),
   _R("nist_ai_rmf", "MAP 2.3", "AI fairness assessment"),
)
_m("AIACT-008",  # CE marking / conformity
   _R("eu_ai_act", "Art.16(g)", "Provider — CE marking"),
   _R("eu_ai_act", "Art.43", "Conformity assessment"),
   _R("eu_ai_act", "Art.47", "EU declaration of conformity"),
)

# ── NIS2 ─────────────────────────────────────────────────────────────

_m("NIS2-001",  # Risk assessment
   _R("nis2", "Art.21(2)(a)", "Risk analysis and information system security"),
   _R("iso_27001", "§6.1.2", "Information security risk assessment"),
   _R("iso_23894", "§6.2", "AI risk assessment"),
)
_m("NIS2-002",  # Incident response
   _R("nis2", "Art.21(2)(b)", "Incident handling"),
   _R("nis2", "Art.23", "Reporting obligations"),
   _R("iso_27001", "§A.5.24-5.28", "Incident management"),
   _R("gdpr", "Art.33", "Breach notification"),
)
_m("NIS2-003",  # Business continuity
   _R("nis2", "Art.21(2)(c)", "Business continuity and crisis management"),
   _R("iso_27001", "§A.5.29-5.30", "Business continuity"),
   _R("soc2", "A1.2", "Availability — recovery plans"),
)
_m("NIS2-004",  # Supply chain security
   _R("nis2", "Art.21(2)(d)", "Supply chain security"),
   _R("iso_27001", "§A.5.19-5.22", "Supplier relationships"),
   _R("eu_ai_act", "Art.25", "Obligations of distributors"),
)
_m("NIS2-005",  # Vulnerability management
   _R("nis2", "Art.21(2)(e)", "Vulnerability handling and disclosure"),
   _R("iso_27001", "§A.8.8", "Management of technical vulnerabilities"),
)
_m("NIS2-006",  # Effectiveness assessment
   _R("nis2", "Art.21(2)(f)", "Assessment of cybersecurity measures"),
   _R("iso_27001", "§9.2", "Internal audit"),
   _R("iso_27001", "§9.3", "Management review"),
)
_m("NIS2-007",  # Cyber hygiene
   _R("nis2", "Art.21(2)(g)", "Basic cyber hygiene and training"),
   _R("iso_27001", "§A.6.3", "Information security awareness"),
)
_m("NIS2-008",  # Cryptography
   _R("nis2", "Art.21(2)(h)", "Cryptography and encryption policies"),
   _R("iso_27001", "§A.8.24", "Use of cryptography"),
)
_m("NIS2-009",  # Access control
   _R("nis2", "Art.21(2)(i)", "HR security and access control"),
   _R("iso_27001", "§A.5.15-5.18", "Access control"),
   _R("soc2", "CC6.1-6.3", "Logical and physical access"),
)
_m("NIS2-010",  # MFA / secure auth
   _R("nis2", "Art.21(2)(j)", "Multi-factor authentication"),
   _R("iso_27001", "§A.8.5", "Secure authentication"),
)

# ── TLS / Certificate Checks ────────────────────────────────────────

_m("TLS-001",  # Chain integrity
   _R("iso_27001", "§A.8.24", "Use of cryptography — certificate chain"),
   _R("nis2", "Art.21(2)(h)", "Cryptography and encryption"),
   _R("soc2", "CC6.1", "Logical access — encryption in transit"),
)
_m("TLS-002",  # Certificate expiry
   _R("iso_27001", "§A.8.24", "Cryptographic key lifecycle"),
   _R("nis2", "Art.21(2)(e)", "Vulnerability handling — certificate management"),
)
_m("TLS-003",  # Protocol version
   _R("iso_27001", "§A.8.24", "Cryptographic controls — protocol strength"),
   _R("nis2", "Art.21(2)(h)", "Encryption — modern protocols"),
)
_m("TLS-004",  # Cipher strength
   _R("iso_27001", "§A.8.24", "Cryptographic controls — cipher selection"),
   _R("nis2", "Art.21(2)(h)", "Encryption — cipher suite policy"),
)
_m("TLS-005",  # Hostname verification
   _R("iso_27001", "§A.5.17", "Authentication — server identity"),
   _R("soc2", "CC6.1", "Logical access — entity authentication"),
)
_m("TLS-006",  # Key strength
   _R("iso_27001", "§A.8.24", "Cryptographic key strength"),
   _R("nis2", "Art.21(2)(h)", "Encryption — key management"),
)
_m("TLS-007",  # Security headers
   _R("iso_27001", "§A.8.9", "Configuration management — HTTP headers"),
   _R("nis2", "Art.21(2)(a)", "Information system security — transport"),
)
_m("TLS-008",  # Version disclosure
   _R("iso_27001", "§A.8.9", "Configuration management — information disclosure"),
   _R("nis2", "Art.21(2)(a)", "Information system security — hardening"),
)

# ── Provider Security ────────────────────────────────────────────────

_m("PROV-001",  # Firewall
   _R("iso_27001", "§A.8.20", "Network security"),
   _R("nis2", "Art.21(2)(a)", "Information system security"),
)
_m("PROV-002",  # Updates
   _R("iso_27001", "§A.8.8", "Technical vulnerability management"),
   _R("nis2", "Art.21(2)(e)", "Vulnerability handling"),
)

# ── Sovereignty ──────────────────────────────────────────────────────

_m("SOV-001",  # Data residency
   _R("gdpr", "Art.44-49", "International transfers"),
   _R("iso_27701", "§7.5", "PII transfer controls"),
   _R("eu_ai_act", "Art.10(5)", "Data governance — geographical scope"),
)

# ── Regional Privacy Laws ────────────────────────────────────────────
# These map back to ISO 27701 (privacy) as the universal standard

# ── Humotica Pillars (actual IDs) ────────────────────────────────────

_m("PILLAR-000",  # Three Pillars Gate
   _R("iso_42001", "§5.1", "Leadership and commitment — AI governance"),
   _R("eu_ai_act", "Art.9", "Risk management system"),
   _R("iso_27001", "§5.1", "Leadership and commitment"),
)
_m("PILLAR-001",  # SNAFT integration
   _R("iso_42001", "§8.4", "AI system security controls"),
   _R("iso_23894", "§6.3", "AI risk treatment — syscall filtering"),
   _R("eu_ai_act", "Art.15", "Accuracy, robustness, cybersecurity"),
   _R("nis2", "Art.21(2)(a)", "Risk analysis and system security"),
)
_m("PILLAR-002",  # JIS Router integration
   _R("iso_27001", "§A.5.16", "Identity management"),
   _R("eu_ai_act", "Art.14(4)(c)", "Human oversight — identify AI system"),
   _R("iso_42001", "§7.3", "AI system identification"),
)
_m("PILLAR-003",  # TIBET Engine integration
   _R("iso_42001", "§9.1", "Monitoring and measurement"),
   _R("iso_5338", "§7.3.2", "AI lifecycle traceability"),
   _R("eu_ai_act", "Art.12", "Record-keeping"),
)
_m("PILLAR-004",  # AETHER integration
   _R("iso_42001", "§8.4", "AI system operation and monitoring"),
   _R("eu_ai_act", "Art.14", "Human oversight mechanisms"),
   _R("nist_ai_rmf", "GOVERN 3.2", "Human-AI teaming"),
)

# ── Additional AINS ──────────────────────────────────────────────────

_m("AINS-004",  # Discovery endpoint
   _R("iso_42001", "§7.5", "Documented information — accessibility"),
   _R("iso_27001", "§A.5.23", "Cloud/service discovery security"),
)

# ── Additional JIS ───────────────────────────────────────────────────

_m("JIS-005",  # Intent declaration
   _R("iso_42001", "§8.2", "AI development — intent specification"),
   _R("eu_ai_act", "Art.13(3)(b)(ii)", "Transparency — intended purpose"),
   _R("iso_5338", "§7.2.3", "AI system requirements specification"),
)
_m("JIS-006",  # JIS URI scheme
   _R("iso_27001", "§A.5.16", "Identity management — URI scheme"),
   _R("iso_42001", "§7.3", "AI system identification — addressing"),
)

# ── Additional UPIP ─────────────────────────────────────────────────

_m("UPIP-005",  # Build reproducibility
   _R("iso_42001", "§8.2", "AI development — reproducibility"),
   _R("iso_5338", "§7.2.5", "Verification and validation — builds"),
   _R("eu_ai_act", "Art.15(3)", "Robustness — reproducible results"),
   _R("soc2", "PI1.4", "Processing integrity — completeness"),
)

# ── Additional RVP ──────────────────────────────────────────────────

_m("RVP-004",  # Incident response & trust recovery
   _R("nis2", "Art.21(2)(b)", "Incident handling — recovery"),
   _R("iso_27001", "§A.5.26", "Response to information security incidents"),
   _R("eu_ai_act", "Art.9(8)", "Risk management — corrective actions"),
)

# ── Additional Health ────────────────────────────────────────────────

for hid, clause, title in [
    ("HEALTH-006", "§A.8.6", "Capacity management — swap"),
    ("HEALTH-007", "§A.8.9", "Configuration management — temp files"),
    ("HEALTH-008", "§A.8.6", "Capacity management — process health"),
    ("HEALTH-009", "§A.8.6", "Capacity management — service manager"),
    ("HEALTH-010", "§A.8.6", "Capacity management — uptime"),
    ("HEALTH-011", "§A.8.6", "Capacity management — session type"),
    ("HEALTH-012", "§A.8.20", "Network security — connection monitoring"),
    ("HEALTH-013", "§A.8.20", "Network security — service monitoring"),
    ("HEALTH-014", "§A.8.6", "Capacity management — GPU monitoring"),
]:
    _m(hid,
       _R("iso_27001", clause, title),
       _R("nis2", "Art.21(2)(c)", "Business continuity"),
    )

# ── Additional Provider Security ─────────────────────────────────────

_m("PROV-003",  # AI model integrity
   _R("iso_42001", "§8.4", "AI system operation — model integrity"),
   _R("eu_ai_act", "Art.15", "Accuracy, robustness, cybersecurity"),
)
_m("PROV-004",  # AI-to-AI lane encryption
   _R("iso_27001", "§A.8.24", "Cryptography — transit encryption"),
   _R("nis2", "Art.21(2)(h)", "Cryptography and encryption"),
)
_m("PROV-005",  # ASP/DRM binding
   _R("iso_27001", "§A.5.19", "Supplier relationship — binding"),
   _R("nis2", "Art.21(2)(d)", "Supply chain security"),
)

# ── Additional Sovereignty ───────────────────────────────────────────

_m("SOV-002",  # Third-party processor
   _R("gdpr", "Art.28", "Processor obligations"),
   _R("iso_27001", "§A.5.19-5.22", "Supplier relationships"),
   _R("iso_27701", "§7.2.6", "Contracts with PII processors"),
)
_m("SOV-003",  # Cross-border transfer policy
   _R("gdpr", "Art.44-49", "International transfers"),
   _R("iso_27701", "§7.5", "PII transfer controls"),
)
_m("SOV-004",  # Encryption at rest
   _R("iso_27001", "§A.8.24", "Use of cryptography — at rest"),
   _R("nis2", "Art.21(2)(h)", "Cryptography and encryption"),
)

# ── UCP Commerce Protocol ───────────────────────────────────────────

for uid in [f"UCP-{i:03d}" for i in range(1, 9)]:
    _m(uid,
       _R("iso_42001", "§7.5", "Documented information — commerce protocol"),
       _R("eu_ai_act", "Art.13", "Transparency — commerce capabilities"),
    )

# ── Australia Privacy (actual IDs: AUPA) ────────────────────────────

for i in range(1, 6):
    _m(f"AUPA-{i:03d}",
       _R("iso_27701", "§7.2-7.5", "Privacy information management"),
       _R("iso_27001", "§A.5.34", "Privacy and PII protection"),
    )

# ── Regional Privacy Laws ────────────────────────────────────────────

for prefix in ["PIPA", "APPI", "PDPA", "LGPD", "GULF", "NDPR"]:
    for i in range(1, 9):
        cid = f"{prefix}-{i:03d}"
        _m(cid,
           _R("iso_27701", "§7.2-7.5", "Privacy information management"),
           _R("iso_27001", "§A.5.34", "Privacy and PII protection"),
        )


# ══════════════════════════════════════════════════════════════════════
# Query API
# ══════════════════════════════════════════════════════════════════════

def get_mapping(check_id: str) -> Optional[CheckMapping]:
    """Get compliance mapping for a check ID."""
    return COMPLIANCE_MAP.get(check_id)


def get_all_mappings() -> Dict[str, CheckMapping]:
    """Get all compliance mappings."""
    return COMPLIANCE_MAP


def get_framework_coverage(results: list, framework: str = None) -> dict:
    """
    Calculate framework coverage from scan results.

    Args:
        results: List of CheckResult objects from a scan
        framework: Optional specific framework (e.g., "iso_42001"). None = all.

    Returns:
        Dict with coverage stats per framework:
        {
            "iso_42001": {
                "name": "ISO/IEC 42001:2023",
                "total_clauses": 15,
                "covered_clauses": 12,
                "passed": 10,
                "failed": 2,
                "coverage_pct": 80.0,
                "clauses": [...]
            }
        }
    """
    from .checks.base import Status

    coverage = {}

    for result in results:
        mapping = COMPLIANCE_MAP.get(result.check_id)
        if not mapping:
            continue

        for ref in mapping.refs:
            if framework and ref.framework != framework:
                continue

            fw = ref.framework
            if fw not in coverage:
                info = FRAMEWORKS.get(fw, {"name": fw, "title": fw})
                coverage[fw] = {
                    "name": info["name"],
                    "title": info["title"],
                    "clauses": {},
                    "total_checks": 0,
                    "passed": 0,
                    "warned": 0,
                    "failed": 0,
                }

            cov = coverage[fw]
            cov["total_checks"] += 1

            if result.status == Status.PASSED:
                cov["passed"] += 1
            elif result.status == Status.WARNING:
                cov["warned"] += 1
            elif result.status == Status.FAILED:
                cov["failed"] += 1

            # Track unique clauses
            clause_key = ref.clause
            if clause_key not in cov["clauses"]:
                cov["clauses"][clause_key] = {
                    "clause": ref.clause,
                    "title": ref.title,
                    "checks": [],
                    "status": "pass",
                }
            cov["clauses"][clause_key]["checks"].append(result.check_id)
            if result.status == Status.FAILED:
                cov["clauses"][clause_key]["status"] = "fail"
            elif result.status == Status.WARNING and cov["clauses"][clause_key]["status"] != "fail":
                cov["clauses"][clause_key]["status"] = "warn"

    # Calculate percentages
    for fw, cov in coverage.items():
        total = cov["total_checks"]
        cov["coverage_pct"] = round(cov["passed"] / total * 100, 1) if total > 0 else 0
        cov["total_clauses"] = len(cov["clauses"])
        cov["passed_clauses"] = sum(1 for c in cov["clauses"].values() if c["status"] == "pass")

    return coverage


def generate_jis_compliance_block(results: list) -> dict:
    """
    Generate the compliance block for jis.json.

    This is the machine-readable trustworthiness report that goes into
    every package's identity document.
    """
    from .checks.base import Status

    checks = []
    for result in results:
        mapping = COMPLIANCE_MAP.get(result.check_id)
        entry = {
            "id": result.check_id,
            "description": result.name,
            "status": result.status.value.upper(),
        }

        if mapping:
            for ref in mapping.refs:
                fw_key = ref.framework
                if fw_key == "iso_42001":
                    entry["iso_42001"] = f"ISO/IEC 42001:2023 {ref.clause}"
                elif fw_key == "iso_27001":
                    entry["iso_27001"] = f"ISO/IEC 27001:2022 {ref.clause}"
                elif fw_key == "iso_23894":
                    entry["iso_23894"] = f"ISO/IEC 23894:2023 {ref.clause}"
                elif fw_key == "iso_5338":
                    entry["iso_5338"] = f"ISO/IEC 5338:2023 {ref.clause}"
                elif fw_key == "iso_27701":
                    entry["iso_27701"] = f"ISO/IEC 27701:2019 {ref.clause}"
                elif fw_key == "eu_ai_act":
                    entry.setdefault("eu_ai_act", f"EU AI Act {ref.clause}")
                elif fw_key == "nis2":
                    entry.setdefault("nis2", f"NIS2 {ref.clause}")
                elif fw_key == "gdpr":
                    entry.setdefault("gdpr", f"GDPR {ref.clause}")
                elif fw_key == "nist_ai_rmf":
                    entry.setdefault("nist_ai_rmf", f"NIST AI RMF {ref.clause}")
                elif fw_key == "soc2":
                    entry.setdefault("soc2", f"SOC 2 {ref.clause}")

        if result.status != Status.PASSED and result.message:
            entry["evidence"] = result.message[:200]
        elif result.status == Status.PASSED:
            entry["evidence"] = f"tibet://audit/{result.check_id}/pass"

        checks.append(entry)

    # Calculate coverage summary
    coverage = get_framework_coverage(results)
    summary = {
        "total": len(checks),
        "passed": sum(1 for c in checks if c["status"] == "PASS"),
        "warned": sum(1 for c in checks if c["status"] == "WARNING"),
        "failed": sum(1 for c in checks if c["status"] == "FAILED"),
    }
    for fw_key, cov in coverage.items():
        summary[f"{fw_key}_coverage"] = f"{cov['coverage_pct']}%"

    return {
        "compliance": {
            "scanner": "tibet-audit",
            "version": "0.23.0",
            "frameworks": list(FRAMEWORKS.keys()),
            "checks": checks,
            "summary": summary,
        }
    }
