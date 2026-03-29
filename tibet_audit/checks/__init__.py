"""Compliance checks - pluggable check system."""

from .base import BaseCheck, CheckResult, Status, Severity
from .gdpr import GDPR_CHECKS          # EU
from .ai_act import AI_ACT_CHECKS      # EU AI Regulation
from .pipa import PIPA_CHECKS          # South Korea
from .appi import APPI_CHECKS          # Japan
from .pdpa import PDPA_CHECKS          # Singapore
from .privacy_act_au import AU_PRIVACY_CHECKS  # Australia
from .lgpd import LGPD_CHECKS          # Brazil
from .gulf_pdpl import GULF_CHECKS     # Saudi Arabia, UAE, Gulf region
from .ndpr import NDPR_CHECKS          # Nigeria
from .penguin_act import PENGUIN_CHECKS  # Antarctica (Easter egg!)
from .jis import JIS_CHECKS            # JIS compliance (IETF draft)
from .tibet import TIBET_CHECKS        # TIBET provenance (IETF draft)
from .upip import UPIP_CHECKS         # UPIP process integrity (IETF draft)
from .rvp import RVP_CHECKS           # RVP continuous verification (IETF draft)
from .ains import AINS_CHECKS         # AINS discovery (IETF draft)
from .sovereignty import SOVEREIGNTY_CHECKS  # Sovereignty and residency
from .provider_security import PROVIDER_SECURITY_CHECKS  # Provider security
from .nis2 import NIS2_CHECKS            # EU NIS2 Directive
from .ucp import UCP_CHECKS              # UCP Commerce Protocol
from .health import HEALTH_CHECKS        # System health & energy
from .humotica_pillars import HUMOTICA_PILLAR_CHECKS  # Three Pillars for A-grade

# All available checks - Global Coverage!
ALL_CHECKS = []
ALL_CHECKS.extend(HUMOTICA_PILLAR_CHECKS)  # 🏛️ Three Pillars (A-grade gate!)
ALL_CHECKS.extend(HEALTH_CHECKS)       # 💚 System Health & Energy
ALL_CHECKS.extend(TIBET_CHECKS)        # 📜 TIBET Provenance (IETF)
ALL_CHECKS.extend(JIS_CHECKS)         # 🧭 JIS Identity (IETF)
ALL_CHECKS.extend(UPIP_CHECKS)        # 🔒 UPIP Process Integrity (IETF)
ALL_CHECKS.extend(RVP_CHECKS)         # 🔄 RVP Continuous Verification (IETF)
ALL_CHECKS.extend(AINS_CHECKS)        # 🌐 AINS Discovery (IETF)
ALL_CHECKS.extend(GDPR_CHECKS)         # 🇪🇺 Europe
ALL_CHECKS.extend(AI_ACT_CHECKS)       # 🇪🇺 EU AI Act
ALL_CHECKS.extend(PIPA_CHECKS)         # 🇰🇷 South Korea
ALL_CHECKS.extend(APPI_CHECKS)         # 🇯🇵 Japan
ALL_CHECKS.extend(PDPA_CHECKS)         # 🇸🇬 Singapore
ALL_CHECKS.extend(AU_PRIVACY_CHECKS)   # 🇦🇺 Australia
ALL_CHECKS.extend(LGPD_CHECKS)         # 🇧🇷 Brazil
ALL_CHECKS.extend(GULF_CHECKS)         # 🇸🇦🇦🇪 Gulf Region
ALL_CHECKS.extend(NDPR_CHECKS)         # 🇳🇬 Nigeria
ALL_CHECKS.extend(PENGUIN_CHECKS)      # 🐧 Antarctica
ALL_CHECKS.extend(SOVEREIGNTY_CHECKS)  # 🛰 Sovereignty
ALL_CHECKS.extend(PROVIDER_SECURITY_CHECKS)  # 🛡 Provider security
ALL_CHECKS.extend(NIS2_CHECKS)            # 🇪🇺 NIS2 Directive
ALL_CHECKS.extend(UCP_CHECKS)             # 🛒 UCP Commerce Protocol

# IETF Compliance Pack - all 5 IETF Internet-Drafts
IETF_COMPLIANCE_CHECKS = []
IETF_COMPLIANCE_CHECKS.extend(TIBET_CHECKS)    # Provenance
IETF_COMPLIANCE_CHECKS.extend(JIS_CHECKS)      # Identity
IETF_COMPLIANCE_CHECKS.extend(UPIP_CHECKS)     # Process Integrity
IETF_COMPLIANCE_CHECKS.extend(RVP_CHECKS)      # Continuous Verification
IETF_COMPLIANCE_CHECKS.extend(AINS_CHECKS)     # Agent Discovery

# EU Compliance Pack - bundle for US companies targeting EU market
EU_COMPLIANCE_CHECKS = []
EU_COMPLIANCE_CHECKS.extend(GDPR_CHECKS)      # Privacy
EU_COMPLIANCE_CHECKS.extend(AI_ACT_CHECKS)    # AI Regulation
EU_COMPLIANCE_CHECKS.extend(NIS2_CHECKS)      # Cybersecurity

__all__ = [
    "BaseCheck", "CheckResult", "Status", "Severity",
    "ALL_CHECKS", "IETF_COMPLIANCE_CHECKS", "EU_COMPLIANCE_CHECKS",
    "TIBET_CHECKS", "JIS_CHECKS", "UPIP_CHECKS", "RVP_CHECKS", "AINS_CHECKS",
    "HEALTH_CHECKS", "HUMOTICA_PILLAR_CHECKS",
]
