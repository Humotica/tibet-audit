"""
tibet-audit integrations

Export tibet-audit checks to other security tools:
- Checkov (IaC scanning)
- SARIF (GitHub Security, IDE integration)
- More coming...
"""

from .checkov_adapter import export_checkov_policies, TIBET_CHECKS

__all__ = ['export_checkov_policies', 'TIBET_CHECKS']
