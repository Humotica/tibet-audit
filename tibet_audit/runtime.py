"""
TIBET Audit - Runtime Verification & Semantic Reporting
=======================================================
The 'Kinetic' layer of TIBET Audit.
Links static checks to runtime identity and intent.
"""

import json
import os
import time
import hashlib
from dataclasses import dataclass, asdict
from typing import Dict, Any, Optional

try:
    import tibet_rs
except ImportError:
    tibet_rs = None

@dataclass
class AuditContext:
    """Who, Where and Why of the audit."""
    user_id: str          # JIS Identity
    environment: str      # prod, dev, sandbox
    intent: str           # routine_scan, emergency_fix, ci_cd
    timestamp: float

class RuntimeAudit:
    """
    The active guardian.
    Converts static scan results into a verified narrative.
    """

    def __init__(self, user_id: str = "unknown", intent: str = "manual_scan"):
        self.context = AuditContext(
            user_id=user_id,
            environment=os.getenv("JIS_ENV", "local"),
            intent=intent,
            timestamp=time.time()
        )

    def semantify(self, scan_result: Dict[str, Any]) -> str:
        """
        Translate raw data into a human-readable narrative.
        """
        score = scan_result.get("score", 0)
        failed = scan_result.get("failed", 0)

        # The Narrative Engine
        story = [f"Audit performed by {self.context.user_id} in {self.context.environment}."]

        if score >= 90:
            story.append(f"🟢 Excellent! Score {score}/100. The system is compliant.")
        elif score >= 70:
            story.append(f"🟠 Moderate (Score {score}). There are {failed} items that require attention.")
        else:
            story.append(f"🔴 Critical (Score {score}). Security is at risk. Start Diaper Protocol!")

        # Semantic Deep Dive
        if "AI Act" in str(scan_result):
            story.append("   - AI Act: Decision audit trail is missing.")

        return "\n".join(story)

    def secure_log(self, scan_result: Dict[str, Any]) -> str:
        """
        Prepare the TIBET token (cryptographic evidence).
        Uses Rust-powered signing if available.
        """
        # Canonicalize payload for deterministic signing
        payload = {
            "meta": asdict(self.context),
            "score": scan_result.get("score"),
            "failed_count": scan_result.get("failed", 0)
        }
        canonical_json = json.dumps(payload, sort_keys=True, separators=( ",", ":"))

        # Get secret (TIBET_SECRET)
        secret = os.getenv("TIBET_SECRET", "dev-secret-do-not-use-in-prod")

        if tibet_rs:
            # Rust-powered speed & safety 🦀
            signature = tibet_rs.tibet_sign(canonical_json, secret)
            method = "tibet-rs-hmac-sha256"
        else:
            # Python fallback (slower) 🐍
            signature = hashlib.sha256(f"{canonical_json}{secret}".encode()).hexdigest()
            method = "python-fallback-sha256"

        return f"TIBET_V1.{method}.{signature}.{self.context.user_id}"

# Example usage:
# auditor = RuntimeAudit(user_id="user_1", intent="optimization")
# print(auditor.semantify({"score": 73, "failed": 3}))
