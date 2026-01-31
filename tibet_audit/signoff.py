"""
TIBET Sign-off Module - Human Verification with JIS Bilateral Consent

"TIBET prepares, Human verifies, JIS seals."

This module implements the jurist sign-off workflow:
1. AI/Tool generates compliance assessment (TIBET token)
2. Human reviews and approves
3. JIS bilateral consent cryptographically seals the approval

Authors: Jasper van de Meent & Root AI
License: MIT
"""

import hashlib
import json
import uuid
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import Optional, List
from enum import Enum


class SignoffState(Enum):
    """States for the sign-off workflow."""
    PENDING_REVIEW = "PENDING_REVIEW"      # AI work done, awaiting human
    UNDER_REVIEW = "UNDER_REVIEW"          # Human is reviewing
    HUMAN_VERIFIED = "HUMAN_VERIFIED"      # Human approved
    HUMAN_REJECTED = "HUMAN_REJECTED"      # Human rejected
    JIS_SEALED = "JIS_SEALED"              # Cryptographically sealed


@dataclass
class SignoffRecord:
    """
    A sign-off record for audit trail.

    Maps to TIBET provenance: ERIN (what), ERAAN (attached),
    EROMHEEN (context), ERACHTER (intent).
    """
    signoff_id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])

    # ERIN - What's being signed off
    scan_id: str = ""
    scan_path: str = ""
    scan_score: int = 0
    scan_grade: str = ""
    issues_fixed: int = 0

    # ERAAN - What's attached
    tibet_token_id: Optional[str] = None
    parent_signoff_id: Optional[str] = None

    # EROMHEEN - Context
    tool_version: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    state: SignoffState = SignoffState.PENDING_REVIEW

    # ERACHTER - Intent
    reviewer_name: Optional[str] = None
    reviewer_did: Optional[str] = None  # did:jis:reviewer:xxx
    review_comment: Optional[str] = None

    # JIS Seal
    jis_consent_hash: Optional[str] = None
    sealed_at: Optional[datetime] = None

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        d = asdict(self)
        d['timestamp'] = self.timestamp.isoformat()
        d['state'] = self.state.value
        if self.sealed_at:
            d['sealed_at'] = self.sealed_at.isoformat()
        return d

    @classmethod
    def from_dict(cls, data: dict) -> 'SignoffRecord':
        """Create from dictionary."""
        data['timestamp'] = datetime.fromisoformat(data['timestamp'])
        data['state'] = SignoffState(data['state'])
        if data.get('sealed_at'):
            data['sealed_at'] = datetime.fromisoformat(data['sealed_at'])
        return cls(**data)


class SignoffManager:
    """
    Manages the sign-off workflow for tibet-audit.

    The Diaper Protocol addendum:
    "AI verschoont de luier, jurist checkt of de baby lacht, JIS plakt de sticker 'goedgekeurd'."
    """

    def __init__(self, storage_path: Optional[str] = None):
        """Initialize sign-off manager."""
        from pathlib import Path
        self.storage_path = Path(storage_path) if storage_path else Path.home() / ".tibet-audit" / "signoffs"
        self.storage_path.mkdir(parents=True, exist_ok=True)

    def create_signoff_request(
        self,
        scan_id: str,
        scan_path: str,
        scan_score: int,
        scan_grade: str,
        issues_fixed: int,
        tool_version: str,
        tibet_token_id: Optional[str] = None
    ) -> SignoffRecord:
        """
        Create a new sign-off request after fixes are applied.

        Args:
            scan_id: The original scan ID
            scan_path: Path that was scanned
            scan_score: Compliance score
            scan_grade: Grade (A-F)
            issues_fixed: Number of issues that were fixed
            tool_version: tibet-audit version
            tibet_token_id: Optional TIBET token ID for provenance

        Returns:
            SignoffRecord in PENDING_REVIEW state
        """
        record = SignoffRecord(
            scan_id=scan_id,
            scan_path=scan_path,
            scan_score=scan_score,
            scan_grade=scan_grade,
            issues_fixed=issues_fixed,
            tool_version=tool_version,
            tibet_token_id=tibet_token_id,
            state=SignoffState.PENDING_REVIEW
        )

        self._save_record(record)
        return record

    def start_review(self, signoff_id: str, reviewer_name: str, reviewer_did: Optional[str] = None) -> SignoffRecord:
        """
        Mark a sign-off as under review.

        Args:
            signoff_id: The sign-off ID
            reviewer_name: Name of the reviewer (e.g., "Eva de Vries, Jurist")
            reviewer_did: Optional DID of reviewer (e.g., "did:jis:jurist:eva.devries")
        """
        record = self._load_record(signoff_id)
        if not record:
            raise ValueError(f"Sign-off {signoff_id} not found")

        record.state = SignoffState.UNDER_REVIEW
        record.reviewer_name = reviewer_name
        record.reviewer_did = reviewer_did

        self._save_record(record)
        return record

    def approve(self, signoff_id: str, comment: Optional[str] = None) -> SignoffRecord:
        """
        Human approves the compliance assessment.

        Args:
            signoff_id: The sign-off ID
            comment: Optional review comment
        """
        record = self._load_record(signoff_id)
        if not record:
            raise ValueError(f"Sign-off {signoff_id} not found")

        if record.state not in [SignoffState.PENDING_REVIEW, SignoffState.UNDER_REVIEW]:
            raise ValueError(f"Cannot approve sign-off in state {record.state.value}")

        record.state = SignoffState.HUMAN_VERIFIED
        record.review_comment = comment

        self._save_record(record)
        return record

    def reject(self, signoff_id: str, reason: str) -> SignoffRecord:
        """
        Human rejects the compliance assessment.

        Args:
            signoff_id: The sign-off ID
            reason: Reason for rejection
        """
        record = self._load_record(signoff_id)
        if not record:
            raise ValueError(f"Sign-off {signoff_id} not found")

        record.state = SignoffState.HUMAN_REJECTED
        record.review_comment = reason

        self._save_record(record)
        return record

    def seal_with_jis(self, signoff_id: str) -> SignoffRecord:
        """
        Cryptographically seal the sign-off with JIS bilateral consent.

        This creates a hash that proves:
        - What was reviewed (scan results)
        - Who reviewed it (reviewer DID)
        - When it was approved
        - The reviewer's intent

        Args:
            signoff_id: The sign-off ID (must be in HUMAN_VERIFIED state)
        """
        record = self._load_record(signoff_id)
        if not record:
            raise ValueError(f"Sign-off {signoff_id} not found")

        if record.state != SignoffState.HUMAN_VERIFIED:
            raise ValueError(f"Can only seal HUMAN_VERIFIED sign-offs, current state: {record.state.value}")

        # Create JIS consent structure
        consent = {
            "protocol": "did:jis",
            "version": "1.0",
            "parties": [
                {
                    "id": f"tibet:audit:{record.scan_id}",
                    "role": "preparer",
                    "type": "tool"
                },
                {
                    "id": record.reviewer_did or f"reviewer:{record.reviewer_name}",
                    "role": "verifier",
                    "type": "human"
                }
            ],
            "subject": {
                "type": "compliance_assessment",
                "scan_id": record.scan_id,
                "scan_path": record.scan_path,
                "score": record.scan_score,
                "grade": record.scan_grade,
                "issues_fixed": record.issues_fixed
            },
            "intent": {
                "action": "verify",
                "statement": "I verify this compliance assessment is accurate and complete",
                "comment": record.review_comment
            },
            "timestamp": datetime.now().isoformat()
        }

        # Create deterministic hash
        consent_json = json.dumps(consent, sort_keys=True)
        consent_hash = hashlib.sha256(consent_json.encode()).hexdigest()

        record.jis_consent_hash = consent_hash
        record.sealed_at = datetime.now()
        record.state = SignoffState.JIS_SEALED

        self._save_record(record)

        # Also save the full consent for audit trail
        consent_path = self.storage_path / f"{signoff_id}_consent.json"
        with open(consent_path, 'w') as f:
            json.dump(consent, f, indent=2)

        return record

    def get_record(self, signoff_id: str) -> Optional[SignoffRecord]:
        """Get a sign-off record by ID."""
        return self._load_record(signoff_id)

    def list_pending(self) -> List[SignoffRecord]:
        """List all pending sign-off requests."""
        records = []
        for path in self.storage_path.glob("*.json"):
            if "_consent" in path.name:
                continue
            try:
                with open(path) as f:
                    data = json.load(f)
                    record = SignoffRecord.from_dict(data)
                    if record.state in [SignoffState.PENDING_REVIEW, SignoffState.UNDER_REVIEW]:
                        records.append(record)
            except Exception:
                continue
        return sorted(records, key=lambda r: r.timestamp, reverse=True)

    def count_by_state(self) -> dict:
        """Count sign-offs by state (for tibet-pol)."""
        counts = {state.value: 0 for state in SignoffState}
        for path in self.storage_path.glob("*.json"):
            if "_consent" in path.name:
                continue
            try:
                with open(path) as f:
                    data = json.load(f)
                    state = data.get('state', 'UNKNOWN')
                    if state in counts:
                        counts[state] += 1
            except Exception:
                continue
        return counts

    def _save_record(self, record: SignoffRecord):
        """Save a sign-off record to disk."""
        path = self.storage_path / f"{record.signoff_id}.json"
        with open(path, 'w') as f:
            json.dump(record.to_dict(), f, indent=2)

    def _load_record(self, signoff_id: str) -> Optional[SignoffRecord]:
        """Load a sign-off record from disk."""
        path = self.storage_path / f"{signoff_id}.json"
        if not path.exists():
            return None
        try:
            with open(path) as f:
                data = json.load(f)
                return SignoffRecord.from_dict(data)
        except Exception:
            return None


# Convenience functions for CLI integration
def create_signoff_prompt(record: SignoffRecord) -> str:
    """Generate a human-readable sign-off prompt."""
    return f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  📋 SIGN-OFF REQUEST                                                         ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  ID: {record.signoff_id:<67} ║
║  Path: {record.scan_path[:65]:<65} ║
║  Score: {record.scan_score}/100 (Grade: {record.scan_grade})                                              ║
║  Issues Fixed: {record.issues_fixed:<57} ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  By signing off, you verify:                                                 ║
║  • The compliance assessment is accurate                                     ║
║  • The fixes applied are appropriate                                         ║
║  • You accept responsibility for this verification                           ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""


def format_sealed_certificate(record: SignoffRecord) -> str:
    """Generate a certificate for a sealed sign-off."""
    if record.state != SignoffState.JIS_SEALED:
        return "Sign-off not sealed yet."

    return f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  ✅ JIS SEALED CERTIFICATE                                                   ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  Sign-off ID: {record.signoff_id:<58} ║
║  Scan ID: {record.scan_id:<63} ║
║  Score: {record.scan_score}/100 (Grade: {record.scan_grade})                                              ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  Verified by: {(record.reviewer_name or 'Unknown')[:58]:<58} ║
║  DID: {(record.reviewer_did or 'N/A')[:66]:<66} ║
║  Sealed at: {record.sealed_at.isoformat() if record.sealed_at else 'N/A':<61} ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  JIS Consent Hash:                                                           ║
║  {record.jis_consent_hash:<71} ║
╚══════════════════════════════════════════════════════════════════════════════╝

"TIBET prepares, Human verifies, JIS seals."
"""
