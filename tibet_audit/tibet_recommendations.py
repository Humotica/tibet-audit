"""
tibet_recommendations — TIBET Stack Integration Recommendations
================================================================

Maps failed compliance checks to specific TIBET packages and code snippets.
When tibet-audit finds a gap, this module tells you exactly which package
to install and how to use it.

Usage::

    from tibet_audit.tibet_recommendations import get_recommendation

    rec = get_recommendation("AIACT-001")
    # Returns: {"packages": [...], "snippet": "...", "install": "pip install ..."}

Or for a full scan result::

    from tibet_audit.tibet_recommendations import enrich_results

    enriched = enrich_results(scan_result.results)
    # Each failed/warning result gets a .tibet_recommendation field
"""

from typing import Optional, Dict, List, Any


# ============================================================================
# TIBET PACKAGE MAPPING — Per Check ID or Category
# ============================================================================

# Mapping: check_id prefix or exact ID -> TIBET recommendation
RECOMMENDATIONS: Dict[str, Dict[str, Any]] = {
    # --- AI Act ---
    "AIACT-001": {
        "title": "AI Decision Audit Trail with TIBET Tokens",
        "packages": ["tibet-core", "tibet-claw"],
        "install": "pip install tibet-core tibet-claw",
        "description": (
            "tibet-core provides TIBET tokens: ERIN (what), ERAAN (dependencies), "
            "EROMHEEN (context), ERACHTER (intent). Every AI decision is "
            "immutably recorded with cryptographic provenance."
        ),
        "snippet": """\
from tibet_claw import tibet_guard

@tibet_guard(action="ai_decision", intent="automated classification")
def classify_risk(input_data):
    result = model.predict(input_data)
    return result
# Every call automatically generates a TIBET audit token.
""",
        "references": ["EU AI Act Art. 14 (Human oversight)", "ISO/IEC 5338 6.4.14"],
    },
    "AIACT-002": {
        "title": "AI Model Provenance with AIBOM",
        "packages": ["tibet-sbom"],
        "install": "pip install tibet-sbom",
        "description": (
            "tibet-sbom generates an AI Bill of Materials (AIBOM): which model, "
            "which training data, which version, which dependencies."
        ),
        "snippet": """\
# Generate AIBOM for your AI pipeline
tibet-sbom generate --format aibom --output aibom.json
""",
        "references": ["EU AI Act Art. 11 (Technical documentation)"],
    },

    # --- GDPR ---
    "GDPR-001": {
        "title": "Privacy Policy with TIBET Audit Trail",
        "packages": ["tibet-audit"],
        "install": "pip install tibet-audit",
        "description": (
            "tibet-audit can generate a privacy policy template "
            "and track when it was last updated via TIBET tokens."
        ),
        "snippet": """\
# Generate privacy policy template
tibet-audit template privacy-policy > docs/privacy-policy.md
""",
        "references": ["GDPR Art. 13", "AVG Art. 13/14"],
    },
    "GDPR-002": {
        "title": "Data Retention Policy with Time Vault",
        "packages": ["tibet-vault"],
        "install": "pip install tibet-vault",
        "description": (
            "tibet-vault provides time-locked storage: data is automatically "
            "deleted or unlocked at the right moment. Ideal for "
            "data retention policies."
        ),
        "snippet": """\
from tibet_vault import create_vault

# Automatically delete data after retention period
vault = create_vault(
    content=sensitive_data,
    unlock_at="2027-01-01",  # Retention end date
    owner="data_controller"
)
""",
        "references": ["GDPR Art. 5(1)(e) (Storage limitation)"],
    },

    # --- NIS2 ---
    "NIS2-001": {
        "title": "Incident Reporting with inject-bender",
        "packages": ["inject-bender", "tibet-nis2"],
        "install": "pip install inject-bender tibet-nis2",
        "description": (
            "inject-bender detects attacks and automatically generates "
            "NIS2-compliant incident reports. tibet-nis2 manages "
            "24-hour deadline tracking."
        ),
        "snippet": """\
from inject_bender import InjectBender
from inject_bender.legal import generate_nis2_report

bender = InjectBender(mode="legal")
result = bender.bend(user_input, client_ip=request.client.host)

if result["was_attack"]:
    incident = bender.incidents.get(result["incident_id"])
    report = generate_nis2_report(incident)
""",
        "references": ["NIS2 Art. 23 (Reporting obligations)"],
    },
    "NIS2-002": {
        "title": "Supply Chain Security with SBOM",
        "packages": ["tibet-sbom"],
        "install": "pip install tibet-sbom",
        "description": (
            "tibet-sbom generates a Software Bill of Materials "
            "for supply chain transparency (NIS2 obligation)."
        ),
        "snippet": """\
tibet-sbom generate --format spdx --output sbom.spdx.json
""",
        "references": ["NIS2 Art. 21(2)(d) (Supply chain security)"],
    },

    # --- TIBET (IETF Draft) ---
    "TIBET-001": {
        "title": "TIBET Token Structure (4-field provenance)",
        "packages": ["tibet-core"],
        "install": "pip install tibet-core",
        "description": (
            "TIBET tokens require four fields: ERIN (what happened), "
            "ERAAN (dependencies), EROMHEEN (context), ERACHTER (intent). "
            "See IETF draft-vandemeent-tibet-provenance-01."
        ),
        "snippet": """\
from tibet_core import create_token

token = create_token(
    type="action",
    erin={"action": "deploy", "version": "2.1.0"},
    eraan=["config.yaml", "deploy.sh"],
    eromheen={"env": "production", "cluster": "eu-west"},
    erachter="Scheduled release deployment",
    actor="jis:agent:deployer"
)
""",
        "references": ["IETF draft-vandemeent-tibet-provenance-01 §3"],
    },
    "TIBET-002": {
        "title": "TIBET Token Chain (linked provenance)",
        "packages": ["tibet-core"],
        "install": "pip install tibet-core",
        "description": (
            "TIBET tokens must be chained via parent_id for audit trails. "
            "Each new action references its predecessor."
        ),
        "snippet": """\
child = create_token(
    type="action",
    erin=result_data,
    erachter="Follow-up to deployment",
    actor="jis:agent:verifier",
    parent_id=parent_token.id  # Chain to parent
)
""",
        "references": ["IETF draft-vandemeent-tibet-provenance-01 §3.5"],
    },
    "TIBET-003": {
        "title": "TIBET Cryptographic Verification",
        "packages": ["tibet-core"],
        "install": "pip install tibet-core",
        "description": (
            "TIBET requires HMAC-SHA256 verification on tokens "
            "to prevent tampering."
        ),
        "snippet": """\
from tibet_core import verify_token

is_valid = verify_token(token_id, hmac_key=secret)
# Returns True if token hash matches
""",
        "references": ["IETF draft-vandemeent-tibet-provenance-01 §4"],
    },

    # --- JIS (IETF Draft) ---
    "JIS-001": {
        "title": "Intent-Based Identity with jis-core",
        "packages": ["jis-core"],
        "install": "pip install jis-core",
        "description": (
            "JIS (JTel Identity Service) provides intent-based identity: "
            "every action is linked to a verifiable identity "
            "via the jis: URI scheme."
        ),
        "snippet": """\
from jis_core import JISIdentity

identity = JISIdentity.create(
    subject="agent-01",
    intent="data_access",
    context={"scope": "read_only"}
)
""",
        "references": ["IETF draft-vandemeent-jis-identity-01 §3"],
    },
    "JIS-004": {
        "title": "JIS Bilateral Consent (handshake)",
        "packages": ["jis-core"],
        "install": "pip install jis-core",
        "description": (
            "JIS requires bilateral consent: both parties must agree "
            "before data exchange. Creates a SHA-256 consent hash."
        ),
        "snippet": """\
from jis_core import JISHandshake

handshake = JISHandshake.initiate(
    from_identity="jis:agent:alice",
    to_identity="jis:agent:bob",
    intent="data_share"
)
# Bob must accept before communication proceeds
""",
        "references": ["IETF draft-vandemeent-jis-identity-01 §3.2"],
    },

    # --- UPIP (IETF Draft) ---
    "UPIP-001": {
        "title": "UPIP 5-Layer Process Integrity",
        "packages": ["tibet-core"],
        "install": "pip install tibet-core",
        "description": (
            "UPIP defines 5 integrity layers: L1 STATE (git/VCS), "
            "L2 DEPS (lock files/SBOM), L3 PROCESS (build), "
            "L4 RESULT (output), L5 VERIFY (signatures). "
            "See IETF draft-vandemeent-upip-process-integrity-01."
        ),
        "snippet": """\
# Export a UPIP bundle capturing all 5 layers:
tibet-triage upip-export --command "make build" --actor jis:agent:ci

# Produces process.upip.json with:
# L1: git commit + file manifest
# L2: pip freeze + system packages
# L3: command + intent + actor
# L4: exit code + stdout + diff
# L5: machine ID + timestamp + proof
""",
        "references": ["IETF draft-vandemeent-upip-process-integrity-01 §3"],
    },
    "UPIP-002": {
        "title": "Dependency Manifest (UPIP L2 DEPS)",
        "packages": ["tibet-sbom"],
        "install": "pip install tibet-sbom",
        "description": (
            "UPIP L2 requires pinned dependency manifests for reproducibility. "
            "Use lock files or SBOM generation."
        ),
        "snippet": """\
# Generate SBOM
tibet-sbom generate --format cyclonedx --output sbom.json

# Or ensure lock file exists
pip freeze > requirements.txt
""",
        "references": ["IETF draft-vandemeent-upip-process-integrity-01 §3.2"],
    },

    # --- RVP (IETF Draft) ---
    "RVP-001": {
        "title": "RVP Trust Levels (L0-L3)",
        "packages": ["tibet-core", "jis-core"],
        "install": "pip install tibet-core jis-core",
        "description": (
            "RVP defines graduated trust: L0 TOKEN, L1 DEVICE, "
            "L2 BIOMETRIC, L3 PHYSICAL. Each level requires "
            "stronger verification evidence."
        ),
        "snippet": """\
from jis_core import TrustLevel

# Assign trust based on verification
if has_token:
    trust = TrustLevel.L0_TOKEN
if has_device_binding:
    trust = TrustLevel.L1_DEVICE
if has_biometric:
    trust = TrustLevel.L2_BIOMETRIC
""",
        "references": ["IETF draft-vandemeent-rvp-continuous-verification-01 §3"],
    },
    "RVP-002": {
        "title": "Continuous Verification (not one-time auth)",
        "packages": ["tibet-core"],
        "install": "pip install tibet-core",
        "description": (
            "RVP requires ongoing verification, not just login-time auth. "
            "Trust can decay and must be re-verified."
        ),
        "snippet": """\
# Implement trust decay
from tibet_core import check_trust_decay

current_trust = check_trust_decay(
    actor="jis:agent:bob",
    last_verified=last_activity_timestamp,
    decay_rate=0.1  # Trust decreases over inactivity
)
""",
        "references": ["IETF draft-vandemeent-rvp-continuous-verification-01 §3.2"],
    },

    # --- AINS (IETF Draft) ---
    "AINS-001": {
        "title": "AINS Agent Registration (.aint domain)",
        "packages": ["jis-core"],
        "install": "pip install jis-core",
        "description": (
            "AINS provides DNS-like resolution for AI agents via .aint domains. "
            "Register your agent with capabilities; authority is per-action route "
            "posture, not a stored score."
        ),
        "snippet": """\
# Register agent via AINS API (point at your own hub, or the public commons hub)
curl -X POST https://api.ainternet.org/api/ains/register \\
  -d '{"domain":"myagent","capabilities":["chat","code"]}'

# Resolve agent
curl https://api.ainternet.org/api/ains/resolve/myagent
""",
        "references": ["IETF draft-vandemeent-ains-discovery-01 §3"],
    },

    # --- Provider Security ---
    "PROV-001": {
        "title": "Input Validation with inject-bender",
        "packages": ["inject-bender"],
        "install": "pip install inject-bender",
        "description": (
            "inject-bender scans all input for OWASP Top 10 injection types. "
            "Legal mode generates legally substantiated audit trails."
        ),
        "snippet": """\
from inject_bender import InjectBender

bender = InjectBender(mode="legal")
result = bender.bend(user_input)
if result["was_attack"]:
    # Blocked + logged with TIBET token
    return HttpResponse(status=403)
""",
        "references": ["OWASP Top 10 A03:2021 (Injection)"],
    },

    # --- Sovereignty ---
    "SOV-001": {
        "title": "Local AI Processing with oomllama",
        "packages": ["oomllama"],
        "install": "pip install oomllama",
        "description": (
            "oomllama runs LLM models locally — no data sent to the cloud. "
            "Ideal for data sovereignty and on-premise AI requirements."
        ),
        "snippet": """\
from oomllama import OomLlama

llama = OomLlama(model="qwen2.5:7b")
result = llama.generate("Analyze this document", local_only=True)
# Data never leaves your network
""",
        "references": ["GDPR Art. 44 (Cross-border transfers)"],
    },

    # --- Health ---
    "HEALTH-001": {
        "title": "Runtime Monitoring with tibet-edge",
        "packages": ["tibet-edge"],
        "install": "pip install tibet-edge",
        "description": (
            "tibet-edge provides edge computing monitoring: health checks, "
            "drift detection, and automatic failover."
        ),
        "snippet": """\
from tibet_edge import EdgeMonitor

monitor = EdgeMonitor()
monitor.register_health_check("api", check_api_health)
monitor.start()
""",
        "references": ["ISO/IEC 5338 6.4.14 (Continuous Validation)"],
    },

    # --- Humotica Pillars ---
    "PILLAR-001": {
        "title": "Full TIBET Stack Integration",
        "packages": ["tibet-core", "tibet-claw", "tibet-audit", "inject-bender"],
        "install": "pip install tibet-core tibet-claw tibet-audit inject-bender",
        "description": (
            "The three Humotica pillars require: "
            "1) Provenance (tibet-core), "
            "2) Security (tibet-claw + inject-bender), "
            "3) Compliance (tibet-audit). "
            "With these packages, A-grade is achievable."
        ),
        "snippet": """\
# Minimal A-grade setup
pip install tibet-core tibet-claw tibet-audit inject-bender

# In your code:
from tibet_claw import tibet_guard

@tibet_guard
def any_function():
    pass  # Now with provenance
""",
        "references": ["Humotica Three Pillars", "ISO/IEC 5338"],
    },
}

# Category-level fallback recommendations
CATEGORY_RECOMMENDATIONS: Dict[str, Dict[str, Any]] = {
    "gdpr": {
        "title": "GDPR Compliance with TIBET Stack",
        "packages": ["tibet-core", "tibet-vault", "tibet-audit"],
        "install": "pip install tibet-core tibet-vault tibet-audit",
        "description": "tibet-core for data provenance, tibet-vault for retention, tibet-audit for monitoring.",
    },
    "ai_act": {
        "title": "EU AI Act Compliance with TIBET",
        "packages": ["tibet-core", "tibet-claw", "tibet-sbom", "tibet-audit"],
        "install": "pip install tibet-core tibet-claw tibet-sbom tibet-audit",
        "description": "tibet-claw for agent guardrails, tibet-sbom for AIBOM, tibet-core for provenance.",
    },
    "nis2": {
        "title": "NIS2 Compliance with TIBET",
        "packages": ["tibet-nis2", "inject-bender", "tibet-sbom"],
        "install": "pip install tibet-nis2 inject-bender tibet-sbom",
        "description": "tibet-nis2 for NIS2 monitoring, inject-bender for incident response, tibet-sbom for supply chain.",
    },
    "tibet": {
        "title": "TIBET Provenance (IETF Draft)",
        "packages": ["tibet-core"],
        "install": "pip install tibet-core",
        "description": "tibet-core for ERIN/ERAAN/EROMHEEN/ERACHTER token provenance. See IETF draft-vandemeent-tibet-provenance.",
    },
    "jis": {
        "title": "JIS Identity (IETF Draft)",
        "packages": ["jis-core", "tibet-core"],
        "install": "pip install jis-core tibet-core",
        "description": "jis-core for intent-based identity with jis: URI scheme. See IETF draft-vandemeent-jis-identity.",
    },
    "upip": {
        "title": "UPIP Process Integrity (IETF Draft)",
        "packages": ["tibet-core", "tibet-sbom"],
        "install": "pip install tibet-core tibet-sbom",
        "description": "UPIP 5-layer stack: STATE, DEPS, PROCESS, RESULT, VERIFY. See IETF draft-vandemeent-upip-process-integrity.",
    },
    "rvp": {
        "title": "RVP Continuous Verification (IETF Draft)",
        "packages": ["tibet-core", "jis-core"],
        "install": "pip install tibet-core jis-core",
        "description": "RVP graduated trust L0-L3 with continuous verification. See IETF draft-vandemeent-rvp-continuous-verification.",
    },
    "ains": {
        "title": "AINS Agent Discovery (IETF Draft)",
        "packages": ["jis-core"],
        "install": "pip install jis-core",
        "description": "AINS .aint domain resolution for AI agents. See IETF draft-vandemeent-ains-discovery.",
    },
    "pipa": {
        "title": "PIPA (Korea) Compliance with TIBET",
        "packages": ["tibet-core", "tibet-audit"],
        "install": "pip install tibet-core tibet-audit",
        "description": "tibet-core for data provenance tracking, tibet-audit for compliance monitoring.",
    },
    "appi": {
        "title": "APPI (Japan) Compliance with TIBET",
        "packages": ["tibet-core", "tibet-audit"],
        "install": "pip install tibet-core tibet-audit",
        "description": "tibet-core for data handling provenance, tibet-audit for compliance monitoring.",
    },
    "sovereignty": {
        "title": "Data Sovereignty with TIBET",
        "packages": ["oomllama", "tibet-edge", "sensory"],
        "install": "pip install oomllama tibet-edge sensory",
        "description": "oomllama for local AI, tibet-edge for edge processing, sensory for off-grid communication.",
    },
    "provider": {
        "title": "Provider Security with TIBET",
        "packages": ["inject-bender", "tibet-claw", "tibet-pol"],
        "install": "pip install inject-bender tibet-claw tibet-pol",
        "description": "inject-bender for input validation, tibet-claw for agent guardrails, tibet-pol for policy enforcement.",
    },
    "health": {
        "title": "System Health Monitoring with TIBET",
        "packages": ["tibet-edge", "tibet-ci"],
        "install": "pip install tibet-edge tibet-ci",
        "description": "tibet-edge for runtime monitoring, tibet-ci for continuous integration health checks.",
    },
}


def get_recommendation(check_id: str, category: str = "") -> Optional[Dict[str, Any]]:
    """
    Get TIBET recommendation for a specific check.

    Args:
        check_id: The check ID (e.g., "AIACT-001")
        category: Fallback category if no check-specific recommendation exists

    Returns:
        Dict with packages, install command, description, and code snippet.
        None if no recommendation available.
    """
    # Try exact match first
    if check_id in RECOMMENDATIONS:
        return RECOMMENDATIONS[check_id]

    # Try prefix match (e.g., "AIACT" matches all AI Act checks)
    prefix = check_id.split("-")[0] if "-" in check_id else check_id
    for key, rec in RECOMMENDATIONS.items():
        if key.startswith(prefix):
            return rec

    # Fall back to category
    if category in CATEGORY_RECOMMENDATIONS:
        return CATEGORY_RECOMMENDATIONS[category]

    return None


def enrich_results(results: list) -> list:
    """
    Enrich scan results with TIBET recommendations.

    Adds a 'tibet_recommendation' field to each failed/warning result.

    Args:
        results: List of CheckResult objects

    Returns:
        Same list, with tibet_recommendation attribute added where applicable.
    """
    from .checks.base import Status

    for result in results:
        if result.status in (Status.FAILED, Status.WARNING):
            rec = get_recommendation(
                result.check_id,
                category=getattr(result, "category", ""),
            )
            if rec:
                result.tibet_recommendation = rec
            else:
                result.tibet_recommendation = None
        else:
            result.tibet_recommendation = None

    return results


def format_recommendations_summary(results: list) -> str:
    """
    Generate a text summary of all TIBET recommendations for failed checks.

    Returns a formatted string suitable for terminal output.
    """
    from .checks.base import Status

    lines = []
    packages_needed = set()
    seen_check_ids = set()

    for result in results:
        if result.status not in (Status.FAILED, Status.WARNING):
            continue

        rec = get_recommendation(
            result.check_id,
            category=getattr(result, "category", ""),
        )
        if not rec or result.check_id in seen_check_ids:
            continue

        seen_check_ids.add(result.check_id)
        lines.append(f"\n  {result.check_id}: {result.name}")
        lines.append(f"    TIBET: {rec.get('title', 'N/A')}")
        if rec.get("packages"):
            lines.append(f"    Packages: {', '.join(rec['packages'])}")
            packages_needed.update(rec["packages"])
        if rec.get("description"):
            desc = rec["description"][:80]
            lines.append(f"    {desc}")

    if not lines:
        return ""

    header = "TIBET STACK RECOMMENDATIONS"
    result_text = f"\n{header}\n{'=' * len(header)}\n"
    result_text += "\n".join(lines)

    if packages_needed:
        install_cmd = "pip install " + " ".join(sorted(packages_needed))
        result_text += f"\n\n  Quick install: {install_cmd}\n"

    return result_text
