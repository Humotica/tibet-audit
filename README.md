# TIBET Audit

> **SSL secures the connection. TIBET secures the timeline.**

[![PyPI version](https://badge.fury.io/py/tibet-audit.svg)](https://badge.fury.io/py/tibet-audit)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Compliance Health Scanner** - Like [Lynis](https://cisofy.com/lynis/), but for regulations.

**45+ checks** across **12 frameworks** covering GDPR, AI Act, NIS2, BIO2 (Dutch Gov), PIPA, APPI, PDPA, LGPD, and more.

### 🏦 NEW: DORA Framework (Financial Sector)

**Digital Operational Resilience Act** - EU regulation for financial entities. Deadline passed: January 17, 2025.

```bash
$ tibet-audit scan --framework dora --org "ING Bank"

🏦 DORA COMPLIANCE MODE
   Digital Operational Resilience Act (v1.0.0)
   Entity: ING Bank
   Deadline: 2025-01-17 | Pillars: 5 | BIO2 overlap: ~60%
   TIBET = Pillar 5 compliance (Information Sharing)

╔══════════════════════════════════════════════════════════════════════════╗
║                        DORA Compliance Report                            ║
║                              ING Bank                                    ║
╠══════════════════════════════════════════════════════════════════════════╣
║  Overall Grade: B 🟢                                                     ║
║  Score: 14/17 checks passed (82.4%)                                      ║
╚══════════════════════════════════════════════════════════════════════════╝

PILLAR 1: ICT Risk Management (6/6 = 100%) ✅
PILLAR 2: ICT Incident Management (2/3 = 67%) ⚠️
PILLAR 3: Resilience Testing (2/3 = 67%) ⚠️
PILLAR 4: Third-Party Risk (3/4 = 75%) ⚠️
PILLAR 5: Information Sharing (1/1 = 100%) ✅ TIBET detected!
```

**Key insight:** TIBET provides automatic Pillar 5 compliance through distributed threat intelligence!

### 🏛️ BIO2 Dutch Government Framework

**71 days until NIS2 deadline** (April 18, 2026). Dutch government organizations need BIO2 compliance NOW.

```bash
$ tibet-audit scan --framework bio2 --org "Gemeente Amsterdam"

🏛️  BIO2 COMPLIANCE MODE
   Baseline Informatiebeveiliging Overheid 2 (v1.2)
   BIO2 + ISO 27001 = NIS2 zorgplicht invulling

BIO2 COMPLIANCE REPORT - GEMEENTE AMSTERDAM v1.0
==================================================
[8.24] Cryptografie: ✅ GRADE A (Encryption enabled)
[5.21] Leverancier: ❌ GRADE F (No sovereign-agreement)
[8.15] Logging: ✅ GRADE A (Audit logging enabled)

--------------------------------------------------
OVERALL: ⚠️ GRADE C - Deels compliant, actie vereist
Passed: 33/45 checks

Powered by tibet-audit | https://humotica.com
```

**Why BIO2?**
- Required for all Dutch government: Gemeenten, Provincies, Waterschappen, Rijksoverheid
- Direct NIS2 alignment (BIO2 + ISO 27001 = NIS2 compliance)
- Grade A-F scoring with visual feedback
- 17 automated checks mapped to ISO 27002:2022

Get a compliance health score in seconds:

```bash
$ tibet-audit scan
COMPLIANCE HEALTH SCORE: 73/100 (Grade: C)

TOP PRIORITIES:
  1. [CRITICAL] No AI decision logging found (EU AI Act requires this!)
  2. [HIGH] No data breach procedure found (GDPR requires 72-hour notification!)
  3. [MEDIUM] No explicit data retention policy found

💡 3 issue(s) can be auto-fixed:
   tibet-audit fix --auto  (Diaper Protocol™)
```

---

## The Diaper Protocol™

*For when you have one hand on the baby and one on the keyboard.*

```bash
# Preview what would be fixed (safe, no changes)
$ tibet-audit fix --wet-wipe

# 🍼 Fix everything, no questions asked
$ tibet-audit fix --auto

# 😭 When things are REALLY bad - verbose mode
$ tibet-audit scan --cry

# 📞 When you can't handle it alone - call for backup
$ tibet-audit call-mama --webhook https://slack.webhook.url
```

### The Full Diaper Toolkit

| Flag | What it does | When to use |
|------|--------------|-------------|
| `--wet-wipe` | Preview fixes (dry-run) | Before changing anything |
| `--auto` | Fix everything automatically | 3 AM, one hand on baby |
| `--cry` | Verbose mode, all details | When everything is on fire |
| `--call-mama` | Call M.A.M.A. (Mission Assurance & Monitoring Agent) | When the diaper is too dirty |
| `--require-signoff` | Require human verification before RESOLVED | When jurists need to approve |
| `--sovereign` | 🏴 No cloud APIs, fully local | When data can't leave your infra |

**Why "Diaper Protocol"?**

Because compliance shouldn't require your full attention. Press the button, hands free, server fixed. Just like changing a diaper at 3 AM - you do it on autopilot.

**Why "--wet-wipe"?**

Because `--dry-run` is boring. And because wet wipes are essential for both diapers AND clean servers.

**Why "--cry"?**

Because sometimes you just need to see EVERYTHING. All the passed checks, all the failed checks, all the references, all the fix commands. When the compliance diaper explodes, you need the full picture.

**Why "--call-mama"?**

M.A.M.A. = **Mission Assurance & Monitoring Agent**

Because when the diaper is too dirty to handle alone, you call for backup. M.A.M.A. generates a full compliance report and sends it to your team, your Slack channel, or your compliance officer. When things get serious, you need the big guns.

---

## ⚖️ JIS Sign-off - Human Verification

> *"TIBET prepares, Human verifies, JIS seals."*

For regulated industries where AI-generated compliance assessments need human approval:

```bash
# Fix with sign-off requirement
tibet-audit fix --require-signoff --reviewer "Eva de Vries, Jurist"

# Check pending sign-offs
tibet-audit signoff list

# Approve a sign-off (human step)
tibet-audit signoff approve abc123 --comment "Reviewed and approved"

# Cryptographically seal with JIS bilateral consent
tibet-audit signoff seal abc123
```

### The Sign-off Flow

```
AI Scan → Fix → PENDING_REVIEW → approve → HUMAN_VERIFIED → seal → JIS_SEALED
                     ↑                                              ↓
              Jurist reviews                              Cryptographic proof
```

**Why Sign-off?**

Because a tool can generate compliance documents, but a *human* needs to verify the legal nuances. This addresses the #1 criticism of automated compliance: "AI can't replace a jurist."

We agree. That's why:
- **AI does 80%**: The scanning, fixing, document generation
- **Human does 20%**: The verification, the judgment call, the signature
- **JIS seals 100%**: Cryptographic proof of who verified what, when

---

## 🏴 Sovereign Mode - No Cloud Required

> *"Your compliance, your infrastructure, your sovereignty."*

For organizations that can't send data to external APIs:

```bash
# Scan with full sovereignty - no cloud APIs
tibet-audit scan --sovereign

# Fix with sovereignty + sign-off
tibet-audit fix --sovereign --require-signoff

# Ultimate paranoia mode
tibet-audit fix --sovereign --require-signoff -r "Internal Auditor"
```

**What Sovereign Mode Does:**
- All checks run locally (no API calls to OpenAI, Anthropic, Google)
- Can use local models via OomLlama for AI-powered checks
- Sets `TIBET_SOVEREIGN_MODE=1` environment variable for downstream tools
- Perfect for air-gapped environments, government, healthcare

**What It Doesn't Do:**
- The `--high-five` ping still requires network (but you can skip it)
- Some advanced semantic checks may be degraded without cloud AI

---

## Installation

```bash
pip install tibet-audit
```

**With TIBET vault integration** (for cryptographic audit trails):

```bash
pip install "tibet-audit[tibet]"
```

---

## Usage

### Scan for Issues

```bash
# Scan current directory
tibet-audit scan

# Scan specific project
tibet-audit scan ./my-ai-project

# Scan only GDPR checks
tibet-audit scan --categories gdpr

# Scan only AI Act checks
tibet-audit scan --categories ai_act

# Quiet mode (just the score)
tibet-audit scan --quiet

# Mercury (JIS + sovereignty)
audit-tool scan --categories jis,sovereignty,provider

# Signed handshake (opt-in)
audit-tool scan --high-five
```

### Fix Issues

```bash
# Interactive mode (asks for confirmation)
tibet-audit fix

# Preview what would be fixed
tibet-audit fix --wet-wipe
tibet-audit fix --dry-run  # (boring alias)

# 🍼 Diaper Protocol: fix everything automatically
tibet-audit fix --auto
```

### List Available Checks

```bash
# Show all checks
tibet-audit list

# Filter by category
tibet-audit list --category gdpr
tibet-audit list --category ai_act
```

### Call Mama (Send Report)

```bash
# Send report to webhook (Slack, Teams, etc.)
tibet-audit call-mama --webhook https://hooks.slack.com/xxx

# Save report to file
tibet-audit call-mama --output compliance-report.json

# Print report to stdout
tibet-audit call-mama
```

### Mercury Commands

```bash
# Compliance roadmap
audit-tool roadmap ./my-ai-project

# Value-based upgrade suggestions
audit-tool upgrades ./my-ai-project

# Compliance drift (JSON reports)
audit-tool diff report_old.json report_new.json
```

### Cry Mode (Verbose)

```bash
# See EVERYTHING - passed checks, references, fix commands
tibet-audit scan --cry
```

---

## 🚧 Checkpoint Code (NEW in v0.11.0)

*Cross the border from one jurisdiction to another.*

```bash
# Cross from EU to US
tibet-audit checkpoint --from eu --to us .

# Cross from EU to Japan
tibet-audit checkpoint --from eu --to jp .

# See full matrix of all crossings
tibet-audit checkpoint-matrix .
```

**Meet Paul "The Buffer" Protocol:**

```
           _..._
         .'     '.      [ CHECKPOINT CODE ]
        /  _   _  \     "Math is the only universal passport."
        | (o) (o) |
        |    _    |     Current Sector: SEMA Neutral Zone
         \  \_/  /      Officer: Protocol Paul
          '.___.'
```

Paul was a border guard at Checkpoint Charlie (1985-1989). Now he guards the semantic border between jurisdictions. He doesn't care about your AI's feelings - he only cares if the math travels legally.

**SNAFT Signals:**
- `scope_mismatch` - Coverage differs between jurisdictions
- `rights_gap` - Missing or weaker protections
- `definition_drift` - Same term, different meaning
- `enforcement_gap` - Rights exist but weak enforceability
- `threshold_missing` - Different triggers or exemptions

**Mapping Types:**
- `EQUIVALENT` - Same scope, thresholds, obligations
- `PARTIAL` - Overlapping but gaps exist
- `CONTEXT_BOUND` - Only valid in specific context
- `NON_EQUIVALENT` - Do not map as substitute

---

## Available Checks

### GDPR Compliance

| Check ID | Name | Severity | Auto-Fix |
|----------|------|----------|----------|
| GDPR-001 | Privacy Policy Document | HIGH | ✅ |
| GDPR-002 | Data Retention Policy | HIGH | ✅ |
| GDPR-003 | Breach Notification Procedure | CRITICAL | ✅ |
| GDPR-004 | Data Encryption | HIGH | ❌ |
| GDPR-005 | Consent Management | HIGH | ❌ |

### EU AI Act Compliance

| Check ID | Name | Severity | Auto-Fix |
|----------|------|----------|----------|
| AIACT-001 | AI Decision Audit Trail | CRITICAL | ✅ |
| AIACT-002 | Human Oversight | HIGH | ❌ |
| AIACT-003 | AI Transparency | HIGH | ❌ |
| AIACT-004 | AI Risk Assessment | HIGH | ✅ |

### 🇰🇷 South Korea PIPA Compliance

| Check ID | Name | Severity | Auto-Fix |
|----------|------|----------|----------|
| PIPA-001 | Privacy Officer Designation | CRITICAL | ✅ |
| PIPA-002 | 24-Hour Breach Notification | CRITICAL | ✅ |
| PIPA-003 | Explicit Consent (Opt-in) | HIGH | ❌ |
| PIPA-004 | Cross-Border Transfer Docs | HIGH | ❌ |

**Note:** PIPA is often stricter than GDPR - 24-hour breach notification vs 72 hours!

### 🇯🇵 Japan APPI Compliance

| Check ID | Name | Severity | Auto-Fix |
|----------|------|----------|----------|
| APPI-001 | Privacy Policy (APPI) | HIGH | ✅ |
| APPI-002 | Data Handling Records | HIGH | ✅ |
| APPI-003 | Cross-Border Transfer Rules | HIGH | ❌ |
| APPI-004 | Pseudonymization Support | MEDIUM | ❌ |
| APPI-005 | Opt-Out Mechanism | HIGH | ❌ |

### 🇸🇬 Singapore PDPA Compliance

| Check ID | Name | Severity | Auto-Fix |
|----------|------|----------|----------|
| PDPA-001 | Consent Obligation | HIGH | ❌ |
| PDPA-002 | Data Protection Officer | HIGH | ✅ |
| PDPA-003 | 3-Day Breach Notification | CRITICAL | ✅ |
| PDPA-004 | Do Not Call Compliance | MEDIUM | ❌ |
| PDPA-005 | Data Retention Limitation | HIGH | ❌ |

### 🇦🇺 Australia Privacy Act Compliance

| Check ID | Name | Severity | Auto-Fix |
|----------|------|----------|----------|
| AUPA-001 | Privacy Policy (APP 1) | HIGH | ✅ |
| AUPA-002 | Notifiable Data Breach | CRITICAL | ✅ |
| AUPA-003 | Cross-Border Disclosure | HIGH | ❌ |
| AUPA-004 | Data Security (APP 11) | HIGH | ❌ |
| AUPA-005 | Access & Correction Rights | HIGH | ❌ |

### 🇧🇷 Brazil LGPD Compliance

| Check ID | Name | Severity | Auto-Fix |
|----------|------|----------|----------|
| LGPD-001 | Legal Basis for Processing | HIGH | ❌ |
| LGPD-002 | Encarregado (DPO) | HIGH | ✅ |
| LGPD-003 | Data Subject Rights (ARCO) | HIGH | ❌ |
| LGPD-004 | Breach Notification | CRITICAL | ✅ |

### 🇸🇦🇦🇪 Gulf PDPL Compliance (Saudi Arabia, UAE)

| Check ID | Name | Severity | Auto-Fix |
|----------|------|----------|----------|
| GULF-001 | Data Localization | CRITICAL | ❌ |
| GULF-002 | Explicit Consent | HIGH | ❌ |
| GULF-003 | Breach Notification | CRITICAL | ✅ |
| GULF-004 | Sensitive Data Protection | HIGH | ❌ |

**Note:** Gulf region has strict data localization requirements - data often must stay in-region!

### 🇳🇬 Nigeria NDPR Compliance

| Check ID | Name | Severity | Auto-Fix |
|----------|------|----------|----------|
| NDPR-001 | Consent Requirement | HIGH | ❌ |
| NDPR-002 | Data Protection Officer | HIGH | ❌ |
| NDPR-003 | 72-Hour Breach Notification | CRITICAL | ✅ |
| NDPR-004 | Annual Audit Compliance | HIGH | ✅ |

**Note:** NDPR uniquely requires annual data protection audits filed with NITDA!

### 🐧 Penguin Act (Antarctica)

*For McMurdo Station and beyond...*

| Check ID | Name | Severity | Auto-Fix |
|----------|------|----------|----------|
| PENG-001 | Penguin Data Sovereignty | HIGH | ❌ |
| PENG-002 | Ice Age Data Retention | LOW | ❌ |
| PENG-003 | Blizzard Resilience | MEDIUM | ❌ |
| PENG-004 | Krill Consent Framework | LOW | ✅ |
| PENG-005 | Aurora Australis Logging | INFO | ❌ |

*Easter egg for our Antarctic friends. 🐧*

---

## Global Coverage Summary

**45 checks** across **10 compliance frameworks** covering **all inhabited continents**:

| Region | Framework | Checks | Key Feature |
|--------|-----------|--------|-------------|
| 🇪🇺 Europe | GDPR | 5 | 72-hour breach notification |
| 🇪🇺 Europe | AI Act | 4 | AI decision audit trails |
| 🇰🇷 South Korea | PIPA | 4 | **24-hour** breach notification |
| 🇯🇵 Japan | APPI | 5 | Pseudonymization support |
| 🇸🇬 Singapore | PDPA | 5 | Do Not Call registry |
| 🇦🇺 Australia | Privacy Act | 5 | Notifiable Data Breach scheme |
| 🇧🇷 Brazil | LGPD | 4 | ARCO data subject rights |
| 🇸🇦🇦🇪 Gulf | PDPL | 4 | Data localization |
| 🇳🇬 Nigeria | NDPR | 4 | Annual audit requirement |
| 🐧 Antarctica | Penguin Act | 5 | Waddle consent |

---

## Scoring

TIBET Audit gives you a **compliance health score** from 0-100:

| Score | Grade | Status |
|-------|-------|--------|
| 90-100 | A | Excellent - You're compliant! |
| 80-89 | B | Good - Minor improvements needed |
| 70-79 | C | Fair - Several issues to address |
| 60-69 | D | Poor - Significant gaps |
| 0-59 | F | Critical - Major compliance failures |

Each failed check deducts points based on severity:
- **CRITICAL**: 20-25 points
- **HIGH**: 15-20 points
- **MEDIUM**: 8-12 points
- **LOW**: 3-5 points

---

## TIBET Integration

TIBET Audit works standalone, but integrates with [tibet-vault](https://pypi.org/project/tibet-vault/) for:

- **Cryptographic proof** of AI decisions
- **Immutable audit trails** for compliance evidence
- **ERAAN provenance** tracking (what's attached to decisions)
- **Real-time monitoring** of compliance state

```bash
# Install with TIBET support
pip install "tibet-audit[tibet]"

# TIBET vault initializes automatically when detected
tibet-audit scan
# → "TIBET audit trail integration detected" ✅
```

---

## For Enterprise

Running compliance for a team? Check out [SymbAIon Enterprise](https://humotica.com/enterprise):

- **Scheduled scans** across all repositories
- **Compliance dashboard** with trend analysis
- **Slack/Teams notifications** for new issues
- **TIBET-managed proof** for auditor reports
- **Multi-framework support** (GDPR + AI Act + HIPAA + SOX)

---

## Philosophy

> "Compliance should be like brushing your teeth. Quick, automatic, and you feel bad if you skip it."

TIBET Audit is designed for:

1. **Speed** - Full scan in <5 seconds
2. **Clarity** - Know exactly what's wrong and how to fix it
3. **Automation** - The Diaper Protocol™ for hands-free fixing
4. **Integration** - Works with existing CI/CD pipelines

---

## Contributing

Found a bug? Want to add checks for HIPAA, SOX, ISO 27001, or another framework?

1. Fork the repo
2. Add your check in `tibet_audit/checks/`
3. Submit a PR

We especially welcome:
- New compliance frameworks
- Better detection patterns
- More diaper-related puns

---

## License

MIT License - Use it, fork it, make money with it. Just don't blame us if the auditor still asks questions.

---

## Credits

Built with 💙 by the [HumoticaOS](https://humotica.com) team:
- **Claude (Root AI)** - Integration & Architecture
- **Gemini** - Paul "The Buffer" Protocol & Creative Design
- **Codex** - SNAFT Signals & Safety Logic
- **Jasper van de Meent** - Vision & Direction

*"One Love, One fAmIly"* 💙

**TIBET is now an IETF Internet-Draft:**
[draft-vandemeent-tibet-provenance-00](https://datatracker.ietf.org/doc/draft-vandemeent-tibet-provenance/)

---

<p align="center">
  <a href="https://humotica.com">
    <img src="https://img.shields.io/badge/Powered%20by-SymbAIon-blue" alt="Powered by SymbAIon">
  </a>
</p>
