# TIBET Audit As Governance Conclusion

Date: 2026-05-15
Status: architecture note

## Core Claim

`tibet-audit` should be the **governance conclusion layer**, not the
origin of every truth it concludes from.

That means:

- `tibet-audit` should synthesize
- not pretend to replace
- the underlying evidence systems

## The Four Governance Questions

For AI governance, four different questions must be answered:

- `WHAT is there?`
  - answered by `AI-SBOM`
  - inventory, models, datasets, infrastructure, configured providers

- `HOW did it get there / how did it happen?`
  - answered by `CBOM` / `TIBET`
  - provenance, causal path, continuity, custody, chain-of-command

- `WHO is acting?`
  - answered by `AINS` / `.aint`
  - active actor identity, domains, roles, ownership, routing surfaces

- `WHY do we believe this?`
  - answered by `JIS`
  - attestation, signature, key binding, trust-bearing authority

`tibet-audit` belongs **above** these layers.

It answers:

- `SO WHAT does this mean for compliance and governance?`

## Correct Role Division

### 1. AI-SBOM

Use for:

- static inventory truth
- model/provider presence
- artifact and package context
- evidence of configured or observed capability

### 2. CBOM / TIBET

Use for:

- causal history
- provenance integrity
- continuity legitimacy
- custody and usage evidence

### 3. AINS / .aint

Use for:

- actor identity
- active operating entities
- agent/service/domain binding

### 4. JIS

Use for:

- trust foundation
- signature-backed claims
- attestation and authority

### 5. TIBET Audit

Use for:

- regulatory interpretation
- control coverage
- gap assessment
- conclusion quality
- evidence-backed compliance narrative

## Why This Matters

Without this separation, an audit tool risks overclaiming.

Examples:

- A compliance check passes, but the inventory is weak.
- A model is configured, but no actor linkage exists.
- A provenance trail exists, but no trust anchor is present.
- An actor exists, but the usage route is not attested.

In those cases, `tibet-audit` may still produce text, but the
**governance confidence** of that conclusion is weaker.

So the audit output should not only say:

- which checks passed
- which controls failed
- which frameworks are covered

It should also say:

- how strong the underlying governance evidence is

## Proposed Conclusion Model

`tibet-audit` should expose a conclusion block shaped roughly like this:

```json
{
  "governance_conclusion": {
    "what_status": "sufficient | partial | weak | absent",
    "how_status": "sufficient | partial | weak | absent",
    "who_status": "sufficient | partial | weak | absent",
    "why_status": "sufficient | partial | weak | absent",
    "overall_governance_confidence": "high | medium | low",
    "conclusion_basis": [
      "ai-sbom",
      "cbom",
      "ains",
      "jis"
    ]
  }
}
```

This does not replace the normal compliance report.

It strengthens it by making the evidence quality visible.

## Suggested Evidence Refs

The audit layer should ideally point to upstream evidence, for example:

- `ai_sbom_evidence_ref`
- `cbom_evidence_ref`
- `ains_evidence_ref`
- `jis_evidence_ref`
- `usage_events_ref`

This allows an auditor or regulator to inspect not only the conclusion,
but the basis for that conclusion.

## Example Reading

A strong audit conclusion would mean something like:

- inventory truth is present
- provenance truth is present
- active identity truth is present
- attestation truth is present
- therefore the compliance conclusion is high confidence

A weaker audit conclusion would mean:

- some controls may appear covered
- but the evidence basis is incomplete
- therefore the conclusion should be marked medium or low confidence

## Practical Product View

This leads to a clean stack:

- `tibet-ai-sbom` says what exists
- `tibet-cbom` / `TIBET` say how it happened
- `AINS` says who is active
- `JIS` says why the claim is believable
- `tibet-audit` says what that means for compliance

That is a much stronger story than asking `tibet-audit` to do
everything itself.

## Strategic Implication

If `tibet-audit` is already the most visible package by adoption,
then this is an advantage:

- it can remain the familiar front door
- while becoming the conclusion layer over a richer governance stack

So:

- keep `tibet-audit` prominent
- but let it conclude from `AI-SBOM + CBOM + AINS + JIS`
- instead of flattening those into one opaque compliance score

## One-Line Summary

`tibet-audit` should conclude, not pretend to originate the truth it is concluding from.
