# Changelog

## 0.26.0 — 2026-05-30

**Professionalization Pass 1 — audit cockpit + evidence adapters.** Production-merge van Codex' `tibet-audit-pro-workcopy`. tibet-audit verschuift van scanner naar **governance conclusion layer**: bewijs ophalen uit continuityd / cap-bus / snaft / pol / gateway / cmail / cortex en samenstellen tot operator-leesbare verhalen.

### Added (Pass 1)

- `tibet_audit/cockpit.py` (581 LOC) — `build_cockpit_snapshot`, `discover_evidence_sources`, `load_tail_events`, `classify_event` + `EvidenceSource` / `ComponentStatus` / `CockpitFinding` / `ReadinessLane` dataclasses.
- `tibet_audit/evidence_adapters.py` (236 LOC) — 7 typed adapters: `ContinuitydAdapter`, `CapBusAdapter`, `SnaftAdapter`, `TibetPolAdapter`, `GatewayAdapter`, `CmailAdapter`, `CortexAdapter`. Elke adapter heeft `matches(source, record) → bool` en `assess(source, records) → AdapterAssessment`.
- `tibet_audit/correlation.py` (225 LOC) — `EvidenceChain` + `ChainStep` voor incident-stories (External AI containment, Cmail operator send).
- 2 nieuwe sub-commands in `tibet-audit` CLI:
  - `tibet-audit evidence [PATH]` — indexeer JSONL/JSON evidence-bronnen (lokaal of `--system`)
  - `tibet-audit tail [PATH] [--source FILE]` — live tail van JSONL bronnen met filters
  - `tibet-audit cockpit [PATH]` — dual-pane operator overview: evidence + components + readiness lanes
  - `tibet-audit ops-report [PATH] [--format markdown|json]` — operator-vriendelijk rapport
  - `tibet-audit status` enhanced — runtime posture + evidence summary in default output

### Posture-awareness

Cockpit consumeert `posture.transition.v1` events uit cap-bus en toont actuele snaft-posture (`normal_zero_trust` / `quarantine_external_ai` / `hard_quarantine`) + switches changed (deny_external_ai_inbound, require_airlock_marker_on_tokens, etc). Sluit aan op `tibet-cap-bus 0.1.3+` + `snaft 1.4.0+` immune-switch keten.

### Cmail koppeling

`CmailAdapter` herkent `tibet-cmail 0.2.4+` events op top-level `kind = "cmail.message.event.v1"` of `sealed: bool` of `content_hash` duck-type fallback. Light vs Sealed counts zijn accuraat. Plus voorbereiding voor live-stream via `CMAIL_CAPBUS_URL` env var op cmail kant.

### Readiness lanes

7 lanes met status (`ready` / `active` / `partial` / `baseline` / `missing`):
1. Identity + provenance (OSAPI bootstrap-pair)
2. Continuity daemon
3. Evidence spine
4. Agent communication
5. Immune controls
6. Runtime hardening
7. External AI containment

### Tests

- `tests/test_cockpit.py` + `tests/test_governance_conclusion.py` — 11 nieuwe tests groen.
- Geen regressie op bestaande tests.

### Read-only by design

De cockpit start geen daemons, muteert geen policy, en schrijft geen systeem-config. Het leest evidence en presenteert. Production-pass houdt deze discipline aan.

### Reference docs

- `PROFESSIONALIZATION_PASS_1.md` (in package root) — Codex' intent + 7 vervolgstappen voor 0.27.x roadmap.
- `TIBET-AUDIT-AS-GOVERNANCE-CONCLUSION.md` — 4-vragen-architectuur (WHAT/HOW/WHO/WHY → SO WHAT).
- `examples/p520-passive/` — demo fixture met live continuityd-audit.jsonl.

---

## 0.25.0 — 2026-05-28

**First-mover release for the OSAPI bootstrap-pair discipline** (per Jasper's "vanaf nu meeslepen" rule, 28 mei). `tibet-audit` is the first non-kernel package to declare `tibet-core` + `jis-core` as runtime-deps — laying the pattern every other touched package will follow.

### Added
- `tibet-core>=0.5.0b2` as runtime dependency (provenance OSAPI — chain, emit, query, fork)
- `jis-core>=0.4.0b1` as runtime dependency (identity OSAPI — claim, bind, FIR/A)

### Why
- Compliance scans now run against the **central chain** + **central identity-store**, not local Provider instances. The audit-trail of an audit-run is itself part of the chain.
- No-fail-open at the audit level: if either OSAPI is down, `tibet-audit` cannot silently succeed — the spec failure-protocol applies.
- This release establishes the **template**: bump version, add the two deps, document in CHANGELOG.

### Non-breaking
- Existing CLI surfaces (`tibet-audit scan`, etc.) unchanged.
- Runtime-bootstrap-call (the actual `tibet_core.bootstrap()` + `jis_core.osapi.bootstrap()`) wires in the next minor (0.26.0); 0.25.0 = dep-declaration so downstream `tibet[full]==2.1.1` users immediately pull the pair.

## 0.24.1 - 2026-05-15

- Added governance conclusion output as a first-class audit result layer.
- Detected upstream governance stack sources for:
  - `AI-SBOM` / `tibet-ai-sbom`
  - `tibet-sbom`
  - `CBOM` / `tibet-core`
  - `AINS` / `ainternet`
  - `JIS` / `jis-core`
- Reworked the CLI presentation to a cleaner business style:
  - removed large ASCII banner blocks
  - unified scan, checkpoint, sign-off, sovereign, framework, and status headers
  - simplified score card and verbose/fix messaging
- Kept the tool voice intact while making terminal output more professional.

## 0.24.0

- Added `tibet-core` / `jis-core` integration, `[full]` extras, and SBOM baseline support.
