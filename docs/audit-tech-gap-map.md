# tibet-audit — tech gap map V2 (the road to audit.aint)

> **Audit as a precondition, not an observation.** Audit is not something done after the fact to describe what
> happened — it is the gate *before* action. A broken causal chain caps confidence and blocks the profile; a
> fix that regresses turns a guard EXPOSED. The verdict is a precondition to trust, not a report about it.

tibet-audit scans for *compliance* well (regulatory frameworks + IAB-native checks), and it is the project's
#1 PyPI download since day one — so it must keep improving. But it was built before much of the current stack
existed, and lately a lot of IAB goes in **directly, in Rust**. This map is the honest inventory of **what it
already sees** vs **what it does not** — the backbone of a future `audit.aint`: the box auditing itself,
causally, in one legible voice.

Legend: ✅ closed · ◑ partial · ✗ blind spot.

## ⚠️ The structural blind spot: Rust / crates

tibet-audit is **Python**. Anywhere a Rust component and tibet-audit stand side by side is a gap **by
construction** — the Python auditor cannot see into a crate's execution. This covers CRUST (Capsulated Rust),
the Rust airlock, the memfd runtime, and tibet-zip (which already self-validates). The lesson shapes *how*
these gaps close: audit should **invoke the Rust tool's own verify / read its emitted receipts**, not
re-implement the check in Python. Provenance is read in the component's own terms — never re-asserted.

## What it already sees

**Evidence adapters:** `continuityd · cap-bus · snaft · tibet-pol · gateway · cmail · tibet-cortex`
**Sources:** `audit · trail / tibet-trail · continuityd(-audit) · gateway(-events) · cap-bus(-events) ·
snaft(-audit) · pol-verdicts · cmail(-events) · cortex(-events)`
**Checks / frameworks:** AI-Act · GDPR · NIS2 · DORA · BIO2 · privacy laws (APPI · LGPD · NDPR · PDPA · PIPA ·
Gulf PDPL · Privacy Act AU) · IAB-native: `ains · jis · tibet · rvp · sovereignty · upip · provider_security · tls`

## The gap → the roadmap

| # | tech component | status in audit (the blind spot) |
|---|----------------|----------------------------------|
| **1** | **time-vector / causal-chain integrity** | **✅ CLOSED (#67, commit 9760ad7)** — verifies `prev = sha256(previous raw line)`; a broken chain caps confidence + sets profile `integrity-compromised`. |
| **2** | **open-tail / Pol'n** | ✅ (with #1) — flags the stalled-process symptom (started, never resolved). |
| 3 | **MUX 16-bit status language & `mux-events`** | ✗ no mux source, no `0x4000`/`0x0000:<reason>` vocabulary. |
| 4 | **comms-core / tibet-calling** | ✗ unknown (#63) — lane-contract + proof-manifest, the identity-bound line. |
| 5 | **NIGHTFALL caller_freshness / tombstone** | ✗ does not know tombstoned-as-caller admission. |
| 6 | **scharnier-locality** | ✗ measured-path-truth vs IP-inferred. |
| **7** | **PQC / HNDL** (Ed25519 + ML-DSA-65) | **✅ CLOSED (audit half)** — `tibet-audit pqc` flags long-lived provenance signed classical-only as HNDL-exposed (retroactively forgeable by a CRQC) and recommends the hybrid response; credited to Red Specter's open HNDL research. Box-side hybrid *implementation* remains #66. |
| 8 | **phantom states & cross-device lineage** | ✗ no adapter for the t-1 ↔ t0 fork / resume / seal states. |
| 9 | **triage / parentAttest (k/it) / admissibility** | ✗ `triage/events` not a source; does not understand parentAttest / OBO logic. |
| 10 | **t-1 / genesis-guard / phoenix / EXIT** | ✗ anti-genesis and transition-rails are complete blind spots. |
| 11 | **KEYSTONE runtime-binding** | ◑ partly via `jis`, not audited as its own layer / tibet-chip. |
| 12 | **crust / memfd runtime (Rust)** | ✗ Capsulated Rust execution is not verified. *(Rust blind spot.)* |
| 13 | **work-ledger** | ✗ not a source — misses ticks-as-labour provenance. |
| 14 | **tibet-zip** | ✗ no audit logic for compressed/sealed payload integrity. *(Self-validates; Rust-adjacent.)* |
| 15 | **tibet-drop / id-drop** | ✗ does not check correct identity-shedding on drops. |
| 16 | **ZTIP protocol** | ✗ the Zero-Trust Identity Protocol is not yet decomposed by the radar. |
| 17 | **bearer handover** | ✗ state transfer between carriers is not causally verified. |
| **18** | **the BOM suite** (sys-bom · ai-sbom · mux-bom · ram-bom) | **✅ CLOSED** — `tibet-audit bom` reflects on the box's OWN sealed `system-bom-<build>.json` (sensor readiness + **digest verification**, hashes decide → digest-mismatch is an integrity break). Does not re-collect; reflects against the sealed floor. |
| 19 | **tibet-sam & tibet-nc** | ✗ missing evidence adapters. |
| 20 | **tibet-cmail deep checks** | ◑ knows cmail as a source, but likely misses deep payload/integrity checks. |
| 21 | **airlock (Rust & Python)** | ✗ boundary controls around the isolated execution environments are missing. *(Rust half is a blind spot.)* |
| **22** | **Red Specter red-teaming (Richard's findings)** | **✅ CLOSED** — `tibet-audit red-specter` regression-guards T143/T152/MED (self-proving where possible); credited to Red Specter, open + his to try. See [red-specter-credits.md](red-specter-credits.md). |
| 23 | **voice cache / voice lane (KIT)** | ✗ audio lanes + cache provenance are outside the radar. |
| 24 | **TPM2 download signing (IAB updates)** | ✗ misses hardware-rooted signature validation for binaries. |
| 25 | **connection posture (open connections)** | ✗ passive connections / network hygiene under-checked / under-enforced. |
| 26 | **general encryption baseline** | ✗ does not actively check cipher-suites / encryption standards across the board. |
| **27** | **human presence** (machine-floor · egress actors · humane presence) | **✅ CLOSED (read, not gauged)** — `tibet-audit bom` now READS the box's own presence evidence (owner-binding.json RVP token · custody · TPM2 substrate · expiry; presence-live.json posture) and reflects it: present / stale / deferred / unbound. Open half: fold it into the sys-bom SENSOR family (#49) so the self-portrait sees its human. |
| 28 | **tibet-cascade** (stack-wide causal-correlation feed) | **◑ audit reads it** — the shipped cross-stack observability layer (JIS→TIBET→cap-bus→gateway→ping→continuityd→Phantom→evidence). `causal_integrity` now verifies its `cascade/events.jsonl` as another causal spoor. The box-native koepel (`tick_trail`) is the box-local embodiment of the same idea; full IAB cockpit/radar wiring (its placement note) is the open half. |

## Principle for the coupling

Every gap closes the way #1 did: the box already **emits** the evidence; audit must **read it in the box's own
terms** — causal order and integrity first, wall-clock never as the source of truth, and for Rust components,
the crate's own verify/receipts rather than a Python re-implementation. A broken causal chain caps governance
confidence: no claim stands on evidence that fails its own provenance. That is `audit.aint`.

## North Star — a per-runtime audit layer

The closing form of this map: **audit is not one central scanner, it is a layer every runtime carries.** When
the substrate can host any runtime, each one gets its **own** audit lens — its own causal-integrity, its own
red-team regression guards, its own presence/HNDL/BOM reflection — scoped to what it may see. Runtimes then
**push and pull over a typed, contractual lane** (admitted on identity, content-blind between; the comms-core
lane-contract + proof-manifest), inside a **sandbox++**: enriched, bounded autonomy where more is possible
precisely because the boundary is *structural, not trust-based*.

This is what lets a creative-but-unbounded runtime run safely: you do not tame the genius, you give it a
structure where its verdicts gate before action (audit-as-a-precondition) and its reach is a lane it cannot
exceed. Kerckhoffs for behaviour — it does not matter how wild the reasoning is; the structure decides what can
carry. Each runtime sovereign, self-auditing, lane-contractual. The specialist swarm, each honest about itself.

_Living document (V2). Ordering is rough priority, not fixed. Co-owned; extend as the stack grows — much of IAB
now lands directly in Rust, so the map will keep moving._
