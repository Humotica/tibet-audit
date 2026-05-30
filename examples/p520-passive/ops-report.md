# TIBET Audit Ops Report

- Path: `examples/p520-passive`
- Posture: `degraded`
- Evidence sources: 8/8 active
- Latest events indexed: 14
- Warnings: 2

## Posture

- Current posture: `hard_quarantine`
- External AI inbound denied: `True`
- Airlock marker required: `True`
- Quarantine events: `1`

## Readiness Lanes

| Lane | Status | Observed | Reason |
|---|---:|---|---|
| Identity + provenance | `ready` | tibet-core, jis-core | OSAPI pair packages are available |
| Continuity daemon | `ready` | tibet-continuityd, continuityd-audit.jsonl | continuityd package and audit lane are present |
| Evidence spine | `ready` | tibet-audit, tibet-sbom, tibet-cbom, ai-sbom.json | audit/SBOM/CBOM package surface and an AI-SBOM artifact are present |
| Agent communication | `ready` | ainternet, ipoll, cmail | AInternet, I-Poll package and Cmail operator surface are available |
| Immune controls | `ready` | snaft, tibet-airlock, tibet-triage, tibet-pol | SNAFT, airlock, triage and policy operator packages are available |
| Runtime hardening | `partial` | snaft-core | Missing: tibet-trust-kernel, tibet-zip-core |
| External AI containment | `active` | deny_external_ai_inbound, quarantine evidence | Posture/evidence shows external AI containment or quarantine activity |

## Evidence Sources

| Source | Kind | Records | Latest |
|---|---:|---:|---|
| `ai-sbom.json` | json | 1 | 1780030083.0 |
| `cap-bus-events.jsonl` | jsonl | 2 | 1780030082.2 |
| `cmail-events.jsonl` | jsonl | 2 | 1780030091.0 |
| `continuityd-audit.jsonl` | jsonl | 2 | 1780030080.1101 |
| `cortex-events.jsonl` | jsonl | 2 | 1780030093.0 |
| `gateway-events.jsonl` | jsonl | 2 | 1780030089.0 |
| `pol-verdicts.jsonl` | jsonl | 2 | 1780030087.0 |
| `snaft-audit.jsonl` | jsonl | 2 | 1780030085.0 |

## Evidence Adapters

| Adapter | Status | Records | Summary |
|---|---:|---:|---|
| cap-bus | `active` | 2 | 2 posture transitions, 8 switches observed |
| cmail | `ready` | 2 | 2 hashed/sealed messages, 1 command messages |
| continuityd | `attention` | 2 | 2 intake events, 1 require attention |
| tibet-cortex | `observed` | 2 | 2 cortex management events |
| gateway | `observed` | 2 | 2 gateway lane events |
| tibet-pol | `active` | 2 | 2 operator policy events |
| snaft | `ready` | 2 | 2 policy/verdict events, fail-closed=True |

## Evidence Chains

| Chain | Status | Steps | Missing |
|---|---:|---:|---|
| External AI containment chain | `complete` | 7 | - |
| - cap-bus | `info` | posture-transition | normal_zero_trust -> quarantine_external_ai |
| - snaft | `warning` | precheck | deny_external_ai_inbound ON |
| - continuityd | `warning` | intake | agent-drop.exe -> quarantine |
| - gateway | `info` | lane-policy | external-ai -> deny |
| - tibet-pol | `info` | operator-policy | external_ai_tool_call -> blocked |
| - cmail | `info` | operator-notice | External AI quarantined |
| - tibet-cortex | `info` | context-policy | L4: external-ai-context |
| Cmail operator send chain | `complete` | 2 | - |
| - cmail | `info` | sealed-message | jasper -> root_idd.aint: Re: Welkom in cmail |
| - tibet-pol | `info` | operator-approval | cmail_313d29d7f46d4087 -> approved |

## Latest Findings

| Severity | Message | Source |
|---|---|---|
| `info` | posture_c2254c0feb2743aa: posture event | `examples/p520-passive/cap-bus-events.jsonl` |
| `info` | posture_hard_quarantine_demo: posture event | `examples/p520-passive/cap-bus-events.jsonl` |
| `info` | cmail message: Re: Welkom in cmail | `examples/p520-passive/cmail-events.jsonl` |
| `info` | cmail command: External AI quarantined | `examples/p520-passive/cmail-events.jsonl` |
| `ok` | codex-passive-test-2.json: reseal-candidate (json-text) | `examples/p520-passive/continuityd-audit.jsonl` |
| `warning` | agent-drop.exe: quarantine (executable) | `examples/p520-passive/continuityd-audit.jsonl` |
| `info` | cortex L2: local-memory | `examples/p520-passive/cortex-events.jsonl` |
| `info` | cortex L4: external-ai-context | `examples/p520-passive/cortex-events.jsonl` |
| `info` | gateway lane agent-high: graceful_yield | `examples/p520-passive/gateway-events.jsonl` |
| `info` | gateway lane external-ai: deny | `examples/p520-passive/gateway-events.jsonl` |
| `info` | tibet-pol approved: cmail_313d29d7f46d4087 | `examples/p520-passive/pol-verdicts.jsonl` |
| `info` | tibet-pol blocked: external_ai_tool_call | `examples/p520-passive/pol-verdicts.jsonl` |
| `warning` | SNAFT deny: deny_external_ai_inbound ON | `examples/p520-passive/snaft-audit.jsonl` |
| `ok` | SNAFT allow: local operator intent | `examples/p520-passive/snaft-audit.jsonl` |

## Next Actions

- Package gap: ipoll is installed as a library but has no operator CLI binary.
- Install or expose Rust runtime pieces: tibet-trust-kernel, tibet-zip-core and snaft-core.
