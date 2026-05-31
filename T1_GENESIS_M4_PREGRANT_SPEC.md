# T-1 Genesis Airlock for M4 Pre-Grant Substitution

Status: sandbox audit design  
Scope: `tibet-audit` read-only evidence assessment  
Date: 2026-05-31

## Problem

Chain pinning is a post-grant defense. It catches mutation after a tool has a
known clean identity, schema, endpoint and capability set.

It does not, by itself, prove that the registry state was clean at the moment
the first grant was created.

That is Mahipal's M4:

> Registry-phase substitution before t0: tool swap during schema ingestion
> before capability grant.

## Revised claim

Do not claim that post-grant pinning closes pre-grant substitution.

Use this claim instead:

> M1-M3 are post-grant mutation classes; chain pinning blocks those after T0.
> M4 is pre-grant. M4 is handled by a T-1 genesis airlock: no T0, no grant, no
> capability-bearing tool unless a clean T-1 candidate merges into ready state.

Short version:

> Pinning starts after truth exists. Genesis airlock creates the first truth.

## State model

```text
untrusted registry/tool/schema source
    ↓
T-1 airlock import
    ↓
capture first observed schema/description/endpoint/allowed-tools/magic bytes
    ↓
dual verify: JIS identity + TIBET provenance
    ↓
clean-slate attestation
    ↓
fork candidate
    ↓
diff against claimed registry state
    ↓
merge into T0 only if clean
    ↓
capability grant allowed
```

Until merge, the object is not a tool. It is an untrusted candidate.

## T-1 Genesis Contract

Required fields for a complete pre-grant candidate:

- `tool_id`
- `schema_hash`
- `description_hash`
- `allowed_tools_hash`
- `endpoint_hash`
- `registry_source`
- `retrieved_at`
- `retriever_identity`
- `magic_bytes`
- `tibet_token`
- `jis_claim`
- `airlock_verdict`
- `fork_id`
- `merge_to_t0_verdict`

## M4 variants

### M4a: dirty registry before T-1 airlock

Expected result:

- candidate captured
- airlock verdict = `poisoned` or `blocked`
- merge verdict = `no-grant`
- no T0 ready state

### M4b: substitution between T-1 capture and T0 merge

Expected result:

- candidate captured
- diff detects mutation
- new fork or merge failure
- no silent overwrite
- no capability grant from mutated candidate

### M4c: substitution after T0

Expected result:

- handled as ordinary post-grant mutation
- chain pinning / SNAFT / policy should hard-fail

## tibet-audit implementation

Sandbox files:

- `tibet_audit/genesis.py`
- `examples/p520-passive/genesis-events.jsonl`

Snapshot field:

- `genesis_assessment`

Report surfaces:

- `tibet-audit cockpit`
- `tibet-audit status --output json`
- `tibet-audit ops-report --format ops-contract`

The assessment reports:

- `status`: `absent`, `observed`, `ready`, or `attention`
- candidate counts
- ready / blocked / forked counts
- findings
- contract status
- reproducible content hash over the assessment

## Important boundary

This is an audit/evidence model, not a granting engine.

`tibet-audit` should not mutate policy, grant capabilities, or start daemons.
It verifies whether evidence shows that the runtime enforced the T-1 model.

