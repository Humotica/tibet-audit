# tibet-audit professionalization pass 1

Sandbox workcopy:
`/srv/jtel-stack/sandbox/ai/codex/tibet-audit-pro-workcopy`

## Intent

Move `tibet-audit` from a mostly preflight compliance scanner toward an
operator-grade audit cockpit:

- preflight scan still answers "is this project ready?"
- evidence index answers "what runtime evidence exists?"
- tail answers "what just happened?"
- cockpit answers "what is the local trust posture right now?"

## Added surface

New module:

- `tibet_audit/cockpit.py`

New CLI commands:

- `tibet-audit evidence [PATH]`
- `tibet-audit tail [PATH] [--source FILE]`
- `tibet-audit cockpit [PATH]`
- `tibet-audit ops-report [PATH] [--format markdown|json] [--out FILE]`

Enhanced command:

- `tibet-audit status [PATH]` now includes runtime posture and evidence summary.
- `tibet-audit cockpit [PATH]` now includes posture summary, readiness lanes,
  next actions and component availability.

## Pass 2 additions

The cockpit now translates raw events into an operator assessment:

- posture transitions from `posture.transition.v1`
- changed switches, including `deny_external_ai_inbound` and
  `require_airlock_marker_on_tokens`
- quarantine/reject/disguised intake warnings
- readiness lanes:
  - Identity + provenance
  - Continuity daemon
  - Evidence spine
  - Agent communication
  - Immune controls
  - Runtime hardening
  - External AI containment
- concrete next actions for package gaps and missing evidence

## Pass 3 additions

Typed evidence adapters now turn raw JSONL into subsystem-specific audit
signals:

- `continuityd`: intake classes, dispositions, quarantine/reject counts
- `cap-bus`: posture transitions, last posture, changed switches
- `snaft`: verdict distribution, deny-by-default / fail-closed signal
- `tibet-pol`: operator approval/blocked states
- `gateway`: lane classes and emitters
- `cmail`: hashed/sealed mail and command messages
- `tibet-cortex`: L0-L4 / cortex level observations

These adapters are exposed in:

- `tibet-audit cockpit`
- `tibet-audit status --output json`
- `tibet-audit ops-report`

## Pass 5 additions

Correlation now turns typed evidence into operator-readable chains:

- External AI containment chain:
  `cap-bus posture -> SNAFT deny -> continuityd quarantine -> gateway lane policy -> tibet-pol block -> cmail operator notice -> cortex context policy`
- Cmail operator send chain:
  `cmail hashed/sealed message -> tibet-pol approval`

The chain layer reports:

- complete vs partial status
- ordered steps
- missing links
- subsystem/action summaries suitable for W3C/offline demos and incident review

## Evidence sources indexed

Local project paths:

- `.tibet/`, `.tibet/provenance/`, `.tibet/audit/`
- `audit/`, `audits/`, `evidence/`, `reports/`, `compliance/`, `logs/`
- local `var/log/tibet` and `var/lib/tibet` folders for repo fixtures

Optional system paths with `--system`:

- `/var/log/tibet`
- `/var/lib/tibet`
- `/root/.tibet`
- `/root/.snaft`

File patterns:

- `continuityd-audit.jsonl`, `gateway-events.jsonl`, `cap-bus-events.jsonl`
- `snaft-audit.jsonl`, `pol-verdicts.jsonl`, `tibet-trail.jsonl`
- `ai-sbom.json`, `sbom.json`, `cbom.json`, `nis2.json`, `wayback.json`

## Demo commands

```bash
cd /srv/jtel-stack/sandbox/ai/codex/tibet-audit-pro-workcopy
PYTHONPATH=. python3 -m tibet_audit.cli evidence .
PYTHONPATH=. python3 -m tibet_audit.cli cockpit .
PYTHONPATH=. python3 -m tibet_audit.cli status --output json .
PYTHONPATH=. python3 -m tibet_audit.cli ops-report examples/p520-passive
```

With live P520-style logs:

```bash
PYTHONPATH=. python3 -m tibet_audit.cli cockpit --system /root
PYTHONPATH=. python3 -m tibet_audit.cli tail --system /root --source continuityd-audit.jsonl
```

## Notes for Claude / Root AI

This is intentionally read-only. It does not start daemons, mutate policy, or
write system config. The next production pass should wire the same evidence
schema to:

- `tibet-continuityd` audit log
- `tibet-gateway events`
- `tibet-cap-bus gateway-export`
- `snaft status` / posture verdicts
- `tibet-pol` posture and operator approvals
- `tibet-cmail` command mail receipts
