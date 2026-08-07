# Red Specter — credits & the open invitation

The `red-specter` regression guards in tibet-audit (`tibet_audit/red_specter.py`) exist because of a real
adversary who did it right.

## Credit

**Red Specter · `richard.specter.aint`** — NIGHTFALL engagement, 2026-08-06 (RS2026-002).

Richard red-teamed AInternet-in-a-Box and found what mattered:

- **T143 — TIBET ledger tampering.** The audit trail was forgeable and unverified. → fix **C1: verify-on-read**
  (`prev = sha256(previous line)`); a broken chain now fails closed.
- **T152 — unsigned `.waint.json` manifest injection.** Tool manifests were unsigned and injectable (he planted
  a working backdoor manifest). → fix **C2: sign + admit on read**.
- **MED — tombstoned identity accepted as caller.** Signature validity was not enough. → fix **caller_freshness**
  (verify + tombstone + freshness + monotone lineage).

Every one of these is now a **permanent regression guard**: if a fix ever silently regresses, `tibet-audit
red-specter` turns EXPOSED. That is the most durable thanks we can give — his work defends the box forever.

## Open, and his to try

Richard publishes his research in the open:

- <https://zenodo.org/records/21834333>
- <https://zenodo.org/records/21834202>

tibet-audit is **MIT-licensed** and open source — like the rest of the stack, built *for humAnIty*. So the
invitation is open both ways: the guards that carry his findings are public and verifiable, and the repo is his
to run against the box himself.

> **Try for yourself:** `pip install tibet-audit` → `tibet-audit red-specter <box-path>` — and the source is at
> `github.com/Humotica/tibet-audit`.

OS rocks. 💙
