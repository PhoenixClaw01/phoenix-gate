# Phoenix Gate Kit

> Thin policy gate for agent tool calls: **named locks · allow / deny / ask_human · receipts.**  
> Speaks Osmantic APE-shaped verify. Not another agent. Not a model SKU. Not a chat bus.

**Story arc:** Governance → Gate → packets → businesses we serve

```
[0] Governance             named intents · Founder last-yes
[1] Gate Kit (this repo)   named locks · allow/deny/ask_human · receipts
[2] Ops packets            intent · bounds · won’t · AUTHORIZE
[3] Field faces            businesses served (private)
```

---

## Why this exists

Agents will act. Someone has to gate irreversible acts **without killing speed**.

A gate that only denies is a **corpse**.  
A gate that always allows is a **wound**.  
Governance = named intents → `allow` / `require_approval` / `deny` **and** explicit allow paths so craft still lives.

**Intelligence should increase sovereignty, not diminish it.**  
Humans hold intent and last-yes. Agents execute. Every consequential act leaves provenance.

---

## What this is

- **Named locks** for irreversible acts (Publish, spend, wipe, invent-SKU, …)
- **Policy pack** shape: allow / deny / need-human (`ask_human` ↔ APE `require_approval`)
- **Receipt trail** agents and humans can cite (Continuity-shaped; no vault dump)
- **APE-shaped verify** vocabulary so peers can wire Hermes → policy without inventing a new religion
- **Offline adapter demo** pattern (mock APE + locks + receipts) — laptop-proven policy loop
- **Thin scope (Fork A)** — proof artifact, not an oxygen cathedral

### Vocabulary map (peer-shaped)

| Phoenix | APE `/verify` |
|---------|----------------|
| proceed | `allow` |
| block | `deny` |
| ask_human | `require_approval` → human approve |

---

## What this is NOT

| Not this | Why |
|----------|-----|
| Capture / SlipVault / contractor paper UX | Small-biz FDE face stays private; free seats ≠ OSS |
| Tenant auth / multi-tenant ledger / invoice parties | Selling the store |
| Continuity vault dumps | Trust ≠ dump; private spine stays closed |
| Hub / Content Hub / outbound SaaS | Hub-as-service starved — not a product in this narrative |
| “We replaced Hermes” / gym-Dojo software | Optional later fractal; not this face |
| A paid oxygen cathedral or smarter judge SKU | Thin brick, not an unpaid cathedral |

**Private fence (hard):** Capture factory · ledgers · tenant auth · Continuity vault / PII · wood / Starlink cash streams · Hub Make tokens · full SIOS tip dump.

---

## Quick start

```bash
git clone https://github.com/PhoenixClaw01/phoenix-gate.git
cd phoenix-gate
python3 demo_loop.py
# → ALLOW / DENY / NEED_HUMAN lines + Continuity-shaped receipt JSONL
```

No install required for the offline demo (stdlib + in-tree phoenix_gate package).

**Honest ceiling:** offline policy loop is proven craft. Live Hermes wire-up / production APE strength / Founder click in the wild = residuals. Humans remain the last story. Seam choice (hooks vs proxy vs in-Hermes) belongs with the peer who owns the gateway.

---

## Testing

```bash
python3 -m unittest discover -s tests -v
```

Stdlib unittest against `phoenix_gate` with the offline mock APE. Attack classes stay covered: named locks, args smuggle, receipt chain, multi-agent grants, supply/env, jailbreak echoes, enablement false-positives, and an in-process seam sim (skip-gate, compose, flood). That sim is not Hermes in production. The suite checks the policy loop on this laptop; it is not a claim of live production use.

CI runs the same command on Python 3.11+ (`.github/workflows/unittest.yml`). No attack class is skipped.

---

## Doctrine metabolism (public-safe)

| Intent class | Default | Allow path |
|--------------|---------|------------|
| Local craft (read / draft / analyze / plan) | **ALLOW** | Benign allowlist — livelihood |
| Speak in public / Publish | **NEED_HUMAN** | Founder approve · fingerprint · TTL |
| Spend / turn live scenario On / shell-risk | **NEED_HUMAN** | Founder last-yes |
| Wipe / invent SKU / exfil | **DENY** | none — fail-closed |

Anti-paralysis craft: every new hard deny needs a paired allow story; gate **acts**, not English morality on draft notes; false-positive NEED_HUMAN burns Founder attention — don’t flood via prose.

---

## Field proof (small biz FDE — no private UX)

We run the **same spine** in the dirt for small business: hold before send, named last-yes, receipts you can cite.  
Public desks and Capture seats are **field deployment for small business** — quiet proof the doctrine works — **not** the README hero and **not** open-sourced here.

If you need help on the ground (Valley Maps / GBP listing fix, Capture seat ask), see the Collective site soft footer when live — not this repo’s issues as a sales channel.

---

## Interest (soft)

Want the thin Gate Kit when the public tree lands? Leave a quiet note via the Collective site waitlist (when GO) — **pattern + receipts, not another chat bus.** No Hub seats pitch. No spray.

---

## Status

Public thin cut (Fork A). **Founder last-yes** on anything irreversible.  
Sequence lock for Phoenix public face: **Git → Collective site → LinkedIn** (this README is the Git face).

## Substrate next

Same locks, still thin. Permissionless sovereignty surfaces: **CLI · MCP · HTTP API · plugins**. Workers stay model-agnostic; the gate is not a model SKU.

**Nodes** are optional community / Osmantic-class compute under Gate receipts for small-biz workloads — architecture and inspiration only, no partnership. A node is a watershed you can ignore. The kit runs without one.

Hub stays off this face (not a product here). Sketch: [`docs/NODES-AND-SUBSTRATE.md`](docs/NODES-AND-SUBSTRATE.md).

## Support

GitHub Sponsors — [PhoenixClaw01](https://github.com/sponsors/PhoenixClaw01).

## License

Apache-2.0 · contributions: talk first · no drive-by cathedral PRs

## Links

- Substrate sketch — [`docs/NODES-AND-SUBSTRATE.md`](docs/NODES-AND-SUBSTRATE.md)
- Phoenix Collective — https://phoenix-collective.app *(philosophy page when live)*  

---

*Heart cathedral · invisible founder · no hype BS.*  
*Populate, don’t spray.*
