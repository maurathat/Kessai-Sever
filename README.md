# Sever — revocation by chain-walk

Agent authority as hash-linked, strictly-attenuated capabilities with a
cryptographic kill-switch. Built for **Agent Identity Build Day** (AGI House,
June 27 2026).

## The four questions

| Question | Answer |
|---|---|
| **Who authorized this agent?** | A root capability signed by a human Ed25519 key. |
| **What is it allowed to do?** | Caveats on the capability — spend caps, venue allow-lists, expiry. |
| **How does trust travel A → B?** | Hash-linked delegation that provably narrows (attenuation). |
| **How do you kill it?** | Publish a revocation. The verifier walks the chain; the whole subtree dies. |

## Worked example

Pre-IPO private-share transfer (SpaceX Series J) executed by a chain of
agents — KYC, document review, seller confirmation, settlement. The stakes
are legible: uncontrolled agent authority could move securities or approve a
transfer that shouldn't happen.

## The three beats

### Beat 1 — Attenuation

Human authorizes Agent A: "transfer SpaceX J, up to $1 M, three approved
venues." A delegates to B, narrowing to $50 k / one venue. B delegates to C,
narrowing to $10 k. B attempts a *broader* delegation — the token itself
rejects it. Trust visibly shrinks as it travels.

### Beat 2 — Settlement gating

An escrow is funded with a hashlock on the *expected* work-claim content
address. The agent submits wrong work — no release. Correct work — releases.
Verified work, not a signed promise.

### Beat 3 — Kill-switch cascade

Full chain is live and green. Compromise detected at B. Publish revocation.
B turns red; everything below it (C) goes orphaned. C replays its still-signed
token — the verifier walks the chain — **DEAD**. Killing the middle killed
everything below it, provably, because the links are hashes, not database rows.

## Run it

```bash
pip install -r requirements.txt
uvicorn server:app --port 8000
# open http://127.0.0.1:8000
```

Python 3.11+. The UI is served at `/` and calls the API at the same origin.

## Architecture

```
index.html  ──▶  server.py (FastAPI)  ──▶  capability_spine.py
   UI               HTTP wrapper              source of truth
```

- **`capability_spine.py`** — canonical addressing (UOR-ADDR), Ed25519
  identities, `attenuate()` (provably narrows), `Registry` + `walk_validity()`
  (revocation chain-walk), `WorkClaim` + `Escrow` (settlement gating).
- **`server.py`** — thin FastAPI layer. Endpoints: `/reset`, `/delegate`,
  `/check_action`, `/fund_escrow`, `/settle`, `/revoke`, `/chain`.
- **`index.html`** — single-file demo UI. Three beats as control panels;
  the authorization chain animates live → revoked → orphaned.

## Why this is rigorous

1. **Attenuation only narrows.** Every caveat in a child capability is checked
   against the parent — numeric caps must be ≤, allow-lists must be ⊆, omitted
   caveats are inherited. `attenuate()` raises `AttenuationError` on any
   widening attempt.

2. **Canonicalization is byte-exact.** NFC-normalized, sorted keys, no
   insignificant whitespace, UTF-8. Two semantically-equal objects always
   produce the same content address.

3. **Validity = chain-walk + freshness, not addressing alone.** Content
   addressing gives stable names; validity requires walking every ancestor and
   checking: present, signature verifies, unexpired, not revoked. The registry
   check at decision time is the freshness mechanism.

4. **Delegation is cryptographically bound.** Only the key that holds a
   capability can delegate from it. Forged delegations are rejected.

5. **Real signatures.** Ed25519 via PyNaCl — not mocks, not HMACs.

## Built on

Two open standards, both CC0, no vendor lock-in:

- **UOR-ADDR** — serialization-invariant content addressing.
- **VTEAI** — verified-work settlement (escrow gates on content-addressed work
  claims, not signed assertions).

## Honest limits

- Resource/action matching is exact-match; hierarchical resources are future
  work.
- The escrow models crypto-conditions (PREIMAGE-SHA-256) hashlock logic
  in-process by default. Live settlement on XRPL testnet using
  crypto-conditions escrow is a toggleable stretch path. The on-chain check
  gates on a preimage; the work-claim address is bound to that preimage
  off-chain. XLS-100 Smart Escrows would move the address check on-chain but
  the spec is in review and not yet transactable.
- LLM-driven agents can fabricate data within a valid schema — the cert chain
  proves work *happened per spec*, not that inputs were correct.
- Verifiable ≠ enforceable: the system serves the regulated process (transfer
  agent, consent, ROFR stay in the loop); it does not disintermediate it.

## License

CC0
