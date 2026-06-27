# Sever — build instructions for Claude Code

Project name: **Sever**. Tagline: **"revocation by chain-walk."** "Sever" names the money shot (cut a node, everything below it dies); "chain-walk" is the mechanism (the verifier walks the hash-linked authority chain and dies on any revoked ancestor) and lives in the tagline/subtitle, not the name. The name is cosmetic; the architecture and invariants below are not.

## What this is

A hackathon demo for **Agent Identity Build Day (AGI House, June 27, 2026\)**. The event asks four questions; this project answers all four on screen:

1. **Who authorized this agent?** — root capability signed by a human key.  
2. **What is it allowed to do?** — caveats on the capability (scope, caps, venues).  
3. **How does trust travel A→B?** — hash-linked, strictly-attenuated delegation.  
4. **How do you kill it?** — publish a revocation; the verifier walks the chain and the whole subtree dies, including replays.

Worked example throughout: a **pre-IPO private-share transfer** executed by agents (KYC → document review → seller confirmation → transfer-agent approval → settlement). The stakes are legible: uncontrolled agent authority could move securities or approve a transfer that shouldn't happen.

Built on two open standards (the author's own, both already exist — do NOT redesign them): **UOR-ADDR** (serialization-invariant content addressing) and **VTEAI** (verified-work settlement). The brand line is "two open standards, CC0, no vendor lock-in." Preserve that framing.

This is a NEW project, distinct from the older **AgentLevy** commerce demo (x402 payments, TEE-verified KYC). They share UOR-ADDR/VTEAI underneath but answer different questions. Do not import AgentLevy framing or call this AgentLevy.

## Environment

Developing on a **MacBook Pro (macOS)**. Python 3.11+. Run locally:

pip install \-r requirements.txt

uvicorn server:app \--port 8000

\# open http://127.0.0.1:8000

The API binds to 127.0.0.1 only — never expose it. The UI is served at `/` and calls the same origin with relative URLs, so nothing is hard-coded to a port.

## Current state (already built — start here, do not rewrite)

Runnable. `pip install -r requirements.txt`, then `uvicorn server:app --port 8000` and open [http://127.0.0.1:8000](http://127.0.0.1:8000).

- **`capability_spine.py`** — the library and single source of truth. Canonical addressing, Ed25519 identities, `attenuate()` (provably narrows), `Registry` \+ `walk_validity()` (revocation chain-walk), `WorkClaim` \+ `Escrow` (settlement gating), `provenance_view()` (terminal chain renderer).  
- **`server.py`** — FastAPI wrapper exposing the spine over HTTP. The UI calls THIS; the browser never reimplements the load-bearing logic. Endpoints: /reset /delegate /check\_action /fund\_escrow /settle /revoke /chain.  
- **`index.html`** — the P0 demo UI (DONE). Single file, served by the API at /. Three beats as control panels; the authorization-provenance chain is the hero and animates: nodes are green/LIVE, severing a node turns it red/REVOKED and marks all descendants ORPHANED (dashed red) while the verdict flips to INVALID. This is the projector demo and it works end-to-end.  
- **`demo.py`** — terminal version of the three beats (fallback / sanity check).

The spine is correct and tested via the UI walkthrough and demo.py. Build ON it. Do not regenerate from scratch. P0 (web UI) is COMPLETE — remaining work is P1 (README) and the P2 stretch (live XRPL), plus any polish requested.

## INVARIANTS — never violate these (they are the whole thesis)

1. **Attenuation only narrows, never widens.** A delegated capability must be provably ≤ its parent: numeric caps ≤ parent, allow-lists ⊆ parent, omitted caveats inherited (you cannot drop a limit by leaving it out). `attenuate()` raises `AttenuationError` on any widening. A demo where "attenuate" can widen destroys the entire argument. (The reference Qwen version had this bug — `capabilities.extend()`. Never reintroduce it.)  
     
2. **Canonicalization is byte-exact.** NFC-normalized, sorted keys, no insignificant whitespace, UTF-8. Use `canonical_bytes()`. Never hash pretty-printed JSON (`indent=2`) — that breaks serialization-invariance and produces non-reproducible addresses. This is the exact bug UOR-ADDR exists to prevent.  
     
3. **Validity \= chain-walk \+ freshness, NOT addressing alone.** Content addressing gives stable *names*; it does not by itself tell you a capability is *currently valid*. Validity requires walking every ancestor and checking: present, signature verifies, unexpired, not revoked. The registry check at decision time IS the freshness mechanism. Keep this distinction explicit in code comments and any UI copy — it's the honest answer to "how does the verifier know it's seen the revocation."  
     
4. **Delegation is cryptographically bound to the holder.** Only the key that holds a capability can delegate from it (`attenuate` checks `issuer.did == parent.audience`). A forged delegation must be rejected.  
     
5. **Real signatures, not stand-ins.** Ed25519 via PyNaCl. The sign/verify seam is two functions; ML-DSA-65 swap is a roadmap note, not a build task unless explicitly requested.

## Build priority (8 PM comes fast — one target at a time, in order)

### P0 — Web UI for the demo  ✅ DONE

Built: `index.html` \+ `server.py`. Three beats, animated kill-switch cascade, projector-ready. If you touch it, preserve the invariants and the same-origin fetch (the UI calls relative URLs when served over http). Polish only on request.

### P1 — README for judges

Short. The four questions, the three beats, how to run it, the invariants as "why this is rigorous," and the honest limits (below). No marketing fluff.

### P2 — Live XRPL testnet settlement for Beat 2  (do AFTER P0+P1 are solid)

Make Beat 2 settle on a **real XRPL testnet ledger** — a genuine on-chain release, with a transaction hash you can show in a block explorer. This is a strong closer but the part most likely to break live, so build it as a **toggleable path with the in-process model as guaranteed fallback**. The demo must NEVER depend on the live call: if testnet is slow/down at 8 PM, flip to the in-process `Escrow` (already built) and the demo is unaffected.

**Use the primitive that is actually live: classic crypto-conditions escrow (PREIMAGE-SHA-256). DO NOT use XLS-100 Smart Escrows / WASM FinishFunction** — as of June 2026 the XLS-100 spec is "in review," there is no enabled amendment, and it is NOT transactable on any network. (The author used PREIMAGE-SHA-256 crypto-conditions in the earlier AgentLevy build; reuse that approach.)

Flow (xrpl-py or xrpl.js):

1. Generate a PREIMAGE-SHA-256 crypto-condition. The **preimage IS bound to the work-claim**: preimage \= the canonical bytes of the expected `WorkClaim` (or a value committed alongside it). `condition = SHA-256(preimage)`.  
2. `EscrowCreate` on testnet: fund from the buyer's testnet wallet to the seller, with `Condition` \= that condition and a `CancelAfter` safety window.  
3. Agent "does the work" → produces the work-claim → its canonical bytes are the `Fulfillment`.  
4. `EscrowFinish` submitting the `Fulfillment`. The ledger verifies SHA-256(fulfillment) \== condition and releases. Show the tx hash.  
5. Wrong work → wrong fulfillment → SHA-256 mismatch → ledger rejects. Same pass/fail story as the in-process model, now on-chain.

**Honest framing (REQUIRED — state it, don't paper over it):** classic crypto-conditions escrow gates on a **preimage**, not on the content address directly. The work-claim address is bound to the preimage **off-chain**; the on-chain check is "agent presented the secret whose hash was committed at funding." XLS-100 Smart Escrows (spec in review) would move the content-address verification **on-chain** into a WASM FinishFunction — that is the roadmap, not the demo. Say exactly this if a judge asks; it makes you more credible, not less.

Wiring notes:

- Testnet wallets via the faucet ([https://faucet.altnet.rippletest.net](https://faucet.altnet.rippletest.net)) or xrpl-py `generate_faucet_wallet`. Pre-fund and hardcode the demo wallets so there's no faucet dependency at 8 PM.  
- Add a `LIVE_XRPL` flag (env var or toggle in `server.py`). Default OFF (in-process). When ON, `/fund_escrow` and `/settle` call testnet; on ANY error or timeout, log it and fall back to the in-process result so the UI still resolves. Never let a testnet failure hang the demo.  
- Keep the in-process `Escrow` class exactly as-is; the live path is additive.

## NON-GOALS — do not build these (they will burn the clock)

- **Do NOT integrate any external credential vault** (1Password agent kit, cloud KMS, etc.). Mock any credential an agent "uses." These are a roadmap mention only: capabilities are the layer that says *whether* an agent may act; a vault is the separate layer that *holds* the secret. Saying that sentence is the whole integration. Never wire a real vault to a real key in a stage demo, and never have an agent enter real credentials into a real service — especially under a securities framing.  
- **Do NOT build the full asset-identity stack** (AssetSpec / ProvenanceSpec / SourceProof, the four provenance layers, double-sale/tropical detection). That is a separate body of work for a different audience. Here it is at most ONE architecture slide: "the asset being transferred is itself content-addressed and provenance-verified all the way down." Do not try to run it live.  
- **Do NOT redesign UOR-ADDR or VTEAI.** They exist. Use them as given.  
- **Do NOT add hierarchical resource matching, ZK proofs, or post-quantum signatures** unless P0 and P1 are done and explicitly requested. Note them as future work.

## Honest limits (keep these true in code and pitch — they are a credibility asset)

- Resource/action matching is exact-match; hierarchical resources are future work.  
- The escrow models crypto-conditions (PREIMAGE-SHA-256) hashlock logic in-process; live settlement on XRPL **testnet** using crypto-conditions escrow is the P2 stretch. The on-chain check gates on a preimage; the work-claim address is bound to that preimage off-chain. XLS-100 Smart Escrows would move the address check on-chain but its spec is in review and it is not yet transactable.  
- LLM-driven agents (if added) can fabricate data within a valid schema — the cert chain proves the work *happened per spec*, not that inputs were correct.  
- Verifiable ≠ enforceable: a verified chain proves what was authorized; whether a court treats a transfer as valid is jurisdiction-bound. The system serves the regulated process (transfer agent, consent, ROFR stay in the loop); it does not disintermediate it.

## Demo script (the 8 PM run, \~4 min) — single-escrow flow

The escrow is FUNDED in Beat 2 and RESOLVED in Beat 3, so the kill-switch decides whether real money moves. This is what makes the escrow relevant to the agents rather than a bolted-on crypto demo.

1. **Setup (15s):** human authorizes Agent A — "transfer SpaceX Series J, up to $1M, three approved venues." One signed root capability.  
2. **Beat 1 — attenuation (60s):** A→B narrows to $50k/one venue. B→C narrows to $10k. Show B trying to delegate something *broader* → rejected by the token.  
3. **Beat 2 — fund settlement (40s):** fund the escrow on XRPL testnet with a hashlock on the expected work-claim (preimage \= SHA-256 of the work-claim's canonical bytes). Submit WRONG work → ledger rejects, no release. HOLD the correct-work release — do not settle yet. The money stays locked.  
4. **Beat 3 — kill-switch \+ the stakes (100s, THE CLOSER):** full chain live, escrow still pending. Sever B. B \+ C die (chain-walk). C replays → DEAD. THEN try to settle C's pending escrow → REFUSED, because `try_release` re-checks `walk_validity` and the authority is revoked. In LIVE mode, no EscrowFinish is submitted at all (authority pre-check fails first — nothing hits the ledger). The line: "severing B stopped the money C was about to move."  
5. **Land it (25s):** four questions answered; prompt-injection containment is the same story; two open standards, CC0; authority layer chain-agnostic, chain only at settlement.

**Required wiring for this flow:**

- `Escrow.try_release` MUST re-check `walk_validity` and refuse on a revoked authorizing capability (reason: "authority revoked — settlement blocked", distinct from the hashlock-mismatch reason). Confirm it does.  
- UI: a button in the kill-switch panel — "Try to settle C's pending escrow" — that shows the refusal post-sever.  
- UI: surface the live settlement on-screen, not just the log — clickable testnet explorer links ([https://testnet.xrpl.org/transactions/{hash}](https://testnet.xrpl.org/transactions/{hash})) for EscrowCreate and EscrowFinish, and a LIVE/SIMULATED badge driven off a `live` flag in the API response (so the badge is truthful when the fallback fires).

