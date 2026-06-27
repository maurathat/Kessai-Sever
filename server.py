"""
Sever — API server wrapping the real capability spine.

The UI calls THIS. There is exactly one implementation of attenuation, canonical
addressing, and the revocation walk — the spine. The browser never reimplements
the load-bearing logic, so what you demo is literally what runs.

Run:  uvicorn server:app --reload --port 8000
Then open index.html (it points at http://127.0.0.1:8000).
"""
from __future__ import annotations
import hashlib
import logging
import time
from dataclasses import dataclass
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
import os

from dotenv import load_dotenv
load_dotenv()

from capability_spine import (
    Capability, Identity, attenuate, check_action, AttenuationError,
    Registry, walk_validity, WorkClaim, Escrow, sign, address,
    canonical_bytes,
)

logger = logging.getLogger("sever")

# ── LIVE_XRPL toggle ──────────────────────────────────────────────────────────
# When True, /fund_escrow and /settle call the XRPL testnet using
# classic PREIMAGE-SHA-256 crypto-conditions escrow.  Default OFF.
# On ANY error or timeout, fall back to in-process model — never hang the demo.
LIVE_XRPL = os.getenv("LIVE_XRPL", "false").lower() in ("true", "1", "yes")


# ── PREIMAGE-SHA-256 crypto-condition helpers ─────────────────────────────────
# Uses the cryptoconditions library (RFC 8090). The preimage is the canonical
# bytes of the WorkClaim; condition and fulfillment are read from the library.

def cc_fulfillment(preimage: bytes) -> str:
    """PREIMAGE-SHA-256 fulfillment as uppercase hex (what XRPL expects)."""
    from cryptoconditions import PreimageSha256
    ff = PreimageSha256(preimage=preimage)
    return ff.serialize_binary().hex().upper()


def cc_condition(preimage: bytes) -> str:
    """PREIMAGE-SHA-256 condition as uppercase hex (what XRPL expects)."""
    from cryptoconditions import PreimageSha256
    ff = PreimageSha256(preimage=preimage)
    return ff.condition_binary.hex().upper()


# ── Live XRPL helpers (loaded lazily so the server starts even if xrpl-py
#    has issues or env vars are missing) ────────────────────────────────────────

def _xrpl_create_escrow(preimage: bytes, amount_drops: str) -> dict:
    """EscrowCreate on testnet. Returns {"tx_hash": ..., "sequence": ...}."""
    from xrpl.clients import JsonRpcClient
    from xrpl.wallet import Wallet
    from xrpl.constants import CryptoAlgorithm
    from xrpl.models.transactions import EscrowCreate
    from xrpl.transaction import submit_and_wait
    from xrpl.utils import datetime_to_ripple_time
    from datetime import datetime, timedelta, timezone

    client = JsonRpcClient(os.environ["XRPL_RPC_URL"])
    buyer = Wallet.from_seed(
        os.environ["XRPL_BUYER_SEED"], algorithm=CryptoAlgorithm.ED25519
    )
    destination = Wallet.from_seed(
        os.environ["XRPL_COMPLIANCE_SEED"], algorithm=CryptoAlgorithm.ED25519
    )
    cancel_after = datetime_to_ripple_time(
        datetime.now(timezone.utc) + timedelta(hours=1)
    )
    tx = EscrowCreate(
        account=buyer.address,
        amount=amount_drops,
        destination=destination.address,
        condition=cc_condition(preimage),
        cancel_after=cancel_after,
    )
    response = submit_and_wait(tx, client, buyer)
    result = response.result
    return {
        "tx_hash": result.get("hash", ""),
        "sequence": result.get("Sequence") or result.get("tx_json", {}).get("Sequence"),
    }


def _xrpl_finish_escrow(preimage: bytes, escrow_sequence: int) -> dict:
    """EscrowFinish on testnet. Returns {"tx_hash": ..., "result": ...}."""
    from xrpl.clients import JsonRpcClient
    from xrpl.wallet import Wallet
    from xrpl.constants import CryptoAlgorithm
    from xrpl.models.transactions import EscrowFinish
    from xrpl.transaction import submit_and_wait

    client = JsonRpcClient(os.environ["XRPL_RPC_URL"])
    buyer = Wallet.from_seed(
        os.environ["XRPL_BUYER_SEED"], algorithm=CryptoAlgorithm.ED25519
    )
    tx = EscrowFinish(
        account=buyer.address,
        owner=buyer.address,
        offer_sequence=escrow_sequence,
        condition=cc_condition(preimage),
        fulfillment=cc_fulfillment(preimage),
    )
    response = submit_and_wait(tx, client, buyer)
    result = response.result
    engine_result = result.get("meta", {}).get("TransactionResult", "unknown")
    return {
        "tx_hash": result.get("hash", ""),
        "engine_result": engine_result,
    }

app = FastAPI(title="Sever — revocation by chain-walk")
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)

# ── In-memory demo world. Reset by POST /reset. ─────────────────────────────
@dataclass
class World:
    reg: Registry
    ids: dict          # name -> Identity
    caps: dict         # name -> Capability
    escrow: object = None
    expected_claim: object = None
    # Live XRPL state (only populated when LIVE_XRPL is on)
    xrpl_escrow_sequence: int | None = None
    xrpl_preimage: bytes | None = None
    xrpl_create_tx_hash: str | None = None


W: World = None


def fresh_world() -> World:
    reg = Registry()
    ids = {n: Identity.create(n) for n in ("HUMAN", "Agent A", "Agent B", "Agent C")}
    root = Capability(
        issuer=ids["HUMAN"].did, audience=ids["Agent A"].did,
        resource=address({"asset_class": "equity.private", "issuer": "SpaceX",
                          "security_class": "preferred:j"}),
        action="transfer:shares",
        caveats={"max_usd": 1_000_000, "venues": ["hill", "forge", "npm"]},
        parent=None, not_after=time.time() + 3600,
    )
    root.signature = sign(root.addr(), ids["HUMAN"].signing_key)
    reg.register(root)
    return World(reg=reg, ids=ids, caps={"Agent A": root})


def names_map() -> dict:
    return {idn.did: name for name, idn in W.ids.items()}


def cap_to_json(name: str, cap: Capability) -> dict:
    nm = names_map()
    v = walk_validity(cap.addr(), W.reg)
    return {
        "name": name,
        "issuer": nm.get(cap.issuer, cap.issuer[:12] + "…"),
        "audience": nm.get(cap.audience, cap.audience[:12] + "…"),
        "action": cap.action,
        "caveats": cap.caveats,
        "addr": cap.addr(),
        "parent": cap.parent,
        "revoked": cap.addr() in W.reg.revoked,
        "expired": cap.not_after < time.time(),
        "valid": v.valid,
        "reason": v.reason,
    }


def chain_json(leaf_name: str) -> list:
    """Full chain root→leaf as a list, each node annotated. Walks parent links
    regardless of validity so a revoked middle node is still shown."""
    cap = W.caps[leaf_name]
    addr_to_name = {c.addr(): n for n, c in W.caps.items()}
    full = []
    a = cap.addr()
    while a is not None and a in W.reg.caps:
        c = W.reg.caps[a]
        full.append(cap_to_json(addr_to_name.get(a, "?"), c))
        a = c.parent
    return list(reversed(full))


# ── API ─────────────────────────────────────────────────────────────────────
@app.post("/reset")
def reset():
    global W
    W = fresh_world()
    return {"ok": True, "caps": [cap_to_json("Agent A", W.caps["Agent A"])]}


class DelegateReq(BaseModel):
    frm: str            # delegator (must hold the parent)
    to: str             # audience
    max_usd: float
    venues: list[str] | None = None
    ttl_seconds: float | None = None


@app.post("/delegate")
def delegate(req: DelegateReq):
    """Attenuate from frm's capability to `to`. Returns the new cap, or the
    AttenuationError that the token itself raised (widening / forgery)."""
    parent = W.caps.get(req.frm)
    if parent is None:
        return {"ok": False, "error": f"{req.frm} holds no capability"}
    new_caveats = {"max_usd": req.max_usd}
    if req.venues is not None:
        new_caveats["venues"] = req.venues
    try:
        child = attenuate(parent, audience=W.ids[req.to].did,
                          new_caveats=new_caveats, issuer=W.ids[req.frm],
                          ttl_seconds=req.ttl_seconds)
    except AttenuationError as e:
        return {"ok": False, "error": str(e), "rejected_by": "the token itself"}
    W.reg.register(child)
    W.caps[req.to] = child
    return {"ok": True, "cap": cap_to_json(req.to, child)}


class ActionReq(BaseModel):
    who: str
    max_usd: float
    venue: str


@app.post("/check_action")
def check(req: ActionReq):
    cap = W.caps.get(req.who)
    if cap is None:
        return {"ok": False, "error": f"{req.who} holds no capability"}
    permitted_by_caveats = check_action(cap, {"max_usd": req.max_usd, "venues": req.venue})
    v = walk_validity(cap.addr(), W.reg)
    return {
        "ok": True,
        "permitted": permitted_by_caveats and v.valid,
        "within_scope": permitted_by_caveats,
        "authority_valid": v.valid,
        "reason": v.reason,
    }


class EscrowReq(BaseModel):
    who: str
    units: int


@app.post("/fund_escrow")
def fund_escrow(req: EscrowReq):
    cap = W.caps.get(req.who)
    task = address({"task": "settle transfer of SpaceX J units", "buyer": "B"})
    expected = WorkClaim(task_spec_addr=task,
                         output_addr=address({"units": req.units, "status": "transferred"}),
                         performed_by=cap.audience, inputs=[address({"kyc": "passed"})])
    W.expected_claim = expected
    W.escrow = Escrow(amount=f"{req.units} units RLUSD",
                      expected_claim_addr=expected.addr(), authorizing_cap_addr=cap.addr())

    result = {"ok": True, "hashlock": expected.addr(), "expected_units": req.units,
              "live_xrpl": False}

    # ── Live XRPL path (additive) ────────────────────────────────────────
    if LIVE_XRPL:
        try:
            # The preimage is SHA-256(canonical_bytes(WorkClaim)) — 32 bytes,
            # well within XRPL's 256-byte fulfillment limit. The binding to
            # the work-claim is off-chain; the on-chain check gates on the
            # preimage hash. (See "Honest framing" in CLAUDE.md.)
            preimage = hashlib.sha256(canonical_bytes({
                "task_spec_addr": expected.task_spec_addr,
                "output_addr": expected.output_addr,
                "performed_by": expected.performed_by,
                "inputs": expected.inputs,
            })).digest()
            xrpl_result = _xrpl_create_escrow(preimage, "1000000")  # 1 XRP
            W.xrpl_preimage = preimage
            W.xrpl_escrow_sequence = xrpl_result["sequence"]
            W.xrpl_create_tx_hash = xrpl_result["tx_hash"]
            result["live_xrpl"] = True
            result["xrpl_tx_hash"] = xrpl_result["tx_hash"]
            result["xrpl_escrow_sequence"] = xrpl_result["sequence"]
            result["xrpl_note"] = (
                "EscrowCreate submitted on XRPL testnet. The condition commits "
                "to SHA-256(canonical_bytes(WorkClaim)). The on-chain check gates "
                "on this preimage; the work-claim address is bound off-chain."
            )
            logger.info("XRPL EscrowCreate tx: %s", xrpl_result["tx_hash"])
        except Exception as exc:
            logger.warning("XRPL EscrowCreate failed, falling back to in-process: %s", exc)
            result["xrpl_error"] = str(exc)
            result["xrpl_fallback"] = True

    return result


class SettleReq(BaseModel):
    units: int          # what the agent actually delivered


@app.post("/settle")
def settle(req: SettleReq):
    if W.escrow is None:
        return {"ok": False, "error": "no escrow funded"}
    task = W.expected_claim.task_spec_addr
    claim = WorkClaim(task_spec_addr=task,
                      output_addr=address({"units": req.units, "status": "transferred"}),
                      performed_by=W.expected_claim.performed_by,
                      inputs=[address({"kyc": "passed"})])
    released, why = W.escrow.try_release(claim, W.reg)

    result = {"ok": True, "released": released, "reason": why,
              "submitted_units": req.units,
              "claim_addr": claim.addr(),
              "matches_hashlock": claim.addr() == W.escrow.expected_claim_addr,
              "live_xrpl": False}

    # ── Live XRPL path (additive) ────────────────────────────────────────
    # Only attempt on-chain finish if the in-process model released —
    # if authority is revoked, the pre-check already blocked it and we
    # must NOT submit EscrowFinish (no on-chain release for dead authority).
    if LIVE_XRPL and W.xrpl_escrow_sequence is not None and released:
        try:
            # Build the fulfillment preimage from the SUBMITTED claim —
            # same SHA-256(canonical_bytes(...)) as at funding time.
            submitted_preimage = hashlib.sha256(canonical_bytes({
                "task_spec_addr": claim.task_spec_addr,
                "output_addr": claim.output_addr,
                "performed_by": claim.performed_by,
                "inputs": claim.inputs,
            })).digest()
            xrpl_result = _xrpl_finish_escrow(submitted_preimage, W.xrpl_escrow_sequence)
            engine = xrpl_result["engine_result"]
            if engine == "tesSUCCESS":
                result["live_xrpl"] = True
                result["xrpl_tx_hash"] = xrpl_result["tx_hash"]
                result["xrpl_settled"] = True
                result["xrpl_note"] = (
                    "EscrowFinish succeeded on XRPL testnet. The ledger verified "
                    "SHA-256(fulfillment) == condition and released the funds."
                )
                logger.info("XRPL EscrowFinish tx: %s", xrpl_result["tx_hash"])
            else:
                # Ledger rejected — wrong preimage or other issue
                result["live_xrpl"] = True
                result["xrpl_settled"] = False
                result["xrpl_engine_result"] = engine
                result["xrpl_tx_hash"] = xrpl_result.get("tx_hash", "")
                result["xrpl_note"] = (
                    f"EscrowFinish rejected by ledger: {engine}. "
                    "Wrong work produces wrong fulfillment — SHA-256 mismatch."
                )
                logger.info("XRPL EscrowFinish rejected: %s", engine)
        except Exception as exc:
            logger.warning("XRPL EscrowFinish failed, falling back to in-process: %s", exc)
            result["xrpl_error"] = str(exc)
            result["xrpl_fallback"] = True

    return result


class RevokeReq(BaseModel):
    who: str            # whose capability to revoke


@app.post("/revoke")
def revoke(req: RevokeReq):
    cap = W.caps.get(req.who)
    if cap is None:
        return {"ok": False, "error": f"{req.who} holds no capability"}
    W.reg.revoke(cap.addr())
    return {"ok": True, "revoked": req.who, "addr": cap.addr()}


@app.get("/chain")
def chain(leaf: str = "Agent C"):
    if leaf not in W.caps:
        return {"ok": False, "error": f"{leaf} holds no capability"}
    return {"ok": True, "chain": chain_json(leaf)}


@app.get("/")
def index():
    here = os.path.dirname(os.path.abspath(__file__))
    return FileResponse(os.path.join(here, "index.html"))


W = fresh_world()
