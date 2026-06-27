"""
AgentLevy / Kessai — capability spine for Agent Identity Build Day (June 27, 2026).

Three demo beats, all in one file:
  1. Attenuation handoff   — delegation that PROVABLY narrows (rejects any widening).
  2. Settlement gating     — escrow releases only when a work-claim address matches.
  3. Kill-switch cascade   — revoke a root; the verifier walks the chain and the
                             whole subtree dies, including replays.

Design stance (say this in the room):
  - Authority is content-addressed (UOR-ADDR-style canonical hashing).
  - Trust travels as hash-linked, strictly-attenuated capabilities.
  - Validity is a CHAIN-WALK + FRESHNESS property layered over addressing —
    content-addressing alone gives stable names, not "currently valid".
  - Settlement (VTEAI) fires on a verified work claim, not a signed assertion.

Signatures are real Ed25519 (PyNaCl). Swap in ML-DSA-65 for the post-quantum
story; the sign/verify seam is two functions. Canonicalization is the one thing
that must be byte-exact, so it's done properly: sorted keys, no whitespace,
UTF-8/NFC. Install: pip install pynacl
"""

from __future__ import annotations
import hashlib
import json
import time
import unicodedata
from dataclasses import dataclass, field
from fractions import Fraction
from typing import Any, Optional

from nacl import signing, encoding
from nacl.exceptions import BadSignatureError


# ─────────────────────────────────────────────────────────────────────────────
# Canonical addressing  (the one part that must be byte-exact)
# ─────────────────────────────────────────────────────────────────────────────

def canonical_bytes(obj: Any) -> bytes:
    """Serialization-invariant canonical form: NFC-normalized, sorted keys,
    no insignificant whitespace. Two semantically-equal objects -> identical bytes
    -> identical address, regardless of how they were originally serialized.
    This is the property that closes the 're-encode to dodge revocation' hole."""
    def nfc(x: Any) -> Any:
        if isinstance(x, str):
            return unicodedata.normalize("NFC", x)
        if isinstance(x, dict):
            return {nfc(k): nfc(v) for k, v in x.items()}
        if isinstance(x, list):
            return [nfc(v) for v in x]
        return x
    return json.dumps(
        nfc(obj), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def address(obj: Any) -> str:
    """UOR-ADDR-style content address."""
    return "sha256:" + hashlib.sha256(canonical_bytes(obj)).hexdigest()


def sign(addr: str, signing_key: "signing.SigningKey") -> str:
    """Real Ed25519 signature over the content address, hex-encoded."""
    return signing_key.sign(addr.encode("utf-8")).signature.hex()


def verify_sig(addr: str, sig_hex: str, public_key_hex: str) -> bool:
    """Verify an Ed25519 signature against a hex-encoded public key."""
    try:
        vk = signing.VerifyKey(public_key_hex, encoder=encoding.HexEncoder)
        vk.verify(addr.encode("utf-8"), bytes.fromhex(sig_hex))
        return True
    except (BadSignatureError, ValueError):
        return False


@dataclass
class Identity:
    """An agent's keypair. `did` is the hex public key — the on-the-wire id.
    A real build uses did:key encoding; hex keeps the demo readable."""
    name: str
    signing_key: "signing.SigningKey"

    @classmethod
    def create(cls, name: str) -> "Identity":
        return cls(name=name, signing_key=signing.SigningKey.generate())

    @property
    def did(self) -> str:
        return self.signing_key.verify_key.encode(encoding.HexEncoder).decode()


# ─────────────────────────────────────────────────────────────────────────────
# Capability + attenuation  (Beat 1)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Capability:
    """A UCAN-style capability: User-Controlled Authorization Network token.
    `parent` is the content address of the capability this was delegated FROM —
    that hash-link is what makes the delegation chain a Merkle structure."""
    issuer: str                 # who is granting (public key)
    audience: str               # who receives it (public key)
    resource: str               # what it applies to
    action: str                 # what may be done
    caveats: dict               # the CONSTRAINTS (this is where narrowing lives)
    parent: Optional[str]       # content address of parent capability, or None at root
    not_after: float            # freshness: unix expiry (revocation safety net)
    signature: str = ""

    def body(self) -> dict:
        return {
            "issuer": self.issuer, "audience": self.audience,
            "resource": self.resource, "action": self.action,
            "caveats": self.caveats, "parent": self.parent,
            "not_after": self.not_after,
        }

    def addr(self) -> str:
        return address(self.body())


class AttenuationError(Exception):
    """Raised when a delegation tries to GRANT MORE than the parent held.
    The whole point: B's authority must be provably <= A's authority."""


def _caveat_is_narrower(parent_v: Any, child_v: Any) -> bool:
    """Is the child's constraint at least as restrictive as the parent's?
    Numeric caps: child must be <=. Allow-lists: child must be a subset.
    Scalars: must match exactly. This is the heart of 'provably narrows'."""
    # numeric ceilings (e.g. max spend) — child cap cannot exceed parent cap
    if isinstance(parent_v, (int, float, str)) and isinstance(child_v, (int, float, str)):
        try:
            return Fraction(str(child_v)) <= Fraction(str(parent_v))
        except (ValueError, ZeroDivisionError):
            return parent_v == child_v       # non-numeric scalar: exact match only
    # allow-lists (e.g. vendors) — child must be a subset of parent
    if isinstance(parent_v, list) and isinstance(child_v, list):
        return set(child_v) <= set(parent_v)
    return parent_v == child_v


def attenuate(parent: Capability, audience: str, new_caveats: dict,
              issuer: "Identity", ttl_seconds: Optional[float] = None) -> Capability:
    """Delegate a STRICTLY WEAKER capability. Rejects any attempt to widen.

    A correct attenuate() can only ever shrink the grant. The Qwen version did
    `capabilities.extend(...)` — that ADDS scope, the opposite of attenuation.
    Here every new caveat is checked against the parent and rejected if broader,
    and any parent caveat the child omits is inherited (you can't drop a limit).
    The delegator must be the parent's holder (audience) — checked here."""
    if issuer.did != parent.audience:
        raise AttenuationError(
            f"{issuer.name} cannot delegate a capability it does not hold "
            f"(holder is {parent.audience[:16]}…)"
        )
    # every caveat the child sets must be narrower-or-equal to the parent's
    merged = dict(parent.caveats)            # inherit all parent limits by default
    for k, v in new_caveats.items():
        if k in parent.caveats and not _caveat_is_narrower(parent.caveats[k], v):
            raise AttenuationError(
                f"caveat '{k}'={v!r} is broader than parent {parent.caveats[k]!r} "
                f"— delegation may only narrow authority"
            )
        merged[k] = v                        # narrower (or a brand-new restriction)

    # child cannot outlive the parent
    parent_remaining = parent.not_after - time.time()
    horizon = parent_remaining if ttl_seconds is None else min(ttl_seconds, parent_remaining)
    not_after = time.time() + max(0.0, horizon)

    child = Capability(
        issuer=parent.audience,              # the delegator is the parent's holder
        audience=audience,
        resource=parent.resource,
        action=parent.action,
        caveats=merged,
        parent=parent.addr(),                # ← hash-link to parent = the chain
        not_after=not_after,
    )
    child.signature = sign(child.addr(), issuer.signing_key)
    return child


def check_action(cap: Capability, request: dict) -> bool:
    """Would this capability permit this concrete request, on its own terms?
    (Validity-against-the-chain is checked separately in walk_validity.)"""
    for k, limit in cap.caveats.items():
        if k not in request:
            continue
        req = request[k]
        if isinstance(limit, list):
            if req not in limit:
                return False
        else:
            try:
                if Fraction(str(req)) > Fraction(str(limit)):
                    return False
            except (ValueError, ZeroDivisionError):
                if req != limit:
                    return False
    return True


# ─────────────────────────────────────────────────────────────────────────────
# The chain store + revocation-walk  (Beat 3)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Registry:
    """Holds capabilities by address and the revocation set. The verifier checks
    this at decision time — that check IS the freshness mechanism. A revocation
    published here kills the address and everything descended from it."""
    caps: dict = field(default_factory=dict)         # addr -> Capability
    revoked: set = field(default_factory=set)        # set of revoked addresses

    def register(self, cap: Capability) -> str:
        self.caps[cap.addr()] = cap
        return cap.addr()

    def revoke(self, addr: str) -> None:
        self.revoked.add(addr)


@dataclass
class ValidityResult:
    valid: bool
    reason: str
    chain: list            # addresses from leaf -> root, for the provenance view


def walk_validity(cap_addr: str, reg: Registry, now: Optional[float] = None) -> ValidityResult:
    """Walk leaf -> root. The capability is valid ONLY IF every ancestor:
      - exists, - has a verifying signature, - is unexpired, - is NOT revoked.
    Revoking ANY ancestor fails the whole branch. This is the kill-switch."""
    now = now if now is not None else time.time()
    chain: list = []
    addr = cap_addr
    while addr is not None:
        cap = reg.caps.get(addr)
        if cap is None:
            return ValidityResult(False, f"missing capability {addr[:18]}…", chain)
        chain.append(addr)
        if addr in reg.revoked:
            return ValidityResult(False, f"REVOKED ancestor {addr[:18]}…", chain)
        if not verify_sig(addr, cap.signature, cap.issuer):
            return ValidityResult(False, f"bad signature {addr[:18]}…", chain)
        if cap.not_after < now:
            return ValidityResult(False, f"expired {addr[:18]}…", chain)
        addr = cap.parent
    return ValidityResult(True, "valid: every ancestor present, fresh, unrevoked", chain)


# ─────────────────────────────────────────────────────────────────────────────
# Work claim + escrow settlement  (Beat 2 — the VTEAI beat)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class WorkClaim:
    """What an agent actually did, content-addressed. Settlement gates on THIS,
    not on a signed 'trust me'. The escrow's hashlock commits to its address."""
    task_spec_addr: str
    output_addr: str
    performed_by: str
    inputs: list
    signature: str = ""

    def addr(self) -> str:
        return address({
            "task_spec_addr": self.task_spec_addr, "output_addr": self.output_addr,
            "performed_by": self.performed_by, "inputs": self.inputs,
        })


@dataclass
class Escrow:
    """XRPL XLS-100-style: funded with a hashlock on the EXPECTED work-claim
    address. Releases iff a submitted claim's address matches and the authorizing
    capability still validates against the chain (so a late revocation blocks it)."""
    amount: str
    expected_claim_addr: str       # hashlock committed at funding time
    authorizing_cap_addr: str
    released: bool = False

    def try_release(self, claim: WorkClaim, reg: Registry) -> tuple[bool, str]:
        if claim.addr() != self.expected_claim_addr:
            return False, "claim address does not match hashlock — work != spec"
        v = walk_validity(self.authorizing_cap_addr, reg)
        if not v.valid:
            return False, f"authority invalid at settlement: {v.reason}"
        self.released = True
        return True, "released: work matches hashlock AND authority is live"


# ─────────────────────────────────────────────────────────────────────────────
# Provenance view — "show me the chain"  (Beat 3's artifact)
# ─────────────────────────────────────────────────────────────────────────────

def provenance_view(cap_addr: str, reg: Registry,
                    names: Optional[dict] = None, now: Optional[float] = None) -> str:
    """Render the full authority chain root→leaf: who authorized each step, what
    scope it actually held, and whether it's live. This is the auditability
    artifact — given any action, reconstruct exactly what authority stood behind
    it and where (if anywhere) the chain is broken. Renders the COMPLETE chain
    even when a node is revoked, so the break point is visible."""
    names = names or {}
    now = now if now is not None else time.time()

    # Build the full chain leaf→root by following parent links, independent of
    # validity, so a revoked middle node doesn't truncate the picture.
    full: list = []
    addr = cap_addr
    while addr is not None and addr in reg.caps:
        full.append(addr)
        addr = reg.caps[addr].parent
    chain = list(reversed(full))             # root first

    v = walk_validity(cap_addr, reg, now)
    lines = ["  AUTHORIZATION PROVENANCE  (root → leaf)", "  " + "─" * 60]
    for depth, addr in enumerate(chain):
        cap = reg.caps[addr]
        who = names.get(cap.issuer, cap.issuer[:14] + "…")
        to = names.get(cap.audience, cap.audience[:14] + "…")
        revoked = addr in reg.revoked
        expired = cap.not_after < now
        status = "REVOKED" if revoked else ("EXPIRED" if expired else "live")
        mark = "✗" if (revoked or expired) else "✓"
        indent = "    " * depth
        role = "ROOT — human grant" if cap.parent is None else "delegation"
        lines.append(f"  {indent}{mark} [{status:7}] {role}")
        lines.append(f"  {indent}  {who} → {to}")
        lines.append(f"  {indent}  may: {cap.action}  scope: {cap.caveats}")
        lines.append(f"  {indent}  addr: {addr[:30]}…")
    lines.append("  " + "─" * 60)
    lines.append(f"  VERDICT: {'VALID' if v.valid else 'INVALID'} — {v.reason}")
    return "\n".join(lines)
