"""
Demo runner — three beats, each showing the SUCCESS and the FAILURE it prevents,
plus the provenance "show me the chain" view. Real Ed25519 throughout.
Run: python3 demo.py
"""
import time
from capability_spine import (
    Capability, Identity, attenuate, check_action, AttenuationError,
    Registry, walk_validity, provenance_view, WorkClaim, Escrow, sign, address,
)

LINE = "─" * 70

HUMAN = Identity.create("HUMAN")
A = Identity.create("Agent A")
B = Identity.create("Agent B")
C = Identity.create("Agent C")
NAMES = {HUMAN.did: "HUMAN", A.did: "Agent A", B.did: "Agent B", C.did: "Agent C"}


def root_capability(reg: Registry) -> Capability:
    root = Capability(
        issuer=HUMAN.did, audience=A.did,
        resource=address({"asset_class": "equity.private", "issuer": "SpaceX",
                          "security_class": "preferred:j"}),
        action="transfer:shares",
        caveats={"max_usd": 1_000_000, "venues": ["hill", "forge", "npm"]},
        parent=None, not_after=time.time() + 3600,
    )
    root.signature = sign(root.addr(), HUMAN.signing_key)
    reg.register(root)
    return root


def beat1_attenuation(reg: Registry, root: Capability):
    print(LINE); print("BEAT 1 - Attenuation handoff (trust shrinks as it travels)"); print(LINE)
    b = attenuate(root, audience=B.did,
                  new_caveats={"max_usd": 50_000, "venues": ["hill"]},
                  issuer=A, ttl_seconds=900)
    reg.register(b)
    print("  A->B delegation OK   max_usd 1,000,000 -> 50,000 | venues 3 -> 1")
    print(f"     signed by Agent A's real key; parent hash-link: {b.parent[:20]}...")
    try:
        attenuate(b, audience=C.did, new_caveats={"max_usd": 500_000}, issuer=B)
        print("  !! widening accepted - BUG")
    except AttenuationError as e:
        print(f"  B->C widening REJECTED by the token itself: {e}")
    try:
        attenuate(b, audience=C.did, new_caveats={"max_usd": 10_000}, issuer=C)
        print("  !! forged delegation accepted - BUG")
    except AttenuationError as e:
        print(f"  C forging a B->C delegation REJECTED: {e}")
    c = attenuate(b, audience=C.did, new_caveats={"max_usd": 10_000},
                  issuer=B, ttl_seconds=300)
    reg.register(c)
    print("  B->C delegation OK   max_usd 50,000 -> 10,000 (venues 'hill' inherited)")
    print(f"  C requests $8,000 on hill  -> permitted: {check_action(c, {'max_usd':8000,'venues':'hill'})}")
    print(f"  C requests $8,000 on forge -> permitted: {check_action(c, {'max_usd':8000,'venues':'forge'})}  (forge not in C's venues)")
    return b, c


def beat2_settlement(reg: Registry, c: Capability):
    print(); print(LINE); print("BEAT 2 - Settlement gates on verified work, not a signed claim"); print(LINE)
    task = address({"task": "settle transfer of 100 SpaceX J units", "buyer": "B", "seller": "S"})
    expected = WorkClaim(task_spec_addr=task,
                         output_addr=address({"units": 100, "status": "transferred"}),
                         performed_by=C.did, inputs=[address({"kyc": "passed"})])
    escrow = Escrow(amount="100 units RLUSD", expected_claim_addr=expected.addr(),
                    authorizing_cap_addr=c.addr())
    print(f"  Escrow funded. Hashlock = expected work-claim addr {expected.addr()[:24]}...")
    wrong = WorkClaim(task_spec_addr=task,
                      output_addr=address({"units": 90, "status": "transferred"}),
                      performed_by=C.did, inputs=[address({"kyc": "passed"})])
    ok, why = escrow.try_release(wrong, reg)
    print(f"  Submit WRONG work (90!=100): released={ok} - {why}")
    ok, why = escrow.try_release(expected, reg)
    print(f"  Submit CORRECT work:         released={ok} - {why}")


def beat3_killswitch(reg: Registry, root: Capability, b: Capability, c: Capability):
    print(); print(LINE); print("BEAT 3 - Kill-switch cascade + provenance view"); print(LINE)
    print("\n  C's authority chain BEFORE revocation:\n")
    print(provenance_view(c.addr(), reg, NAMES))
    reg.revoke(b.addr())
    print(f"\n  > Compromise detected at Agent B. Published revocation against B.\n")
    print("  C's authority chain AFTER revocation:\n")
    print(provenance_view(c.addr(), reg, NAMES))
    v = walk_validity(c.addr(), reg)
    print(f"\n  C replays its still-signed, unexpired token -> {v.reason}")
    print("  Killing B killed C. The replay cannot succeed against a fresh verifier.")


if __name__ == "__main__":
    reg = Registry()
    root = root_capability(reg)
    b, c = beat1_attenuation(reg, root)
    beat2_settlement(reg, c)
    beat3_killswitch(reg, root, b, c)
    print(); print(LINE)
    print("  WHO (root Ed25519 sig) . WHAT (caveats) . HOW TRUST TRAVELS")
    print("  (hash-linked attenuation) . HOW TO KILL (revocation chain-walk).")
    print(LINE)
