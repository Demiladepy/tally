# Layer 4 evidence: a 5-bidder sealed-bid auction on testnet (Oct 22, 2026)

**Network:** Zcash testnet, NU7, v6 transactions, Ironwood only.

**Auction:** `f021530df4346d67f6aefb698794852cafcb6867cacc3e5563193522a402ddcc`
- Supply 2 (collection 3, two vault-art items).
- Ladder of 16 levels, 0.001 to 0.016 TAZ.
- Bond 0.001 TAZ, minimum batch 5.
- Committee 2-of-3, from a DKG with age-encrypted shares. All three members were run by @dd for the demo, so they are not independent.

The full public record is in [`auction-log.json`](auction-log.json): manifest, 5 ciphertext ballots with proofs, close, bonded-set attestation, 9 decryption records, result and 2 settlements. `tally-committee verify --log auction-log.json` re-checks all of it.

## Timeline
| Step | Evidence |
|---|---|
| Mint 2 items into vault accounts | `60750fd536def2cba0dedae9adf08e497fa7129e88fb313380435122de78bdbf` |
| Fund 5 bidder accounts, 0.02 TAZ each | `923013c0416c28bd56476e0d370491d1c80adfb04426b32fada353f5632c484c` |
| Escrow fee float | `a3d696333b287dabbea93e96d704bc63bb901f30c80b38962d9a75c723b3c7d2` |
| 5 sealed ballots, receipted as entries #0–#4 | `auction-log.json` → `entries` |
| 5 bonds with `TLYB` memos | shielded; not listed here |
| Close at height 4529569, root `e86af265…` | `close` |
| Escrow scan: 5 bonds of 100000 zat. Members A and C attest 5 of 5 bonded. | `bonds` |
| Clearing: T₈=4, T₁₂=2, T₁₄=1, T₁₃=1. Then c₁₂ for each of the 5 ballots, since T₁₂ = N is an exact fill and needs no tie-break. | `decryptions` |
| **Result: cleared at level 12 = 0.012 TAZ, 2 winners** | `result` |
| A winner buys item 0 | `b997e5c3a3757a339d59557464b8a758c251dc051d4c26d1173411e6ddc89281` |
| The other winner buys item 1 | `965332c0510f9a28f52d138fae2fcea60183991cb88d8635a46cf27edfcc85a8` |
| Refund of all 5 bonds to one-time addresses, 0 forfeits | `27d097a39d3447afa894e61b9c05c55b837b5bcf64050f8f7e4cc53208f4dd59` |

The bidders' private maxima are not published here: a record that pairs maxima with entries would de-anonymise the sample log. (An earlier version of this file did list them, for a demo where one person played all five bidders.) The clearing price is the uniform 0.012 that both winners paid.

This log is a **legacy v1** manifest: it predates the id-binding and committee endorsements, so the verifier labels it legacy and new ballots can't be sealed against it.

## Public verifier (`tally-committee verify`), final run
```
PASS Manifest signed by the seller
PASS Bulletin hash chain (5 entries)
PASS Every ballot's proofs and signature (5 ballots, 0 invalid or duplicate)
PASS Log closed at the published root (e86af265…)
PASS Bonded set attested by a committee quorum (5 of 5 ballots bonded)
PASS Minimum batch (5 ≥ 5)
PASS Every decryption share and DLEQ proof (9 records, 0 invalid)
PASS Only the needed totals and cells were decrypted (4 of 16 totals; 0 extra, 0 missing)
PASS Clearing price, winners and tie-break seed recompute exactly (Cleared at level 12 = 1200000 zat, 2 winners)
PASS Settlements signed by the seller, one per winner (2 of 2 winners settled)
```

## Checks after mining
| Check | Result |
|---|---|
| Each winner holds its item | `item_index 0` / `1`, `hop 1`, `seller_sig_ok true`, `rho==prev_nf true` |
| Every bidder got its bond back | 0.001 TAZ each |
| A single committee member can't clear | `need at least t = 2 members` |
| A loser claims an item | Seller refuses: `claimant is not a winner` |
| A sale without a win claim | Seller refuses: `auction sale requires a win claim` |
| A bid amount appears on disk or on the bulletin | No. Bid records hold only the ballot key, hash and receipt. The only matches were ladder values in the public manifest. |

## What this run does not show
- **Escrow custody is a single key** held by the coordinator (no FROST for Ironwood yet). See `docs/THREAT_MODEL.md`.
- **The committee isn't independent.** All three keys were run by one person.
- **The forfeit path ran only as "0 forfeits"**, because both winners settled. The forfeit routing is in code but hasn't been exercised on chain.
- **The bulletin ran on localhost**, not on a public host.
