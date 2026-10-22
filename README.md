# Tally

A sealed-bid auction on Zcash where nobody's bid is ever opened, yet anyone can prove the clearing price is right.

ZECATHON, Private Markets track. Work in progress.

## Status
| Layer | State |
|---|---|
| 1. PCZT settlement on testnet | ✅ two-party sale through files only, redacted handoff (`evidence/testnet-2026-10-22-hardened`) |
| 2. `tally-crypto`: ElGamal, ballot proofs | ✅ done, tests pass |
| 3. DKG, threshold decryption, clearing | ✅ offline simulation matches the plaintext reference |
| 4. Full auction on testnet | ✅ 5 bidders, cleared at 0.012 TAZ, 2 winners settled, bonds refunded, verifier all green (`evidence/testnet-2026-10-22-auction`) |
| 5. Verify page, heist UI, mainnet | — |

## Run the tests
```
cargo test --release
```

Read next:
- `docs/THREAT_MODEL.md`: what is hidden, from whom, and what isn't.
- `docs/LAYER4.md`: the auction runbook.
- `docs/PROTOCOL.md`: the protocol, as implemented.
- `docs/DAY_ONE.md`: spec claims checked against current sources.

## Credits
- Zarrier (carrier notes, PCZT atomic sale): inspiration, re-implemented.
- Zakura: one-time IVKs.
- Penumbra: batch swaps.
- Choudhuri et al.: batched threshold encryption.
