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
| 5. Verify page, heist UI, mainnet | 🚧 in-browser verify page (WASM) and bidding UI done; mainnet run next |

## Run it
```
cargo build --release -p tally-bulletin
target/release/tally-bulletin --listen 127.0.0.1:8787 --data ./bulletin-data --key ./bulletin.key --web ./web
```
Then open `http://127.0.0.1:8787`:
- **Cases (`/`)**: the auctions on this bulletin.
- **Verify (`/verify.html`)**: every public check, run in your browser in WebAssembly, green or red. It also verifies a saved `auction-log.json` offline. Try `?sample=testnet-2026-10-22`.
- **Bid (`/bid.html?auction=…`)**: turn the dial, seal (in WASM, in the tab), get a signed receipt, pay the bond through a ZIP 321 request, and download your bid key.

The pages load nothing from third parties. The bulletin serves them under a strict self-only CSP.

## Run the tests
```
cargo test --release
cargo build --release --target wasm32-unknown-unknown -p tally-wasm
cp target/wasm32-unknown-unknown/release/tally_wasm.wasm web/
node web/test/wasm.test.mjs web/tally_wasm.wasm
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
