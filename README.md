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

## Try it
**No install:** the verify page runs entirely in your browser (WebAssembly). Open `verify.html?sample=testnet-2026-10-22` on the project's GitHub Pages site to re-check the Oct 22 testnet auction yourself.

**Locally, one command (no Docker):**
```
bash scripts/run-local.sh          # then open http://127.0.0.1:8787
```
**Or with Docker:**
```
docker build -t tally .
docker run --rm -p 8787:8787 -v tally-data:/data tally
```

What you get:
- **Cases (`/`):** the auctions on this bulletin.
- **Verify (`/verify.html`):** every public check, run in your browser, green or red. It also verifies a saved `auction-log.json` offline.
- **Bid (`/bid.html?auction=…`):** turn the dial, seal in the tab, get a signed receipt, pay the bond (ZIP 321 link or by hand with a text memo), and download your bid key.

The pages load nothing from third parties and carry a strict self-only CSP.

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
