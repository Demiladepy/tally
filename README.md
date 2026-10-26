# Tally

**A sealed-bid auction on Zcash where nobody's bid is ever opened, yet anyone can prove the clearing price is right.**

ZECATHON · Private Markets track

**→ [Verify a real testnet auction in your browser](https://demiladepy.github.io/tally/verify.html?sample=testnet-2026-10-22).** Ten checks run in WebAssembly in your tab, and nothing is taken on trust from a server.

---

## The problem
Private markets on Zcash run on trust today. A recent sealed-bid sale on Zcash cleared 12,000 ZEC, yet nobody outside the operator can check the clearing price, the bids, or who owns what. The community's main objection to the last serious shielded-exchange proposal was that its state couldn't be verified publicly. And at the edges, privacy leaks: swap refund addresses land on public chains, where a future quantum computer could link everything an exposed address ever received.

## The insight
Clearing a sealed-bid auction is a **private vote on prices**. Each bidder says yes or no at every price level. Add the votes up encrypted, and open only the few sums a binary search needs. *Intent hidden, result public.*

## How it works
1. **List.** The seller mints items as zero-value Ironwood notes whose memo holds the item (carrier notes), and publishes a signed manifest: supply, a 16-level price ladder, bond size, close height, and a 2-of-3 committee key.
2. **Bid.** On the order ticket, you set a limit price. Your tab encrypts a 0/1 for every price level (exponential ElGamal on Pallas) and attaches proofs that each cell is 0 or 1, the cells only step down, and the first cell is 1. Only that ciphertext goes to the bulletin, which returns a signed receipt. A small shielded bond, with a plain-text memo `TLYB1 <auction> <ballot-hash> <one-time refund address>`, keeps bids honest.
3. **Close.** The seller signs the hash-chained log at its final root.
4. **Tally.** Anyone can add the ciphertexts per level. The committee threshold-decrypts **only the totals a binary search needs (4 of 16 in our run)**, each share with a DLEQ proof. The bulletin refuses any decryption the search doesn't need.
5. **Clear.** The price is the highest level whose yes-count covers supply. Winners are named by anonymous ballot key. On an exact fill only one cell per ballot is opened; on a tie, a seed from the close block's hash decides.
6. **Settle.** Each winner buys its item at the uniform price in **one atomic Ironwood transaction (PCZT)**. The buyer signs and redacts its half, and the seller checks it and signs last. Neither can finish alone, and no one ever holds the other's funds.
7. **Refund.** Bonds go back to one-time addresses. A winner who doesn't pay forfeits to a separate address, never to the seller.
8. **Verify.** Anyone re-runs every check from the public log: in the browser, or with `tally-committee verify`.

## What's proven, on Zcash testnet (NU7, v6 transactions, Ironwood only)
| What | Evidence |
|---|---|
| A full 5-bidder auction: 5 bonded ballots, **4 of 16 totals opened**, cleared at **0.012 TAZ**, 2 winners settled atomically, all 5 bonds refunded | [`evidence/testnet-2026-10-22-auction`](evidence/testnet-2026-10-22-auction/README.md) and its public [`auction-log.json`](evidence/testnet-2026-10-22-auction/auction-log.json) |
| A two-party sale through files only: the buyer builds from a listing and redacts, the seller can't see where the item went | [`evidence/testnet-2026-10-22-hardened`](evidence/testnet-2026-10-22-hardened/README.md) |
| Item lineage holds: each new note's rho equals the previous note's nullifier | the same, `inspect-item` → `rho==prev_nf true` |
| On chain: no transparent, Sapling or Orchard data; only the fee is public; mint, sale and refund look alike | `tally-settle try-extract` output in the evidence |
| Attacks refused | a half-signed sale, tampered terms, a re-listed price, a loser claiming an item, a lone committee member decrypting, a replayed transaction, and 9 kinds of log tampering caught by the verifier |

## What's hidden, and from whom
Full table: [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).
- **Your bid** never leaves your browser. The bulletin, the seller and the public see only ciphertexts. A colluding committee quorum could decrypt ballots, and this demo's committee is not independent.
- **What is public:** the ⌈log₂(L+1)⌉ totals on the search path, the clearing price, the winners' anonymous ballot keys, and (for opened cells) which side of the clearing price an anonymous ballot fell on.
- **Who you are:** the bulletin stores no IPs, user agents or timings, and its errors never echo what you sent. Ballots carry no addresses. Refund addresses must be Orchard-only. The bulletin and the escrow must be run by different parties, and bidders should use Tor (see `docs/THREAT_MODEL.md` for what is disclosed rather than hidden).
- **Payments and items:** shielded Ironwood notes. A sold item's destination is redacted even from the seller.

## Honest limits
- **Escrow is one key**, held by the coordinator. FROST can't yet sign Ironwood spends through PCZTs (ZcashFoundation/frost#1094).
- **The demo committee's three keys are run by one person.** The DKG tooling supports three real members.
- **Bonds are shielded**, so the public trusts the same 2-of-3 quorum for the bonded set as for decryption.
- **Item lineage** is checked one hop back from a listing, not all the way to the mint.
- **An unpaid item** isn't automatically offered to the next bidder; it stays with the seller.
- **Mainnet:** wallets and tooling are ready, and the stable NU7-ready libraries (mainnet NU7 at height 3,543,405) are in use. A funded mainnet run hasn't happened yet.

## Try it
- **No install:** [the verify page](https://demiladepy.github.io/tally/verify.html?sample=testnet-2026-10-22). You can also drop any `auction-log.json` on it.
- **Locally, one command:** `bash scripts/run-local.sh`, then open http://127.0.0.1:8787 for cases, verify and bid.
- **Docker:** `docker build -t tally . && docker run --rm -p 8787:8787 -v tally-data:/data tally`
- **The whole auction, end to end:** [`docs/LAYER4.md`](docs/LAYER4.md). Settlement on its own: [`docs/LAYER1.md`](docs/LAYER1.md).

## Layout
| Path | What |
|---|---|
| `crates/tally-crypto` | Pallas ElGamal, ballot proofs (CDS OR-proofs, DLEQ), Feldman DKG, threshold decryption, binary-search clearing, the public auction record and its verifier |
| `crates/tally-zcash` | Carrier-item and bond memo formats |
| `crates/tally-settle` | Wallet side, built on librustzcash: mint, list, atomic PCZT sale, bids and bonds, escrow scan and refunds |
| `crates/tally-wasm` | The verifier and ballot sealing for the browser (plain C-ABI WASM) |
| `services/bulletin` | Append-only hash-chained log with signed receipts. It enforces clearing minimality and keeps no request logs. |
| `services/committee-cli` | DKG with age-encrypted shares, bond attestation, shares, adaptive clearing, `verify` |
| `web/` | Heist UI: cases, verify, bid. Self-hosted, strict CSP. |

## Tests
```
cargo test --release                                             # crypto, simulation, bulletin, memos
cargo build --release --target wasm32-unknown-unknown -p tally-wasm
cp target/wasm32-unknown-unknown/release/tally_wasm.wasm web/
node web/test/wasm.test.mjs web/tally_wasm.wasm                  # browser verifier vs. the real testnet log
```

## Docs
- [`docs/PROTOCOL.md`](docs/PROTOCOL.md): the protocol as implemented, and where it departs from the original spec.
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md): what is hidden, from whom, and what isn't.
- [`docs/DAY_ONE.md`](docs/DAY_ONE.md): spec claims checked against live sources, including what turned out wrong.

## Credits
- **Zarrier** (Reiunmute/zcash-carrier): carrier notes and the atomic PCZT sale pattern. This is inspiration, re-implemented, not vendored.
- **Zakura / Adam Tucker**, "Quantum Unlinkability for Zcash Swaps": the one-time-address discipline.
- **Penumbra** batch swaps, **Renegade**, and Choudhuri et al., "Mempool Privacy via Batched Threshold Encryption": design references.
- **librustzcash, orchard, pczt** and **zcash-devtool** by ECC and the Zcash Foundation.
