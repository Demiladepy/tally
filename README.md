# Tally

### Sealed-bid block auctions on Zcash. No order is ever opened. Anyone can prove the price.

**ZECATHON 2026 · Private Markets track**

[**Audit a real clearing in your browser →**](https://demiladepy.github.io/tally/verify.html?sample=testnet-2026-10-22) &nbsp;·&nbsp; [Desk (static demo)](https://demiladepy.github.io/tally/) &nbsp;·&nbsp; [Threat model](docs/THREAT_MODEL.md) &nbsp;·&nbsp; [Protocol](docs/PROTOCOL.md)

---

## In 30 seconds

A seller wants to sell a block of something to several buyers at a fair price. Today they can (a) shop it around over RFQ/OTC, which leaks their intent to every desk they ask, (b) run a public on-chain auction, which shows every bid to every bot, or (c) trust a dark pool operator not to peek.

**Tally is option (d).** Buyers submit sealed orders from their browser. At close, a 2-of-3 committee opens **only a handful of aggregate totals**, never an individual order. One uniform clearing price falls out. Every winner settles delivery-versus-payment in **one shielded Zcash transaction**. Then anyone, anywhere, re-runs **ten checks in their browser** and gets the same price, or catches the cheat.

On testnet, a 5-bidder auction cleared at 0.012 TAZ. The committee opened **4 of 16** totals. No bid was decrypted, and both winners settled atomically. [The record is public.](evidence/testnet-2026-10-22-auction/README.md)

---

## Why this problem

**1. Information leakage is a measured, recurring cost for institutions.**
- BlackRock documented an ETF execution where shopping an order to several market makers put **0.73% of the trade's value** at risk through information leakage. ([ETF Stream, on BlackRock's case study](https://www.etfstream.com/articles/blackrock-information-leakage-impacts-best-execution-when-trading-etfs-in-europe))
- Tradeweb studied how much price-moving information escapes through RFQs in US credit, and found the protocol you choose changes how much leaks. ([Tradeweb, *Information Leakage in US Credit*](https://www.tradeweb.com/newsroom/media-center/insights/blog/information-leakage-in-us-credit-evidence-from-all-to-all-rfqs/))

The more people who see your order before it fills, the worse your price. That is true off-chain, and it is worse on-chain.

**2. Public blockchains turn leakage into a business model.**
The EU's securities regulator tracked Ethereum **sandwich attacks alone at up to $55M of revenue in a single month** (May 2023), and tens of millions in many months since. Those are bots trading against orders they can see before they settle. ([ESMA, *Maximal Extractable Value: Implications for crypto markets*, July 2025](https://www.esma.europa.eu/sites/default/files/2025-07/ESMA50-481369926-29744_Maximal_Extractable_Value_Implications_for_crypto_markets.pdf))
A transparent auction contract is the worst case: every bid is public the moment it's placed.

**3. The fix the traditional market settled on is the sealed, uniform-price auction.**
The US Treasury moved its auctions to a **single-price (uniform-price) format** and extended it to all offerings in 1998. ([NY Fed, *The Treasury Auction Process*](https://www.newyorkfed.org/medialibrary/media/research/current_issues/ci11-2.html); [US Treasury, *Uniform-Price Auctions: Update of the Treasury Experience*](https://home.treasury.gov/system/files/276/update-of-the-treasury-experience-october-1998.pdf))
Everyone who clears pays the same price, so bidding your true value is safe. What Treasury relies on, and crypto can't, is a trusted auctioneer who sees every bid.

**Tally keeps the auction format institutions already use and removes the trusted auctioneer.** The bids stay sealed even from the people who compute the price. Zcash's shielded pool supplies what no transparent chain can: deposits, payment and delivery with no public amounts or counterparties.

---

## How Tally compares

| | Bids hidden from the operator | Bids hidden after close | Price publicly verifiable | Atomic settlement | Leaks intent while shopping |
|---|:-:|:-:|:-:|:-:|:-:|
| OTC desk / RFQ | ✗ | ✗ | ✗ | ✗ | **yes** |
| Dark pool | ✗ (you trust it) | ✗ | ✗ | varies | no |
| Public on-chain auction | ✗ | ✗ | ✓ | ✓ | **yes, to every bot** |
| Threshold-encrypted order book that decrypts at close | ✓ until close | ✗ (whole book revealed) | ✓ | varies | no |
| **Tally** | **✓** | **✓ only a few aggregates are opened** | **✓ in any browser** | **✓ one Ironwood tx** | **no** |

The column that matters most is the second one. Hiding orders until the auction ends and then decrypting them all still hands the whole book, with every participant's exact limit, to whoever decrypts. Tally never decrypts an order. It opens the yes-counts at a few price levels, which is just enough for a binary search to find the clearing price.

---

## How it works

**For a buyer, it looks like any primary allocation desk:** Offerings → term sheet → order ticket → fund the deposit → track the order → read the clearing report.

Under the hood:

1. **Offering.** The seller publishes signed terms: units, a price ladder, deposit size, close height, and the clearing committee's public key. The offering's ID **is the hash of its terms**, and **every committee member co-signs** them, so a link can't be served with different terms or a fake committee.
2. **Sealed order.** The buyer's browser turns a limit price into an encrypted yes/no at every price level (exponential ElGamal on Pallas). It attaches zero-knowledge proofs that each cell is 0 or 1, that the answers only step down, and that the first is yes. The desk receives ciphertext and returns a signed receipt. The limit is wiped from the page.
3. **Deposit.** A small refundable deposit in shielded ZEC commits the order. Its memo carries only the order's hash and an Orchard-only refund address.
4. **Clearing.** Ciphertexts add up homomorphically per price level. The committee threshold-decrypts **only the totals a binary search needs**, and every share carries a DLEQ proof. The desk **refuses** any decryption the search doesn't need, and the verifier fails if one happens. The count at the lowest level is the public number of funded orders, so an undersubscribed sale decrypts nothing at all.
5. **Settlement.** Each winner buys its unit at the clearing price in **one atomic Ironwood transaction**, built as a PCZT. The buyer signs and redacts its half, and the seller checks it and signs last. Neither can finish alone, and the seller never learns where the item went or the buyer's balances.
6. **Audit.** The full record (terms, ciphertexts, proofs, decryption shares, result, settlements) is public. [The clearing report](https://demiladepy.github.io/tally/verify.html?sample=testnet-2026-10-22) recomputes all of it in WebAssembly in your browser.

---

## What's proven on Zcash testnet

Network: testnet after NU7, v6 transactions, Ironwood pool only.

| Claim | Evidence |
|---|---|
| A full 5-bidder auction: 5 funded orders, **4 of 16 totals opened**, cleared at **0.012 TAZ**, 2 winners settled atomically, all 5 deposits refunded | [`evidence/testnet-2026-10-22-auction`](evidence/testnet-2026-10-22-auction/README.md), with the public [`auction-log.json`](evidence/testnet-2026-10-22-auction/auction-log.json) |
| A buyer and seller complete a sale exchanging only files. The buyer's half can't be finished alone, and the seller can't see the item's destination | [`evidence/testnet-2026-10-22-hardened`](evidence/testnet-2026-10-22-hardened/README.md) |
| After the leak review, the sale still settles with every action's value randomness redacted from the seller | [`evidence/testnet-2026-10-25-rcv`](evidence/testnet-2026-10-25-rcv/README.md), tx `faadaee1…4fb4` |
| Item lineage: each new note's rho equals the previous note's nullifier | `inspect-item` → `rho==prev_nf true` in the evidence |
| On chain: no transparent, Sapling or Orchard data. The only public value is the fee | `try-extract` output in the evidence |
| Attacks refused | a half-signed sale, tampered terms, a loser claiming an item, a lone committee member decrypting, a replayed transaction, a manifest with a swapped committee, and 9 kinds of log tampering caught by the verifier |

## Adversarial leak review

Before submission, a second model was asked to do one thing: find every way Tally links a person to a bid, an address or a payment. It found 4 high, 8 medium and 9 low issues. Code fixed every one that code can fix, and the [threat model](docs/THREAT_MODEL.md) discloses the rest. The highlights:

- **Fixed:** the sale file handed to the seller still carried value-commitment randomness, which would have exposed the buyer's balances. It's now redacted on every action, and re-proven on chain.
- **Fixed:** refund addresses could smuggle a transparent receiver. They must now be Orchard-only.
- **Fixed:** the committee received the order-to-refund-address map. It now gets hashes and amounts only, and its tool rejects anything more.
- **Fixed:** a malicious server could serve terms with its own committee key. The offering ID is now the terms' hash, and every member co-signs.
- **Disclosed, not fixable in code:** an order that lands exactly at the clearing level reveals that its limit equals the price. Fake bidders can steer which aggregates open. The desk and the escrow must be run by different operators.

---

## Honest limits

- **Deposit escrow is one key** held by a coordinator. FROST can't yet sign Ironwood spends through PCZTs ([ZcashFoundation/frost#1094](https://github.com/ZcashFoundation/frost/issues/1094)). The escrow holds deposits only, never payment for the item.
- **The demo committee's three keys are run by one person.** The DKG tooling supports three independent members.
- **Testnet only.** Wallets and tooling are ready for mainnet, on stable NU7-ready libraries with mainnet NU7 at height 3,543,405. A funded mainnet run hasn't happened.
- **What's sold is a Tally carrier note**, an on-chain item with verifiable lineage. Selling arbitrary assets needs Zcash Shielded Assets.
- **The live desk isn't hosted.** The clearing report runs anywhere. Placing orders needs a running desk (one command, below).
- Deposits are shielded, so the public trusts the same 2-of-3 quorum for which orders were funded as for decryption.
- Lineage is checked one hop back, not to the mint. An unsettled allocation isn't re-offered automatically.

## Try it

- **No install:** [the clearing report](https://demiladepy.github.io/tally/verify.html?sample=testnet-2026-10-22). Drop any `auction-log.json` on it, or edit one number and watch it go red.
- **Run the desk locally:** `bash scripts/run-local.sh`, then open http://127.0.0.1:8787.
- **Docker:** `docker build -t tally . && docker run --rm -p 8787:8787 -v tally-data:/data tally`
- **The whole auction from the command line:** [`docs/LAYER4.md`](docs/LAYER4.md). Settlement alone: [`docs/LAYER1.md`](docs/LAYER1.md).

## Architecture

| Path | What |
|---|---|
| `crates/tally-crypto` | Pallas ElGamal, order proofs (CDS OR-proofs, DLEQ), Feldman DKG, threshold decryption, binary-search clearing, the public record and its verifier |
| `crates/tally-zcash` | Carrier-item and deposit memo formats; Orchard-only address checks |
| `crates/tally-settle` | Wallet side on librustzcash: mint, list, atomic PCZT sale, orders and deposits, escrow scan and refunds |
| `crates/tally-wasm` | Verifier and order sealing for the browser (plain C-ABI WASM, no imports); rebuilt from source on every Pages deploy with a published sha256 |
| `services/bulletin` | The desk: append-only hash-chained log with signed receipts. It enforces clearing minimality and keeps no request logs |
| `services/committee-cli` | DKG with age-encrypted shares, term endorsement, deposit attestation, decryption shares, clearing, `verify` |
| `web/` | The desk UI: offerings, order ticket, orders, clearing report. Self-hosted fonts, strict CSP, no third-party code |

```
cargo test --release                                          # 33 tests: crypto, simulation, desk API, memos
cargo build --release --target wasm32-unknown-unknown -p tally-wasm
node web/test/wasm.test.mjs target/wasm32-unknown-unknown/release/tally_wasm.wasm
```

## Docs
- [`docs/PROTOCOL.md`](docs/PROTOCOL.md): the protocol as implemented.
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md): what is hidden, from whom, and what isn't.
- [`docs/DAY_ONE.md`](docs/DAY_ONE.md): every spec claim checked against live sources, including the ones that turned out wrong.

## Credits
- **Zarrier** (Reiunmute/zcash-carrier): carrier notes and the atomic PCZT sale pattern. Re-implemented, not vendored.
- **Zakura / Adam Tucker**, "Quantum Unlinkability for Zcash Swaps": the one-time-address discipline.
- **Penumbra** batch swaps, **Renegade**, and Choudhuri et al., "Mempool Privacy via Batched Threshold Encryption": design references.
- **librustzcash, orchard, pczt** and **zcash-devtool** by ECC and the Zcash Foundation.
