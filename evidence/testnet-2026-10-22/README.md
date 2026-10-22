# Layer 1 evidence: atomic carrier-note sale on testnet (Oct 22, 2026)

The network is Zcash testnet with NU7 active and 25-second blocks. Every transaction is v6, Ironwood only.
The tools used are `tally-settle` (this repo) and `zcash-devtool` at `0b3436b`, built against librustzcash `eb38d7a`.

## Transactions
| Step | txid | Height |
|---|---|---|
| Mint two items (collection `5d8e7fa7…793c`) | `62c791a09dd198010381bdef0d9cc546b2e02c03a89bc9084cffb316489e74f5` | ~4528720 |
| Sale of item 0 for 0.01 TAZ | `1257c5b85eaa7b574808641299c12bd9497efb8fff649a7430fd810b126a99de` | 4528734 |

## What the chain shows (`tally-settle try-extract`)
Both transactions show the same shape:

```
version          V6
transparent      none
sprout           none
sapling          none
orchard          none
ironwood actions 3
ironwood balance 15000 zat   (the ZIP 317 fee; the only public value)
```

A mint and a sale cannot be told apart. No address, amount, memo or item appears on chain.

## Acceptance checks
| Check | Result |
|---|---|
| One txid moves the item to the buyer and ZEC to the seller | ✅ `1257c5b8…`. The buyer's wallet holds a 0-value note at Action 2 and paid 0.01 TAZ plus the fee. |
| Item lineage: the new note's rho equals the old carrier's nullifier | ✅ `rho==prev_nf true` from `inspect-item`. Binding succeeded on build attempt 5. |
| Item content is genuine | ✅ `collection_ok true`, `seller_sig_ok true`, `hop 1`, `item_index 0` |
| A half-signed (buyer-only) PCZT can't be extracted | ✅ `REFUSED Ironwood(Extract(MissingSpendAuthSig))` |
| The seller refuses terms that don't match the PCZT (price doubled) | ✅ `PCZT does not spend our carrier in the agreed action, or does not pay the agreed price to our address` |
| A replay of the sale is rejected | ✅ The node said: `transaction was committed to the best chain` |
| Re-selling the spent carrier | ✅ The seller's wallet refuses (`note not found or not spendable`) |

**Not tested yet.** No one has broadcast a hand-forged transaction that spends the carrier's nullifier a second time. Consensus nullifier uniqueness covers that case, but we haven't exercised it ourselves.

## Known limits of this run
- Both wallets ran on one machine, so `sale-build` read the seller's carrier note and witness directly. In a real sale the seller sends only that note's data.
- Recipients get fresh diversified addresses. No address is reused, but all addresses of one account share an IVK. One-time IVKs or per-auction accounts arrive in Layer 4.
- The PCZT isn't redacted before handoff, so the seller sees the buyer's spend details. Redaction, as in Zarrier, is still to do.
- Light clients don't receive memos from compact blocks. Run `zcash-devtool wallet enhance` before `inspect-item`.
