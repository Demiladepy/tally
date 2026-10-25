# Sale with `rcv` redacted (testnet, Oct 25, 2026)

The adversarial leak review found that the buyer's redacted PCZT still carried
every action's value-commitment randomness `rcv`, which would let the seller
open the buyer's funding and change amounts. `sale-build` now clears `rcv` on
all actions and refuses to write a PCZT with any left. This run shows a real
sale still completes without it.

**Network:** Zcash testnet, NU7, v6 transactions, Ironwood only.
**Item:** collection `3a0d40b1…`, item 1, from its own vault account, sold to a fresh inbox account, paid to a fresh payout account. Price 0.005 TAZ.

| Check | Result |
|---|---|
| Buyer-built PCZT has no `rcv` on any action | ✅ `sale-build`'s self-check passed (it bails if any action keeps `rcv`) |
| Carrier spend and successor share an Action | ✅ action 1, bound on build attempt 3 |
| Buyer-only PCZT can't be extracted | ✅ `REFUSED Ironwood(Extract(MissingSpendAuthSig))` |
| Seller checks, signs last, extracts | ✅ `EXTRACTED faadaee1362a94727333143317a5d16b3e0c0f232723090e8259b308cd6db4fb` |
| On-chain shape | V6; no transparent, Sprout, Sapling or Orchard parts; 3 Ironwood actions; the only public value is the 15000 zat fee |
| Node accepted and mined it | ✅ txid `faadaee1362a94727333143317a5d16b3e0c0f232723090e8259b308cd6db4fb` |
| Buyer holds the item | ✅ `value_zat 0`, `item_index 1`, `hop 1`, `seller_sig_ok true`, `rho==prev_nf true`, `same_item true`, `hop_advanced true` |

The listing and PCZT files are not published: the listing carries the vault's
viewing key.
