# Layer 1, hardened: two-party sale through files only (Oct 22, 2026)

This run repeats the [first sale](../testnet-2026-10-22/README.md) under the hardened protocol:

- Each item lives in its **own vault account**, and the payment goes to a **fresh payout account**.
- The seller hands the buyer a **listing file**. The buyer never opens the seller's wallet.
- The buyer **redacts** its spend, its change and the item's destination before handing the PCZT back, and **self-checks** that none of its keys or addresses survive in the bytes.
- The seller checks the listing hash, the expiry window, a single spend of its carrier, and the payout. Only then does it sign, last.

Network: Zcash testnet, NU7, v6 transactions, Ironwood only.

## Transactions
| Step | txid |
|---|---|
| Mint 2: two items into vault accounts `vault-c2-0` and `vault-c2-1` | `aca3764d762cb44a5339f198584cbcc3f64a9b56cc8aa985e79954ce6ea68793` |
| Sale of item 0 for 0.01 TAZ into payout account `payout-c2-0` | `3a8ee8981e877f4c6a85a41138f6f1881dcac0fb55d35a267ab17f5f8c25a37b` |

Both transactions have the same public shape: v6, no transparent, Sprout, Sapling or Orchard data, 3 Ironwood actions, and a value balance of 15000 zat (the fee).

## What crossed between the parties
| Seller to buyer | Buyer to seller |
|---|---|
| `listing2.json`: vault viewing key (item only), carrier note parts, witness, anchor height and root, item memo, collection key, price, payout address, valid-until height | `sale2.pczt` (redacted), `sale2.terms.json` (listing hash, carrier and payout action indices, expiry) |

## Adversarial checks on this run
| Attempt | Result |
|---|---|
| Extract the buyer's half-signed, redacted PCZT | `REFUSED Ironwood(Extract(MissingSpendAuthSig))` |
| Terms claim the payout is in the carrier's action | Seller refuses: `does not pay the listed price to our payout address` |
| Seller's listing changed after the buyer built (price raised) | Seller refuses: `terms refer to a different listing` |
| Buyer's keys, item destination, change address or funding rseed left in the PCZT | Build-time byte scan passed: none present |
| Buyer could finish the transaction alone | Build-time check passed: extraction refused |

## After mining
The sale was mined at height **4529014**.

| Check | Result |
|---|---|
| Buyer: the item arrived in its inbox vault `inbox-c2-0` (`inspect-item --listing`) | `value_zat 0`, `item_index 0`, `hop 1`, `seller_sig_ok true` |
| Buyer: the new note's rho equals the listed note's nullifier | `rho==prev_nf true`, `same_item true`, `hop_advanced true` |
| Seller: payout received | 0.01 TAZ in Output 0, received by `payout-c2-0` |
| Seller: can it see where the item went? | No. The seller's wallet lists only the payout output for this transaction. |

## Still open
- **Addresses aren't fully one-time yet.** Vault and payout accounts are separate, but each is still a reusable account and nothing yet guarantees a new account for every listing. One account per listing (or Zakura's one-time IVKs) becomes mandatory in the auction flow (Layer 4).
- **Lineage is checked one step back only.** The buyer checks the seller's signature and the previous nullifier, not the full chain back to the mint. A full lineage walk, as in Zarrier's verifier, belongs on the verify page.
