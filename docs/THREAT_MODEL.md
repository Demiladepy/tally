# Threat model

Everything below describes what the code in this repository does today. It claims nothing the code doesn't do.

## Who sees what
| Data | Public | Bulletin operator | Committee (a t-of-n quorum) | Seller | Escrow holder |
|---|---|---|---|---|---|
| A bidder's maximum price | never | never | **could** decrypt it by colluding beyond the protocol | never | never |
| Which price bracket a ballot ended in (k\* and k\*+1 cells) | only for ballots whose cells are opened, by anonymous ballot ID | same | same | same | same |
| Totals on the binary-search path (≤ ⌈log₂(L+1)⌉ of L) | yes | yes | yes | yes | yes |
| Clearing price and winners' anonymous ballot IDs | yes | yes | yes | yes | yes |
| Who a bidder is (wallet, addresses, IP) | no | no addresses ever. IP is visible at the network layer but never logged | no | no | sees each bond's one-time refund address |
| Bond payments | no (shielded) | no | attests the set | no | yes (memos: ballot hash and one-time refund address) |
| Item ownership | no (shielded notes) | no | no | knows its own vault | no |
| Where a sold item went | no | no | no | **no**: the buyer redacts it | no |
| Buyer's funding note, change, keys | no | no | no | **no**: redacted, and the buyer checks this by scanning the bytes | no |

## Attacks and defenses
| Attack or leak | Defense in code | Residual risk |
|---|---|---|
| Seller shill-bids to raise the price | Every counted ballot needs a bond. Winners who don't settle forfeit the bond to `forfeit_ua`, which `Manifest::verify` requires to differ from the escrow, and which is never the seller. | A seller willing to burn bonds can still distort a thin auction. |
| Inferring bids from totals | Only the binary-search totals are opened. The bulletin **refuses** any decryption the search doesn't need (`next_targets`), and the verifier fails if anything extra was opened. Cells are opened only when needed: none if undersubscribed, only c_{k\*} on an exact fill. `min_batch` voids small auctions with nothing decrypted. | The opened totals and cells are public. |
| Committee collusion | t-of-n threshold ElGamal (demo: 2-of-3). Every share carries a DLEQ proof bound to its target. | A colluding quorum could decrypt every ballot. The demo committee is three keys run by one person (@dd), which is not independent. |
| Fake bonded set | The bonded set needs ≥ t member signatures over the final log root. | Bonds are shielded, so the public trusts the same quorum for the bonded set as for decryption. |
| Bulletin censors or reorders ballots | The log is hash-chained, each append returns a signed receipt, and the seller signs the close at an exact (count, root). | A censored bidder can prove exclusion with the receipt, but can't force inclusion. |
| Bulletin learns identities | The service logs nothing: no IPs, user agents or timings, and no tracing layer. Errors never echo inputs. Ballots contain no addresses. | Network-level metadata. Run bidders through Tor (`zcash-devtool --connection tor`) and Tor-route the bulletin. |
| Linking a bidder across auctions | A fresh ballot key per bid, and one wallet account per bid (its own IVK). The bond refund address is a fresh address of that account. | The demo bidders live in one wallet file. That's fine for privacy on chain, but they share a seed. |
| Quantum harvest-now-decrypt-later | No long-lived address is published. Every address that leaves a wallet (refund, payout, vault) belongs to an account used for one purpose. | Ballot ElGamal isn't post-quantum. Zakura's one-time IVK isn't used yet (its library isn't released); per-account separation stands in for it. |
| Winner doesn't pay | `refund --forfeit-unsettled` sends that winner's bond to the forfeit address. | Re-offering the item to the next eligible ballot isn't automated yet. |
| Fake or copied item | The seller's collection key signs the item memo. The new note's rho must equal the previous carrier's nullifier, checked by the buyer (`inspect-item --listing`). | Only one hop is verified. A full lineage walk back to the mint belongs on the verify page. |
| Half-built sale | The buyer signs only its own spend. A buyer-only PCZT can't be extracted, which is checked at build time. The seller signs last, after checking the listing hash, expiry, a single carrier spend and the payout. | None known. |

## Escrow custody (honest statement)
The spec asked for FROST threshold signing of the escrow. As of Oct 2026 the official `frost` crate has no public API that accepts the per-action randomizer an Ironwood PCZT fixes (ZcashFoundation/frost#1094). The escrow is therefore **one ordinary account held by the committee coordinator**. It holds only bonds (0.001 TAZ each in the demo) and a small fee float. The coordinator could steal bonds, and that is the trust users extend. The verifier can't check refunds, because they are shielded.

## Hardening, Oct 23
| Weak spot found | Fix |
|---|---|
| The web bond memo was binary (ZIP 302 F5). Many wallets only send UTF-8 memos, so the memo could be rejected or dropped, and the bond would then not match its ballot. | The bond memo is now plain text: `TLYB1 <auction> <ballot-hash> <refund-ua>`. The bid page also offers a "pay by hand" fallback with copyable address and memo. The decoder still reads the earlier binary bonds. |
| After `send-without-storing` a wallet doesn't know its notes are spent until the next block. The next build could reuse a spent note, and the mempool would reject it (this happened once with the escrow float). | `tally-settle record --wallet W --input final.pczt` stores the broadcast transaction in each involved wallet at once. Tested on testnet: the next build refuses the spent note instead of reusing it. |
| The bulletin accepted unlimited auctions and ballots, and every ballot costs real CPU to verify. | Capped at 1,000 auctions and 5,000 ballots per auction, with HTTP 507 past the cap. Tested. |
| A forfeit could be triggered before winners had their chance to pay. | `refund --forfeit-unsettled` refuses until `close_height + settle_window_blocks`. Which winners forfeit is computed by the shared `AuctionLog::unsettled_winners()`, which is tested. |
| The tie-break seed's block hash could be any block the coordinator chose. | The verifier now prints the seed block hash and the height it must come from (the manifest's `close_height`), so anyone can check it against an explorer. |

## Still open (stated, not fixed)
- **Re-offering an unsettled item** to the next eligible ballot isn't automated. A forfeited item stays with the seller.
- **Lineage** is checked one hop back from a listing, not all the way to the mint.
- **Escrow is one key**, and the demo committee is one person. Both are explained above.
- **Mainnet NU7.** The pinned libraries have no mainnet NU7 height (see `DAY_ONE.md`). They must be bumped before activation (~Nov 5).
