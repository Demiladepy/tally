# Threat model

Everything below describes what the code in this repository does today. It claims nothing the code doesn't do.

## Who sees what
| Data | Public | Bulletin operator | Committee (a t-of-n quorum) | Seller | Escrow holder |
|---|---|---|---|---|---|
| A bidder's maximum price | never | never | **could** decrypt it by colluding beyond the protocol | never | never |
| Which price bracket a ballot ended in (k\* and k\*+1 cells) | only for ballots whose cells are opened, by anonymous ballot ID. A ballot that is yes at k\* and no at k\*+1 is revealed as bidding **exactly** p_k\* (the ladder is the bid) | same | same | same | same |
| Totals on the binary-search path (≤ ⌈log₂ L⌉ of L) | yes. T_1 is never decrypted: it is the public bonded count. T_k\* − T_k\*+1, the number of ballots at exactly the clearing level, is public | yes | yes | yes | yes |
| Clearing price and winners' anonymous ballot IDs | yes | yes | yes | yes | yes |
| Who a bidder is (wallet, addresses, IP) | no | no addresses ever. IP and arrival time are visible at the network layer but never logged | no: it gets ballot hashes and amounts only, and the committee CLI refuses a bonds file that carries refund addresses | no | sees each bond's refund address (Orchard-only, enforced) |
| Bond payments | no (shielded) | no | attests the set | no | yes (memos: ballot hash and refund address) |
| Item ownership | no (shielded notes) | no | no | knows its own vault | no |
| Where a sold item went | no | no | no | **no**: the buyer redacts it | no |
| Buyer's funding note, change, keys | no | no | no | **no**: redacted, including every action's value-commitment randomness `rcv` (without that the seller could open the buyer's amounts); the buyer re-checks the redacted bytes | no |
| Which anonymous winner key P a buyer is | P and the sale txid are public in the settlement | no | no | **yes**: the winner sends the seller its claim for P over some channel, so the seller can tie that channel to P | no |

## Attacks and defenses
| Attack or leak | Defense in code | Residual risk |
|---|---|---|
| Seller shill-bids to raise the price | Every counted ballot needs a bond. Winners who don't settle forfeit the bond to `forfeit_ua`, which `Manifest::verify` requires to differ from the escrow, and which is never the seller. | Shills are cheap, not free: bonds are refunded, and a shill "winner" can settle by buying from its own seller for the fee. A seller can therefore place sybil ballots at a level ℓ to push k\* to ℓ, which makes the committee open c_ℓ and c_ℓ+1 for every real ballot: a seller-chosen threshold test on each real bid. The protocol can't tell a sybil from a bidder. Defenses: the `min_batch` floor, and bidders should treat a thin auction as a weak hiding set. |
| Inferring bids from totals | Only the binary-search totals are opened. The bulletin **refuses** any decryption the search doesn't need (`next_targets`), and the verifier fails if anything extra was opened. T_1 is the public bonded count, so an undersubscribed auction decrypts **nothing**. Cells are opened only when needed: none if undersubscribed, only c_{k\*} on an exact fill. `min_batch` voids small auctions with nothing decrypted, and v2 manifests require `min_batch ≥ 5`. | The opened totals and cells are public. In a small auction they bound each bid tightly, and a bracket ballot's bid is revealed exactly. |
| Rogue manifest (a bulletin or link serves a manifest with a committee key it controls) | v2: the auction id **is** the hash of the manifest's contents, so the id in a link pins the committee key, escrow and ladder. Every committee member endorses the manifest with its DKG key share, and the browser refuses to seal unless all n endorsements verify. | A bidder must get the link from someone they trust. A rogue seller can still invent a whole fake committee; the bid page shows the member names so bidders can check them. |
| Committee collusion | t-of-n threshold ElGamal (demo: 2-of-3). Every share carries a DLEQ proof bound to its target. | A colluding quorum could decrypt every ballot. The demo committee is three keys run by one person (@dd), which is not independent. |
| Fake bonded set | The bonded set needs ≥ t member signatures over the final log root. | Bonds are shielded, so the public trusts the same quorum for the bonded set as for decryption. |
| Bulletin censors or reorders ballots | The log is hash-chained, each append returns a signed receipt, and the seller signs the close at an exact (count, root). | A censored bidder can prove exclusion with the receipt, but can't force inclusion. |
| Bulletin learns identities | The service logs nothing: no IPs, user agents or timings, and no tracing layer. Rejections are fixed strings and never echo the request (tested). Ballots contain no addresses. | Network-level metadata: the server sees the IP and time of every ballot. **The bulletin and the escrow must be run by different parties**: one operator holding both could join IP → ballot hash (bulletin) → refund address (bond memo). Bidders should submit over Tor (`zcash-devtool --connection tor` for the wallet side, Tor Browser for the bid page). |
| Linking a bidder across auctions | A fresh ballot key per bid. The CLI bids from the account it is given; use a fresh account per bid. The refund address must be Orchard-only (no transparent or Sapling receiver can ride along). | Nothing enforces a fresh account. In the browser the refund address comes from whatever wallet the bidder uses; reusing it links their bids for the escrow. The demo bidders live in one wallet file. |
| Quantum harvest-now-decrypt-later | Item vaults, payout and change addresses belong to accounts used for one purpose. | The escrow and forfeit addresses are **public by design** (they are in the manifest), so a quantum adversary could recover the escrow account's viewing key and read every bond memo it received. Use a **fresh escrow account per auction** so that exposes one auction only. Ballot ElGamal isn't post-quantum. Zakura's one-time IVK isn't used yet (its library isn't released). |
| Timing | The bulletin stores no timestamps. Transactions use the wallet-default expiry for their height (40 blocks before NU7, 120 after), so expiry doesn't single them out. | Anyone can poll the public log and timestamp each ballot as it appears. `persist` rewrites the log file on every append, so file times on the server record arrival. Refund transactions have N+1 actions for N bonds. |
| Rogue or spam auctions on a shared bulletin | Each auction needs a valid, fully endorsed v2 manifest, and auctions and ballots are capped (1,000 / 5,000). | Anyone with their own committee keys can still create auctions on an open bulletin. Run one bulletin per seller, or put `create` behind the operator. |
| Winner doesn't pay | `refund --forfeit-unsettled` sends that winner's bond to the forfeit address. | Re-offering the item to the next eligible ballot isn't automated yet. |
| Fake or copied item | The seller's collection key signs the item memo. The new note's rho must equal the previous carrier's nullifier, checked by the buyer (`inspect-item --listing`). | Only one hop is verified. A full lineage walk back to the mint belongs on the verify page. |
| Half-built sale | The buyer signs only its own spend. A buyer-only PCZT can't be extracted, which is checked at build time. The seller signs last, after checking the listing hash, expiry, a single carrier spend and the payout. | None known. |
| Vault viewing key given to the buyer | The listing hands the buyer the vault's full viewing key, so it can check the carrier note. Each item lives in its own vault account. | It includes outgoing view. Safe only while a vault account is never reused, which the code doesn't enforce. |
| Tampered or substituted WASM | The verifier and the sealing code are one WASM blob with no imports. The Pages workflow rebuilds it from source on every deploy and publishes its sha256 (`tally_wasm.wasm.sha256`). Pages refuse to render inside another site's frame. | A bidder trusts whoever serves the page. Rebuild at the deployed commit and compare the hash. The static site can't send HSTS or a header CSP. |
| Local traces on the bidder's machine | After sealing, the page removes the bid from the DOM (readout, accessible value, dial angle, notches) and WASM zeroes its input and reply buffers. The key file has a generic name (`tally-key.json`). | The key file is unencrypted, and the bond URI and memo pass through the clipboard. JavaScript strings can't be wiped, so the bid may linger in the JS heap until garbage collection. |

## Escrow custody (honest statement)
The spec asked for FROST threshold signing of the escrow. As of Oct 2026 the official `frost` crate has no public API that accepts the per-action randomizer an Ironwood PCZT fixes (ZcashFoundation/frost#1094). The escrow is therefore **one ordinary account held by the committee coordinator**. It holds only bonds (0.001 TAZ each in the demo) and a small fee float. The coordinator could steal bonds, and that is the trust users extend. The verifier can't check refunds, because they are shielded.

## Adversarial leak review, Oct 24
A second model was asked only to find ways the system links a person to a bid, an address or a payment. Fixed in code (with tests):
- **Seller could open the buyer's amounts**: the sale PCZT kept `rcv`. All actions now have `rcv` cleared, and the build refuses to write a PCZT with any left.
- **Transparent/Sapling receivers in refund addresses**: the bond memo now requires an Orchard-only unified address (WASM, CLI and decoder).
- **Committee received the ballot → refund-address map**: `scan-bonds` writes a committee file (hashes and amounts) and a separate escrow-only file; the committee CLI rejects the escrow file.
- **Rogue manifests**: manifest v2 (id = content hash, all-member endorsements, `min_batch ≥ 5`); bulletin and browser accept only v2 for new auctions. The Oct 22 testnet log is v1 and still verifies, labelled as legacy.
- **Undersubscribed auctions opened totals for nothing**: T_1 is now the public bonded count.
- **Bid left in the DOM**, **error echoes**, **non-default expiry**, **frameable pages**, **unbuilt WASM**: fixed as described in the tables above.

Disclosed rather than fixed: bracket ballots reveal an exact bid; sybil steering of k\*; the seller learns which channel claimed P; bulletin and escrow must be separate operators; public escrow addresses; polling-based timing; open `create`; the vault FVK.

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
- **The winner's return channel to the seller** is out of band. A Tor drop or a bulletin mailbox with a fresh key would stop the seller learning who claimed P.
- **Mainnet NU7.** Tally uses the Oct 22 stable librustzcash releases, which set the mainnet NU7 height (3,543,405, ~Nov 5; see `DAY_ONE.md`). The flows still need a re-run on mainnet after activation.
