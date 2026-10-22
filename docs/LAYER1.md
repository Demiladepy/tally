# Layer 1: atomic carrier-note sale with PCZT (testnet)

## Stack (checked Oct 22, 2026)
- **librustzcash at the revision zcash-devtool pins** (`eb38d7a`, the NU7 pre-release round):
  `pczt =0.10.0-pre.2`, `zcash_client_backend =0.25.0-pre.2`, `zcash_protocol =0.11.0-pre.1`, `orchard 0.16`.
  - Why not the stable crates (`pczt 0.9.x`, `orchard 0.15.5`) that Zarrier uses? **Testnet activated NU7 on Oct 4**, and Zarrier's evidence predates that. We need NU7-aware consensus parameters to build valid testnet transactions now, and mainnet will need them after the NU7 upgrade.
- **Ironwood PCZTs require the v2 PCZT format (v6 transactions).** The v1 format cannot represent an Ironwood bundle (`pczt/src/lib.rs`).
- **Wallet ops:** `zcash-devtool` (Ironwood balances, PCZT create/prove/sign/send, `--tx-version`). Light client: `testnet.zec.rocks:443`.

## The binding problem, and the fix
Ironwood bundles have cross-address transfers enabled. In that mode `orchard 0.16`'s builder **shuffles spends and outputs independently** (`builder.rs`, the `cross_address_enabled` branch). The carrier output therefore lands in the carrier spend's Action only by chance.

An output's `rho` equals the nullifier of the spend in its own Action. Item lineage (rho_new = nf_old) therefore holds only when the two share an Action.

**Fix (Zarrier's approach, re-implemented and credited):**
1. Build with `build_for_pczt`.
2. Read the Ironwood bundle metadata.
3. Accept only if `output_action_index(carrier_out) == spend_action_index(carrier_spend)`. Otherwise rebuild with fresh randomness.

The odds are about 1/num_actions per try, so a few tries is enough. The seller re-checks the binding before signing.

## Sale flow (one tx per winner)
1. Buyer builds the transaction:
   - spend: the seller's carrier note (the seller shares the note and witness, scoped to that one note), bound to output 0;
   - spend: the buyer's ZEC note;
   - output 0: the carrier note to the buyer's one-time address, with memo `Item.next_hop()`;
   - output 1: the clearing price to the seller's one-time address;
   - output 2: the buyer's change.
2. Buyer proves, signs only their own spend, and redacts their private fields.
3. Seller checks the price, item, binding and expiry, signs the carrier spend last, extracts the transaction and broadcasts it.

## Acceptance (from the spec): done Oct 22, see `evidence/testnet-2026-10-22`
- [x] Mint 2 carrier items on testnet.
- [x] One txid moves an item to the buyer and ZEC to the seller.
- [x] On-chain data is Ironwood-only (no transparent, Sapling or Orchard parts; only the fee is public).
- [x] A half-signed PCZT can't be extracted.
- [x] The node rejects a replay, and a spent carrier can't be re-sold.

## Tooling gaps found (Oct 22)
- `zcash-devtool pczt sign` only signs Orchard spends, not Ironwood, so `tally-settle` signs with `Signer::sign_ironwood`.
- `zcash-devtool pczt send` only accepts PCZTs built by its own wallet (it requires proposal info). Use `pczt send-without-storing`.
- `zcash-devtool inspect` prints only the header of a v6 transaction. `tally-settle try-extract` prints the per-pool structure.
- Compact blocks carry no memos. Run `wallet enhance` before reading item memos.
- The faucet in the spec (faucet.zecpages.com) is down. Fauzec and the Valar and jinolabs faucets work.

## Hardening (Oct 22): see `evidence/testnet-2026-10-22-hardened`
- **Per-item vault accounts and per-sale payout accounts.** A viewing key the seller shares exposes one item and nothing else.
- **Listing handoff.** The buyer builds from `listing.json` alone. It checks the note opens under the vault key, sits in the tree at the stated anchor, and that the anchor matches its own chain view. It also checks the item signature.
- **Redaction.** The buyer strips its funding spend (key, witness, note), its change and the item's destination. A byte scan proves none survive, and a check proves the buyer alone can't extract.
- **The seller checks before signing last:**
  - the listing hash;
  - the expiry window;
  - exactly one spend of its carrier;
  - the price paid to its payout address.

## Run it
```
zcash-devtool wallet -w S generate-account -i S.age --name vault-1     # one per item
zcash-devtool wallet -w S generate-account -i S.age --name payout-1    # one per sale
zcash-devtool wallet -w B generate-account -i B.age --name inbox-1     # buyer's receiving vault
tally-settle mint --wallet S --identity S.age --payer seller --vaults vault-1 --record mint.json --out mint.pczt
zcash-devtool pczt -w S send-without-storing mint.pczt                  # then set txid in mint.json
zcash-devtool wallet -w S enhance                                       # memos are not in compact blocks
tally-settle list --wallet S --record mint.json --item 0 --payout-account payout-1 --price-zat 1000000 --out listing.json
#   seller -> buyer: listing.json
tally-settle sale-build --wallet B --identity B.age --payer buyer --receive-account inbox-1 --listing listing.json --out sale.pczt
#   buyer -> seller: sale.pczt, sale.terms.json
tally-settle sale-accept --wallet S --identity S.age --listing listing.json --input sale.pczt --out sale-final.pczt
zcash-devtool pczt -w S send-without-storing sale-final.pczt
```

## Environment notes
- On Windows, the very long session path breaks `dlltool` and `ring` builds. Build with `CARGO_TARGET_DIR=C:/Users/User/.tally-target`.
- Wallets live in `../wallets/` outside the repo. Seeds are encrypted with an age identity. Nothing from them may be printed or committed.
