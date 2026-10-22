# Layer 4: full sealed-bid auction on testnet

## Pieces
| Piece | Role |
|---|---|
| `tally-crypto::auction` | The public record (`AuctionLog`). `next_targets` drives adaptive clearing. `compute_result` works from published records only. `verify` runs every public check. |
| `tally-bulletin` | Append-only, hash-chained ballot log with signed receipts and no request logging. Enforces the order: close, then bonded set, then only-needed decryptions, then a result that recomputes, then seller-signed settlements. |
| `tally-committee` | DKG with age-encrypted shares, bond attestation signatures, per-target shares, adaptive `clear`, and `verify`. |
| `tally-settle` | Wallet side: `auction-create` and `auction-close`, `fund`, `bid` (sealed ballot plus bond), `scan-bonds`, `refund`, `settle-post`, `block-hash`, and win claims in `sale-build` and `sale-accept`. |

## Lifecycle
```
# committee (once): keygen ×3, deal ×3, finish ×3        -> committee.json (public), mJ.secret (private)
tally-bulletin --listen 127.0.0.1:8787 --data ./data --key ./bulletin.key

# seller
tally-settle auction-create --wallet S --record mint.json --committee committee.json \
  --escrow-wallet E --escrow-account escrow --forfeit-account forfeit \
  --supply 2 --ladder 100000:16 --bond-zat 100000 --close-in 30 --min-batch 5 \
  --bulletin http://127.0.0.1:8787 --out auction.json

# each bidder (own account per bid)
tally-settle bid --wallet B --identity B.age --account bidder-k --bulletin URL --auction-id ID \
  --max-price-zat P --record bid-k.json --out bond-k.pczt
zcash-devtool pczt -w B send-without-storing bond-k.pczt

# at the close height
tally-settle auction-close --auction auction.json
tally-settle scan-bonds --wallet E --account escrow --auction-id ID --out bonds.json   # after `wallet enhance`
tally-committee attest --j 1 --secret m1.secret --log URL/v1/auctions/ID --bonds bonds.json --out sig-1.json
tally-committee attest --j 3 --secret m3.secret --log ... --out sig-3.json
tally-committee post-bonds --log ... --bonds bonds.json --sigs sig-1.json,sig-3.json
tally-committee clear --log ... --member 1:m1.secret --member 3:m3.secret \
  --block-hash $(tally-settle block-hash --wallet S --height CLOSE_HEIGHT)

# each winner, against a listing of one item at the clearing price
tally-settle list ... --price-zat PRICE --out listing.json
tally-settle sale-build ... --listing listing.json --claim bid-k.json --out win.pczt
tally-settle sale-accept ... --listing listing.json --input win.pczt --auction-log URL/v1/auctions/ID --out final.pczt
zcash-devtool pczt -w S send-without-storing final.pczt
tally-settle settle-post --auction auction.json --p P --txid TXID

# escrow
tally-settle refund --wallet E --identity E.age --account escrow --bulletin URL --bonds bonds.json \
  --forfeit-unsettled --out refund.pczt
zcash-devtool pczt -w E send-without-storing refund.pczt

# anyone
tally-committee verify --log URL/v1/auctions/ID
```

## Notes
- Clearing is adaptive. The binary search picks each total from the previous one, so a distributed committee runs `share` and `combine` once per target, and `clear` does the same loop when the members' secrets are local.
- The tie-break seed is the block hash at the manifest's close height combined with the log root. The seller closes at that height, so the seed can't be ground by choosing when to close. For this demo the close is triggered by hand at or after that height.
- A wallet that sends with `send-without-storing` doesn't learn its own spends until it syncs the next block. Sync before building another transaction from the same account.
