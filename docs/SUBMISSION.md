# Submission kit

Deadline: Oct 28, 23:59 UTC (00:59 Oct 29 Lagos). Target: submit by 18:00 Lagos on Oct 28.

## Checklist
- [x] Public repo
- [x] Live URL that works on the first click: https://demiladepy.github.io/tally/verify.html?sample=testnet-2026-10-22 (10/10 in the browser)
- [x] Full auction end to end on testnet, with evidence and a public log
- [x] README: pitch, how it works, what's hidden, honest limits, one-command run, credits
- [x] Threat model (`docs/THREAT_MODEL.md`)
- [x] NU7-ready libraries (stable releases, mainnet NU7 height set)
- [x] Adversarial leak review done; fixes in code, limits disclosed in `docs/THREAT_MODEL.md`
- [x] Sale re-proven on testnet after the `rcv` fix (`evidence/testnet-2026-10-25-rcv`)
- [x] Open v2 auction ready for the recording (see below)
- [ ] 2–3 minute video (script below)
- [ ] Tag `zecathon-submission` on the final commit
- [ ] Track selected: Private Markets
- [ ] Shielded ZEC address for prize payout (a fresh one from your own wallet)
- [ ] Submit by 18:00 Lagos, Oct 28
- [ ] Optional: a funded mainnet run (wallets ready; needs ~0.02 ZEC; not required by any rule we could find)
- [x] Hosted desk so judges can bid live: https://tally-zec.fly.dev (Fly.io, one 256MB machine + 1GB volume, approved for one month; delete reminder set for Nov 26: `fly apps destroy tally-zec`)
- [ ] Re-test after NU7 activates on mainnet (~Nov 5, height 3,543,405)

## Video script (≈2:30)
**0:00–0:20: the problem.** "Private markets on Zcash run on trust. A sale can clear thousands of ZEC and nobody outside the operator can check the price, the bids, or who owns what. The community's main objection to the last shielded-exchange proposal was exactly this: you couldn't verify its state."

**0:20–0:40: the insight.** "Clearing a sealed-bid auction is a private vote on prices. Each bidder votes yes or no at every price level. We add the votes up encrypted, and open only the few sums a binary search needs. Intent hidden, result public."

**0:40–1:20: the demo (screen: Offerings → offering page).** Open the offering from the Offerings table. Show the term sheet and the Committee tab ("every member co-signed these terms; my browser checks each signature"). On the order ticket, set a limit price, click *Review order*, then *Seal & submit*. "My limit was encrypted in this tab. The desk received ciphertext and signed a receipt, and the limit is already gone from the page." Show the deposit step: paste a fresh shielded refund address and show the payment request.

**1:20–1:55: the reveal (screen: verify page).** "At close, a 2-of-3 committee opened 4 of the 16 totals. Everything else stays sealed: see the hatched levels. The clearing price is 0.012, and both winners settled in one atomic shielded transaction each." Scroll the checks as they tick green. "These ten checks just ran in my browser. Drop in a tampered log and they go red." Show a red run.

**1:55–2:20: the guarantees.** "No bid is ever decrypted. No bidder's address is ever published: the only public addresses are the auction's own escrow and forfeit addresses, fresh for each auction. Payments are Ironwood-only, and the seller can't even see where the item went. What we disclose: a few anonymous totals, the price, and the anonymous winners. Honest limits are in the README: the escrow is one key today, and this demo committee is one person."

**2:20–2:30: Monday.** "A seller runs a drop. Instead of a trust-me auction, bidders get privacy and proof together. The repo and the live verifier are linked below."

### Recording tips
- Use the live verify link for the reveal.
- For the bid flow, use the hosted desk:
  https://tally-zec.fly.dev/bid.html?auction=0bbd3ea5c8b2014786de38a62abd9381a2e8e547f19f44e3f3901286de21e94c
  ("Genesis Lot 001": v2 terms endorsed by all 3 members, 2 freshly minted items, open until testnet block 4,564,341, around Nov 21).
  It already holds one unfunded test order (order #0, from the deploy check); unfunded orders are excluded at clearing.
  Fallback if it's down: the local desk, `tally-bulletin --listen 127.0.0.1:8787 --data ../bulletin-run/data --key ../bulletin-run/bulletin.key --web ./web`, same link on http://127.0.0.1:8787.
- For the red run, save `auction-log.json`, edit one `price_zat`, and drop the file on the page.
