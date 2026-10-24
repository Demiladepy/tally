# Submission kit

Deadline: Oct 28, 23:59 UTC (00:59 Oct 29 Lagos). Target: submit by 18:00 Lagos on Oct 28.

## Checklist
- [x] Public repo
- [x] Live URL that works on the first click: https://demiladepy.github.io/tally/verify.html?sample=testnet-2026-10-22 (10/10 in the browser)
- [x] Full auction end to end on testnet, with evidence and a public log
- [x] README: pitch, how it works, what's hidden, honest limits, one-command run, credits
- [x] Threat model (`docs/THREAT_MODEL.md`)
- [x] NU7-ready libraries (stable releases, mainnet NU7 height set)
- [ ] 2–3 minute video (script below)
- [ ] Tag `zecathon-submission` on the final commit
- [ ] Track selected: Private Markets
- [ ] Shielded ZEC address for prize payout (a fresh one from your own wallet)
- [ ] Optional: a funded mainnet run (wallets ready; needs ~0.02 ZEC)
- [ ] Optional: a hosted bulletin so judges can bid live
- [ ] Re-test after NU7 activates on mainnet (~Nov 5, height 3,543,405)

## Video script (≈2:30)
**0:00–0:20: the problem.** "Private markets on Zcash run on trust. A sale can clear thousands of ZEC and nobody outside the operator can check the price, the bids, or who owns what. The community's main objection to the last shielded-exchange proposal was exactly this: you couldn't verify its state."

**0:20–0:40: the insight.** "Clearing a sealed-bid auction is a private vote on prices. Each bidder votes yes or no at every price level. We add the votes up encrypted, and open only the few sums a binary search needs. Intent hidden, result public."

**0:40–1:20: the demo (screen: bid page).** Turn the dial to your max. Click *Seal my bid* and the envelope stamps shut. "My number never left this tab. The browser encrypted sixteen yes/no cells with proofs, and the bulletin signed a receipt." Show the bond request: the ZIP 321 link, and the plain-text memo for any wallet.

**1:20–1:55: the reveal (screen: verify page).** "At close, a 2-of-3 committee opened 4 of the 16 totals. Everything else stays sealed: see the hatched levels. The clearing price is 0.012, and both winners settled in one atomic shielded transaction each." Scroll the checks as they tick green. "These ten checks just ran in my browser. Drop in a tampered log and they go red." Show a red run.

**1:55–2:20: the guarantees.** "No bid is ever decrypted. No address is published. Payments are Ironwood-only, and the seller can't even see where the item went. What we disclose: a few anonymous totals, the price, and the anonymous winners. Honest limits are in the README: the escrow is one key today, and this demo committee is one person."

**2:20–2:30: Monday.** "A seller runs a drop. Instead of a trust-me auction, bidders get privacy and proof together. The repo and the live verifier are linked below."

### Recording tips
- Use the live verify link, plus a local `bash scripts/run-local.sh` for the bid flow.
- Pre-create an open testnet auction so the bid page has a case to show.
- For the red run, save `auction-log.json`, edit one `price_zat`, and drop the file on the page.
