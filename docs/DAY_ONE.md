# Day-one checks: spec vs. the live internet (checked Oct 21, 2026)

Status key: ✅ confirmed · ⚠️ partly true / needs hedging · ❌ wrong or unverifiable · 🔴 risk to the plan

| Spec claim | Status | What the sources say |
|---|---|---|
| NU7 activates on mainnet Nov 5; height set Oct 20 | ⚠️ | Developers agreed on height **3,543,405** (≈ Nov 5), but the PR was still unmerged and the NU7 deployment spec listed mainnet height as undecided during the Oct 21 review. Zebra's readiness tracker was 6/12. Treat Nov 5 as a target, and plan for a slip. |
| NU7: 25-second blocks, no new tx formats | ⚠️ | 25 s blocks confirmed. NU7 also **disables v4 transactions** (Sprout funds become unspendable). Not a problem for us if every tx we build is v5+/Ironwood, but check that the wallet stack doesn't emit v4. |
| NU7 testnet is live | ✅ | Activated on testnet at block 4,465,026 on Oct 4. We can test against it now. |
| Ironwood live (NU6.3, block 3,428,143); Orchard restricted | ✅ | Activated Jul 28, 2026 at 3,428,143. Orchard is sealed: no new deposits or internal transfers; it only drains via the turnstile. |
| PCZT works on Ironwood with librustzcash | ⚠️🔴 | `pczt` 0.9.x is final post-Ironwood; `pczt 0.10.0-pre.2` (NU7 pre-release) landed Oct 14. A librustzcash migration issue said PCZT creation **still used legacy Orchard routing and lacked Ironwood roles** (may be stale). Zarrier's README does claim a working Ironwood PCZT sale on testnet, so a path exists. Must be proven hands-on before anything else in Layer 1. |
| WebZjs as the browser stack | ❌🔴 | No official confirmation of Ironwood support. The only claim is from a grant applicant. **Recommend option B (local Rust service on librustzcash)**, which is what Zarrier used. |
| FROST escrow (rerandomized RedPallas via PCZT) | ⚠️🔴 | Works in community prototypes (`OpenPGP-Wallet/frost-zec`). The official ZF `frost` crate has **no public API that accepts a transaction-supplied randomizer (alpha)** except the deprecated `sign()`. Expect friction; the spec's fallback (document key custody) is likely needed. |
| Zakura one-time IVK library available | ❌ | Post is real (Adam Tucker, Zakura). The library is "in review" and not shipped. Plan: **fresh ZIP 32 account per auction** as the baseline, and implement the post's rivk derivation only if time allows. |
| Zarrier as carrier-note reference | ✅ | `Reiunmute/zcash-carrier`, MIT/Apache-2.0. Provenance answer exists: issuer's viewing key is public, and a verifier walks the chain of bound spends (rho_new = nf_old), with rules R1–R3 and a FINAL note capping supply. Adopt this. Caveat: its verifier trusts lightwalletd (cross-checks two servers, no PoW check). |
| ZPrivDEX "rejected by ZCG on Apr 27, 2026 after a core developer showed its state couldn't be checked publicly" | ❌ | The forum thread exists (Apr 16, 2026). hanh did say unverifiable pool-state deltas can't be trusted, and Zooko did say "more privacy is not always better". But I found **no record of a formal ZCG rejection on Apr 27**; the author said the formal application hadn't been filed yet. **Don't state "rejected by ZCG" in the pitch.** Say "the community's core objection was unverifiable state". |
| No native Zcash dark pool / sealed-bid exists | ❌🔴 | Other Private Markets entries are already public: **Kalyptra** (`Dami904/kalyptra`): threshold-encrypted sealed-bid, uniform price, public checker, atomic settlement, on ZSAs, **regtest only**. **Kakure** (private prediction market). Also `Udoka-AM/sealForge` has FROST 2-of-3 escrow work. Our edges hold: native Ironwood (no ZSAs), testnet → mainnet settlement, and bids never decrypted (Kalyptra decrypts orders after close). Lead with those. |
| Deadline Oct 28 | ✅ | Site and the zkSNARKs post both say Oct 28. Track rules are behind sign-in, so confirm the timezone there. |
| `pasta_curves` compiles to wasm32 | ✅ | `pasta_curves 0.6.1` builds for `wasm32-unknown-unknown` (verified locally). |

## Decisions taken

1. Wallet stack: **option B**, a local Rust service on librustzcash, unless WebZjs proves Ironwood + PCZT on day one.
2. One-time addresses: **fresh account per auction** baseline. The Zakura construction is a stretch goal.
3. Escrow: try FROST. If the alpha API gap blocks it by Oct 25, document key custody in the README.
4. Pitch wording: drop "rejected by ZCG". Name Kalyptra honestly and contrast with it.

## Sources
- NU7: https://github.com/ZcashFoundation/zebra/issues/11674 · https://crypto.news/zcash-nu7-activation-november-5-25-second-blocks/ · https://www.cryptotimes.io/2026/10/05/zcash-nu7-now-live-on-testnet-with-25-second-blocks/
- Ironwood: https://z.cash/upgrade/nu6-3/ · https://forum.zcashcommunity.com/t/ironwood-is-here-updated-wallets-libraries-aug-1/56557 · https://zecstats.org/ironwood
- PCZT: https://github.com/zcash/librustzcash/issues/3149 · https://github.com/zcash/librustzcash/issues/2630
- FROST: https://github.com/ZcashFoundation/frost/issues/1094 · https://github.com/OpenPGP-Wallet/frost-zec
- Zakura: https://zakura.com/engineering/quantum-unlinkability/
- Zarrier: https://github.com/Reiunmute/zcash-carrier
- ZPrivDEX: https://forum.zcashcommunity.com/t/zprivdex-building-a-shielded-amm-on-zcash/55368
- Competitors: https://github.com/Dami904/kalyptra · https://github.com/Blockchain-Oracle/kakure
- Event: https://thezecathon.com/

## Update, Oct 23: NU7 readiness of the pinned libraries
The librustzcash revision pinned here (`eb38d7a`, same as zcash-devtool) has **no mainnet NU7 activation height** (`NetworkUpgrade::Nu7 => None` for mainnet; testnet is set to 4,465,026). That's correct today: mainnet is on NU6.3, and transactions built now use the NU6.3 consensus branch. **After mainnet activates NU7 (target height 3,543,405, around Nov 5), these builds would produce transactions for the wrong branch, and nodes would reject them.**

Action before the post-NU7 re-test: bump to the librustzcash and zcash-devtool releases that set the mainnet height, rebuild, and re-run the testnet and mainnet flows.

`tally-settle` takes its network from each wallet's `keys.toml` and refuses to mix networks in one command. The same binary drives testnet and mainnet.

## Update, Oct 24: NU7 gap closed
librustzcash published stable releases on Oct 22 with the **mainnet NU7 height set (3,543,405)**: `pczt 0.10.0`, `zcash_client_backend 0.25.0`, `zcash_client_sqlite 0.23.0`, `zcash_primitives 0.31.0`, `zcash_protocol 0.11.0`, `zcash_keys 0.17.0`. Tally now uses them, with no git pins.

zcash-devtool (last commit Oct 17) didn't compile against them: 7 errors, all in commands Tally doesn't use (sighash API rename, a new `BlockSpacing` argument). [`patches/zcash-devtool-stable-releases.patch`](../patches/zcash-devtool-stable-releases.patch) fixes them. Apply it to `zcash/zcash-devtool@0b3436b`.

Verified:
- Tally on the stable crates opens wallets written by the old devtool, and the old devtool still syncs them. Tested on a copy.
- A real testnet transaction built by Tally on the stable crates, broadcast by the patched devtool: `c562d50d2089691775429d902898f99f636a0886d3053c3a7cd9d82296b4ad70` (v6, Ironwood only).
