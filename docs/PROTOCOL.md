# Tally protocol (v1)

Implemented in `crates/tally-crypto`. This file records where the code
departs from the Oct 21 build spec, and why.

## Primitives
- Group: Pallas (`pasta_curves 0.6.1`), generator G.
- Hashes: BLAKE2b-512 transcripts starting from the tag `tally/v1/<purpose>`.
  Every item is labelled and length-prefixed. Challenges are the 64-byte
  digest reduced mod q; IDs are the first 32 bytes.
- Encryption: Enc(m; r) = (r·G, m·G + r·H).

## Ballot
- `c_i = Enc(y_i; r_i)` with y = 1…1 0…0 and at least one 1.
- Proofs, all bound to a base transcript over (auction_id, H, P, L, every c_i) plus (kind, index):
  - `proof_bits[i]`: CDS OR-proof that c_i encrypts 0 or 1. Stored as (c0, c1, z0, z1).
  - `proof_monotone[i]`: the same OR-proof on c_i − c_{i+1}.
  - `proof_first_one`: DLEQ that log_G A_1 = log_H (B_1 − G).
- `sig`: Schnorr by the ballot key b over `body_hash`, under purpose `ballot-sig`.
  Win claims use the separate purpose `win-claim`.

## Threshold decryption
- Share for target τ: D_j = x_j·A, with a DLEQ(G, X_j; A, D_j) bound to τ and the ciphertext.
  Targets are `T_k` or `ballot:<P hex>:k`, so a share can't be reused for another target.
- Combine any t distinct valid shares with Lagrange at 0, then recover m by scanning m ≤ #ballots.

## Clearing
- Binary search with invariant T_lo ≥ N (T_0 = ∞), T_hi < N (T_{L+1} = 0).
  It decrypts exactly ⌈log₂(L+1)⌉ totals (5 for L = 16), and T_{k*} and T_{k*+1} are always among them.
- k* = 0 means undersubscribed: every valid ballot wins at p_1.

## Changes from the spec
1. **Hashing uses a binary transcript, not canonical JSON.** Canonical-JSON hashing is fragile across Rust and JS (number formatting, key order, unicode). JSON is still the wire format.
2. **Fewer per-ballot reveals.** The spec decrypts c_{k*} and c_{k*+1} for every ballot. The code decrypts:
   - nothing when undersubscribed,
   - only c_{k*} when T_{k*} = N exactly, or when k* = L,
   - c_{k*} and c_{k*+1} otherwise.

   This leaks strictly less.
3. **Revealed cells are cross-checked against the totals.** The count of yes at k* must equal T_{k*}, and the count at k*+1 must equal T_{k*+1}. Cells must also be monotone.
4. **Ballot size.** Hex JSON is about 11.8 KB at L = 16, against the spec's estimate of 5–6 KB, which assumed binary. It still lives only on the bulletin log, so this has no impact.
5. **The DKG is joint-Feldman.** A rushing dealer can bias H (Gennaro et al.). This is acceptable for an ElGamal key in the demo. Pedersen-VSS would fix it.

## Disclosed leakage
- The ⌈log₂(L+1)⌉ totals on the search path.
- For each anonymous ballot ID, the revealed cell values (whether the bid was ≥ p_{k*}, and ≥ p_{k*+1}).
- No amounts and no identities. A colluding t-of-n quorum could decrypt every cell.
