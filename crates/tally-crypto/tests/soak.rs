//! Soak test of the clearing rules: 10,000 random order books across nine
//! situations. Each one runs the real search, cell selection and winner
//! selection on plaintext totals and checks them against an independent
//! reference computed straight from the bidders' limits. It also checks that
//! the search opens no more totals than a binary search needs, and opens cells
//! at no more than two levels.
//!
//! Encryption is left out here on purpose: `simulation.rs` runs the same
//! rules end to end with real ciphertexts, proofs and a 2-of-3 committee.

use std::collections::BTreeSet;

use pasta_curves::group::GroupEncoding;
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use tally_crypto::clearing::{self, CellReveal};
use tally_crypto::{g, random_scalar, Point};

/// Independent reference: highest level whose demand covers supply, winners
/// strictly above it, then the bracket ordered by the public tie rank.
fn reference(levels: usize, limits: &[usize], keys: &[Point], supply: u64, seed: &[u8; 32]) -> (usize, BTreeSet<[u8; 32]>) {
    let demand = |k: usize| limits.iter().filter(|&&m| m >= k).count() as u64;
    let k_star = (1..=levels).filter(|&k| demand(k) >= supply).max().unwrap_or(0);
    let set = |ps: Vec<Point>| ps.iter().map(|p| p.to_bytes()).collect::<BTreeSet<_>>();
    if k_star == 0 {
        return (0, set(keys.to_vec()));
    }
    let mut won: Vec<Point> = keys.iter().zip(limits).filter(|(_, &m)| m > k_star).map(|(p, _)| *p).collect();
    let mut bracket: Vec<Point> = keys.iter().zip(limits).filter(|(_, &m)| m == k_star).map(|(p, _)| *p).collect();
    bracket.sort_by_key(|p| clearing::tie_rank(seed, p));
    won.extend(bracket.into_iter().take(supply as usize - won.len()));
    (k_star, set(won))
}

struct Book {
    levels: usize,
    supply: u64,
    limits: Vec<usize>,
}

fn clear_and_check(book: &Book, public_t1: bool, rng: &mut ChaCha20Rng) {
    let Book { levels, supply, ref limits } = *book;
    let keys: Vec<Point> = limits.iter().map(|_| g() * random_scalar(rng)).collect();
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    let total = |k: usize| limits.iter().filter(|&&m| m >= k).count() as u64;

    let t1 = public_t1.then_some(limits.len() as u64);
    let search = clearing::binary_search(levels, supply, t1, |k| Ok(total(k))).unwrap();

    // Minimality: a binary search over L levels opens at most ⌈log₂(L+1)⌉ totals.
    let bound = (usize::BITS - levels.leading_zeros()) as usize;
    assert!(search.totals.len() <= bound, "opened {} totals for L = {levels}", search.totals.len());
    if public_t1 && (limits.len() as u64) < supply {
        assert!(search.totals.is_empty(), "undersubscribed must open nothing");
    }

    let cells = clearing::cells_to_reveal(&search, levels, supply);
    assert!(cells.len() <= 2, "cells opened at {} levels", cells.len());
    let reveals: Vec<CellReveal> = cells
        .iter()
        .flat_map(|&lvl| keys.iter().zip(limits).map(move |(p, &m)| CellReveal { p: *p, level: lvl, yes: m >= lvl }))
        .collect();
    let winners = clearing::select_winners(&search, levels, supply, &keys, &reveals, &seed).unwrap();
    let got: BTreeSet<[u8; 32]> = winners.iter().map(|p| p.to_bytes()).collect();

    let (ref_k, ref_won) = reference(levels, limits, &keys, supply, &seed);
    assert_eq!(search.k_star, ref_k, "clearing level, L = {levels}, N = {supply}, limits {limits:?}");
    assert_eq!(got, ref_won, "winners, L = {levels}, N = {supply}, limits {limits:?}");
    assert_eq!(got.len(), winners.len(), "a winner listed twice");
    if ref_k > 0 {
        assert_eq!(winners.len() as u64, supply, "every unit allocated when demand covers supply");
    }
}

#[test]
fn ten_thousand_random_books() {
    let mut rng = ChaCha20Rng::seed_from_u64(2026_10_28);
    let pick = |rng: &mut ChaCha20Rng, lo: usize, hi: usize| lo + (rng.next_u32() as usize % (hi - lo + 1));
    let mut runs = 0;
    for situation in 0..9 {
        for _ in 0..1112 {
            let levels = pick(&mut rng, 1, 32);
            let n = pick(&mut rng, 1, 60);
            let (supply, limits): (u64, Vec<usize>) = match situation {
                // 0: anything goes.
                0 => (pick(&mut rng, 1, n + 5) as u64, (0..n).map(|_| pick(&mut rng, 1, levels)).collect()),
                // 1: heavy ties on two or three levels.
                1 => {
                    let few: Vec<usize> = (0..3).map(|_| pick(&mut rng, 1, levels)).collect();
                    (pick(&mut rng, 1, n) as u64, (0..n).map(|_| few[rng.next_u32() as usize % 3]).collect())
                }
                // 2: undersubscribed: more units than orders.
                2 => ((n + pick(&mut rng, 1, 10)) as u64, (0..n).map(|_| pick(&mut rng, 1, levels)).collect()),
                // 3: exact fill: demand at some level equals supply exactly.
                3 => {
                    let limits: Vec<usize> = (0..n).map(|_| pick(&mut rng, 1, levels)).collect();
                    let k = pick(&mut rng, 1, levels);
                    let supply = limits.iter().filter(|&&m| m >= k).count().max(1) as u64;
                    (supply, limits)
                }
                // 4: everyone bids the ceiling.
                4 => (pick(&mut rng, 1, n) as u64, vec![levels; n]),
                // 5: everyone bids the floor.
                5 => (pick(&mut rng, 1, n) as u64, vec![1; n]),
                // 6: a single unit.
                6 => (1, (0..n).map(|_| pick(&mut rng, 1, levels)).collect()),
                // 7: one order.
                7 => (pick(&mut rng, 1, 3) as u64, vec![pick(&mut rng, 1, levels)]),
                // 8: large books.
                _ => {
                    let n = pick(&mut rng, 200, 500);
                    (pick(&mut rng, 1, n) as u64, (0..n).map(|_| pick(&mut rng, 1, levels)).collect())
                }
            };
            let book = Book { levels, supply, limits };
            clear_and_check(&book, true, &mut rng);
            clear_and_check(&book, false, &mut rng);
            runs += 1;
        }
    }
    assert!(runs >= 10_000);
}
