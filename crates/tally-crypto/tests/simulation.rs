//! Layer 3 acceptance: an offline auction with a 2-of-3 committee matches a
//! plaintext reference clearing exactly, decrypting only ⌈log₂(L+1)⌉ totals,
//! and no single member can decrypt anything.

use std::collections::BTreeSet;

use pasta_curves::group::GroupEncoding;
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use tally_crypto::ballot::Ballot;
use tally_crypto::clearing::{self, CellReveal};
use tally_crypto::dkg::{self, CommitteeKey};
use tally_crypto::elgamal::Ciphertext;
use tally_crypto::threshold::{self, DecryptionRecord};
use tally_crypto::{codec, g, log, Error, Point, Scalar};

const L: usize = 16;
const N_MEMBERS: u32 = 3;
const T: u32 = 2;
const AUCTION: [u8; 32] = [3u8; 32];

struct Committee {
    key: CommitteeKey,
    secrets: Vec<Scalar>,
}

fn run_dkg(rng: &mut ChaCha20Rng) -> Committee {
    let dealings: Vec<_> = (1..=N_MEMBERS).map(|i| dkg::deal(i, N_MEMBERS, T, rng).unwrap()).collect();
    let commitments: Vec<Vec<Point>> = dealings.iter().map(|d| d.commitments.clone()).collect();
    let key = dkg::committee_key(N_MEMBERS, T, &commitments).unwrap();
    let secrets = (1..=N_MEMBERS)
        .map(|j| {
            let received: Vec<_> = dealings
                .iter()
                .map(|d| (d.dealer, d.commitments.as_slice(), d.shares[j as usize - 1]))
                .collect();
            dkg::member_secret(j, &received).unwrap()
        })
        .collect();
    Committee { key, secrets }
}

impl Committee {
    /// Members `who` each produce a share; the result is combined publicly.
    fn decrypt(&self, target: &str, ct: &Ciphertext, who: &[u32], max: u64, rng: &mut ChaCha20Rng) -> Result<DecryptionRecord, Error> {
        let shares = who
            .iter()
            .map(|&j| threshold::make_share(target, j, &self.secrets[j as usize - 1], ct, rng))
            .collect();
        threshold::decrypt(target, &self.key, ct, shares, max)
    }
}

/// Plaintext reference clearing from the bidders' private max levels.
fn reference(maxes: &[usize], keys: &[Point], supply: u64, seed: &[u8; 32]) -> (usize, BTreeSet<[u8; 32]>) {
    let t = |k: usize| maxes.iter().filter(|&&m| m >= k).count() as u64;
    let k_star = (1..=L).filter(|&k| t(k) >= supply).max().unwrap_or(0);
    let set = |ps: Vec<Point>| ps.iter().map(|p| p.to_bytes()).collect::<BTreeSet<_>>();
    if k_star == 0 {
        return (0, set(keys.to_vec()));
    }
    let mut winners: Vec<Point> = keys.iter().zip(maxes).filter(|(_, &m)| m > k_star).map(|(p, _)| *p).collect();
    let mut bracket: Vec<Point> = keys.iter().zip(maxes).filter(|(_, &m)| m == k_star).map(|(p, _)| *p).collect();
    bracket.sort_by_key(|p| clearing::tie_rank(seed, p));
    let slots = supply as usize - winners.len();
    winners.extend(bracket.into_iter().take(slots));
    (k_star, set(winners))
}

fn run_auction(seed: u64, bidders: usize, supply: u64, max_of: impl Fn(&mut ChaCha20Rng) -> usize) {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let committee = run_dkg(&mut rng);
    let h = committee.key.h;

    let maxes: Vec<usize> = (0..bidders).map(|_| max_of(&mut rng)).collect();
    let ballots: Vec<Ballot> = maxes
        .iter()
        .map(|&m| Ballot::build(AUCTION, &h, L, m, &mut rng).unwrap().0)
        .collect();
    for b in &ballots {
        b.verify(&AUCTION, &h, L).unwrap();
    }
    let keys: Vec<Point> = ballots.iter().map(|b| b.p).collect();
    let root = log::root(&AUCTION, ballots.iter().map(|b| b.body_hash()).collect::<Vec<_>>().iter());
    let mut block = [0u8; 32];
    rng.fill_bytes(&mut block);
    let seed_bytes = clearing::tie_seed(&block, &root);

    // Tally and search, using members 1 and 3 only.
    let totals = clearing::tally(&ballots, L);
    let mut records = Vec::new();
    let search = clearing::binary_search(L, supply, None, |k| {
        let rec = committee.decrypt(&format!("T_{k}"), &totals[k - 1], &[1, 3], bidders as u64, &mut rng)?;
        let m = rec.m;
        records.push(rec);
        Ok(m)
    })
    .unwrap();

    let max_probes = (usize::BITS - L.leading_zeros()) as usize; // ⌈log₂(L+1)⌉ = 5 for L = 16
    assert!(search.totals.len() <= max_probes, "decrypted {} totals", search.totals.len());

    // Per-ballot reveals, only for the cells clearing needs (members 2 and 3).
    let mut reveals = Vec::new();
    for lvl in clearing::cells_to_reveal(&search, L, supply) {
        for b in &ballots {
            let target = format!("ballot:{}:{lvl}", codec::point_to_hex(&b.p));
            let rec = committee.decrypt(&target, &b.c[lvl - 1], &[2, 3], 1, &mut rng).unwrap();
            reveals.push(CellReveal { p: b.p, level: lvl, yes: rec.m == 1 });
            records.push(rec);
        }
    }
    for rec in &records {
        assert!(threshold::verify_record(&committee.key, rec), "record {} failed", rec.target);
    }

    let winners = clearing::select_winners(&search, L, supply, &keys, &reveals, &seed_bytes).unwrap();
    let got: BTreeSet<[u8; 32]> = winners.iter().map(|p| p.to_bytes()).collect();
    let (ref_k, ref_winners) = reference(&maxes, &keys, supply, &seed_bytes);

    assert_eq!(search.k_star, ref_k, "seed {seed}");
    assert_eq!(got, ref_winners, "seed {seed}");
    assert_eq!(got.len(), winners.len());
    if ref_k > 0 {
        assert_eq!(winners.len() as u64, supply);
    }
}

#[test]
fn fifty_random_ballots_match_reference() {
    for seed in 0..6 {
        run_auction(seed, 50, 8, |rng| 1 + (rng.next_u32() as usize % L));
    }
}

#[test]
fn undersubscribed_everyone_wins_and_no_cells_revealed() {
    run_auction(100, 6, 8, |rng| 1 + (rng.next_u32() as usize % L));
}

#[test]
fn everyone_at_top_level() {
    run_auction(101, 12, 5, |_| L);
}

#[test]
fn exact_fill_at_clearing_level() {
    // 3 bidders at level 10, 2 at level 4, supply 3 → T_10 = 3 = N exactly.
    let order = std::cell::Cell::new(0usize);
    run_auction(102, 5, 3, |_| {
        let i = order.get();
        order.set(i + 1);
        if i < 3 { 10 } else { 4 }
    });
}

#[test]
fn single_member_cannot_decrypt() {
    let mut rng = ChaCha20Rng::seed_from_u64(9);
    let committee = run_dkg(&mut rng);
    let ct = Ciphertext::encrypt(&committee.key.h, 1, &tally_crypto::random_scalar(&mut rng));
    for j in 1..=N_MEMBERS {
        assert_eq!(committee.decrypt("T_1", &ct, &[j], 10, &mut rng).unwrap_err(), Error::NotEnoughShares);
        // Using a lone share as if it were the whole key yields garbage.
        let share = threshold::make_share("T_1", j, &committee.secrets[j as usize - 1], &ct, &mut rng);
        assert_ne!(ct.b - share.d, g());
    }
    // The same member twice doesn't count as two.
    assert_eq!(committee.decrypt("T_1", &ct, &[2, 2], 10, &mut rng).unwrap_err(), Error::NotEnoughShares);
}

#[test]
fn share_for_one_target_is_rejected_for_another() {
    let mut rng = ChaCha20Rng::seed_from_u64(10);
    let committee = run_dkg(&mut rng);
    let ct = Ciphertext::encrypt(&committee.key.h, 1, &tally_crypto::random_scalar(&mut rng));
    let share = threshold::make_share("T_3", 1, &committee.secrets[0], &ct, &mut rng);
    assert!(threshold::verify_share("T_3", &committee.key, &ct, &share));
    assert!(!threshold::verify_share("T_4", &committee.key, &ct, &share));
}

#[test]
fn forged_record_is_rejected() {
    let mut rng = ChaCha20Rng::seed_from_u64(11);
    let committee = run_dkg(&mut rng);
    let ct = Ciphertext::encrypt(&committee.key.h, 7, &tally_crypto::random_scalar(&mut rng));
    let mut rec = committee.decrypt("T_2", &ct, &[1, 2], 20, &mut rng).unwrap();
    assert_eq!(rec.m, 7);
    assert!(threshold::verify_record(&committee.key, &rec));
    rec.m = 8;
    assert!(!threshold::verify_record(&committee.key, &rec));
}

#[test]
fn bad_dealing_is_detected() {
    let mut rng = ChaCha20Rng::seed_from_u64(12);
    let mut d = dkg::deal(1, 3, 2, &mut rng).unwrap();
    d.shares[1] += Scalar::from(1u64);
    assert_eq!(
        dkg::member_secret(2, &[(1, d.commitments.as_slice(), d.shares[1])]),
        Err(Error::BadDealing(1))
    );
}
