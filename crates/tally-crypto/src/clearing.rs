//! Tally, binary-search clearing and winner selection.
//!
//! Levels are 1-based: level k is price p_k. T_k counts ballots with a yes
//! at level k, so T is non-increasing. k* = max{k : T_k ≥ N}.

use std::collections::BTreeMap;

use pasta_curves::group::GroupEncoding;

use crate::ballot::Ballot;
use crate::elgamal::Ciphertext;
use crate::hash::Transcript;
use crate::{Error, Point};

/// Per-level encrypted totals; anyone can compute this from the log.
pub fn tally(ballots: &[Ballot], levels: usize) -> Vec<Ciphertext> {
    let mut totals = vec![Ciphertext::identity(); levels];
    for b in ballots {
        for (t, c) in totals.iter_mut().zip(&b.c) {
            *t = *t + *c;
        }
    }
    totals
}

/// Result of the binary search. `totals` holds exactly the levels that were
/// decrypted; nothing else about T is ever revealed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Search {
    /// 0 means undersubscribed (T_1 < N).
    pub k_star: usize,
    /// Only the totals that were decrypted.
    pub totals: BTreeMap<usize, u64>,
    /// T_1 when it is public without decryption: every valid ballot says yes
    /// at level 1 (the first-one proof), so T_1 is the bonded count.
    pub public_t1: Option<u64>,
}

impl Search {
    /// T_k if it is known: decrypted, public (T_1), or T_{L+1} = 0.
    pub fn total(&self, k: usize, levels: usize) -> Option<u64> {
        if k == levels + 1 {
            return Some(0);
        }
        if k == 1 {
            if let Some(t1) = self.public_t1 {
                return Some(t1);
            }
        }
        self.totals.get(&k).copied()
    }
}

/// Find k* using `decrypt_total(k)` as the only window into T. Invariant:
/// T_lo ≥ N (T_0 = ∞) and T_hi < N (T_{L+1} = 0), so T_{k*} and T_{k*+1}
/// are both known when the loop ends, with ⌈log₂(L+1)⌉ decryptions.
///
/// With `public_t1 = Some(bonded count)` (manifest v2) nothing is decrypted
/// that the public count already answers: if T_1 < N the auction is
/// undersubscribed with zero decryptions, otherwise the search starts at
/// lo = 1. `None` reproduces the v1 search from lo = 0.
pub fn binary_search(
    levels: usize,
    supply: u64,
    public_t1: Option<u64>,
    mut decrypt_total: impl FnMut(usize) -> Result<u64, Error>,
) -> Result<Search, Error> {
    if levels == 0 || supply == 0 {
        return Err(Error::InvalidParams("levels and supply must be positive"));
    }
    let mut totals = BTreeMap::new();
    let (mut lo, mut hi) = match public_t1 {
        Some(t1) if t1 < supply => return Ok(Search { k_star: 0, totals, public_t1 }),
        Some(_) => (1usize, levels + 1),
        None => (0usize, levels + 1),
    };
    while hi - lo > 1 {
        let mid = (lo + hi) / 2;
        let t = decrypt_total(mid)?;
        totals.insert(mid, t);
        if t >= supply {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    Ok(Search { k_star: lo, totals, public_t1 })
}

/// Which per-ballot cells the committee must decrypt to name winners.
/// Kept minimal: none when undersubscribed, only c_{k*} when T_{k*} = N
/// exactly or k* = L, otherwise c_{k*} and c_{k*+1}.
pub fn cells_to_reveal(search: &Search, levels: usize, supply: u64) -> Vec<usize> {
    let k = search.k_star;
    if k == 0 {
        return vec![];
    }
    let t_k = search.total(k, levels).expect("T_k* is known when k* >= 1");
    if t_k == supply || k == levels {
        vec![k]
    } else {
        vec![k, k + 1]
    }
}

/// Seed for tie-breaks: H(block hash at close height ‖ log root).
pub fn tie_seed(close_block_hash: &[u8; 32], log_root: &[u8; 32]) -> [u8; 32] {
    let mut t = Transcript::new("tie-seed");
    t.append("block", close_block_hash);
    t.append("log_root", log_root);
    t.digest32()
}

pub fn tie_rank(seed: &[u8; 32], p: &Point) -> [u8; 32] {
    let mut t = Transcript::new("tie-rank");
    t.append("seed", seed);
    t.append_point("P", p);
    t.digest32()
}

/// A decrypted per-ballot cell: ballot P said `yes` at `level`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CellReveal {
    pub p: Point,
    pub level: usize,
    pub yes: bool,
}

/// Pick winners from the revealed cells. Also checks that revealed cells
/// are consistent with the decrypted totals, so a committee that lies about
/// a cell is caught even if its shares were valid for a different target.
pub fn select_winners(
    search: &Search,
    levels: usize,
    supply: u64,
    ballot_keys: &[Point],
    reveals: &[CellReveal],
    seed: &[u8; 32],
) -> Result<Vec<Point>, Error> {
    let k = search.k_star;
    if k == 0 {
        return Ok(ballot_keys.to_vec());
    }
    let needed = cells_to_reveal(search, levels, supply);
    let mut cells: BTreeMap<([u8; 32], usize), bool> = BTreeMap::new();
    for r in reveals {
        cells.insert((r.p.to_bytes(), r.level), r.yes);
    }
    let cell = |p: &Point, lvl: usize| -> Result<bool, Error> {
        if lvl == levels + 1 {
            return Ok(false);
        }
        cells
            .get(&(p.to_bytes(), lvl))
            .copied()
            .ok_or(Error::InvalidParams("missing cell reveal"))
    };

    let (mut outright, mut bracket) = (Vec::new(), Vec::new());
    let next = if needed.len() == 2 { k + 1 } else { levels + 1 };
    for p in ballot_keys {
        let yes_k = cell(p, k)?;
        let yes_next = cell(p, next)?;
        if yes_next && !yes_k {
            return Err(Error::InvalidParams("revealed cells not monotone"));
        }
        if yes_next {
            outright.push(*p);
        } else if yes_k {
            bracket.push(*p);
        }
    }

    let t_k = search.total(k, levels).expect("T_k* is known when k* >= 1");
    if (outright.len() + bracket.len()) as u64 != t_k {
        return Err(Error::InvalidParams("reveals disagree with T_k*"));
    }
    if needed.len() == 2 && Some(outright.len() as u64) != search.total(k + 1, levels) {
        return Err(Error::InvalidParams("reveals disagree with T_k*+1"));
    }
    if t_k == supply {
        outright.append(&mut bracket);
        return Ok(outright);
    }

    let slots = (supply as usize).saturating_sub(outright.len());
    bracket.sort_by_key(|p| tie_rank(seed, p));
    outright.extend(bracket.into_iter().take(slots));
    Ok(outright)
}
