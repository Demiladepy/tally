//! The complete public record of one auction, and the checks anyone can run
//! on it. The bulletin serves this record; the committee coordinator uses
//! `next_targets` to drive clearing; the verify page runs `verify`.
//!
//! Bonds are shielded payments, so the public cannot see them. The bonded
//! set is attested instead: each committee member signs the list of bonded
//! log entries with its DKG key share x_j (checked against X_j), and at
//! least t signatures are required. That is the same quorum trust as
//! decryption, and THREAT_MODEL.md says so.

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};

use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::ballot::Ballot;
use crate::clearing::{self, CellReveal, Search};
use crate::dkg::CommitteeKey;
use crate::elgamal::Ciphertext;
use crate::hash::Transcript;
use crate::manifest::{Close, Manifest};
use crate::schnorr::{self, Signature};
use crate::threshold::{self, DecryptionRecord};
use crate::{codec, log, Error, Point, Scalar};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub i: u64,
    pub ballot: Ballot,
    #[serde(with = "codec::bytes32")]
    pub prev_hash: [u8; 32],
    #[serde(with = "codec::bytes32")]
    pub entry_hash: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberSig {
    pub j: u32,
    pub sig: Signature,
}

/// The committee's statement of which log entries are backed by a bond.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BondAttestation {
    #[serde(with = "codec::bytes32")]
    pub auction_id: [u8; 32],
    #[serde(with = "codec::bytes32")]
    pub root: [u8; 32],
    /// Entry indices, strictly increasing.
    pub bonded: Vec<u64>,
    pub sigs: Vec<MemberSig>,
}

const BONDS_PURPOSE: &str = "bonds-attest";

impl BondAttestation {
    pub fn msg(auction_id: &[u8; 32], root: &[u8; 32], bonded: &[u64]) -> [u8; 32] {
        let mut t = Transcript::new("bonds");
        t.append("auction_id", auction_id);
        t.append("root", root);
        t.append_u64("count", bonded.len() as u64);
        for i in bonded {
            t.append_u64("i", *i);
        }
        t.digest32()
    }

    /// Member j's signature with its key share x_j.
    pub fn sign_member<R: RngCore + CryptoRng>(
        auction_id: &[u8; 32],
        root: &[u8; 32],
        bonded: &[u64],
        j: u32,
        x_j: &Scalar,
        rng: &mut R,
    ) -> MemberSig {
        MemberSig { j, sig: schnorr::sign(BONDS_PURPOSE, x_j, &Self::msg(auction_id, root, bonded), rng) }
    }

    pub fn verify(&self, key: &CommitteeKey) -> bool {
        if self.bonded.windows(2).any(|w| w[0] >= w[1]) {
            return false;
        }
        let msg = Self::msg(&self.auction_id, &self.root, &self.bonded);
        let mut ok = BTreeSet::new();
        for s in &self.sigs {
            let Some(x) = (s.j as usize).checked_sub(1).and_then(|i| key.x.get(i)) else { continue };
            if schnorr::verify(BONDS_PURPOSE, x, &msg, &s.sig) {
                ok.insert(s.j);
            }
        }
        ok.len() >= key.t as usize
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    /// Fewer bonded ballots than `min_batch`: nothing is decrypted, all bonds refunded.
    Void,
    /// T_1 < supply: every bonded ballot wins at p_1.
    Undersubscribed,
    Cleared,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuctionResult {
    #[serde(with = "codec::bytes32")]
    pub auction_id: [u8; 32],
    pub outcome: Outcome,
    pub k_star: usize,
    pub price_zat: Option<u64>,
    /// Exactly the totals that were decrypted, by level.
    pub totals: BTreeMap<usize, u64>,
    #[serde(with = "codec::bytes32")]
    pub close_block_hash: [u8; 32],
    #[serde(with = "codec::bytes32")]
    pub seed: [u8; 32],
    #[serde(with = "codec::points")]
    pub winners: Vec<Point>,
}

/// A winner's settlement, signed by the seller once broadcast.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Settlement {
    #[serde(rename = "P", with = "codec::point")]
    pub p: Point,
    pub txid: String,
    pub sig: Signature,
}

const SETTLE_PURPOSE: &str = "settlement";

impl Settlement {
    fn msg(auction_id: &[u8; 32], p: &Point, txid: &str) -> [u8; 32] {
        let mut t = Transcript::new("settlement");
        t.append("auction_id", auction_id);
        t.append_point("P", p);
        t.append("txid", txid.as_bytes());
        t.digest32()
    }

    pub fn sign<R: RngCore + CryptoRng>(seller_sk: &Scalar, auction_id: &[u8; 32], p: Point, txid: String, rng: &mut R) -> Self {
        let sig = schnorr::sign(SETTLE_PURPOSE, seller_sk, &Self::msg(auction_id, &p, &txid), rng);
        Self { p, txid, sig }
    }

    pub fn verify(&self, auction_id: &[u8; 32], seller_pk: &Point) -> bool {
        schnorr::verify(SETTLE_PURPOSE, seller_pk, &Self::msg(auction_id, &self.p, &self.txid), &self.sig)
    }
}

/// The whole public record of one auction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuctionLog {
    pub manifest: Manifest,
    #[serde(with = "codec::point")]
    pub bulletin_pk: Point,
    pub entries: Vec<Entry>,
    #[serde(default)]
    pub close: Option<Close>,
    #[serde(default)]
    pub bonds: Option<BondAttestation>,
    #[serde(default)]
    pub decryptions: Vec<DecryptionRecord>,
    #[serde(default)]
    pub result: Option<AuctionResult>,
    #[serde(default)]
    pub settlements: Vec<Settlement>,
}

pub fn total_target(k: usize) -> String {
    format!("T_{k}")
}

pub fn cell_target(p: &Point, k: usize) -> String {
    format!("ballot:{}:{k}", codec::point_to_hex(p))
}

impl AuctionLog {
    pub fn head(&self) -> [u8; 32] {
        self.entries
            .last()
            .map(|e| e.entry_hash)
            .unwrap_or_else(|| log::genesis(&self.manifest.auction_id))
    }

    /// Winners with no seller-signed settlement. After the settle window
    /// these bonds are forfeited (to `forfeit_ua`, never the seller).
    pub fn unsettled_winners(&self) -> Vec<Point> {
        match &self.result {
            Some(r) => r.winners.iter().filter(|p| !self.settlements.iter().any(|s| &s.p == *p)).copied().collect(),
            None => vec![],
        }
    }

    /// First height at which unsettled winners may be forfeited.
    pub fn forfeit_height(&self) -> u32 {
        self.manifest.close_height.saturating_add(self.manifest.settle_window_blocks)
    }

    /// Ballots in the attested bonded set (empty before attestation).
    pub fn bonded(&self) -> Vec<&Ballot> {
        let Some(b) = &self.bonds else { return vec![] };
        b.bonded
            .iter()
            .filter_map(|i| self.entries.get(*i as usize))
            .map(|e| &e.ballot)
            .collect()
    }

    pub fn is_void(&self) -> bool {
        (self.bonded().len() as u64) < self.manifest.min_batch
    }

    /// The ciphertext a decryption target names, recomputed from the log.
    /// Only bonded ballots count, for totals and for cells.
    pub fn target_ciphertext(&self, target: &str) -> Option<Ciphertext> {
        let levels = self.manifest.levels();
        let bonded = self.bonded();
        let level = |k: &str| k.parse::<usize>().ok().filter(|k| *k >= 1 && *k <= levels);
        if let Some(k) = target.strip_prefix("T_") {
            let k = level(k)?;
            let owned: Vec<Ballot> = bonded.into_iter().cloned().collect();
            return Some(clearing::tally(&owned, levels)[k - 1]);
        }
        let (p_hex, k) = target.strip_prefix("ballot:")?.rsplit_once(':')?;
        let k = level(k)?;
        bonded.iter().find(|b| codec::point_to_hex(&b.p) == p_hex).map(|b| b.c[k - 1])
    }

    fn record(&self, target: &str) -> Option<&DecryptionRecord> {
        self.decryptions.iter().find(|d| d.target == target)
    }

    /// Replay the binary search against published totals. `Ok(None)` means
    /// a total is still missing; the missing level is returned in `.1`.
    fn replay_search(&self) -> Result<(Option<Search>, Option<usize>), Error> {
        let missing = Cell::new(None);
        // v2: T_1 is the public bonded count, never decrypted.
        let public_t1 = (self.manifest.v >= crate::manifest::MANIFEST_V2).then(|| self.bonded().len() as u64);
        let r = clearing::binary_search(self.manifest.levels(), self.manifest.supply, public_t1, |k| {
            match self.record(&total_target(k)) {
                Some(rec) => Ok(rec.m),
                None => {
                    missing.set(Some(k));
                    Err(Error::InvalidParams("missing total"))
                }
            }
        });
        match (r, missing.get()) {
            (Ok(s), _) => Ok((Some(s), None)),
            (Err(_), Some(k)) => Ok((None, Some(k))),
            (Err(e), None) => Err(e),
        }
    }

    fn needed_cells(&self, search: &Search) -> Vec<String> {
        let levels = clearing::cells_to_reveal(search, self.manifest.levels(), self.manifest.supply);
        self.bonded()
            .iter()
            .flat_map(|b| levels.iter().map(move |k| cell_target(&b.p, *k)))
            .collect()
    }

    /// What the committee must decrypt next (empty when clearing is complete).
    /// The search is adaptive, so this returns one total at a time, then all
    /// needed cells at once.
    pub fn next_targets(&self) -> Result<Vec<String>, Error> {
        if self.bonds.is_none() || self.is_void() {
            return Ok(vec![]);
        }
        match self.replay_search()? {
            (None, Some(k)) => Ok(vec![total_target(k)]),
            (Some(s), _) => Ok(self
                .needed_cells(&s)
                .into_iter()
                .filter(|t| self.record(t).is_none())
                .collect()),
            _ => Err(Error::InvalidParams("search state")),
        }
    }

    /// Compute the result from published records only. No secrets involved.
    pub fn compute_result(&self, close_block_hash: [u8; 32]) -> Result<AuctionResult, Error> {
        let m = &self.manifest;
        let seed = clearing::tie_seed(&close_block_hash, &self.head());
        let base = |outcome, k_star, price_zat, totals, winners| AuctionResult {
            auction_id: m.auction_id,
            outcome,
            k_star,
            price_zat,
            totals,
            close_block_hash,
            seed,
            winners,
        };
        if self.bonds.is_none() {
            return Err(Error::InvalidParams("no bond attestation"));
        }
        if self.is_void() {
            return Ok(base(Outcome::Void, 0, None, BTreeMap::new(), vec![]));
        }
        let (Some(search), None) = self.replay_search()? else {
            return Err(Error::InvalidParams("clearing incomplete"));
        };
        let keys: Vec<Point> = self.bonded().iter().map(|b| b.p).collect();
        let mut reveals = vec![];
        for t in self.needed_cells(&search) {
            let rec = self.record(&t).ok_or(Error::InvalidParams("clearing incomplete"))?;
            let (p_hex, k) = t.strip_prefix("ballot:").and_then(|r| r.rsplit_once(':')).expect("cell target");
            reveals.push(CellReveal {
                p: codec::point_from_hex(p_hex)?,
                level: k.parse().expect("level"),
                yes: rec.m == 1,
            });
        }
        let winners = clearing::select_winners(&search, m.levels(), m.supply, &keys, &reveals, &seed)?;
        let (outcome, price_level) = if search.k_star == 0 { (Outcome::Undersubscribed, 1) } else { (Outcome::Cleared, search.k_star) };
        Ok(base(outcome, search.k_star, Some(m.ladder_zat[price_level - 1]), search.totals.clone(), winners))
    }
}

/// Block hashes are shown byte-reversed, as explorers display them.
pub fn display_block_hash(internal: &[u8; 32]) -> String {
    let mut b = *internal;
    b.reverse();
    hex::encode(b)
}

/// One line on the verify page.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Check {
    pub name: String,
    pub ok: bool,
    pub detail: String,
}

fn check(out: &mut Vec<Check>, name: &str, ok: bool, detail: impl Into<String>) -> bool {
    out.push(Check { name: name.into(), ok, detail: detail.into() });
    ok
}

/// Every check in spec §4.7, from the public record alone.
pub fn verify(log: &AuctionLog) -> Vec<Check> {
    let mut out = vec![];
    let m = &log.manifest;

    let manifest_detail = if m.v >= crate::manifest::MANIFEST_V2 {
        format!(
            "v2: auction id is the manifest hash; seller signature; endorsed by all {} committee members; min batch {}",
            m.committee.key.n, m.min_batch
        )
    } else {
        "legacy v1: seller signature only (auction id not bound to the manifest, no member endorsements)".to_string()
    };
    check(&mut out, "Manifest signed by the seller", m.verify().is_ok(), manifest_detail);

    let mut prev = log::genesis(&m.auction_id);
    let mut chain_ok = true;
    for (i, e) in log.entries.iter().enumerate() {
        chain_ok &= e.i == i as u64 && e.prev_hash == prev && e.entry_hash == log::entry_hash(&prev, &e.ballot.body_hash());
        prev = e.entry_hash;
    }
    check(&mut out, "Bulletin hash chain", chain_ok, format!("{} entries", log.entries.len()));

    let mut seen = BTreeSet::new();
    let bad = log
        .entries
        .iter()
        .filter(|e| e.ballot.verify(&m.auction_id, &m.committee.key.h, m.levels()).is_err() || !seen.insert(codec::point_to_hex(&e.ballot.p)))
        .count();
    check(&mut out, "Every ballot's proofs and signature", bad == 0, format!("{} ballots, {bad} invalid or duplicate", log.entries.len()));

    let closed = match &log.close {
        Some(c) => c.verify(&m.seller_pk) && c.count == log.entries.len() as u64 && c.root == log.head(),
        None => false,
    };
    if !check(&mut out, "Log closed at the published root", closed, hex::encode(log.head())) {
        return out;
    }

    let bonds_ok = log
        .bonds
        .as_ref()
        .map(|b| b.auction_id == m.auction_id && b.root == log.head() && b.verify(&m.committee.key) && b.bonded.iter().all(|i| (*i as usize) < log.entries.len()))
        .unwrap_or(false);
    let bonded = log.bonded().len();
    if !check(&mut out, "Bonded set attested by a committee quorum", bonds_ok, format!("{bonded} of {} ballots bonded", log.entries.len())) {
        return out;
    }

    let void = log.is_void();
    check(&mut out, "Minimum batch", true, if void { format!("{bonded} < {}: auction void, nothing decrypted", m.min_batch) } else { format!("{bonded} ≥ {}", m.min_batch) });

    let bad_dec = log
        .decryptions
        .iter()
        .filter(|d| log.target_ciphertext(&d.target) != Some(d.ciphertext()) || !threshold::verify_record(&m.committee.key, d))
        .count();
    check(&mut out, "Every decryption share and DLEQ proof", bad_dec == 0, format!("{} records, {bad_dec} invalid", log.decryptions.len()));

    // Minimality: exactly the binary-search totals and exactly the needed cells.
    let published: BTreeSet<&str> = log.decryptions.iter().map(|d| d.target.as_str()).collect();
    let expected: BTreeSet<String> = if void {
        BTreeSet::new()
    } else {
        match log.replay_search() {
            Ok((Some(s), _)) => s.totals.keys().map(|k| total_target(*k)).chain(log.needed_cells(&s)).collect(),
            _ => {
                check(&mut out, "Binary-search path complete", false, "a needed total is missing");
                return out;
            }
        }
    };
    let extra: Vec<&&str> = published.iter().filter(|t| !expected.contains(**t)).collect();
    let missing = expected.iter().filter(|t| !published.contains(t.as_str())).count();
    let totals = published.iter().filter(|t| t.starts_with("T_")).count();
    check(
        &mut out,
        "Only the needed totals and cells were decrypted",
        extra.is_empty() && missing == 0,
        format!("{totals} of {} totals; {} extra, {missing} missing", m.levels(), extra.len()),
    );

    let Some(r) = &log.result else {
        check(&mut out, "Result published", false, "no result yet");
        return out;
    };
    let recomputed = log.compute_result(r.close_block_hash);
    check(
        &mut out,
        "Clearing price, winners and tie-break seed recompute exactly",
        recomputed.as_ref() == Ok(r),
        match r.price_zat {
            Some(p) => format!(
                "{:?} at level {} = {} zat, {} winners; tie-break seed uses block {} at height {} (check it on any explorer)",
                r.outcome,
                r.k_star.max(1),
                p,
                r.winners.len(),
                display_block_hash(&r.close_block_hash),
                m.close_height
            ),
            None => format!("{:?}", r.outcome),
        },
    );

    let winners: BTreeSet<String> = r.winners.iter().map(codec::point_to_hex).collect();
    let mut settled = BTreeSet::new();
    let bad_settle = log
        .settlements
        .iter()
        .filter(|s| !s.verify(&m.auction_id, &m.seller_pk) || !winners.contains(&codec::point_to_hex(&s.p)) || !settled.insert(codec::point_to_hex(&s.p)))
        .count();
    check(
        &mut out,
        "Settlements signed by the seller, one per winner",
        bad_settle == 0,
        format!("{} of {} winners settled", settled.len(), r.winners.len()),
    );
    out
}
