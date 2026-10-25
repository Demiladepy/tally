//! The auction manifest the seller publishes and signs, the bulletin log's
//! entries and inclusion receipts, and the final result record.
//!
//! Everything here is public. Hashes use binary transcripts (see
//! PROTOCOL.md), never JSON canonicalization.

use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::dkg::CommitteeKey;
use crate::hash::Transcript;
use crate::schnorr::{self, Signature};
use crate::{codec, Error, Point, Scalar};

pub const MANIFEST_PURPOSE: &str = "manifest-sig";
pub const ENDORSE_PURPOSE: &str = "manifest-endorse";

/// v1: the first testnet auction. Kept verifiable, never accepted for new
/// auctions. v2: the auction id IS the hash of the manifest's contents, every
/// committee member endorses it with its key share, and `min_batch` has a floor.
pub const MANIFEST_V1: u8 = 1;
pub const MANIFEST_V2: u8 = 2;
/// Smallest allowed batch in v2. Below this, a handful of opened totals and
/// cells says too much about individual ballots.
pub const MIN_BATCH_FLOOR: u64 = 5;
pub const RECEIPT_PURPOSE: &str = "receipt-sig";
pub const CLOSE_PURPOSE: &str = "close-sig";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Committee {
    #[serde(flatten)]
    pub key: CommitteeKey,
    pub members: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub v: u8,
    #[serde(with = "codec::bytes32")]
    pub auction_id: [u8; 32],
    #[serde(with = "codec::bytes32")]
    pub collection_id: [u8; 32],
    pub supply: u64,
    pub ladder_zat: Vec<u64>,
    pub bond_zat: u64,
    pub open_height: u32,
    pub close_height: u32,
    pub settle_window_blocks: u32,
    pub min_batch: u64,
    pub committee: Committee,
    /// Where bonds are paid. A one-time address for this auction only.
    pub escrow_ua: String,
    /// Where forfeited bonds go. Never the seller.
    pub forfeit_ua: String,
    #[serde(with = "codec::point")]
    pub seller_pk: Point,
    pub sig: Signature,
    /// v2: one signature per committee member, by its key share x_j over
    /// `body_hash`, so a seller can't name a committee that never agreed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endorsements: Vec<Endorsement>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endorsement {
    pub j: u32,
    pub sig: Signature,
}

impl Manifest {
    /// Hash of everything except the id and the signatures. In v2 the auction
    /// id is this hash, so a link that names the id pins the committee key,
    /// escrow, ladder and members: nobody can serve a different manifest
    /// under the same id.
    pub fn content_hash(&self) -> [u8; 32] {
        let mut m = self.clone();
        m.auction_id = [0; 32];
        let mut t = Transcript::new("manifest-content");
        t.append("body", &m.body_hash());
        t.digest32()
    }

    /// Set the auction id to the content hash (v2). Do this before signing.
    pub fn bind_id(&mut self) {
        self.auction_id = self.content_hash();
    }

    /// Member j's endorsement with its DKG key share.
    pub fn endorse<R: RngCore + CryptoRng>(&self, j: u32, x_j: &Scalar, rng: &mut R) -> Endorsement {
        Endorsement { j, sig: schnorr::sign(ENDORSE_PURPOSE, x_j, &self.body_hash(), rng) }
    }

    fn endorsed_by_all(&self) -> bool {
        let k = &self.committee.key;
        let msg = self.body_hash();
        (1..=k.n).all(|j| {
            let x = &k.x[j as usize - 1];
            self.endorsements.iter().any(|e| e.j == j && schnorr::verify(ENDORSE_PURPOSE, x, &msg, &e.sig))
        })
    }
    pub fn levels(&self) -> usize {
        self.ladder_zat.len()
    }

    pub fn body_hash(&self) -> [u8; 32] {
        let mut t = Transcript::new("manifest");
        t.append("v", &[self.v]);
        t.append("auction_id", &self.auction_id);
        t.append("collection_id", &self.collection_id);
        t.append_u64("supply", self.supply);
        t.append_u64("L", self.ladder_zat.len() as u64);
        for p in &self.ladder_zat {
            t.append_u64("p", *p);
        }
        t.append_u64("bond", self.bond_zat);
        t.append_u64("open", self.open_height as u64);
        t.append_u64("close", self.close_height as u64);
        t.append_u64("settle", self.settle_window_blocks as u64);
        t.append_u64("min_batch", self.min_batch);
        t.append_u64("n", self.committee.key.n as u64);
        t.append_u64("t", self.committee.key.t as u64);
        t.append_point("H", &self.committee.key.h);
        for x in &self.committee.key.x {
            t.append_point("X", x);
        }
        for m in &self.committee.members {
            t.append("member", m.as_bytes());
        }
        t.append("escrow", self.escrow_ua.as_bytes());
        t.append("forfeit", self.forfeit_ua.as_bytes());
        t.append_point("seller_pk", &self.seller_pk);
        t.digest32()
    }

    pub fn sign<R: RngCore + CryptoRng>(&mut self, seller_sk: &Scalar, rng: &mut R) {
        self.sig = schnorr::sign(MANIFEST_PURPOSE, seller_sk, &self.body_hash(), rng);
    }

    /// Structural and signature checks anyone can run.
    pub fn verify(&self) -> Result<(), Error> {
        self.check(true)
    }

    /// What a committee member checks before endorsing a v2 draft: everything
    /// except the endorsements themselves.
    pub fn verify_draft(&self) -> Result<(), Error> {
        if self.v < MANIFEST_V2 {
            return Err(Error::InvalidParams("legacy v1 manifest: not accepted for new auctions"));
        }
        self.check(false)
    }

    fn check(&self, endorsements: bool) -> Result<(), Error> {
        if self.v != MANIFEST_V1 && self.v != MANIFEST_V2 {
            return Err(Error::InvalidParams("manifest version"));
        }
        let l = &self.ladder_zat;
        if l.is_empty() || l.windows(2).any(|w| w[0] >= w[1]) {
            return Err(Error::InvalidParams("ladder must be strictly increasing"));
        }
        if self.supply == 0 || self.min_batch == 0 || self.close_height <= self.open_height {
            return Err(Error::InvalidParams("supply, min_batch or heights"));
        }
        let k = &self.committee.key;
        if k.t == 0 || k.t > k.n || k.x.len() != k.n as usize || self.committee.members.len() != k.n as usize {
            return Err(Error::InvalidParams("committee shape"));
        }
        if self.escrow_ua == self.forfeit_ua {
            return Err(Error::InvalidParams("escrow and forfeit addresses must differ"));
        }
        if !schnorr::verify(MANIFEST_PURPOSE, &self.seller_pk, &self.body_hash(), &self.sig) {
            return Err(Error::InvalidParams("manifest signature"));
        }
        if self.v >= MANIFEST_V2 {
            if self.auction_id != self.content_hash() {
                return Err(Error::InvalidParams("auction id is not the manifest's content hash"));
            }
            if self.min_batch < MIN_BATCH_FLOOR {
                return Err(Error::InvalidParams("min_batch below the protocol floor"));
            }
            if endorsements && !self.endorsed_by_all() {
                return Err(Error::InvalidParams("not endorsed by every committee member"));
            }
        }
        Ok(())
    }

    /// Only v2 manifests may open new auctions or receive new ballots.
    pub fn verify_current(&self) -> Result<(), Error> {
        if self.v < MANIFEST_V2 {
            return Err(Error::InvalidParams("legacy v1 manifest: not accepted for new auctions"));
        }
        self.verify()
    }
}

/// A signed inclusion receipt. A bidder keeps it: if their ballot is missing
/// from the final log, the receipt proves the bulletin censored it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    #[serde(with = "codec::bytes32")]
    pub auction_id: [u8; 32],
    pub i: u64,
    #[serde(with = "codec::bytes32")]
    pub entry_hash: [u8; 32],
    pub sig: Signature,
}

fn receipt_msg(auction_id: &[u8; 32], i: u64, entry_hash: &[u8; 32]) -> [u8; 32] {
    let mut t = Transcript::new("receipt");
    t.append("auction_id", auction_id);
    t.append_u64("i", i);
    t.append("entry", entry_hash);
    t.digest32()
}

impl Receipt {
    pub fn issue<R: RngCore + CryptoRng>(
        bulletin_sk: &Scalar,
        auction_id: [u8; 32],
        i: u64,
        entry_hash: [u8; 32],
        rng: &mut R,
    ) -> Self {
        let sig = schnorr::sign(RECEIPT_PURPOSE, bulletin_sk, &receipt_msg(&auction_id, i, &entry_hash), rng);
        Self { auction_id, i, entry_hash, sig }
    }

    pub fn verify(&self, bulletin_pk: &Point) -> bool {
        schnorr::verify(RECEIPT_PURPOSE, bulletin_pk, &receipt_msg(&self.auction_id, self.i, &self.entry_hash), &self.sig)
    }
}

/// Seller's signed instruction to freeze the log at `root` after `count` entries.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Close {
    #[serde(with = "codec::bytes32")]
    pub auction_id: [u8; 32],
    pub count: u64,
    #[serde(with = "codec::bytes32")]
    pub root: [u8; 32],
    pub sig: Signature,
}

fn close_msg(auction_id: &[u8; 32], count: u64, root: &[u8; 32]) -> [u8; 32] {
    let mut t = Transcript::new("close");
    t.append("auction_id", auction_id);
    t.append_u64("count", count);
    t.append("root", root);
    t.digest32()
}

impl Close {
    pub fn sign<R: RngCore + CryptoRng>(seller_sk: &Scalar, auction_id: [u8; 32], count: u64, root: [u8; 32], rng: &mut R) -> Self {
        let sig = schnorr::sign(CLOSE_PURPOSE, seller_sk, &close_msg(&auction_id, count, &root), rng);
        Self { auction_id, count, root, sig }
    }

    pub fn verify(&self, seller_pk: &Point) -> bool {
        schnorr::verify(CLOSE_PURPOSE, seller_pk, &close_msg(&self.auction_id, self.count, &self.root), &self.sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{dkg, g, random_scalar};
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    pub fn sample(rng: &mut ChaCha20Rng) -> (Manifest, Scalar) {
        let dealings: Vec<_> = (1..=3).map(|i| dkg::deal(i, 3, 2, rng).unwrap()).collect();
        let key = dkg::committee_key(3, 2, &dealings.iter().map(|d| d.commitments.clone()).collect::<Vec<_>>()).unwrap();
        let xs: Vec<Scalar> = (1..=3u32)
            .map(|j| {
                let rec: Vec<_> = dealings.iter().map(|d| (d.dealer, d.commitments.as_slice(), d.shares[j as usize - 1])).collect();
                dkg::member_secret(j, &rec).unwrap()
            })
            .collect();
        let sk = random_scalar(rng);
        let mut m = Manifest {
            v: MANIFEST_V2,
            auction_id: [1; 32],
            collection_id: [2; 32],
            supply: 8,
            ladder_zat: (0..16).map(|i| 50_000_000 + i * 10_000_000).collect(),
            bond_zat: 1_000_000,
            open_height: 100,
            close_height: 200,
            settle_window_blocks: 100,
            min_batch: 5,
            committee: Committee { key, members: vec!["a".into(), "b".into(), "c".into()] },
            escrow_ua: "utest1escrow".into(),
            forfeit_ua: "utest1forfeit".into(),
            seller_pk: g() * sk,
            sig: Signature { r: g(), s: Scalar::from(0u64) },
            endorsements: vec![],
        };
        m.bind_id();
        m.sign(&sk, rng);
        m.endorsements = (1..=3u32).map(|j| m.endorse(j, &xs[j as usize - 1], rng)).collect();
        (m, sk)
    }

    #[test]
    fn manifest_sign_verify_and_tamper() {
        let mut rng = ChaCha20Rng::seed_from_u64(5);
        let (m, sk) = sample(&mut rng);
        assert_eq!(m.verify(), Ok(()));
        let json = serde_json::to_string(&m).unwrap();
        let back: Manifest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.verify(), Ok(()));
        let mut t = m.clone();
        t.supply = 9;
        assert!(t.verify().is_err());
        let mut t = m.clone();
        t.forfeit_ua = t.escrow_ua.clone();
        assert!(t.verify().is_err());

        // v2: swapping the committee key under the same id is caught even if
        // the attacker re-signs as "seller" with its own key.
        let mut rogue = m.clone();
        let mut r2 = ChaCha20Rng::seed_from_u64(99);
        rogue.committee.key.h = g() * random_scalar(&mut r2);
        let rogue_sk = random_scalar(&mut r2);
        rogue.seller_pk = g() * rogue_sk;
        rogue.sign(&rogue_sk, &mut r2);
        assert_eq!(rogue.verify(), Err(Error::InvalidParams("auction id is not the manifest's content hash")));
        // ...and re-binding the id gives a different id than the link names,
        // and still lacks the members' endorsements.
        rogue.bind_id();
        rogue.sign(&rogue_sk, &mut r2);
        assert_ne!(rogue.auction_id, m.auction_id);
        assert_eq!(rogue.verify(), Err(Error::InvalidParams("not endorsed by every committee member")));

        // Missing one member's endorsement fails.
        let mut two = m.clone();
        two.endorsements.pop();
        assert!(two.verify().is_err());
        // min_batch floor.
        let mut tiny = m.clone();
        tiny.min_batch = 2;
        assert!(tiny.verify().is_err());
        // Legacy v1 still verifies but is not "current".
        let mut legacy = m.clone();
        legacy.v = MANIFEST_V1;
        legacy.endorsements.clear();
        legacy.sign(&sk, &mut r2);
        assert_eq!(legacy.verify(), Ok(()));
        assert!(legacy.verify_current().is_err());
        assert_eq!(m.verify_current(), Ok(()));
        // A draft without endorsements passes the draft check only.
        let mut draft = m.clone();
        draft.endorsements.clear();
        assert_eq!(draft.verify_draft(), Ok(()));
        assert!(draft.verify().is_err());
        assert!(legacy.verify_draft().is_err());
    }

    #[test]
    fn receipt_and_close() {
        let mut rng = ChaCha20Rng::seed_from_u64(6);
        let sk = random_scalar(&mut rng);
        let r = Receipt::issue(&sk, [1; 32], 3, [9; 32], &mut rng);
        assert!(r.verify(&(g() * sk)));
        let mut bad = r.clone();
        bad.i = 4;
        assert!(!bad.verify(&(g() * sk)));
        let c = Close::sign(&sk, [1; 32], 10, [7; 32], &mut rng);
        assert!(c.verify(&(g() * sk)));
    }
}
