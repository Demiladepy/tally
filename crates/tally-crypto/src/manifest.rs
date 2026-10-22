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
}

impl Manifest {
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
        if self.v != 1 {
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
        Ok(())
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
        let sk = random_scalar(rng);
        let mut m = Manifest {
            v: 1,
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
        };
        m.sign(&sk, rng);
        (m, sk)
    }

    #[test]
    fn manifest_sign_verify_and_tamper() {
        let mut rng = ChaCha20Rng::seed_from_u64(5);
        let (m, _) = sample(&mut rng);
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
