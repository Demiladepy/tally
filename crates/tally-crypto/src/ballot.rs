//! Sealed price-ladder ballots.
//!
//! A bidder whose maximum is level `k` encrypts y_i = 1 for i ≤ k and
//! y_i = 0 above. Proofs show each cell is a bit, each adjacent difference
//! is a bit (so the vector is monotone), and the first cell is 1 (so the
//! ballot is not empty). The ballot key P = b·G is the anonymous ballot ID.

use pasta_curves::group::ff::Field;
use pasta_curves::group::Group;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::elgamal::Ciphertext;
use crate::hash::Transcript;
use crate::proofs::{BitProof, Dleq};
use crate::schnorr::{self, Signature};
use crate::{codec, g, random_scalar, Error, Point, Scalar};

pub const VERSION: u8 = 1;
pub const SIG_PURPOSE: &str = "ballot-sig";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ballot {
    pub v: u8,
    #[serde(with = "codec::bytes32")]
    pub auction_id: [u8; 32],
    #[serde(rename = "P", with = "codec::point")]
    pub p: Point,
    pub c: Vec<Ciphertext>,
    pub proof_bits: Vec<BitProof>,
    pub proof_monotone: Vec<BitProof>,
    pub proof_first_one: Dleq,
    pub sig: Signature,
}

/// The transcript every proof in a ballot is bound to.
fn base_transcript(auction_id: &[u8; 32], h: &Point, p: &Point, c: &[Ciphertext]) -> Transcript {
    let mut t = Transcript::new("ballot");
    t.append("auction_id", auction_id);
    t.append_point("H", h);
    t.append_point("P", p);
    t.append_u64("L", c.len() as u64);
    for ct in c {
        ct.append_to(&mut t, "c");
    }
    t
}

fn proof_ctx(base: &Transcript, kind: &[u8], i: usize) -> Transcript {
    let mut t = base.clone();
    t.append("kind", kind);
    t.append_u64("i", i as u64);
    t
}

impl Ballot {
    /// Build a ballot with `yes_levels` ones followed by zeros.
    /// Returns the ballot and its secret key b (keep it to claim a win).
    pub fn build<R: RngCore + CryptoRng>(
        auction_id: [u8; 32],
        h: &Point,
        levels: usize,
        yes_levels: usize,
        rng: &mut R,
    ) -> Result<(Self, Scalar), Error> {
        if levels == 0 || yes_levels == 0 || yes_levels > levels {
            return Err(Error::InvalidParams("yes_levels must be in 1..=levels"));
        }
        let values: Vec<u64> = (0..levels).map(|i| (i < yes_levels) as u64).collect();
        Ok(Self::build_from_values(auction_id, h, &values, rng))
    }

    /// Build from arbitrary cell values. Honest callers use [`Ballot::build`];
    /// this exists so tests can construct adversarial ballots, whose proofs
    /// are generated as if every claim were true and must fail to verify.
    #[doc(hidden)]
    pub fn build_from_values<R: RngCore + CryptoRng>(
        auction_id: [u8; 32],
        h: &Point,
        values: &[u64],
        rng: &mut R,
    ) -> (Self, Scalar) {
        let b = random_scalar(rng);
        let p = g() * b;
        let rs: Vec<Scalar> = values.iter().map(|_| random_scalar(rng)).collect();
        let c: Vec<Ciphertext> = values
            .iter()
            .zip(&rs)
            .map(|(m, r)| Ciphertext::encrypt(h, *m, r))
            .collect();
        let base = base_transcript(&auction_id, h, &p, &c);

        let proof_bits = (0..c.len())
            .map(|i| BitProof::prove(&proof_ctx(&base, b"bit", i), h, &c[i], values[i] != 0, &rs[i], rng))
            .collect();
        let proof_monotone = (0..c.len().saturating_sub(1))
            .map(|i| {
                let diff = c[i] - c[i + 1];
                let claim = values[i] != values[i + 1];
                BitProof::prove(&proof_ctx(&base, b"mono", i), h, &diff, claim, &(rs[i] - rs[i + 1]), rng)
            })
            .collect();
        let proof_first_one = Dleq::prove(
            &proof_ctx(&base, b"first", 0),
            &g(),
            &c[0].a,
            h,
            &(c[0].b - g()),
            &rs[0],
            rng,
        );

        let mut ballot = Self {
            v: VERSION,
            auction_id,
            p,
            c,
            proof_bits,
            proof_monotone,
            proof_first_one,
            sig: Signature { r: Point::identity(), s: Scalar::ZERO },
        };
        ballot.sig = schnorr::sign(SIG_PURPOSE, &b, &ballot.body_hash(), rng);
        (ballot, b)
    }

    /// Hash of everything except the signature. This is H(ballot): it goes
    /// in the bond memo and the bulletin log, and the signature covers it.
    pub fn body_hash(&self) -> [u8; 32] {
        let mut t = Transcript::new("ballot-hash");
        t.append("v", &[self.v]);
        t.append("auction_id", &self.auction_id);
        t.append_point("P", &self.p);
        t.append_u64("L", self.c.len() as u64);
        for ct in &self.c {
            ct.append_to(&mut t, "c");
        }
        for (label, proofs) in [("bits", &self.proof_bits), ("mono", &self.proof_monotone)] {
            t.append_u64(label, proofs.len() as u64);
            for p in proofs {
                for s in [p.c0, p.c1, p.z0, p.z1] {
                    t.append_scalar("s", &s);
                }
            }
        }
        t.append_scalar("first.c", &self.proof_first_one.c);
        t.append_scalar("first.z", &self.proof_first_one.z);
        t.digest32()
    }

    /// Full public validity check. Error messages name the failed check only.
    pub fn verify(&self, auction_id: &[u8; 32], h: &Point, levels: usize) -> Result<(), Error> {
        if self.v != VERSION {
            return Err(Error::BadBallot("version"));
        }
        if &self.auction_id != auction_id {
            return Err(Error::BadBallot("auction_id"));
        }
        if bool::from(self.p.is_identity()) {
            return Err(Error::BadBallot("ballot key"));
        }
        if levels == 0
            || self.c.len() != levels
            || self.proof_bits.len() != levels
            || self.proof_monotone.len() != levels - 1
        {
            return Err(Error::BadBallot("shape"));
        }
        if !schnorr::verify(SIG_PURPOSE, &self.p, &self.body_hash(), &self.sig) {
            return Err(Error::BadBallot("signature"));
        }
        let base = base_transcript(&self.auction_id, h, &self.p, &self.c);
        for (i, proof) in self.proof_bits.iter().enumerate() {
            if !proof.verify(&proof_ctx(&base, b"bit", i), h, &self.c[i]) {
                return Err(Error::BadBallot("bit proof"));
            }
        }
        for (i, proof) in self.proof_monotone.iter().enumerate() {
            let diff = self.c[i] - self.c[i + 1];
            if !proof.verify(&proof_ctx(&base, b"mono", i), h, &diff) {
                return Err(Error::BadBallot("monotone proof"));
            }
        }
        let c0 = &self.c[0];
        if !self
            .proof_first_one
            .verify(&proof_ctx(&base, b"first", 0), &g(), &c0.a, h, &(c0.b - g()))
        {
            return Err(Error::BadBallot("first-one proof"));
        }
        Ok(())
    }
}

/// Sign a claim that the holder of ballot key P wants to settle `msg`
/// (e.g. the settlement PCZT digest). Domain-separated from ballot sigs.
pub fn sign_claim<R: RngCore + CryptoRng>(b: &Scalar, msg: &[u8], rng: &mut R) -> Signature {
    schnorr::sign("win-claim", b, msg, rng)
}

pub fn verify_claim(p: &Point, msg: &[u8], sig: &Signature) -> bool {
    schnorr::verify("win-claim", p, msg, sig)
}
