//! Verifiable threshold decryption.
//!
//! Member j publishes D_j = x_j·A with a DLEQ proof that
//! log_G X_j = log_A D_j. Any t valid shares combine by Lagrange
//! interpolation to x·A, and M = B − x·A = m·G.

use std::collections::BTreeSet;

use pasta_curves::group::ff::Field;
use pasta_curves::group::Group;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::dkg::CommitteeKey;
use crate::elgamal::Ciphertext;
use crate::hash::Transcript;
use crate::proofs::Dleq;
use crate::{codec, g, Error, Point, Scalar};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecryptionShare {
    pub j: u32,
    #[serde(rename = "D_j", with = "codec::point")]
    pub d: Point,
    pub dleq: Dleq,
}

/// Published record of one decryption: what was opened, every share, and
/// the result. The verify page re-checks all of it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecryptionRecord {
    pub target: String,
    #[serde(rename = "A", with = "codec::point")]
    pub a: Point,
    #[serde(rename = "B", with = "codec::point")]
    pub b: Point,
    pub shares: Vec<DecryptionShare>,
    pub m: u64,
}

impl DecryptionRecord {
    pub fn ciphertext(&self) -> Ciphertext {
        Ciphertext { a: self.a, b: self.b }
    }
}

/// Targets name what is being decrypted ("T_5", "ballot:<P>:5") so a share
/// produced for one target can't be passed off as a share for another.
fn share_ctx(target: &str, ct: &Ciphertext) -> Transcript {
    let mut t = Transcript::new("decrypt-share");
    t.append("target", target.as_bytes());
    ct.append_to(&mut t, "ct");
    t
}

pub fn make_share<R: RngCore + CryptoRng>(
    target: &str,
    j: u32,
    x_j: &Scalar,
    ct: &Ciphertext,
    rng: &mut R,
) -> DecryptionShare {
    let d = ct.a * x_j;
    let dleq = Dleq::prove(&share_ctx(target, ct), &g(), &(g() * x_j), &ct.a, &d, x_j, rng);
    DecryptionShare { j, d, dleq }
}

pub fn verify_share(target: &str, key: &CommitteeKey, ct: &Ciphertext, share: &DecryptionShare) -> bool {
    let Some(x_j) = (share.j as usize).checked_sub(1).and_then(|i| key.x.get(i)) else {
        return false;
    };
    share.dleq.verify(&share_ctx(target, ct), &g(), x_j, &ct.a, &share.d)
}

/// λ_j for interpolating at 0 over the index set `js`.
pub fn lagrange_at_zero(js: &[u32], j: u32) -> Scalar {
    let xj = Scalar::from(j as u64);
    let (num, den) = js.iter().filter(|&&m| m != j).fold((Scalar::ONE, Scalar::ONE), |(n, d), &m| {
        let xm = Scalar::from(m as u64);
        (n * xm, d * (xm - xj))
    });
    num * den.invert().unwrap()
}

/// Combine valid shares into M = m·G. Invalid or duplicate shares are
/// ignored; fewer than t valid shares is an error.
pub fn combine(target: &str, key: &CommitteeKey, ct: &Ciphertext, shares: &[DecryptionShare]) -> Result<Point, Error> {
    let mut seen = BTreeSet::new();
    let valid: Vec<&DecryptionShare> = shares
        .iter()
        .filter(|s| verify_share(target, key, ct, s) && seen.insert(s.j))
        .take(key.t as usize)
        .collect();
    if valid.len() < key.t as usize {
        return Err(Error::NotEnoughShares);
    }
    let js: Vec<u32> = valid.iter().map(|s| s.j).collect();
    let xa = valid
        .iter()
        .fold(Point::identity(), |acc, s| acc + s.d * lagrange_at_zero(&js, s.j));
    Ok(ct.b - xa)
}

/// Recover m from m·G for m ≤ max by linear scan. m is a vote count, so
/// max is the number of ballots.
pub fn small_dlog(m_g: &Point, max: u64) -> Result<u64, Error> {
    let mut acc = Point::identity();
    for m in 0..=max {
        if acc == *m_g {
            return Ok(m);
        }
        acc += g();
    }
    Err(Error::PlaintextOutOfRange)
}

pub fn decrypt(
    target: &str,
    key: &CommitteeKey,
    ct: &Ciphertext,
    shares: Vec<DecryptionShare>,
    max: u64,
) -> Result<DecryptionRecord, Error> {
    let m = small_dlog(&combine(target, key, ct, &shares)?, max)?;
    Ok(DecryptionRecord { target: target.to_string(), a: ct.a, b: ct.b, shares, m })
}

/// Re-check a published record: at least t valid shares, and they combine
/// to exactly m·G.
pub fn verify_record(key: &CommitteeKey, record: &DecryptionRecord) -> bool {
    let ct = record.ciphertext();
    combine(&record.target, key, &ct, &record.shares)
        .map(|p| p == g() * Scalar::from(record.m))
        .unwrap_or(false)
}
