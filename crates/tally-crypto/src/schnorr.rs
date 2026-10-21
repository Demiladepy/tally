//! Schnorr signatures on Pallas, used for ballot keys (P = b·G) and to
//! claim a win at settlement.

use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::hash::Transcript;
use crate::{codec, g, random_scalar, Point, Scalar};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    #[serde(rename = "R", with = "codec::point")]
    pub r: Point,
    #[serde(with = "codec::scalar")]
    pub s: Scalar,
}

fn challenge(purpose: &str, r: &Point, pk: &Point, msg: &[u8]) -> Scalar {
    let mut t = Transcript::new(purpose);
    t.append_point("R", r);
    t.append_point("P", pk);
    t.append("msg", msg);
    t.challenge()
}

/// `purpose` separates ballot signatures from win claims, so one can never
/// be presented as the other.
pub fn sign<R: RngCore + CryptoRng>(purpose: &str, sk: &Scalar, msg: &[u8], rng: &mut R) -> Signature {
    let pk = g() * sk;
    let k = random_scalar(rng);
    let r = g() * k;
    let e = challenge(purpose, &r, &pk, msg);
    Signature { r, s: k + e * sk }
}

pub fn verify(purpose: &str, pk: &Point, msg: &[u8], sig: &Signature) -> bool {
    let e = challenge(purpose, &sig.r, pk, msg);
    g() * sig.s == sig.r + pk * e
}
