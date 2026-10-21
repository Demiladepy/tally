//! Exponential ElGamal: Enc(m; r) = (r·G, m·G + r·H).
//! Componentwise addition of ciphertexts adds plaintexts.

use core::ops::{Add, Sub};

use pasta_curves::group::Group;
use serde::{Deserialize, Serialize};

use crate::hash::Transcript;
use crate::{codec, g, Point, Scalar};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ciphertext {
    #[serde(rename = "A", with = "codec::point")]
    pub a: Point,
    #[serde(rename = "B", with = "codec::point")]
    pub b: Point,
}

impl Ciphertext {
    pub fn encrypt(h: &Point, m: u64, r: &Scalar) -> Self {
        Self {
            a: g() * r,
            b: g() * Scalar::from(m) + h * r,
        }
    }

    /// Encryption of zero with zero randomness; the identity for `+`.
    pub fn identity() -> Self {
        Self {
            a: Point::identity(),
            b: Point::identity(),
        }
    }

    pub fn append_to(&self, t: &mut Transcript, label: &str) {
        t.append(label, b"ct");
        t.append_point("A", &self.a);
        t.append_point("B", &self.b);
    }
}

impl Add for Ciphertext {
    type Output = Self;
    fn add(self, o: Self) -> Self {
        Self {
            a: self.a + o.a,
            b: self.b + o.b,
        }
    }
}

impl Sub for Ciphertext {
    type Output = Self;
    fn sub(self, o: Self) -> Self {
        Self {
            a: self.a - o.a,
            b: self.b - o.b,
        }
    }
}
