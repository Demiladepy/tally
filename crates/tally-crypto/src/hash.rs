//! Domain-separated BLAKE2b transcripts.
//!
//! Every hash starts from the tag `tally/v1/<purpose>`, and every appended
//! item is length-prefixed and labelled, so no two different transcripts
//! can produce the same byte stream.

use blake2b_simd::{Params, State};
use pasta_curves::group::ff::{FromUniformBytes, PrimeField};
use pasta_curves::group::GroupEncoding;

use crate::{Point, Scalar};

#[derive(Clone)]
pub struct Transcript {
    state: State,
}

impl Transcript {
    pub fn new(purpose: &str) -> Self {
        let mut t = Self {
            state: Params::new().hash_length(64).to_state(),
        };
        t.append("domain", format!("tally/v1/{purpose}").as_bytes());
        t
    }

    pub fn append(&mut self, label: &str, data: &[u8]) {
        self.state.update(&(label.len() as u64).to_le_bytes());
        self.state.update(label.as_bytes());
        self.state.update(&(data.len() as u64).to_le_bytes());
        self.state.update(data);
    }

    pub fn append_point(&mut self, label: &str, p: &Point) {
        self.append(label, &p.to_bytes());
    }

    pub fn append_scalar(&mut self, label: &str, s: &Scalar) {
        self.append(label, &s.to_repr());
    }

    pub fn append_u64(&mut self, label: &str, v: u64) {
        self.append(label, &v.to_le_bytes());
    }

    /// Fiat–Shamir challenge: the 64-byte digest reduced to a scalar.
    pub fn challenge(&self) -> Scalar {
        let digest = self.state.clone().finalize();
        let mut wide = [0u8; 64];
        wide.copy_from_slice(digest.as_bytes());
        Scalar::from_uniform_bytes(&wide)
    }

    /// A 32-byte identifier (ballot hash, log entry hash, seeds).
    pub fn digest32(&self) -> [u8; 32] {
        let digest = self.state.clone().finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest.as_bytes()[..32]);
        out
    }
}
