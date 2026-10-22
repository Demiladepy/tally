//! Tally cryptography: threshold exponential ElGamal over Pallas, sigma
//! proofs (Fiat–Shamir over BLAKE2b), sealed price-ladder ballots,
//! Feldman DKG, verifiable threshold decryption and binary-search clearing.
//!
//! Nothing here touches the network or logs anything. Plaintext bids only
//! ever exist as the `max_level` argument to [`ballot::Ballot::build`].

pub mod ballot;
pub mod clearing;
pub mod codec;
pub mod dkg;
pub mod elgamal;
pub mod error;
pub mod hash;
pub mod log;
pub mod manifest;
pub mod proofs;
pub mod schnorr;
pub mod threshold;

pub use error::Error;
pub use pasta_curves::pallas::{Point, Scalar};

use pasta_curves::group::ff::FromUniformBytes;
use pasta_curves::group::Group;
use rand_core::{CryptoRng, RngCore};

/// The Pallas generator G.
pub fn g() -> Point {
    Point::generator()
}

/// A uniformly random scalar (64 bytes reduced mod q, so bias is negligible).
pub fn random_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> Scalar {
    let mut bytes = [0u8; 64];
    rng.fill_bytes(&mut bytes);
    Scalar::from_uniform_bytes(&bytes)
}
