//! Feldman-VSS distributed key generation for an n-member, threshold-t
//! committee. Each member deals a degree t−1 polynomial; the joint secret
//! x = Σ_i f_i(0) is never held by anyone.
//!
//! Known limitation (documented in PROTOCOL.md): plain joint-Feldman lets a
//! rushing dealer bias the distribution of H (Gennaro et al. 1999). This is
//! accepted for ElGamal encryption keys in the demo; Pedersen-VSS commitments
//! would remove it.

use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use pasta_curves::group::ff::Field;
use pasta_curves::group::Group;

use crate::{codec, g, random_scalar, Error, Point, Scalar};

/// One member's dealing. `commitments` are public; `shares[j-1]` must be
/// sent privately to member j and never published.
pub struct Dealing {
    pub dealer: u32,
    pub commitments: Vec<Point>,
    pub shares: Vec<Scalar>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitteeKey {
    pub n: u32,
    pub t: u32,
    #[serde(rename = "H", with = "codec::point")]
    pub h: Point,
    #[serde(rename = "X", with = "codec::points")]
    pub x: Vec<Point>,
}

fn check_params(n: u32, t: u32) -> Result<(), Error> {
    if t == 0 || t > n {
        return Err(Error::InvalidParams("need 1 <= t <= n"));
    }
    Ok(())
}

pub fn deal<R: RngCore + CryptoRng>(dealer: u32, n: u32, t: u32, rng: &mut R) -> Result<Dealing, Error> {
    check_params(n, t)?;
    let coeffs: Vec<Scalar> = (0..t).map(|_| random_scalar(rng)).collect();
    let commitments = coeffs.iter().map(|a| g() * a).collect();
    let shares = (1..=n)
        .map(|j| {
            let x = Scalar::from(j as u64);
            coeffs.iter().rev().fold(Scalar::ZERO, |acc, a| acc * x + a)
        })
        .collect();
    Ok(Dealing { dealer, commitments, shares })
}

/// Σ_k C_k · j^k, i.e. f(j)·G computed from public commitments.
fn eval_commitments(commitments: &[Point], j: u32) -> Point {
    let x = Scalar::from(j as u64);
    commitments.iter().rev().fold(Point::identity(), |acc, c| acc * x + c)
}

pub fn verify_share(commitments: &[Point], j: u32, share: &Scalar) -> bool {
    g() * share == eval_commitments(commitments, j)
}

/// Public key H and per-member verification keys X_j from all dealings'
/// commitments. Anyone can compute this.
pub fn committee_key(n: u32, t: u32, all_commitments: &[Vec<Point>]) -> Result<CommitteeKey, Error> {
    check_params(n, t)?;
    if all_commitments.len() != n as usize || all_commitments.iter().any(|c| c.len() != t as usize) {
        return Err(Error::InvalidParams("need n dealings of t commitments"));
    }
    let h = all_commitments.iter().map(|c| c[0]).fold(Point::identity(), |a, b| a + b);
    let x = (1..=n)
        .map(|j| {
            all_commitments
                .iter()
                .map(|c| eval_commitments(c, j))
                .fold(Point::identity(), |a, b| a + b)
        })
        .collect();
    Ok(CommitteeKey { n, t, h, x })
}

/// Member j's secret share x_j, after checking every received share
/// against its dealer's commitments.
pub fn member_secret(j: u32, received: &[(u32, &[Point], Scalar)]) -> Result<Scalar, Error> {
    let mut x_j = Scalar::ZERO;
    for (dealer, commitments, share) in received {
        if !verify_share(commitments, j, share) {
            return Err(Error::BadDealing(*dealer));
        }
        x_j += share;
    }
    Ok(x_j)
}
