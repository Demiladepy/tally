//! Sigma protocols, made non-interactive with Fiat–Shamir.
//!
//! * [`Dleq`]: Chaum–Pedersen proof that log_{G1} X = log_{G2} Y.
//! * [`BitProof`]: CDS disjunction that a ciphertext encrypts 0 or 1.
//!
//! Callers pass a context transcript that already binds everything the
//! proof must not be replayable outside of (auction, ballot key, index).

use pasta_curves::group::ff::Field;
use pasta_curves::group::Group;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::elgamal::Ciphertext;
use crate::hash::Transcript;
use crate::{codec, g, random_scalar, Point, Scalar};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dleq {
    #[serde(with = "codec::scalar")]
    pub c: Scalar,
    #[serde(with = "codec::scalar")]
    pub z: Scalar,
}

fn dleq_challenge(
    mut t: Transcript,
    g1: &Point,
    x: &Point,
    g2: &Point,
    y: &Point,
    t1: &Point,
    t2: &Point,
) -> Scalar {
    t.append("proof", b"dleq");
    t.append_point("g1", g1);
    t.append_point("x", x);
    t.append_point("g2", g2);
    t.append_point("y", y);
    t.append_point("t1", t1);
    t.append_point("t2", t2);
    t.challenge()
}

impl Dleq {
    /// Prove knowledge of `w` with X = w·G1 and Y = w·G2.
    pub fn prove<R: RngCore + CryptoRng>(
        ctx: &Transcript,
        g1: &Point,
        x: &Point,
        g2: &Point,
        y: &Point,
        witness: &Scalar,
        rng: &mut R,
    ) -> Self {
        let k = random_scalar(rng);
        let (t1, t2) = (g1 * k, g2 * k);
        let c = dleq_challenge(ctx.clone(), g1, x, g2, y, &t1, &t2);
        Self { c, z: k + c * witness }
    }

    pub fn verify(&self, ctx: &Transcript, g1: &Point, x: &Point, g2: &Point, y: &Point) -> bool {
        let t1 = g1 * self.z - x * self.c;
        let t2 = g2 * self.z - y * self.c;
        dleq_challenge(ctx.clone(), g1, x, g2, y, &t1, &t2) == self.c
    }
}

/// Proof that `ct` under key `h` encrypts 0 or 1. Branch j claims
/// log_G A = log_H (B − j·G).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitProof {
    #[serde(with = "codec::scalar")]
    pub c0: Scalar,
    #[serde(with = "codec::scalar")]
    pub c1: Scalar,
    #[serde(with = "codec::scalar")]
    pub z0: Scalar,
    #[serde(with = "codec::scalar")]
    pub z1: Scalar,
}

fn bit_challenge(mut t: Transcript, h: &Point, ct: &Ciphertext, commits: &[(Point, Point); 2]) -> Scalar {
    t.append("proof", b"bit");
    t.append_point("h", h);
    ct.append_to(&mut t, "ct");
    for (a, b) in commits {
        t.append_point("ta", a);
        t.append_point("tb", b);
    }
    t.challenge()
}

impl BitProof {
    /// `bit` is the branch the prover claims. If the ciphertext does not
    /// really encrypt `bit` with randomness `r`, the proof will not verify.
    pub fn prove<R: RngCore + CryptoRng>(
        ctx: &Transcript,
        h: &Point,
        ct: &Ciphertext,
        bit: bool,
        r: &Scalar,
        rng: &mut R,
    ) -> Self {
        let ys = [ct.b, ct.b - g()];
        let real = bit as usize;
        let sim = 1 - real;

        let w = random_scalar(rng);
        let c_sim = random_scalar(rng);
        let z_sim = random_scalar(rng);

        let mut commits = [(Point::identity(), Point::identity()); 2];
        commits[real] = (g() * w, h * w);
        commits[sim] = (g() * z_sim - ct.a * c_sim, h * z_sim - ys[sim] * c_sim);

        let c = bit_challenge(ctx.clone(), h, ct, &commits);
        let c_real = c - c_sim;
        let z_real = w + c_real * r;

        let (mut cs, mut zs) = ([Scalar::ZERO; 2], [Scalar::ZERO; 2]);
        cs[real] = c_real;
        zs[real] = z_real;
        cs[sim] = c_sim;
        zs[sim] = z_sim;
        Self { c0: cs[0], c1: cs[1], z0: zs[0], z1: zs[1] }
    }

    pub fn verify(&self, ctx: &Transcript, h: &Point, ct: &Ciphertext) -> bool {
        let ys = [ct.b, ct.b - g()];
        let cs = [self.c0, self.c1];
        let zs = [self.z0, self.z1];
        let mut commits = [(Point::identity(), Point::identity()); 2];
        for j in 0..2 {
            commits[j] = (g() * zs[j] - ct.a * cs[j], h * zs[j] - ys[j] * cs[j]);
        }
        bit_challenge(ctx.clone(), h, ct, &commits) == self.c0 + self.c1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn setup() -> (ChaCha20Rng, Point, Transcript) {
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        let h = g() * random_scalar(&mut rng);
        (rng, h, Transcript::new("test"))
    }

    #[test]
    fn bit_proof_accepts_0_and_1() {
        let (mut rng, h, ctx) = setup();
        for m in [0u64, 1] {
            let r = random_scalar(&mut rng);
            let ct = Ciphertext::encrypt(&h, m, &r);
            let p = BitProof::prove(&ctx, &h, &ct, m == 1, &r, &mut rng);
            assert!(p.verify(&ctx, &h, &ct));
        }
    }

    #[test]
    fn bit_proof_rejects_2_and_wrong_context() {
        let (mut rng, h, ctx) = setup();
        let r = random_scalar(&mut rng);
        let ct = Ciphertext::encrypt(&h, 2, &r);
        for claim in [false, true] {
            let p = BitProof::prove(&ctx, &h, &ct, claim, &r, &mut rng);
            assert!(!p.verify(&ctx, &h, &ct));
        }
        let ct1 = Ciphertext::encrypt(&h, 1, &r);
        let p = BitProof::prove(&ctx, &h, &ct1, true, &r, &mut rng);
        assert!(!p.verify(&Transcript::new("other"), &h, &ct1));
    }

    #[test]
    fn dleq_roundtrip() {
        let (mut rng, _, ctx) = setup();
        let w = random_scalar(&mut rng);
        let g2 = g() * random_scalar(&mut rng);
        let (x, y) = (g() * w, g2 * w);
        let p = Dleq::prove(&ctx, &g(), &x, &g2, &y, &w, &mut rng);
        assert!(p.verify(&ctx, &g(), &x, &g2, &y));
        assert!(!p.verify(&ctx, &g(), &x, &g2, &(y + g())));
    }
}
