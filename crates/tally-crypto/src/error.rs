use thiserror::Error;

/// Errors never carry bid values, keys or addresses: only what failed.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    #[error("invalid point encoding")]
    InvalidPoint,
    #[error("invalid scalar encoding")]
    InvalidScalar,
    #[error("invalid hex")]
    InvalidHex,
    #[error("invalid parameters: {0}")]
    InvalidParams(&'static str),
    #[error("ballot rejected: {0}")]
    BadBallot(&'static str),
    #[error("decryption share rejected for member {0}")]
    BadShare(u32),
    #[error("not enough valid decryption shares")]
    NotEnoughShares,
    #[error("plaintext out of range")]
    PlaintextOutOfRange,
    #[error("dealing from member {0} failed verification")]
    BadDealing(u32),
}
