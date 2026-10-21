//! Hex encodings for points and scalars, and serde adapters.
//!
//! Points use the canonical 32-byte Pallas compressed encoding; decoding
//! rejects anything non-canonical or off-curve.

use pasta_curves::group::ff::PrimeField;
use pasta_curves::group::GroupEncoding;

use crate::{Error, Point, Scalar};

pub fn point_to_hex(p: &Point) -> String {
    hex::encode(p.to_bytes())
}

pub fn point_from_hex(s: &str) -> Result<Point, Error> {
    let bytes: [u8; 32] = hex::decode(s)
        .map_err(|_| Error::InvalidHex)?
        .try_into()
        .map_err(|_| Error::InvalidPoint)?;
    Option::from(Point::from_bytes(&bytes)).ok_or(Error::InvalidPoint)
}

pub fn scalar_to_hex(s: &Scalar) -> String {
    hex::encode(s.to_repr())
}

pub fn scalar_from_hex(s: &str) -> Result<Scalar, Error> {
    let bytes: [u8; 32] = hex::decode(s)
        .map_err(|_| Error::InvalidHex)?
        .try_into()
        .map_err(|_| Error::InvalidScalar)?;
    Option::from(Scalar::from_repr(bytes)).ok_or(Error::InvalidScalar)
}

pub fn bytes32_from_hex(s: &str) -> Result<[u8; 32], Error> {
    hex::decode(s)
        .map_err(|_| Error::InvalidHex)?
        .try_into()
        .map_err(|_| Error::InvalidHex)
}

macro_rules! serde_adapter {
    ($name:ident, $ty:ty, $to:path, $from:path) => {
        pub mod $name {
            use super::*;
            use serde::{de::Error as _, Deserialize, Deserializer, Serializer};

            pub fn serialize<S: Serializer>(v: &$ty, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(&$to(v))
            }

            pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<$ty, D::Error> {
                let s = String::deserialize(d)?;
                $from(&s).map_err(D::Error::custom)
            }
        }
    };
}

serde_adapter!(point, Point, point_to_hex, point_from_hex);
serde_adapter!(scalar, Scalar, scalar_to_hex, scalar_from_hex);

fn bytes32_to_hex(b: &[u8; 32]) -> String {
    hex::encode(b)
}
serde_adapter!(bytes32, [u8; 32], bytes32_to_hex, bytes32_from_hex);

pub mod points {
    use super::*;
    use serde::{de::Error as _, ser::SerializeSeq, Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[Point], s: S) -> Result<S::Ok, S::Error> {
        let mut seq = s.serialize_seq(Some(v.len()))?;
        for p in v {
            seq.serialize_element(&point_to_hex(p))?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Point>, D::Error> {
        Vec::<String>::deserialize(d)?
            .iter()
            .map(|s| point_from_hex(s).map_err(D::Error::custom))
            .collect()
    }
}
