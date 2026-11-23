use std::io;

use tc_algo::{
    Params,
    params::key::{RsaKey, RsaKeyParams},
};
use tc_asym_cipher::AsymmetricKeyParams;
use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_rsa::RsaKeyOwned;

use crate::operator::rsa_mpi::{read_mpi, write_mpi};

pub(super) fn encode(key: &dyn Params) -> io::Result<Vec<u8>> {
    let key = key
        .as_any()
        .downcast_ref::<RsaKey>()
        .filter(|key| !key.is_private_key())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "expected RSA public key material",
            )
        })?;
    let modulus = ArrayEncoding::<u8>::to_be(key.modulus());
    let exponent = ArrayEncoding::<u8>::to_be(key.exponent());
    let modulus = unsigned(&modulus);
    let exponent = unsigned(&exponent);
    validate_components(modulus, exponent, io::ErrorKind::InvalidInput)?;
    let mut bytes = Vec::new();
    write_mpi(&mut bytes, modulus)?;
    write_mpi(&mut bytes, exponent)?;
    Ok(bytes)
}

pub(super) fn decode(mut bytes: &[u8]) -> io::Result<Box<dyn Params>> {
    let modulus = read_mpi(&mut bytes)?;
    let exponent = read_mpi(&mut bytes)?;
    if !bytes.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "trailing RSA public key material",
        ));
    }
    validate_components(modulus, exponent, io::ErrorKind::InvalidData)?;
    let mut padded = vec![0; modulus.len()];
    let start = padded.len() - exponent.len();
    padded[start..].copy_from_slice(exponent);
    let Ok(modulus) = PaddedBigUint::from_be(modulus);
    let Ok(exponent) = PaddedBigUint::from_be(padded.as_slice());
    Ok(Box::new(RsaKey::Core(RsaKeyOwned::new(
        false, modulus, exponent,
    ))))
}

fn validate_components(n: &[u8], e: &[u8], kind: io::ErrorKind) -> io::Result<()> {
    if !n.last().is_some_and(|last| last & 1 != 0)
        || !e.last().is_some_and(|last| last & 1 != 0)
        || e == [1]
        || (e.len(), e) >= (n.len(), n)
    {
        return Err(io::Error::new(kind, "invalid RSA public key components"));
    }
    Ok(())
}

fn unsigned(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len());
    &bytes[start..]
}
