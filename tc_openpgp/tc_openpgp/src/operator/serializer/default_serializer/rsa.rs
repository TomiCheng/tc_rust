use std::io::{self, Read};

use tc_algo::{
    Params,
    params::key::{RsaKey, RsaKeyParams},
};
use tc_asym_cipher::AsymmetricKeyParams;
use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_rsa::RsaKeyOwned;

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

fn write_mpi(out: &mut Vec<u8>, value: &[u8]) -> io::Result<()> {
    let bits = u16::try_from(bit_len(value)).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "RSA MPI exceeds its bit length field",
        )
    })?;
    out.extend_from_slice(&bits.to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}

fn read_mpi<'a>(input: &mut &'a [u8]) -> io::Result<&'a [u8]> {
    let mut encoded_bits = [0; 2];
    input.read_exact(&mut encoded_bits)?;
    let bits = usize::from(u16::from_be_bytes(encoded_bits));
    let (value, remaining) = input
        .split_at_checked(bits.div_ceil(8))
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "truncated RSA MPI"))?;
    if bit_len(value) != bits {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "noncanonical RSA MPI",
        ));
    }
    *input = remaining;
    Ok(value)
}

fn bit_len(value: &[u8]) -> usize {
    value
        .first()
        .map_or(0, |first| value.len() * 8 - first.leading_zeros() as usize)
}
