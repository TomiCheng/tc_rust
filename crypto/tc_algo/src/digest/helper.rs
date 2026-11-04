use tc_asn1::Asn1Oid;
use tc_digest::{Digest, TryDigest};

use super::{AnyDigest, get_by_name, get_by_oid};
use crate::AlgoError;

pub fn calculate_by_name(name: &str, input: &[u8]) -> Result<Vec<u8>, AlgoError> {
    Ok(finish(get_by_name(name)?, input))
}

pub fn calculate_by_oid(oid: &Asn1Oid, input: &[u8]) -> Result<Vec<u8>, AlgoError> {
    Ok(finish(get_by_oid(oid)?, input))
}

/// Writes the hash to the front of `output` and returns its length; panics if `output` is
/// shorter than the digest.
pub fn calculate_by_name_into(
    name: &str,
    input: &[u8],
    output: &mut [u8],
) -> Result<usize, AlgoError> {
    Ok(finish_into(get_by_name(name)?, input, output))
}

/// Writes the hash to the front of `output` and returns its length; panics if `output` is
/// shorter than the digest.
pub fn calculate_by_oid_into(
    oid: &Asn1Oid,
    input: &[u8],
    output: &mut [u8],
) -> Result<usize, AlgoError> {
    Ok(finish_into(get_by_oid(oid)?, input, output))
}

fn finish(mut digest: AnyDigest, input: &[u8]) -> Vec<u8> {
    digest.update(input);
    digest.finalize()
}

fn finish_into(mut digest: AnyDigest, input: &[u8], output: &mut [u8]) -> usize {
    // Checked here so the panic message does not depend on each digest's implementation, and
    // after the input because NONE's size is the number of bytes it has taken
    digest.update(input);
    assert!(
        output.len() >= digest.digest_size(),
        "output is shorter than the digest"
    );
    Digest::do_final(&mut digest, output)
}
