use std::sync::OnceLock;

use tc_asn1::Asn1Oid;
use tc_digest::{Digest, TryDigest};

use super::table::DIGESTS;
use super::{AnyDigest, DigestEntry};
use crate::{AlgoError, ErrorKind, Policy};

/// Digests by name or OID, after Bouncy Castle's `DigestUtilities`, from
/// [`Algo::digest`](crate::Algo::digest).
///
/// ```
/// # #[cfg(feature = "sha256")] {
/// use tc_algo::Algo;
///
/// let algo = Algo::new();
///
/// // In pieces: get a digest by its name, or by its OID, feed it, then finish
/// let mut sha256 = algo.digest().get_by_name("SHA-256")?;
/// sha256.update(b"hello, ");
/// sha256.update(b"world");
/// let hash = sha256.finalize();
///
/// // All at once
/// assert_eq!(algo.digest().calculate_by_name("SHA-256", b"hello, world")?, hash);
/// # }
/// # Ok::<(), tc_algo::AlgoError>(())
/// ```
#[derive(Clone, Copy, Debug)]
pub struct DigestFactory<'a> {
    policy: &'a Policy,
    // Filtered from the table on the first call of algorithms after a policy is set
    listed: &'a OnceLock<Vec<&'static DigestEntry>>,
}

impl<'a> DigestFactory<'a> {
    pub(crate) fn new(policy: &'a Policy, listed: &'a OnceLock<Vec<&'static DigestEntry>>) -> Self {
        Self { policy, listed }
    }

    pub fn algorithms(self) -> impl Iterator<Item = &'static DigestEntry> {
        self.listed
            .get_or_init(|| {
                DIGESTS
                    .iter()
                    .filter(|entry| self.policy.lists(entry.names()))
                    .collect()
            })
            .iter()
            .copied()
    }

    // Names match without regard to ASCII case; a string that is not a name is parsed as a dotted
    // OID, as in Bouncy Castle
    pub fn get_by_name(self, name: &str) -> Result<AnyDigest, AlgoError> {
        find(name)
            .map(DigestEntry::create)
            .ok_or(AlgoError::new(ErrorKind::UnknownDigest))
    }

    pub fn get_by_oid(self, oid: &Asn1Oid) -> Result<AnyDigest, AlgoError> {
        find_by_oid(oid)
            .map(DigestEntry::create)
            .ok_or(AlgoError::new(ErrorKind::UnknownDigest))
    }

    pub fn calculate_by_name(self, name: &str, input: &[u8]) -> Result<Vec<u8>, AlgoError> {
        Ok(finish(self.get_by_name(name)?, input))
    }

    pub fn calculate_by_oid(self, oid: &Asn1Oid, input: &[u8]) -> Result<Vec<u8>, AlgoError> {
        Ok(finish(self.get_by_oid(oid)?, input))
    }

    /// Writes the hash to the front of `output` and returns its length; panics if `output` is
    /// shorter than the digest.
    pub fn calculate_by_name_into(
        self,
        name: &str,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, AlgoError> {
        Ok(finish_into(self.get_by_name(name)?, input, output))
    }

    /// Writes the hash to the front of `output` and returns its length; panics if `output` is
    /// shorter than the digest.
    pub fn calculate_by_oid_into(
        self,
        oid: &Asn1Oid,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, AlgoError> {
        Ok(finish_into(self.get_by_oid(oid)?, input, output))
    }
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

fn find(name: &str) -> Option<&'static DigestEntry> {
    DIGESTS
        .iter()
        .find(|entry| {
            entry
                .names()
                .iter()
                .any(|known| known.eq_ignore_ascii_case(name))
        })
        .or_else(|| find_by_oid(&name.parse().ok()?))
}

fn find_by_oid(oid: &Asn1Oid) -> Option<&'static DigestEntry> {
    DIGESTS
        .iter()
        .find(|entry| entry.oids().iter().any(|known| *known == *oid))
}
