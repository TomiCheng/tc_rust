use std::sync::OnceLock;

use tc_asn1::Asn1Oid;

use super::table::XOFS;
use super::{AnyXof, AnyXofParams, XofEntry};
use crate::{AlgoError, ErrorKind, Policy};

/// Extendable-output functions by name or OID, from [`Algo::xof`](crate::Algo::xof); Bouncy Castle
/// has no matching factory. An XOF gives as many bytes as you ask for.
///
/// ```
/// # #[cfg(all(feature = "shake128", feature = "parallelhash128"))] {
/// use tc_algo::{Algo, AnyXofParams};
///
/// let algo = Algo::new();
///
/// // An XOF that takes nothing is ready as it comes
/// let mut shake = algo.xof().get_by_name("SHAKE128")?;
/// shake.update(b"hello, world")?;
/// let output = shake.finalize(64)?;
/// assert_eq!(output.len(), 64);
///
/// // One that takes params gets them from init
/// let params = AnyXofParams::new().with_block_size(8192);
/// let mut parallel = algo.xof().get_by_name("PARALLELHASH128")?;
/// parallel.init(&params)?;
/// parallel.update(b"hello, world")?;
/// let output = parallel.finalize(64)?;
/// # }
/// # Ok::<(), tc_algo::AlgoError>(())
/// ```
#[derive(Clone, Copy, Debug)]
pub struct XofFactory<'a> {
    policy: &'a Policy,
    // Filtered from the table on the first call of algorithms after a policy is set
    listed: &'a OnceLock<Vec<&'static XofEntry>>,
}

impl<'a> XofFactory<'a> {
    pub(crate) fn new(policy: &'a Policy, listed: &'a OnceLock<Vec<&'static XofEntry>>) -> Self {
        Self { policy, listed }
    }

    pub fn algorithms(self) -> impl Iterator<Item = &'static XofEntry> {
        self.listed
            .get_or_init(|| {
                XOFS.iter()
                    .filter(|entry| self.policy.lists(entry.names()))
                    .collect()
            })
            .iter()
            .copied()
    }

    // Names match without regard to ASCII case; a string that is not a name is parsed as a dotted
    // OID, as the other factories do
    pub fn get_by_name(self, name: &str) -> Result<AnyXof, AlgoError> {
        find(name)
            .map(XofEntry::xof)
            .ok_or(AlgoError::new(ErrorKind::UnknownXof))
    }

    pub fn get_by_oid(self, oid: &Asn1Oid) -> Result<AnyXof, AlgoError> {
        find_by_oid(oid)
            .map(XofEntry::xof)
            .ok_or(AlgoError::new(ErrorKind::UnknownXof))
    }

    // Finds the XOF by name, initializes it and returns `output_len` bytes of the whole input
    pub fn calculate(
        self,
        name: &str,
        params: &AnyXofParams,
        input: &[u8],
        output_len: usize,
    ) -> Result<Vec<u8>, AlgoError> {
        let mut xof = self.get_by_name(name)?;
        xof.init(params)?;
        xof.update(input)?;
        xof.finalize(output_len)
    }
}

fn find(name: &str) -> Option<&'static XofEntry> {
    XOFS.iter()
        .find(|entry| {
            entry
                .names()
                .iter()
                .any(|known| known.eq_ignore_ascii_case(name))
        })
        .or_else(|| find_by_oid(&name.parse().ok()?))
}

fn find_by_oid(oid: &Asn1Oid) -> Option<&'static XofEntry> {
    XOFS.iter()
        .find(|entry| entry.oids().iter().any(|known| *known == *oid))
}
