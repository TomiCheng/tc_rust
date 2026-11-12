use std::sync::OnceLock;

use tc_asn1::Asn1Oid;

use super::table::build_table;
use super::{AnyMac, AnyMacParams, MacEntry};
use crate::{AlgoError, ErrorKind, Policy};

/// MACs by name or OID, after Bouncy Castle's `MacUtilities`, from [`Algo::mac`](crate::Algo::mac).
/// A MAC is found by name, initialized with an [`AnyMacParams`] that holds the key and, for the MACs
/// that take one, an IV, then fed the message for its tag.
///
/// ```
/// # #[cfg(all(feature = "hmac", feature = "sha256"))] {
/// use tc_algo_old::{Algo, AnyMacParams, SecretKey};
///
/// let algo = Algo::new();
/// let params = AnyMacParams::new(SecretKey::new(b"a secret key".to_vec()));
///
/// // In pieces: find a MAC, initialize it, feed it, then finish
/// let mut hmac = algo.mac().get_by_name("HMAC-SHA256")?;
/// hmac.init(&params)?;
/// hmac.update(b"hello, ")?;
/// hmac.update(b"world")?;
/// let tag = hmac.finalize()?;
///
/// // All at once
/// assert_eq!(algo.mac().calculate("HMAC-SHA256", &params, b"hello, world")?, tag);
///
/// // Checking a tag you received, in constant time
/// hmac.update(b"hello, world")?;
/// assert!(hmac.verify(&tag)?);
/// # }
/// # Ok::<(), tc_algo_old::AlgoError>(())
/// ```
#[derive(Clone, Copy, Debug)]
pub struct MacFactory<'a> {
    policy: &'a Policy,
    // The whole table, built once for the Algo on first use
    table: &'a OnceLock<Vec<MacEntry>>,
    // Filtered from that table on the first call of algorithms after a policy is set
    listed: &'a OnceLock<Vec<MacEntry>>,
}

impl<'a> MacFactory<'a> {
    pub(crate) fn new(
        policy: &'a Policy,
        table: &'a OnceLock<Vec<MacEntry>>,
        listed: &'a OnceLock<Vec<MacEntry>>,
    ) -> Self {
        Self {
            policy,
            table,
            listed,
        }
    }

    pub fn algorithms(self) -> impl Iterator<Item = &'a MacEntry> {
        self.listed
            .get_or_init(|| {
                self.table()
                    .iter()
                    .filter(|entry| self.policy.lists(entry.names()))
                    .cloned()
                    .collect()
            })
            .iter()
    }

    // Names match without regard to ASCII case, aliases included; a string that is not a name is
    // parsed as a dotted OID, as in Bouncy Castle
    pub fn get_by_name(self, name: &str) -> Result<AnyMac, AlgoError> {
        find(self.table(), name)
            .map(MacEntry::mac)
            .ok_or(AlgoError::new(ErrorKind::UnknownMac))
    }

    pub fn get_by_oid(self, oid: &Asn1Oid) -> Result<AnyMac, AlgoError> {
        find_by_oid(self.table(), oid)
            .map(MacEntry::mac)
            .ok_or(AlgoError::new(ErrorKind::UnknownMac))
    }

    // Finds the MAC by name, initializes it and returns the tag of the whole input
    pub fn calculate(
        self,
        name: &str,
        params: &AnyMacParams,
        input: &[u8],
    ) -> Result<Vec<u8>, AlgoError> {
        let mut mac = self.get_by_name(name)?;
        mac.init(params)?;
        mac.update(input)?;
        mac.finalize()
    }

    fn table(self) -> &'a [MacEntry] {
        self.table.get_or_init(build_table)
    }
}

fn find<'a>(table: &'a [MacEntry], name: &str) -> Option<&'a MacEntry> {
    table
        .iter()
        .find(|entry| {
            entry
                .names()
                .iter()
                .any(|known| known.eq_ignore_ascii_case(name))
        })
        .or_else(|| find_by_oid(table, &name.parse().ok()?))
}

fn find_by_oid<'a>(table: &'a [MacEntry], oid: &Asn1Oid) -> Option<&'a MacEntry> {
    table
        .iter()
        .find(|entry| entry.oids().iter().any(|known| *known == *oid))
}
