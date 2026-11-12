use std::sync::OnceLock;

use tc_asn1::Asn1Oid;
use tc_key_wrap::WrapDirection;

use super::table::WRAPPERS;
use super::{AnyWrapParams, AnyWrapper, WrapEntry};
use crate::params::SecretKey;
use crate::{AlgoError, ErrorKind, Policy};

/// Key wrappers by name or OID, after Bouncy Castle's `WrapperUtilities`, from
/// [`Algo::wrap`](crate::Algo::wrap). A wrapper protects a key under another key, the KEK: it is
/// found by name, initialized for one direction with an [`AnyWrapParams`], then wraps or unwraps.
///
/// ```
/// # #[cfg(all(feature = "rfc3394-wrap", feature = "aes"))] {
/// use tc_algo_old::{Algo, AnyWrapParams, SecretKey, WrapDirection};
///
/// let algo = Algo::new();
/// let params = AnyWrapParams::new(SecretKey::new(vec![0x42; 32]));
///
/// let mut wrapper = algo.wrap().get_by_name("AESWRAP")?;
/// wrapper.init(WrapDirection::Wrap, &params)?;
/// let wrapped = wrapper.wrap_key(&[0x24; 32])?;
///
/// wrapper.init(WrapDirection::Unwrap, &params)?;
/// assert_eq!(wrapper.unwrap_key(&wrapped)?.key, [0x24; 32]);
/// # }
/// # Ok::<(), tc_algo_old::AlgoError>(())
/// ```
#[derive(Clone, Copy, Debug)]
pub struct WrapFactory<'a> {
    policy: &'a Policy,
    // Filtered from the table on the first call of algorithms after a policy is set
    listed: &'a OnceLock<Vec<&'static WrapEntry>>,
}

impl<'a> WrapFactory<'a> {
    pub(crate) fn new(policy: &'a Policy, listed: &'a OnceLock<Vec<&'static WrapEntry>>) -> Self {
        Self { policy, listed }
    }

    pub fn algorithms(self) -> impl Iterator<Item = &'static WrapEntry> {
        self.listed
            .get_or_init(|| {
                WRAPPERS
                    .iter()
                    .filter(|entry| self.policy.lists(entry.names()))
                    .collect()
            })
            .iter()
            .copied()
    }

    // Names match without regard to ASCII case, aliases included; a string that is not a name is
    // parsed as a dotted OID, as in Bouncy Castle
    pub fn get_by_name(self, name: &str) -> Result<AnyWrapper, AlgoError> {
        find(name)
            .map(WrapEntry::wrapper)
            .ok_or(AlgoError::new(ErrorKind::UnknownWrapper))
    }

    pub fn get_by_oid(self, oid: &Asn1Oid) -> Result<AnyWrapper, AlgoError> {
        find_by_oid(oid)
            .map(WrapEntry::wrapper)
            .ok_or(AlgoError::new(ErrorKind::UnknownWrapper))
    }

    // Finds the wrapper by name, initializes it and wraps `key`
    pub fn wrap_key(
        self,
        name: &str,
        params: &AnyWrapParams,
        key: &[u8],
    ) -> Result<Vec<u8>, AlgoError> {
        let mut wrapper = self.get_by_name(name)?;
        wrapper.init(WrapDirection::Wrap, params)?;
        wrapper.wrap_key(key)
    }

    // Finds the wrapper by name, initializes it and unwraps `wrapped`
    pub fn unwrap_key(
        self,
        name: &str,
        params: &AnyWrapParams,
        wrapped: &[u8],
    ) -> Result<SecretKey, AlgoError> {
        let mut wrapper = self.get_by_name(name)?;
        wrapper.init(WrapDirection::Unwrap, params)?;
        wrapper.unwrap_key(wrapped)
    }
}

fn find(name: &str) -> Option<&'static WrapEntry> {
    WRAPPERS
        .iter()
        .find(|entry| {
            entry
                .names()
                .iter()
                .any(|known| known.eq_ignore_ascii_case(name))
        })
        .or_else(|| find_by_oid(&name.parse().ok()?))
}

fn find_by_oid(oid: &Asn1Oid) -> Option<&'static WrapEntry> {
    WRAPPERS
        .iter()
        .find(|entry| entry.oids().iter().any(|known| *known == *oid))
}
