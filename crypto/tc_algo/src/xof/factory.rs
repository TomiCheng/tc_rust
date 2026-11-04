use core::iter;

use tc_asn1::Asn1Oid;

use super::{AnyXof, XofEntry};
use crate::{AlgoError, Policy};

/// Extendable-output functions by name or OID, from [`Algo::xof`](crate::Algo::xof); Bouncy Castle
/// has no matching factory.
#[derive(Clone, Copy, Debug)]
pub struct XofFactory<'a> {
    #[allow(dead_code, reason = "the bodies are still todo")]
    policy: &'a Policy,
}

#[allow(unused_variables, reason = "the bodies are still todo")]
impl<'a> XofFactory<'a> {
    pub(crate) fn new(policy: &'a Policy) -> Self {
        Self { policy }
    }

    pub fn algorithms(self) -> impl Iterator<Item = &'static XofEntry> {
        iter::once_with(|| todo!())
    }

    pub fn get_by_name(self, name: &str) -> Result<AnyXof, AlgoError> {
        todo!()
    }

    pub fn get_by_oid(self, oid: &Asn1Oid) -> Result<AnyXof, AlgoError> {
        todo!()
    }
}
