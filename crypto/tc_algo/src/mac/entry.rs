use core::fmt;

use tc_asn1::NamedOid;

use super::dyn_mac::DynMac;
use super::{AnyMac, AnyMacParams};
use crate::AlgoError;
use crate::need::Need;

// A closure rather than a function pointer: the HMAC rows each capture their digest
type CreateMac = Box<dyn Fn() -> Box<dyn DynMac> + Send + Sync>;

pub struct MacEntry {
    // The first is the canonical name, the rest are aliases
    names: Vec<String>,
    oids: &'static [NamedOid],
    iv: Need,
    create: CreateMac,
}

impl MacEntry {
    #[allow(dead_code, reason = "the table is empty when every MAC feature is off")]
    pub(super) fn new(
        names: Vec<String>,
        oids: &'static [NamedOid],
        iv: Need,
        create: impl Fn() -> Box<dyn DynMac> + Send + Sync + 'static,
    ) -> Self {
        Self {
            names,
            oids,
            iv,
            create: Box::new(create),
        }
    }

    pub fn name(&self) -> &str {
        &self.names[0]
    }

    pub(super) fn names(&self) -> &[String] {
        &self.names
    }

    pub fn oids(&self) -> &'static [NamedOid] {
        self.oids
    }

    pub fn mac(&'static self) -> AnyMac {
        AnyMac::new(self)
    }

    pub(super) fn create(&self) -> Box<dyn DynMac> {
        (self.create)()
    }

    // The operation fields against what this MAC takes, so that none is dropped silently
    pub(super) fn check(&self, params: &AnyMacParams) -> Result<(), AlgoError> {
        self.iv.check(params.iv().is_some())
    }
}

impl fmt::Debug for MacEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MacEntry")
            .field("names", &self.names)
            .field("oids", &self.oids)
            .finish_non_exhaustive()
    }
}

// The canonical name, followed by the OIDs when there are any, e.g.
// `HMAC-SHA-256  [hmacWithSHA256]`
impl fmt::Display for MacEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())?;
        if let Some((first, rest)) = self.oids.split_first() {
            write!(f, "  [{}", first.name())?;
            for oid in rest {
                write!(f, ", {}", oid.name())?;
            }
            f.write_str("]")?;
        }
        Ok(())
    }
}
