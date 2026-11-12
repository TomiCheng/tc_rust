use core::fmt;
use core::hash::{Hash, Hasher};

use tc_asn1::NamedOid;

use super::dyn_wrapper::DynWrapper;
use super::{AnyWrapParams, AnyWrapper};
use crate::AlgoError;
use crate::need::Need;

#[derive(Clone, Copy, Debug)]
pub struct WrapEntry {
    // The first is the canonical name, the rest are aliases
    names: &'static [&'static str],
    oids: &'static [NamedOid],
    iv: Need,
    constructor: fn() -> Box<dyn DynWrapper>,
}

impl WrapEntry {
    #[allow(
        dead_code,
        reason = "the table is empty when every key wrap feature is off"
    )]
    pub(super) const fn new(
        names: &'static [&'static str],
        oids: &'static [NamedOid],
        iv: Need,
        constructor: fn() -> Box<dyn DynWrapper>,
    ) -> Self {
        Self {
            names,
            oids,
            iv,
            constructor,
        }
    }

    pub fn name(&self) -> &'static str {
        self.names[0]
    }

    pub(super) fn names(&self) -> &'static [&'static str] {
        self.names
    }

    pub fn oids(&self) -> &'static [NamedOid] {
        self.oids
    }

    pub fn wrapper(&'static self) -> AnyWrapper {
        AnyWrapper::new(self)
    }

    pub(super) fn create(&self) -> Box<dyn DynWrapper> {
        (self.constructor)()
    }

    pub(super) fn check(&self, params: &AnyWrapParams) -> Result<(), AlgoError> {
        self.iv.check(params.iv().is_some())
    }
}

// Each wrapper has one row, so only the canonical name is compared; comparing function pointers is
// unreliable
impl PartialEq for WrapEntry {
    fn eq(&self, other: &Self) -> bool {
        self.name() == other.name()
    }
}

impl Eq for WrapEntry {}

impl Hash for WrapEntry {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.name().hash(state);
    }
}

// The canonical name, followed by the OIDs when there are any, e.g.
// `AESWRAP  [id-aes128-wrap, id-aes192-wrap, id-aes256-wrap]`
impl fmt::Display for WrapEntry {
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
