use core::fmt;
use core::hash::{Hash, Hasher};

use tc_asn1::NamedOid;
use tc_digest::Xof;

use super::{AnyXof, AnyXofParams};
use crate::AlgoError;
use crate::need::Need;

pub(super) type BoxedXof = Box<dyn Xof + Send + Sync>;

// Which fields of the params a row takes
#[derive(Clone, Copy, Debug)]
pub(super) struct Takes {
    pub(super) customization: Need,
    pub(super) function_name: Need,
    pub(super) block_size: Need,
}

#[derive(Clone, Copy, Debug)]
pub struct XofEntry {
    // The first is the canonical name, the rest are aliases
    names: &'static [&'static str],
    oids: &'static [NamedOid],
    takes: Takes,
    constructor: fn(&AnyXofParams) -> Result<BoxedXof, AlgoError>,
}

impl XofEntry {
    #[allow(dead_code, reason = "the table is empty when every XOF feature is off")]
    pub(super) const fn new(
        names: &'static [&'static str],
        oids: &'static [NamedOid],
        takes: Takes,
        constructor: fn(&AnyXofParams) -> Result<BoxedXof, AlgoError>,
    ) -> Self {
        Self {
            names,
            oids,
            takes,
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

    pub fn xof(&'static self) -> AnyXof {
        AnyXof::new(self)
    }

    // A field the row has no use for is refused, not ignored, so that none is dropped silently
    pub(super) fn create(&self, params: &AnyXofParams) -> Result<BoxedXof, AlgoError> {
        self.takes
            .customization
            .check(params.customization().is_some())?;
        self.takes
            .function_name
            .check(params.function_name().is_some())?;
        self.takes.block_size.check(params.block_size().is_some())?;
        (self.constructor)(params)
    }

    // What runs before init, or nothing for a row with a field it cannot do without
    pub(super) fn create_default(&self) -> Option<BoxedXof> {
        self.create(&AnyXofParams::new()).ok()
    }
}

// Each XOF has one row, so only the canonical name is compared; comparing function pointers is
// unreliable
impl PartialEq for XofEntry {
    fn eq(&self, other: &Self) -> bool {
        self.name() == other.name()
    }
}

impl Eq for XofEntry {}

impl Hash for XofEntry {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.name().hash(state);
    }
}

// The canonical name, followed by the OIDs when there are any, e.g. `SHAKE128  [id-shake128]`
impl fmt::Display for XofEntry {
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
