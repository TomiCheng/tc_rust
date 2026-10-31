use core::fmt;
use core::hash::{Hash, Hasher};

use tc_asn1::NamedOid;

use super::dyn_digest::DynDigest;
use super::{Algorithm, AnyDigest};

#[derive(Clone, Copy, Debug)]
pub struct DigestEntry {
    algorithm: Algorithm,
    // The first is the canonical name, the rest are aliases
    names: &'static [&'static str],
    // The first is the digest's own OID; the rest map to this row as in Bouncy Castle
    oids: &'static [NamedOid],
    constructor: fn() -> Box<dyn DynDigest>,
}

impl DigestEntry {
    #[allow(
        dead_code,
        reason = "the table is empty when every digest feature is off"
    )]
    pub(super) const fn new(
        algorithm: Algorithm,
        names: &'static [&'static str],
        oids: &'static [NamedOid],
        constructor: fn() -> Box<dyn DynDigest>,
    ) -> Self {
        Self {
            algorithm,
            names,
            oids,
            constructor,
        }
    }

    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    pub fn name(&self) -> &'static str {
        self.names[0]
    }

    pub(super) fn names(&self) -> &'static [&'static str] {
        self.names
    }

    // Raw Keccak has no OID
    pub fn oid(&self) -> Option<NamedOid> {
        self.oids.first().copied()
    }

    pub fn oids(&self) -> &'static [NamedOid] {
        self.oids
    }

    pub fn create(&'static self) -> AnyDigest {
        AnyDigest {
            entry: self,
            digest: (self.constructor)(),
        }
    }
}

// Each algorithm has one row, so only the algorithm is compared; comparing function pointers is
// unreliable
impl PartialEq for DigestEntry {
    fn eq(&self, other: &Self) -> bool {
        self.algorithm == other.algorithm
    }
}

impl Eq for DigestEntry {}

impl Hash for DigestEntry {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.algorithm.hash(state);
    }
}

// The canonical name, followed by the OIDs when there are any, e.g.
// `SHA-256  [id-sha256, id-hmacWithSHA256]`
impl fmt::Display for DigestEntry {
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
