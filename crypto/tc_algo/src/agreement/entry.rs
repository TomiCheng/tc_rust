use core::fmt;

use tc_asn1::NamedOid;

use super::AnyAgreement;

pub struct AgreementEntry {
    // The canonical name, such as DH
    name: &'static str,
    oids: &'static [NamedOid],
}

impl AgreementEntry {
    pub fn name(&self) -> &str {
        self.name
    }

    pub fn oids(&self) -> &'static [NamedOid] {
        self.oids
    }

    pub fn agreement(&'static self) -> AnyAgreement {
        AnyAgreement::new(self)
    }
}

impl fmt::Debug for AgreementEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AgreementEntry")
            .field("name", &self.name)
            .field("oids", &self.oids)
            .finish_non_exhaustive()
    }
}

// The canonical name, followed by the OIDs when there are any, e.g. `X25519  [id-X25519]`
impl fmt::Display for AgreementEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name)?;
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
