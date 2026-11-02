use core::fmt;

use tc_asn1::NamedOid;

use super::dyn_agreement::DynAgreement;
use super::{AgreementPeer, AnyAgreement, AnyAgreementParams};
use crate::AlgoError;
use crate::need::Need;

pub(super) type CreateAgreement = fn() -> Box<dyn DynAgreement>;

pub struct AgreementEntry {
    // The first is the canonical name, the rest are aliases
    names: &'static [&'static str],
    oids: &'static [NamedOid],
    ukm: Need,
    ephemeral: Need,
    create: CreateAgreement,
}

impl AgreementEntry {
    #[allow(
        dead_code,
        reason = "the table is empty when every agreement feature is off"
    )]
    pub(super) const fn new(
        names: &'static [&'static str],
        oids: &'static [NamedOid],
        ukm: Need,
        ephemeral: Need,
        create: CreateAgreement,
    ) -> Self {
        Self {
            names,
            oids,
            ukm,
            ephemeral,
            create,
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

    pub fn agreement(&'static self) -> AnyAgreement {
        AnyAgreement::new(self)
    }

    pub(super) fn create(&self) -> Box<dyn DynAgreement> {
        (self.create)()
    }

    // The operation fields against what this agreement takes, so that none is dropped silently
    pub(super) fn check(&self, params: &AnyAgreementParams) -> Result<(), AlgoError> {
        self.ukm.check(params.ukm().is_some())
    }

    // The other party's keys against what this agreement takes, likewise
    pub(super) fn check_peer(&self, peer: &AgreementPeer) -> Result<(), AlgoError> {
        self.ephemeral.check(peer.ephemeral().is_some())
    }
}

impl fmt::Debug for AgreementEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AgreementEntry")
            .field("names", &self.names)
            .field("oids", &self.oids)
            .finish_non_exhaustive()
    }
}

// The canonical name, followed by the OIDs when there are any, e.g. `X25519  [id-X25519]`
impl fmt::Display for AgreementEntry {
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
