use std::sync::OnceLock;

use tc_asn1::Asn1Oid;

use super::table::AGREEMENTS;
use super::{AgreementEntry, AgreementPeer, AnyAgreement, AnyAgreementParams, SharedSecret};
use crate::{AlgoError, ErrorKind, Policy};

/// Key agreements by name or OID, after Bouncy Castle's `AgreementUtilities`, from
/// [`Algo::agreement`](crate::Algo::agreement). An agreement is found by name, such as `DH`,
/// initialized with an [`AnyAgreementParams`] that holds one party's private key, then given an
/// [`AgreementPeer`] that holds the other party's public key for their [`SharedSecret`], which a KDF
/// turns into a key.
#[derive(Clone, Copy, Debug)]
pub struct AgreementFactory<'a> {
    policy: &'a Policy,
    // Filtered from the table on the first call of algorithms after a policy is set
    listed: &'a OnceLock<Vec<&'static AgreementEntry>>,
}

impl<'a> AgreementFactory<'a> {
    pub(crate) fn new(
        policy: &'a Policy,
        listed: &'a OnceLock<Vec<&'static AgreementEntry>>,
    ) -> Self {
        Self { policy, listed }
    }

    pub fn algorithms(self) -> impl Iterator<Item = &'static AgreementEntry> {
        self.listed
            .get_or_init(|| {
                AGREEMENTS
                    .iter()
                    .filter(|entry| self.policy.lists(entry.names()))
                    .collect()
            })
            .iter()
            .copied()
    }

    // Names match without regard to ASCII case, aliases such as DIFFIEHELLMAN included; a string
    // that is not a name is parsed as a dotted OID, as in Bouncy Castle
    pub fn get_by_name(self, name: &str) -> Result<AnyAgreement, AlgoError> {
        find(name)
            .map(AgreementEntry::agreement)
            .ok_or(AlgoError::new(ErrorKind::UnknownAgreement))
    }

    pub fn get_by_oid(self, oid: &Asn1Oid) -> Result<AnyAgreement, AlgoError> {
        find_by_oid(oid)
            .map(AgreementEntry::agreement)
            .ok_or(AlgoError::new(ErrorKind::UnknownAgreement))
    }

    // Finds the agreement by name, initializes it with this party's private key and calculates the
    // shared secret with the other party
    pub fn calculate(
        self,
        name: &str,
        params: &AnyAgreementParams,
        peer: &AgreementPeer,
    ) -> Result<SharedSecret, AlgoError> {
        let mut agreement = self.get_by_name(name)?;
        agreement.init(params)?;
        agreement.calculate(peer)
    }
}

fn find(name: &str) -> Option<&'static AgreementEntry> {
    AGREEMENTS
        .iter()
        .find(|entry| matches_name(entry.names(), name))
        .or_else(|| find_by_oid(&name.parse().ok()?))
}

fn matches_name(names: &[&str], name: &str) -> bool {
    names.iter().any(|known| known.eq_ignore_ascii_case(name))
}

fn find_by_oid(oid: &Asn1Oid) -> Option<&'static AgreementEntry> {
    AGREEMENTS
        .iter()
        .find(|entry| entry.oids().iter().any(|known| *known == *oid))
}
