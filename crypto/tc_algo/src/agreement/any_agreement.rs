use core::fmt;

use tc_agreement::{Agreement, AgreementInit};

use super::dyn_agreement::DynAgreement;
use super::{AgreementEntry, AgreementPeer, AnyAgreementParams, SharedSecret};
use crate::{AlgoError, ErrorKind};

pub struct AnyAgreement {
    entry: &'static AgreementEntry,
    agreement: Box<dyn DynAgreement>,
}

impl AnyAgreement {
    pub(super) fn new(entry: &'static AgreementEntry) -> Self {
        Self {
            entry,
            agreement: entry.create(),
        }
    }

    pub fn entry(&self) -> &'static AgreementEntry {
        self.entry
    }

    // Starts from a new agreement each time, so a failed init leaves none of an earlier key
    // behind. An operation field the agreement has no use for is refused, not ignored
    pub fn init(&mut self, params: &AnyAgreementParams) -> Result<(), AlgoError> {
        self.agreement = self.entry.create();
        self.entry.check(params)?;
        self.agreement.init(params)
    }

    // The shared secret with the other party, as many bytes as agreement_size gives, with leading
    // zeros. It is the raw secret: put it through a KDF before using it as a key
    pub fn calculate(&self, peer: &AgreementPeer) -> Result<SharedSecret, AlgoError> {
        let size = self
            .agreement
            .agreement_size()
            .ok_or(AlgoError::new(ErrorKind::NotInitialized))?;
        let mut secret = SharedSecret::zeroed(size);
        Agreement::calculate_agreement(self, peer, secret.as_mut_bytes())?;
        Ok(secret)
    }
}

// Shows the agreement's name, never its key
impl fmt::Debug for AnyAgreement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AnyAgreement")
            .field("name", &self.entry.name())
            .finish_non_exhaustive()
    }
}

impl fmt::Display for AnyAgreement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.entry.name())
    }
}

impl Agreement for AnyAgreement {
    // A peer rather than a public key: ECMQV takes two public keys of the other party, a static
    // one and an ephemeral one
    type PublicKey = AgreementPeer;
    type Error = AlgoError;

    // Panics before a successful init, as the agreements underneath do
    fn agreement_size(&self) -> usize {
        self.agreement
            .agreement_size()
            .expect("the agreement is initialized")
    }

    fn calculate_agreement(
        &self,
        peer: &AgreementPeer,
        output: &mut [u8],
    ) -> Result<(), Self::Error> {
        self.entry.check_peer(peer)?;
        self.agreement.calculate_agreement(peer, output)
    }
}

impl AgreementInit<AnyAgreementParams> for AnyAgreement {
    type Error = AlgoError;

    fn init(&mut self, params: &AnyAgreementParams) -> Result<(), Self::Error> {
        AnyAgreement::init(self, params)
    }
}
