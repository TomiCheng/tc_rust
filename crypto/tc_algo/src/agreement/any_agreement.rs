use core::fmt;

use tc_agreement::{Agreement, AgreementInit};

use super::{AgreementEntry, AnyAgreementParams};
use crate::AlgoError;
use crate::params::{AnyKeyParams, SecretKey};

pub struct AnyAgreement {
    entry: &'static AgreementEntry,
}

impl AnyAgreement {
    pub(super) fn new(entry: &'static AgreementEntry) -> Self {
        Self { entry }
    }

    pub fn entry(&self) -> &'static AgreementEntry {
        self.entry
    }

    pub fn init(&mut self, params: &AnyAgreementParams) -> Result<(), AlgoError> {
        todo!()
    }

    // The shared secret with the other party's public key, as many bytes as agreement_size gives,
    // with leading zeros. It is the raw secret: put it through a KDF before using it as a key
    pub fn calculate(&self, public_key: &AnyKeyParams) -> Result<SecretKey, AlgoError> {
        todo!()
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
    // A key params rather than a public key: ECMQV takes two public keys of the other party, a
    // static one and an ephemeral one
    type PublicKey = AnyKeyParams;
    type Error = AlgoError;

    fn agreement_size(&self) -> usize {
        todo!()
    }

    fn calculate_agreement(
        &self,
        public_key: &AnyKeyParams,
        output: &mut [u8],
    ) -> Result<(), Self::Error> {
        todo!()
    }
}

impl AgreementInit<AnyAgreementParams> for AnyAgreement {
    type Error = AlgoError;

    fn init(&mut self, params: &AnyAgreementParams) -> Result<(), Self::Error> {
        AnyAgreement::init(self, params)
    }
}
