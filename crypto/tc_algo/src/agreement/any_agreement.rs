use core::fmt;

use tc_agreement::{Agreement, AgreementInit};

use super::dyn_agreement::DynAgreement;
use super::{AgreementEntry, AnyAgreementParams};
use crate::params::{AnyKeyParams, SecretKey};
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

    // The shared secret with the other party's public key, as many bytes as agreement_size gives,
    // with leading zeros. It is the raw secret: put it through a KDF before using it as a key
    pub fn calculate(&self, public_key: &AnyKeyParams) -> Result<SecretKey, AlgoError> {
        let size = self
            .agreement
            .agreement_size()
            .ok_or(AlgoError::new(ErrorKind::NotInitialized))?;
        let mut secret = SecretKey::new(vec![0; size]);
        Agreement::calculate_agreement(self, public_key, &mut secret.key)?;
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
    // A key params rather than a public key: ECMQV takes two public keys of the other party, a
    // static one and an ephemeral one
    type PublicKey = AnyKeyParams;
    type Error = AlgoError;

    // Panics before a successful init, as the agreements underneath do
    fn agreement_size(&self) -> usize {
        self.agreement
            .agreement_size()
            .expect("the agreement is initialized")
    }

    fn calculate_agreement(
        &self,
        public_key: &AnyKeyParams,
        output: &mut [u8],
    ) -> Result<(), Self::Error> {
        let AnyKeyParams::Public(public_key) = public_key else {
            return Err(AlgoError::new(ErrorKind::InvalidParams));
        };
        self.agreement.calculate_agreement(public_key, output)
    }
}

impl AgreementInit<AnyAgreementParams> for AnyAgreement {
    type Error = AlgoError;

    fn init(&mut self, params: &AnyAgreementParams) -> Result<(), Self::Error> {
        AnyAgreement::init(self, params)
    }
}
