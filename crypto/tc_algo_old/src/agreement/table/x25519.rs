use tc_agreement::{Agreement, AgreementInit};
use tc_asn1::NamedOid;
use tc_cfrg_curves::{CfrgError, X25519Agreement};

use crate::agreement::dyn_agreement::DynAgreement;
use crate::agreement::{AgreementEntry, AgreementPeer, AnyAgreementParams};
use crate::need::Need;
use crate::params::{AnyPrivateKey, AnyPublicKey};
use crate::{AlgoError, ErrorKind};

// Bouncy Castle's X25519Agreement, which it gives from GetRawAgreement rather than
// GetBasicAgreement; both kinds take a private key and give bytes, so here they share one table.
// Its OID is id-X25519 of RFC 8410, as there
pub(super) const X25519: AgreementEntry = AgreementEntry::new(
    &["X25519"],
    &[NamedOid::new(&[0x2b, 0x65, 0x6e], "1.3.101.110", "id-X25519")],
    Need::Forbidden,
    Need::Forbidden,
    || Box::new(X25519::default()),
);

#[derive(Default)]
struct X25519 {
    agreement: X25519Agreement,
    // X25519Agreement gives its size before init too, so this keeps the None of the trait
    initialized: bool,
}

impl DynAgreement for X25519 {
    fn init(&mut self, params: &AnyAgreementParams) -> Result<(), AlgoError> {
        self.initialized = false;
        let key = match params.key() {
            AnyPrivateKey::X25519(key) => key,
            #[allow(unreachable_patterns, reason = "every other variant may be off")]
            _ => return Err(AlgoError::new(ErrorKind::InvalidParams)),
        };
        self.agreement.init(key).map_err(error)?;
        self.initialized = true;
        Ok(())
    }

    fn agreement_size(&self) -> Option<usize> {
        self.initialized
            .then(|| self.agreement.agreement_size())
    }

    fn calculate_agreement(
        &self,
        peer: &AgreementPeer,
        output: &mut [u8],
    ) -> Result<(), AlgoError> {
        let public_key = match peer.key() {
            AnyPublicKey::X25519(key) => key,
            #[allow(unreachable_patterns, reason = "every other variant may be off")]
            _ => return Err(AlgoError::new(ErrorKind::InvalidParams)),
        };
        self.agreement
            .calculate_agreement(public_key, output)
            .map_err(error)
    }
}

// A secret of all zeros comes from a public key of small order, so it is InvalidParams, as is
// every other error that comes from the keys
fn error(error: CfrgError) -> AlgoError {
    let kind = match error {
        CfrgError::NotInitialized => ErrorKind::NotInitialized,
        CfrgError::OutputTooShort => ErrorKind::DataLength,
        _ => ErrorKind::InvalidParams,
    };
    AlgoError::with_source(kind, error)
}
