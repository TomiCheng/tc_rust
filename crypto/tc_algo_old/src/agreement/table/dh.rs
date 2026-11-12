use tc_agreement::{Agreement, AgreementInit};
use tc_dh::{DhAgreementError, DhBasicAgreement};

use crate::agreement::dyn_agreement::DynAgreement;
use crate::agreement::{AgreementEntry, AgreementPeer, AnyAgreementParams};
use crate::need::Need;
use crate::params::{AnyPrivateKey, AnyPublicKey};
use crate::{AlgoError, ErrorKind};

// Bouncy Castle's DHBasicAgreement, which it gives no OID. DIFFIEHELLMAN is its alias. It takes
// the private key alone, and the other party's public key alone
pub(super) const DH: AgreementEntry = AgreementEntry::new(
    &["DH", "DIFFIEHELLMAN"],
    &[],
    Need::Forbidden,
    Need::Forbidden,
    || Box::new(Dh::default()),
);

#[derive(Default)]
struct Dh {
    agreement: DhBasicAgreement,
    // The length of p in bytes, once init has succeeded
    size: Option<usize>,
}

impl DynAgreement for Dh {
    fn init(&mut self, params: &AnyAgreementParams) -> Result<(), AlgoError> {
        self.size = None;
        let key = match params.key() {
            AnyPrivateKey::Dh(key) => key,
            #[allow(unreachable_patterns, reason = "every other variant may be off")]
            _ => return Err(AlgoError::new(ErrorKind::InvalidParams)),
        };
        self.agreement.init(key).map_err(error)?;
        self.size = Some(self.agreement.agreement_size());
        Ok(())
    }

    fn agreement_size(&self) -> Option<usize> {
        self.size
    }

    fn calculate_agreement(
        &self,
        peer: &AgreementPeer,
        output: &mut [u8],
    ) -> Result<(), AlgoError> {
        let public_key = match peer.key() {
            AnyPublicKey::Dh(key) => key,
            #[allow(unreachable_patterns, reason = "every other variant may be off")]
            _ => return Err(AlgoError::new(ErrorKind::InvalidParams)),
        };
        self.agreement
            .calculate_agreement(public_key, output)
            .map_err(error)
    }
}

// A bad group, a public key of another group or outside the subgroup, and a shared secret of 1
// all come from the keys, so all are InvalidParams
fn error(error: DhAgreementError) -> AlgoError {
    let kind = match error {
        DhAgreementError::NotInitialized | DhAgreementError::MessageNotCalculated => {
            ErrorKind::NotInitialized
        }
        DhAgreementError::BufferTooSmall => ErrorKind::DataLength,
        _ => ErrorKind::InvalidParams,
    };
    AlgoError::with_source(kind, error)
}
