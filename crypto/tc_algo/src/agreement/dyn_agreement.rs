use super::{AgreementPeer, AnyAgreementParams};
use crate::AlgoError;

// The agreement behind an AnyAgreement, one implementation per row of the table. The entry has
// already checked the operation fields and whether the other party gives an ephemeral key; each
// implementation checks that the keys are its own
pub(super) trait DynAgreement: Send {
    fn init(&mut self, params: &AnyAgreementParams) -> Result<(), AlgoError>;

    // None until init succeeds
    fn agreement_size(&self) -> Option<usize>;

    fn calculate_agreement(&self, peer: &AgreementPeer, output: &mut [u8])
    -> Result<(), AlgoError>;
}
