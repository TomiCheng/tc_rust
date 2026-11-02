use super::{AgreementPeer, AnyAgreementParams, get_by_name};
use crate::AlgoError;
use crate::params::SecretKey;

// Finds the agreement by name, initializes it with this party's private key and calculates the
// shared secret with the other party
pub fn calculate(
    name: &str,
    params: &AnyAgreementParams,
    peer: &AgreementPeer,
) -> Result<SecretKey, AlgoError> {
    let mut agreement = get_by_name(name)?;
    agreement.init(params)?;
    agreement.calculate(peer)
}
