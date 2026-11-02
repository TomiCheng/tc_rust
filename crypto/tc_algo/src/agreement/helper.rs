use super::{AnyAgreementParams, get_by_name};
use crate::AlgoError;
use crate::params::{AnyKeyParams, SecretKey};

// Finds the agreement by name, initializes it with this party's private key and calculates the
// shared secret with the other party's public key
pub fn calculate(
    name: &str,
    params: &AnyAgreementParams,
    public_key: &AnyKeyParams,
) -> Result<SecretKey, AlgoError> {
    let mut agreement = get_by_name(name)?;
    agreement.init(params)?;
    agreement.calculate(public_key)
}
