use tc_agreement::AgreementInit;
use tc_zeroize::Zeroize;

use crate::agreement::SharedSecret;
use crate::{AlgoError, Params};

// An Agreement of tc_agreement, with AlgoError for its errors, any params for the other side's
// public key, and an init taking this side's private key as any params, so that every row fits
// behind Box<dyn Agreement> and still goes wherever a tc_agreement Agreement does
pub trait Agreement:
    tc_agreement::Agreement<PublicKey = dyn Params, Error = AlgoError>
    + AgreementInit<dyn Params, Error = AlgoError>
{
    // calculate_agreement into a SharedSecret of its own, which wipes itself when dropped
    fn calculate_shared_secret(&self, public_key: &dyn Params) -> Result<SharedSecret, AlgoError> {
        let mut output = vec![0; self.agreement_size()];
        match self.calculate_agreement(public_key, &mut output) {
            Ok(()) => Ok(SharedSecret::new(output)),
            Err(error) => {
                output.zeroize();
                Err(error)
            }
        }
    }
}
