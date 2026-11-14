use tc_agreement::AgreementInit;

use crate::{AlgoError, Params};

// An Agreement of tc_agreement, with AlgoError for its errors, any params for the other side's
// public key, and an init taking this side's private key as any params, so that every row fits
// behind Box<dyn Agreement> and still goes wherever a tc_agreement Agreement does. The secret goes
// into a buffer of agreement_size bytes, the caller's to wipe
pub trait Agreement:
    tc_agreement::Agreement<PublicKey = dyn Params, Error = AlgoError>
    + AgreementInit<dyn Params, Error = AlgoError>
{
}
