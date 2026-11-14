use tc_kdf::KdfInit;

use crate::{AlgoError, Params};

// A Kdf of tc_kdf, Bouncy Castle's IDerivationFunction, with AlgoError for its errors and an init
// taking any params, so that every row fits behind Box<dyn Kdf> and still goes wherever a tc_kdf
// Kdf does. It stands apart from Agreement, since which KDF follows which agreement is up to the
// protocol
pub trait Kdf: tc_kdf::Kdf<Error = AlgoError> + KdfInit<dyn Params, Error = AlgoError> {}
