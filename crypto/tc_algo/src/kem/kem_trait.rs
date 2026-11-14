use tc_kem::{KemDecapsulator, KemEncapsulator, KemInit};

use crate::{AlgoError, Params};

// Bouncy Castle's IKemEncapsulator: a KemEncapsulator of tc_kem, with AlgoError for its errors and
// an init taking the other side's public key as any params, so that every row fits behind
// Box<dyn Encapsulator> and still goes wherever a tc_kem KemEncapsulator does
pub trait Encapsulator:
    KemEncapsulator<Error = AlgoError> + KemInit<dyn Params, Error = AlgoError>
{
}

// Bouncy Castle's IKemDecapsulator: a KemDecapsulator of tc_kem, as Encapsulator, with an init
// taking this side's private key
pub trait Decapsulator:
    KemDecapsulator<Error = AlgoError> + KemInit<dyn Params, Error = AlgoError>
{
}
