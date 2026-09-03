//! Generic RSA core engine.

use core::convert::Infallible;
use core::marker::PhantomData;

use tc_cipher::CipherDirection;

use crate::{BigInt, RsaCore, RsaKeyParams};

/// RSA core backed by the big-integer type `I`.
///
/// The engine shape and trait wiring are established, but its operations are
/// intentionally deferred until the [`BigInt`] contract is complete.
pub struct RsaCoreEngine<I> {
    integer: PhantomData<fn() -> I>,
}

impl<I> RsaCoreEngine<I> {
    /// Creates an uninitialized RSA core.
    pub const fn new() -> Self {
        Self {
            integer: PhantomData,
        }
    }
}

impl<I> Default for RsaCoreEngine<I> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K: ?Sized, I> RsaCore<K, I> for RsaCoreEngine<I>
where
    K: RsaKeyParams<I>,
    I: BigInt,
{
    type InitError = Infallible;
    type Error = Infallible;

    fn init(&mut self, _direction: CipherDirection, _params: &K) -> Result<(), Self::InitError> {
        todo!("initialize the RSA core after the BigInt contract is complete")
    }

    fn input_block_size(&self) -> usize {
        todo!("derive the RSA input block size from the modulus")
    }

    fn output_block_size(&self) -> usize {
        todo!("derive the RSA output block size from the modulus")
    }

    fn convert_input(&self, _input: &[u8]) -> Result<I, Self::Error> {
        todo!("convert unsigned big-endian input through the BigInt backend")
    }

    fn process_block(&mut self, _input: I) -> Result<I, Self::Error> {
        todo!("apply the standard or CRT RSA operation through the BigInt backend")
    }

    fn convert_output(&self, _result: &I, _output: &mut [u8]) -> Result<usize, Self::Error> {
        todo!("encode the RSA result through the BigInt backend")
    }
}

#[cfg(test)]
mod tests {
    use core::convert::Infallible;

    use super::RsaCoreEngine;
    use crate::{BigInt, RsaCore, RsaKeyParams};

    struct TestBigInt;

    impl BigInt for TestBigInt {}

    struct TestKey;

    impl RsaKeyParams<TestBigInt> for TestKey {
        fn modulus(&self) -> &TestBigInt {
            &TestBigInt
        }

        fn exponent(&self) -> &TestBigInt {
            &TestBigInt
        }
    }

    fn assert_core<T>()
    where
        T: RsaCore<TestKey, TestBigInt, InitError = Infallible, Error = Infallible>,
    {
    }

    #[test]
    fn implements_rsa_core_for_caller_selected_types() {
        assert_core::<RsaCoreEngine<TestBigInt>>();
        let _ = RsaCoreEngine::<TestBigInt>::new();
    }
}
