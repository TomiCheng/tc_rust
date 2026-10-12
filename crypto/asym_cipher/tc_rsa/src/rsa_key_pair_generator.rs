//! RSA key pair generation.

use core::marker::PhantomData;

use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
use tc_zeroize::Zeroize;

use crate::{RsaError, RsaKeyGenerationParams, RsaKeyOwned, RsaPrivateCrtKeyOwned};

/// Generates RSA key pairs as Bouncy Castle's `RsaKeyPairGenerator` does,
/// the modulus and the exponents as integers of type `T`, the primes and
/// the values modulo them as integers of type `H`, drawing from the random
/// source its parameters own.
pub struct RsaKeyPairGenerator<T, H = T> {
    #[expect(dead_code, reason = "read once generation is written")]
    params: Option<RsaKeyGenerationParams>,
    integers: PhantomData<(T, H)>,
}

impl<T, H> RsaKeyPairGenerator<T, H> {
    /// A generator to be initialized before it generates. Constant time.
    pub const fn new() -> Self {
        Self {
            params: None,
            integers: PhantomData,
        }
    }
}

/// Through [`new`](RsaKeyPairGenerator::new). Constant time.
impl<T, H> Default for RsaKeyPairGenerator<T, H> {
    fn default() -> Self {
        Self::new()
    }
}

/// Keeps the parameters, with their random source, once they are checked.
/// Constant time: the values checked are public.
impl<T, H> KeyPairGeneratorInit<RsaKeyGenerationParams> for RsaKeyPairGenerator<T, H> {
    type Error = RsaError;

    fn init(&mut self, _params: RsaKeyGenerationParams) -> Result<(), RsaError> {
        todo!()
    }
}

/// Draws primes until they make a key, as Bouncy Castle does. Variable
/// time: how many candidates are drawn, and which tests turn them down,
/// shows in the running time.
impl<T, H> KeyPairGenerator for RsaKeyPairGenerator<T, H>
where
    T: Zeroize,
    H: Zeroize,
{
    type PublicKey = RsaKeyOwned<T>;
    type PrivateKey = RsaPrivateCrtKeyOwned<T, H>;
    type Error = RsaError;

    fn generate_key_pair(
        &mut self,
    ) -> Result<(RsaKeyOwned<T>, RsaPrivateCrtKeyOwned<T, H>), RsaError> {
        todo!()
    }
}
