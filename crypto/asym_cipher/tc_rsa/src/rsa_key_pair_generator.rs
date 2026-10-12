//! RSA key pair generation.

use core::marker::PhantomData;

use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
use tc_zeroize::Zeroize;

#[cfg(feature = "alloc")]
use crate::RsaKeyGenerationParamsOwned;
use crate::{RsaError, RsaKeyGenerationParamsRef, RsaKeyOwned, RsaPrivateCrtKeyOwned};

/// The parameters a generator was initialized with, of either kind.
#[expect(dead_code, reason = "read once generation is written")]
enum Params<'a> {
    Borrowed(RsaKeyGenerationParamsRef<'a>),
    #[cfg(feature = "alloc")]
    Owned(RsaKeyGenerationParamsOwned),
}

/// Generates RSA key pairs as Bouncy Castle's `RsaKeyPairGenerator` does,
/// the modulus and the exponents as integers of type `T`, the primes and
/// the values modulo them as integers of type `H`. It draws from the random
/// source of the parameters it is initialized with, which it borrows for
/// `'a` from [`RsaKeyGenerationParamsRef`], or owns from
/// `RsaKeyGenerationParamsOwned`; `'a` is inferred, and is `'static` for
/// the owned parameters.
pub struct RsaKeyPairGenerator<'a, T, H = T> {
    params: Option<Params<'a>>,
    integers: PhantomData<(T, H)>,
}

impl<T, H> RsaKeyPairGenerator<'_, T, H> {
    /// A generator to be initialized before it generates. Constant time.
    pub const fn new() -> Self {
        Self {
            params: None,
            integers: PhantomData,
        }
    }
}

/// Through [`new`](RsaKeyPairGenerator::new). Constant time.
impl<T, H> Default for RsaKeyPairGenerator<'_, T, H> {
    fn default() -> Self {
        Self::new()
    }
}

/// Keeps the parameters, with the random source they borrow. The checks of
/// the parameters are yet to be written. Constant time: the parameters are
/// public.
impl<'a, T, H> KeyPairGeneratorInit<RsaKeyGenerationParamsRef<'a>>
    for RsaKeyPairGenerator<'a, T, H>
{
    type Error = RsaError;

    fn init(&mut self, params: RsaKeyGenerationParamsRef<'a>) -> Result<(), RsaError> {
        self.params = Some(Params::Borrowed(params));
        Ok(())
    }
}

/// Keeps the parameters, with the random source they own. The checks of the
/// parameters are yet to be written. Constant time: the parameters are
/// public.
#[cfg(feature = "alloc")]
impl<T, H> KeyPairGeneratorInit<RsaKeyGenerationParamsOwned> for RsaKeyPairGenerator<'_, T, H> {
    type Error = RsaError;

    fn init(&mut self, params: RsaKeyGenerationParamsOwned) -> Result<(), RsaError> {
        self.params = Some(Params::Owned(params));
        Ok(())
    }
}

/// Draws primes until they make a key, as Bouncy Castle does. Variable
/// time: how many candidates are drawn, and which tests turn them down,
/// shows in the running time.
impl<T, H> KeyPairGenerator for RsaKeyPairGenerator<'_, T, H>
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

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use tc_asym_cipher::KeyPairGeneratorInit;

    use crate::{RsaKeyGenerationParamsRef, RsaKeyPairGenerator};

    #[test]
    fn a_generator_takes_parameters_that_borrow_their_source() {
        let mut rng = StdRng::seed_from_u64(1);
        let mut generator = RsaKeyPairGenerator::<u64, u32>::new();
        assert!(
            generator
                .init(RsaKeyGenerationParamsRef::new(&mut rng))
                .is_ok()
        );
        assert!(generator.params.is_some());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn a_generator_takes_parameters_that_own_their_source() {
        let mut generator = RsaKeyPairGenerator::<u64, u32>::new();
        let params = crate::RsaKeyGenerationParamsOwned::new(rand::rng());
        assert!(generator.init(params).is_ok());
        assert!(generator.params.is_some());
    }
}
