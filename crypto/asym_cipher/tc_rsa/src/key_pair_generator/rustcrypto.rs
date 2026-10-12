//! RSA key pair generation through the RustCrypto `rsa` crate.

use alloc::boxed::Box;

use rsa::{BoxedUint, RsaPrivateKey, RsaPublicKey};
use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};

use crate::{RsaError, RsaKeyGenerationParams, RsaKeyRustCrypto, RsaPrivateCrtKeyRustCrypto};

/// The smallest modulus `rsa` generates, in bits.
const MIN_STRENGTH: u32 = 1024;

/// The largest modulus `rsa` takes, in bits, as `RsaPublicKey::MAX_SIZE` is.
const MAX_STRENGTH: u32 = RsaPublicKey::MAX_SIZE as u32;

/// Generates RSA key pairs through the RustCrypto `rsa` crate, as
/// [`RsaKeyRustCrypto`] and [`RsaPrivateCrtKeyRustCrypto`]. It takes the
/// parameters the generator of this crate takes, of any kind that
/// implements [`RsaKeyGenerationParams`], and draws from their random
/// source, which `rsa` takes as it is, as both use `rand_core` 0.10; it
/// keeps them behind `dyn` for as long as `'a`, which is inferred. `rsa`
/// tests its primes as it sees fit, so the certainty of the parameters is
/// checked but not used.
///
/// ```
/// use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
/// use tc_rsa_v2::{RsaKeyGenerationParamsOwned, RsaKeyPairGeneratorRustCrypto};
///
/// // The defaults: a 2048-bit modulus and the public exponent 65537, drawn
/// // from the system's random source; `with_strength` and the other
/// // `with_*` methods change them.
/// let params = RsaKeyGenerationParamsOwned::new(rand::rng());
/// let mut generator = RsaKeyPairGeneratorRustCrypto::new();
/// generator.init(params)?;
///
/// // The keys of `rsa`, wrapped as the keys of this crate: the public key
/// // holds `n` and `e`, the private one adds `d` and the values of the CRT.
/// let (public, private) = generator.generate_key_pair()?;
/// # Ok::<(), tc_rsa_v2::RsaError>(())
/// ```
pub struct RsaKeyPairGeneratorRustCrypto<'a> {
    params: Option<Box<dyn RsaKeyGenerationParams + 'a>>,
}

impl RsaKeyPairGeneratorRustCrypto<'_> {
    /// A generator to be initialized before it generates. Constant time.
    pub const fn new() -> Self {
        Self { params: None }
    }
}

/// Through [`new`](RsaKeyPairGeneratorRustCrypto::new). Constant time.
impl Default for RsaKeyPairGeneratorRustCrypto<'_> {
    fn default() -> Self {
        Self::new()
    }
}

/// Keeps the parameters, of any kind, once they are checked: an odd public
/// exponent of at least three, a certainty of at least one, and a modulus
/// of 1024 to 8192 bits, the sizes `rsa` generates and takes. Variable
/// time: only for public values, as the parameters are.
impl<'a, P> KeyPairGeneratorInit<P> for RsaKeyPairGeneratorRustCrypto<'a>
where
    P: RsaKeyGenerationParams + 'a,
{
    type Error = RsaError;

    fn init(&mut self, params: P) -> Result<(), RsaError> {
        let e = params.public_exponent();
        if e < 3 || e & 1 == 0 {
            return Err(RsaError::InvalidPublicExponent);
        }
        if params.certainty() == 0 {
            return Err(RsaError::InvalidCertainty);
        }
        if !(MIN_STRENGTH..=MAX_STRENGTH).contains(&params.strength()) {
            return Err(RsaError::InvalidStrength);
        }
        self.params = Some(Box::new(params));
        Ok(())
    }
}

/// Generates a key pair through `RsaPrivateKey::new_with_exp`. Variable
/// time, as key generation everywhere is: how many candidates `rsa` draws
/// shows in the running time.
impl KeyPairGenerator for RsaKeyPairGeneratorRustCrypto<'_> {
    type PublicKey = RsaKeyRustCrypto;
    type PrivateKey = RsaPrivateCrtKeyRustCrypto;
    type Error = RsaError;

    fn generate_key_pair(
        &mut self,
    ) -> Result<(RsaKeyRustCrypto, RsaPrivateCrtKeyRustCrypto), RsaError> {
        let params = self.params.as_deref_mut().ok_or(RsaError::NotInitialized)?;
        let (e, strength) = (params.public_exponent(), params.strength());
        // The checks at init leave `rsa` no size or exponent to turn down.
        let key = RsaPrivateKey::new_with_exp(
            params.rng(),
            strength as usize,
            BoxedUint::from(u64::from(e)),
        )
        .map_err(|_| RsaError::InvalidStrength)?;
        let public = RsaKeyRustCrypto::new(key.to_public_key());
        Ok((public, RsaPrivateCrtKeyRustCrypto::new(key)?))
    }
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};

    use super::RsaKeyPairGeneratorRustCrypto;
    use crate::{RsaError, RsaKeyGenerationParamsOwned, RsaKeyParams, RsaPrivateCrtKeyParams};

    fn params() -> RsaKeyGenerationParamsOwned {
        RsaKeyGenerationParamsOwned::new(StdRng::seed_from_u64(1))
    }

    #[test]
    fn a_generated_pair_shares_its_modulus_and_exponent() {
        let mut generator = RsaKeyPairGeneratorRustCrypto::new();
        generator
            .init(params().with_strength(1024).with_public_exponent(3))
            .unwrap();
        let (public, private) = generator.generate_key_pair().unwrap();
        assert_eq!(public.modulus(), private.modulus());
        assert_eq!(public.exponent(), private.public_exponent());
        assert_eq!(public.modulus().bits(), 1024);
    }

    #[test]
    fn init_turns_down_what_rsa_cannot_generate() {
        let init = |params| RsaKeyPairGeneratorRustCrypto::new().init(params);
        assert_eq!(
            init(params().with_public_exponent(4)),
            Err(RsaError::InvalidPublicExponent)
        );
        assert_eq!(
            init(params().with_certainty(0)),
            Err(RsaError::InvalidCertainty)
        );
        assert_eq!(
            init(params().with_strength(512)),
            Err(RsaError::InvalidStrength)
        );
        assert_eq!(
            init(params().with_strength(8200)),
            Err(RsaError::InvalidStrength)
        );
    }

    #[test]
    fn a_generator_not_yet_initialized_generates_nothing() {
        let mut generator = RsaKeyPairGeneratorRustCrypto::new();
        assert_eq!(
            generator.generate_key_pair().err(),
            Some(RsaError::NotInitialized)
        );
    }
}
