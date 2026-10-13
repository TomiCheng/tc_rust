//! The generator of [`RsaKey`] pairs, on the safest generator available.

use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};

use crate::{RsaError, RsaKey, RsaKeyGenerationParams};

/// The generator underneath: that of the RustCrypto `rsa` crate when the
/// `rustcrypto` feature is on, and that of this crate otherwise.
#[cfg(feature = "rustcrypto")]
type Inner<'a> = crate::RsaKeyPairGeneratorRustCrypto<'a>;
#[cfg(not(feature = "rustcrypto"))]
type Inner<'a> = crate::RsaKeyPairGenerator<'a, tc_bigint::PaddedBigUint>;

/// Generates pairs of [`RsaKey`], the public one a
/// [`Core`](RsaKey::Core) key and the private one a [`Crt`](RsaKey::Crt)
/// key, as Bouncy Castle's `RsaKeyPairGenerator` does: through the
/// RustCrypto `rsa` crate when the `rustcrypto` feature is on, and through
/// [`RsaKeyPairGenerator`](crate::RsaKeyPairGenerator) over
/// `PaddedBigUint` otherwise. The type and its API are the same either
/// way; only the generator inside changes. It takes the parameters both
/// take, of any kind that implements [`RsaKeyGenerationParams`], for as
/// long as `'a`, which is inferred.
///
/// ```
/// use tc_asym_cipher::{AsymmetricKeyParams, KeyPairGenerator, KeyPairGeneratorInit};
/// use tc_rsa_v2::{RsaKey, RsaKeyGenerationParamsOwned, RsaKeyGenerator};
///
/// // A 2048-bit pair, with the public exponent 65537, drawn from the
/// // system's random source.
/// let mut generator = RsaKeyGenerator::new();
/// generator.init(RsaKeyGenerationParamsOwned::new(rand::rng()))?;
/// let (public, private) = generator.generate_key_pair()?;
///
/// // The public key is raised by `e`; the private one through the CRT.
/// assert!(matches!(public, RsaKey::Core(_)) && !public.is_private_key());
/// assert!(matches!(private, RsaKey::Crt(_)));
/// # Ok::<(), tc_rsa_v2::RsaError>(())
/// ```
pub struct RsaKeyGenerator<'a> {
    inner: Inner<'a>,
}

impl RsaKeyGenerator<'_> {
    /// A generator to be initialized before it generates. Constant time.
    pub fn new() -> Self {
        Self {
            inner: Inner::new(),
        }
    }
}

/// Through [`new`](RsaKeyGenerator::new). Constant time.
impl Default for RsaKeyGenerator<'_> {
    fn default() -> Self {
        Self::new()
    }
}

/// Keeps the parameters once the generator underneath checks them.
/// Variable time: only for public values, as the parameters are.
impl<'a, P> KeyPairGeneratorInit<P> for RsaKeyGenerator<'a>
where
    P: RsaKeyGenerationParams + 'a,
{
    type Error = RsaError;

    fn init(&mut self, params: P) -> Result<(), RsaError> {
        self.inner.init(params)
    }
}

/// A pair from the generator underneath, as [`RsaKey`]. Variable time, as
/// key generation everywhere is: how many candidates are drawn shows in
/// the running time; the generator underneath tells the rest.
impl KeyPairGenerator for RsaKeyGenerator<'_> {
    type PublicKey = RsaKey;
    type PrivateKey = RsaKey;
    type Error = RsaError;

    fn generate_key_pair(&mut self) -> Result<(RsaKey, RsaKey), RsaError> {
        let (public, private) = self.inner.generate_key_pair()?;
        Ok((public.into(), private.into()))
    }
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use tc_asym_cipher::{
        AsymmetricBlockCipher, AsymmetricBlockCipherInit, AsymmetricKeyParams, CipherDirection,
        KeyPairGenerator, KeyPairGeneratorInit,
    };

    use super::RsaKeyGenerator;
    use crate::{PaddedRsaCoreEngine, RsaKey, RsaKeyGenerationParamsOwned, RsaKeyParams};

    #[test]
    fn a_generated_pair_is_a_public_core_key_and_a_private_crt_key_of_one_modulus() {
        let mut generator = RsaKeyGenerator::new();
        let params = RsaKeyGenerationParamsOwned::new(StdRng::seed_from_u64(1)).with_strength(1024);
        generator.init(params).unwrap();
        let (public, private) = generator.generate_key_pair().unwrap();
        assert!(matches!(public, RsaKey::Core(_)) && !public.is_private_key());
        assert!(matches!(private, RsaKey::Crt(_)) && private.is_private_key());
        assert_eq!(public.modulus(), private.modulus());
        assert_eq!(public.modulus().bits(), 1024);
        assert!(public.validate() && private.validate());
    }

    #[test]
    fn a_generated_pair_encrypts_and_decrypts_a_block() {
        let mut generator = RsaKeyGenerator::new();
        let params = RsaKeyGenerationParamsOwned::new(StdRng::seed_from_u64(2)).with_strength(1024);
        generator.init(params).unwrap();
        let (public, private) = generator.generate_key_pair().unwrap();
        let message = [0x5a; 127];
        let mut engine = PaddedRsaCoreEngine::new();
        engine.init(CipherDirection::Encrypt, &public).unwrap();
        let mut ciphertext = [0; 128];
        engine.process_block(&message, &mut ciphertext).unwrap();
        engine.init(CipherDirection::Decrypt, &private).unwrap();
        let mut plaintext = [0; 128];
        engine.process_block(&ciphertext, &mut plaintext).unwrap();
        assert_eq!(&plaintext[1..], &message[..]);
    }
}
