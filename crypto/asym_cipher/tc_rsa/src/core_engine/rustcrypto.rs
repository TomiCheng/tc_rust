//! The RSA operation of a public key through the RustCrypto `rsa` crate.

use rsa::hazmat::rsa_encrypt;
use rsa::{BoxedUint, RsaPublicKey};
use tc_asym_cipher::{AsymmetricBlockCipher, AsymmetricBlockCipherInit, CipherDirection};
use zeroize::Zeroizing;

use crate::block::{input_block_size, output_block_size};
use crate::{RsaError, RsaKeyParams};

/// What an engine keeps from its initialization: the key as `rsa` holds
/// it, `n - 1` for the range check of the input, the size of the modulus
/// in bits, and the direction.
struct Key {
    key: RsaPublicKey,
    modulus_less_one: BoxedUint,
    bits: u32,
    direction: CipherDirection,
}

/// The RSA operation of a public key, `x^e mod n`, through the hazmat
/// `rsa_encrypt` of the RustCrypto `rsa` crate, for encryption and for the
/// check of a signature. A private key goes through
/// [`RsaCrtCoreEngineRustCrypto`](crate::RsaCrtCoreEngineRustCrypto), as
/// `rsa` cannot build one of `n` and `d` alone. The blocks are as those of
/// [`FixedRsaCoreEngine`](crate::FixedRsaCoreEngine): the output always
/// takes the full length of the modulus, leading zeros kept.
///
/// From a new key to a block encrypted and decrypted through `rsa`:
///
/// ```
/// use tc_asym_cipher::{
///     AsymmetricBlockCipher, AsymmetricBlockCipherInit, CipherDirection, KeyPairGenerator,
///     KeyPairGeneratorInit,
/// };
/// use tc_rsa_v2::{
///     RsaCoreEngineRustCrypto, RsaCrtCoreEngineRustCrypto, RsaKeyGenerationParamsOwned,
///     RsaKeyPairGeneratorRustCrypto,
/// };
///
/// // 1. Generate a key pair through `rsa`: a 2048-bit modulus and the
/// //    public exponent 65537, drawn from the system's random source.
/// let mut generator = RsaKeyPairGeneratorRustCrypto::new();
/// generator.init(RsaKeyGenerationParamsOwned::new(rand::rng()))?;
/// let (public, private) = generator.generate_key_pair()?;
///
/// // 2. Encrypt a block with the public key. Raw RSA is shown here; a real
/// //    message goes through a padding, such as OAEP, first.
/// let message = b"a block of at most 255 bytes";
/// let mut encrypt = RsaCoreEngineRustCrypto::new();
/// encrypt.init(CipherDirection::Encrypt, &public)?;
/// let mut ciphertext = [0; 256];
/// encrypt.process_block(message, &mut ciphertext)?;
///
/// // 3. Decrypt it with the private key, through the CRT of `rsa`.
/// let mut decrypt = RsaCrtCoreEngineRustCrypto::new();
/// decrypt.init(CipherDirection::Decrypt, &private)?;
/// let mut plaintext = [0; 256];
/// decrypt.process_block(&ciphertext, &mut plaintext)?;
/// let recovered = &plaintext[256 - message.len()..];
/// # Ok::<(), tc_rsa_v2::RsaError>(())
/// ```
pub struct RsaCoreEngineRustCrypto {
    key: Option<Key>,
}

impl RsaCoreEngineRustCrypto {
    /// An engine to be initialized before it processes. Constant time.
    pub const fn new() -> Self {
        Self { key: None }
    }

    /// The key, once the engine is initialized. Constant time.
    fn key(&self) -> Result<&Key, RsaError> {
        self.key.as_ref().ok_or(RsaError::NotInitialized)
    }
}

/// Through [`new`](RsaCoreEngineRustCrypto::new). Constant time.
impl Default for RsaCoreEngineRustCrypto {
    fn default() -> Self {
        Self::new()
    }
}

/// Writes [`ALGO_NAME`](crate::ALGO_NAME) without inspecting key material.
/// Constant time with respect to the key; output timing depends on the
/// formatter.
impl core::fmt::Display for RsaCoreEngineRustCrypto {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(crate::ALGO_NAME)
    }
}

/// Builds the `rsa` key of the modulus and the public exponent, once
/// [`validate`](RsaKeyParams::validate) passes the key and `rsa` takes it,
/// and fails with `InvalidKey` otherwise, or for a private key. Variable
/// time: only for public values, as a public key is.
impl<P> AsymmetricBlockCipherInit<P> for RsaCoreEngineRustCrypto
where
    P: RsaKeyParams<BoxedUint>,
{
    type Error = RsaError;

    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), RsaError> {
        if params.is_private_key() || !params.validate() {
            return Err(RsaError::InvalidKey);
        }
        let (n, e) = (params.modulus(), params.exponent());
        let key = RsaPublicKey::new(n.clone(), e.clone()).map_err(|_| RsaError::InvalidKey)?;
        self.key = Some(Key {
            modulus_less_one: n.wrapping_sub(BoxedUint::one_with_precision(n.bits_precision())),
            bits: n.bits(),
            direction,
            key,
        });
        Ok(())
    }
}

/// Reads the input as a big-endian integer `x` with `1 < x < n - 1`, as
/// Bouncy Castle does, raises it to `e` through `rsa_encrypt`, and writes
/// the result over the full length of the modulus. Variable time: only for
/// public values, as `rsa_encrypt` raises to the public `e` from its top
/// bit; the outcome of the range check shows in the error.
impl AsymmetricBlockCipher for RsaCoreEngineRustCrypto {
    type Error = RsaError;

    /// `(bits - 1) / 8` bytes when encrypting, and `(bits + 7) / 8` when
    /// checking a signature; zero before initialization. Constant time.
    fn input_block_size(&self) -> usize {
        self.key
            .as_ref()
            .map_or(0, |key| input_block_size(key.bits, key.direction))
    }

    /// `(bits + 7) / 8` bytes in both directions; zero before
    /// initialization. Constant time.
    fn output_block_size(&self) -> usize {
        self.key
            .as_ref()
            .map_or(0, |key| output_block_size(key.bits))
    }

    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, RsaError> {
        let key = self.key()?;
        if input.len() > self.input_block_size() {
            return Err(RsaError::InputTooLarge);
        }
        let length = self.output_block_size();
        if output.len() < length {
            return Err(RsaError::OutputTooShort);
        }
        let x = read_be(input, &key.modulus_less_one)?;
        let result = rsa_encrypt(&key.key, &x).map_err(|_| RsaError::InputTooLarge)?;
        write_be(&result, &mut output[..length]);
        Ok(length)
    }
}

/// `input` as a big-endian integer at the precision of `modulus_less_one`,
/// once it lies in `1 < x < n - 1`, as Bouncy Castle asks, wiped when it
/// is dropped. Constant time, apart from the outcome of the range check.
pub(crate) fn read_be(
    input: &[u8],
    modulus_less_one: &BoxedUint,
) -> Result<Zeroizing<BoxedUint>, RsaError> {
    let x = BoxedUint::from_be_slice(input, modulus_less_one.bits_precision())
        .map_err(|_| RsaError::InputTooLarge)?;
    let x = Zeroizing::new(x);
    if x.bits() <= 1 {
        return Err(RsaError::InputTooSmall);
    }
    if *x >= *modulus_less_one {
        return Err(RsaError::InputTooLarge);
    }
    Ok(x)
}

/// `value` big-endian over all of `output`, which holds it: the low bytes
/// of the full precision of `value`, its bytes wiped once they are copied.
/// Constant time: the lengths are public.
pub(crate) fn write_be(value: &BoxedUint, output: &mut [u8]) {
    let bytes = Zeroizing::new(value.to_be_bytes());
    output.copy_from_slice(&bytes[bytes.len() - output.len()..]);
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use rsa::BoxedUint;
    use tc_asym_cipher::{
        AsymmetricBlockCipher, AsymmetricBlockCipherInit, CipherDirection, KeyPairGenerator,
        KeyPairGeneratorInit,
    };
    use tc_bigint::{ArrayEncoding, PaddedBigUint};

    use super::RsaCoreEngineRustCrypto;
    use crate::{
        PaddedRsaCoreEngine, RsaError, RsaKeyGenerationParamsOwned, RsaKeyOwned,
        RsaKeyPairGeneratorRustCrypto, RsaKeyParams,
    };

    #[test]
    fn it_encrypts_as_the_padded_engine_of_this_crate_does() {
        let mut generator = RsaKeyPairGeneratorRustCrypto::new();
        generator
            .init(RsaKeyGenerationParamsOwned::new(StdRng::seed_from_u64(1)).with_strength(1024))
            .unwrap();
        let (public, _) = generator.generate_key_pair().unwrap();
        let mut engine = RsaCoreEngineRustCrypto::new();
        engine.init(CipherDirection::Encrypt, &public).unwrap();

        let padded = |value: &BoxedUint| PaddedBigUint::from_be(&value.to_be_bytes()).unwrap();
        let ours = RsaKeyOwned::new(false, padded(public.modulus()), padded(public.exponent()));
        let mut padded_engine = PaddedRsaCoreEngine::new();
        padded_engine.init(CipherDirection::Encrypt, &ours).unwrap();

        let (mut theirs_out, mut ours_out) = ([0; 128], [0; 128]);
        engine.process_block(&[0x5a; 127], &mut theirs_out).unwrap();
        padded_engine
            .process_block(&[0x5a; 127], &mut ours_out)
            .unwrap();
        assert_eq!(theirs_out, ours_out);
    }

    /// A private key of `n` and `d` over `BoxedUint`, which passes its
    /// checks.
    struct Private {
        n: BoxedUint,
        d: BoxedUint,
    }

    impl RsaKeyParams<BoxedUint> for Private {
        fn is_private_key(&self) -> bool {
            true
        }

        fn modulus(&self) -> &BoxedUint {
            &self.n
        }

        fn exponent(&self) -> &BoxedUint {
            &self.d
        }

        fn validate(&self) -> bool {
            true
        }
    }

    #[test]
    fn a_private_key_is_turned_down() {
        let key = Private {
            n: BoxedUint::from(1_022_117u32),
            d: BoxedUint::from(180_017u32),
        };
        let mut engine = RsaCoreEngineRustCrypto::new();
        assert_eq!(
            engine.init(CipherDirection::Decrypt, &key),
            Err(RsaError::InvalidKey)
        );
    }

    #[test]
    fn an_engine_not_yet_initialized_processes_nothing() {
        let mut engine = RsaCoreEngineRustCrypto::new();
        assert_eq!(
            (engine.input_block_size(), engine.output_block_size()),
            (0, 0)
        );
        assert_eq!(
            engine.process_block(&[2], &mut [0; 2]),
            Err(RsaError::NotInitialized)
        );
    }
}
