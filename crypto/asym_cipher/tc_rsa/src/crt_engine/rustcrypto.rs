//! The RSA operation of a private key with the CRT through the RustCrypto
//! `rsa` crate.

use alloc::vec;
use core::convert::Infallible;

use rand_core::{CryptoRng, TryCryptoRng, TryRng};
use rsa::hazmat::rsa_decrypt_and_check;
use rsa::{BoxedUint, RsaPrivateKey};
use tc_asym_cipher::{AsymmetricBlockCipher, AsymmetricBlockCipherInit, CipherDirection};
use zeroize::Zeroizing;

use crate::block::{input_block_size, output_block_size};
use crate::core_engine::rustcrypto::{read_be, write_be};
use crate::{RsaBlinding, RsaError, RsaPrivateCrtKeyParams};

/// What an engine keeps from its initialization: the key as `rsa` holds
/// it, `n - 1` for the range check of the input, the size of the modulus
/// in bits, and the direction. `rsa` wipes its key.
struct CrtKey {
    key: RsaPrivateKey,
    modulus_less_one: BoxedUint,
    bits: u32,
    direction: CipherDirection,
}

/// No random source, for the `rsa` calls that take one only to blind; it
/// has no value, so none is ever drawn from.
enum NoRng {}

/// Never called, as there is no `NoRng`. Constant time.
impl TryRng for NoRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        match *self {}
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        match *self {}
    }

    fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), Infallible> {
        match *self {}
    }
}

impl TryCryptoRng for NoRng {}

/// The RSA operation of a private key with the CRT, `x^d mod n`, through
/// the hazmat `rsa_decrypt_and_check` of the RustCrypto `rsa` crate, which
/// checks the result by raising it back to `e`, as Lenstra's attack on the
/// CRT needs, for decryption and for signing. The blocks are as those of
/// [`FixedRsaCoreEngine`](crate::FixedRsaCoreEngine): the output always
/// takes the full length of the modulus, leading zeros kept. There is no
/// blinding, as in Bouncy Castle's core engine.
///
/// From a new key to a block encrypted with the public key and decrypted
/// through the CRT; the example of
/// [`RsaCoreEngineRustCrypto`](crate::RsaCoreEngineRustCrypto) runs the
/// same steps:
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
/// // 1. Generate a key pair through `rsa`.
/// let mut generator = RsaKeyPairGeneratorRustCrypto::new();
/// generator.init(RsaKeyGenerationParamsOwned::new(rand::rng()))?;
/// let (public, private) = generator.generate_key_pair()?;
///
/// // 2. Sign a block with the private key, through the CRT. Raw RSA is
/// //    shown here; a real signature goes through a padding, such as PSS.
/// let block = b"a block of at most 255 bytes";
/// let mut sign = RsaCrtCoreEngineRustCrypto::new();
/// sign.init(CipherDirection::Encrypt, &private)?;
/// let mut signature = [0; 256];
/// sign.process_block(block, &mut signature)?;
///
/// // 3. Raise the signature back with the public key: the block comes back
/// //    at the end, after leading zeros, for the padding to check.
/// let mut verify = RsaCoreEngineRustCrypto::new();
/// verify.init(CipherDirection::Decrypt, &public)?;
/// let mut recovered = [0; 256];
/// verify.process_block(&signature, &mut recovered)?;
/// # Ok::<(), tc_rsa_v2::RsaError>(())
/// ```
pub struct RsaCrtCoreEngineRustCrypto {
    key: Option<CrtKey>,
}

impl RsaCrtCoreEngineRustCrypto {
    /// An engine to be initialized before it processes. Constant time.
    pub const fn new() -> Self {
        Self { key: None }
    }

    /// The key, once the engine is initialized. Constant time.
    fn key(&self) -> Result<&CrtKey, RsaError> {
        self.key.as_ref().ok_or(RsaError::NotInitialized)
    }
}

/// Through [`new`](RsaCrtCoreEngineRustCrypto::new). Constant time.
impl Default for RsaCrtCoreEngineRustCrypto {
    fn default() -> Self {
        Self::new()
    }
}

/// Writes [`ALGO_NAME`](crate::ALGO_NAME) without inspecting key material.
/// Constant time with respect to the key; output timing depends on the
/// formatter.
impl core::fmt::Display for RsaCrtCoreEngineRustCrypto {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(crate::ALGO_NAME)
    }
}

/// Builds the `rsa` key of the modulus, the exponents and the primes
/// through `RsaPrivateKey::from_components`, which checks the key and works
/// out its CRT values, once [`validate`](crate::RsaKeyParams::validate)
/// passes the key, and fails with `InvalidKey` otherwise. Variable time:
/// only for public values, as the modulus and the outcome of the checks
/// are; the secret values are worked through by `rsa`, as it makes them.
impl<P> AsymmetricBlockCipherInit<P> for RsaCrtCoreEngineRustCrypto
where
    P: RsaPrivateCrtKeyParams<BoxedUint>,
{
    type Error = RsaError;

    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), RsaError> {
        if !params.validate() {
            return Err(RsaError::InvalidKey);
        }
        let n = params.modulus();
        let key = RsaPrivateKey::from_components(
            n.clone(),
            params.public_exponent().clone(),
            params.exponent().clone(),
            vec![params.p().clone(), params.q().clone()],
        )
        .map_err(|_| RsaError::InvalidKey)?;
        self.key = Some(CrtKey {
            modulus_less_one: n.wrapping_sub(BoxedUint::one_with_precision(n.bits_precision())),
            bits: n.bits(),
            direction,
            key,
        });
        Ok(())
    }
}

/// Reads the input as a big-endian integer `x` with `1 < x < n - 1`, as
/// Bouncy Castle does, computes `x^d mod n` through the CRT of
/// `rsa_decrypt_and_check`, and fails with `FaultyDecryptionOrSigning`
/// when the result does not raise back to `x`, writing nothing; otherwise
/// it writes the result over the full length of the modulus. As constant
/// time as `rsa` and `crypto-bigint` make the powers in the secret values;
/// the check raises to the public `e` in variable time, and the outcome of
/// the range check and of the check of the result show in the error.
impl AsymmetricBlockCipher for RsaCrtCoreEngineRustCrypto {
    type Error = RsaError;

    /// `(bits - 1) / 8` bytes when encrypting, which here is signing, and
    /// `(bits + 7) / 8` when decrypting; zero before initialization.
    /// Constant time.
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
        self.run(input, output, None::<&mut NoRng>)
    }
}

/// Hands the random source to `rsa_decrypt_and_check`, which blinds with
/// it as Bouncy Castle's `RsaBlindedEngine` does: `x · r^e` goes through
/// the CRT, and `r` is taken away from the result. As constant time as
/// `rsa` and `crypto-bigint` make the blinding and the powers.
impl RsaBlinding for RsaCrtCoreEngineRustCrypto {
    fn process_block_blinded<R: CryptoRng + ?Sized>(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        rng: &mut R,
    ) -> Result<usize, RsaError> {
        self.run(input, output, Some(rng))
    }
}

impl RsaCrtCoreEngineRustCrypto {
    /// Checks the blocks, reads the input as a big-endian integer `x` with
    /// `1 < x < n - 1`, computes `x^d mod n` through `rsa_decrypt_and_check`,
    /// blinded when `rng` is given, and writes the result over the full
    /// length of the modulus. Timing as the impls that call it state.
    fn run<R: TryCryptoRng + ?Sized>(
        &self,
        input: &[u8],
        output: &mut [u8],
        rng: Option<&mut R>,
    ) -> Result<usize, RsaError> {
        let key = self.key()?;
        if input.len() > self.input_block_size() {
            return Err(RsaError::InputTooLarge);
        }
        let length = self.output_block_size();
        if output.len() < length {
            return Err(RsaError::OutputTooShort);
        }
        let x = read_be(input, &key.modulus_less_one)?;
        // The input lies below the modulus, so `rsa` only fails the check,
        // or a blinding factor it cannot invert.
        let m = rsa_decrypt_and_check(&key.key, rng, &x)
            .map_err(|_| RsaError::FaultyDecryptionOrSigning)?;
        let m = Zeroizing::new(m);
        write_be(&m, &mut output[..length]);
        Ok(length)
    }
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use tc_asym_cipher::{
        AsymmetricBlockCipher, AsymmetricBlockCipherInit, CipherDirection, KeyPairGenerator,
        KeyPairGeneratorInit,
    };

    use super::RsaCrtCoreEngineRustCrypto;
    use crate::{
        RsaCoreEngineRustCrypto, RsaError, RsaKeyGenerationParamsOwned,
        RsaKeyPairGeneratorRustCrypto,
    };

    #[test]
    fn a_block_encrypted_with_the_public_key_comes_back_through_the_crt() {
        let mut generator = RsaKeyPairGeneratorRustCrypto::new();
        generator
            .init(RsaKeyGenerationParamsOwned::new(StdRng::seed_from_u64(1)).with_strength(1024))
            .unwrap();
        let (public, private) = generator.generate_key_pair().unwrap();

        let mut encrypt = RsaCoreEngineRustCrypto::new();
        encrypt.init(CipherDirection::Encrypt, &public).unwrap();
        let mut message = [0x42; 127];
        message[0] = 0x01;
        let mut ciphertext = [0; 128];
        encrypt.process_block(&message, &mut ciphertext).unwrap();

        let mut decrypt = RsaCrtCoreEngineRustCrypto::new();
        decrypt.init(CipherDirection::Decrypt, &private).unwrap();
        let mut plaintext = [0; 128];
        assert_eq!(decrypt.process_block(&ciphertext, &mut plaintext), Ok(128));
        assert_eq!(plaintext[0], 0);
        assert_eq!(&plaintext[1..], &message[..]);
        assert_eq!(
            decrypt.process_block(&[1], &mut plaintext),
            Err(RsaError::InputTooSmall)
        );
    }

    #[test]
    fn a_blinded_block_comes_out_as_the_unblinded_one() {
        let mut generator = RsaKeyPairGeneratorRustCrypto::new();
        generator
            .init(RsaKeyGenerationParamsOwned::new(StdRng::seed_from_u64(4)).with_strength(1024))
            .unwrap();
        let (_, private) = generator.generate_key_pair().unwrap();
        let mut plain = RsaCrtCoreEngineRustCrypto::new();
        plain.init(CipherDirection::Encrypt, &private).unwrap();
        let mut blinded =
            crate::RsaBlindedEngine::<RsaCrtCoreEngineRustCrypto, _>::new(StdRng::seed_from_u64(5));
        blinded.init(CipherDirection::Encrypt, &private).unwrap();
        let (mut expected, mut output) = ([0; 128], [0; 128]);
        plain.process_block(&[0x29; 127], &mut expected).unwrap();
        blinded.process_block(&[0x29; 127], &mut output).unwrap();
        assert_eq!(output, expected);
    }

    #[test]
    fn an_engine_not_yet_initialized_processes_nothing() {
        let mut engine = RsaCrtCoreEngineRustCrypto::new();
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
