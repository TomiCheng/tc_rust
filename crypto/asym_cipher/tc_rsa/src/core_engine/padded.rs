//! The RSA operation without the CRT, as Bouncy Castle's `RsaCoreEngine`
//! runs it for a key that is not a CRT key, over `PaddedBigUint`.

use tc_asym_cipher::{AsymmetricBlockCipher, AsymmetricBlockCipherInit, CipherDirection};
use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_modular::{Odd, PaddedMontyForm, PaddedMontyParams};
use tc_zeroize::{Zeroize, Zeroizing};

use crate::block::{input_block_size, output_block_size, write_be};
use crate::{RsaError, RsaKeyParams};

/// What an engine keeps from its initialization: `n - 1` for the range
/// check of the input, the exponent and whether it is private, the
/// Montgomery parameters of the modulus, the size of the modulus in bits,
/// and the direction. The exponent, `n - 1` and the parameters are wiped on
/// drop.
struct Key {
    modulus_less_one: PaddedBigUint,
    exponent: PaddedBigUint,
    is_private: bool,
    params: PaddedMontyParams,
    bits: u32,
    direction: CipherDirection,
}

/// Wipes the exponent, which is `d` for a private key, `n - 1` and the
/// parameters. Constant time: the widths are public.
impl Drop for Key {
    fn drop(&mut self) {
        self.exponent.zeroize();
        self.modulus_less_one.zeroize();
        self.params.zeroize();
    }
}

/// The RSA operation without the CRT over [`PaddedBigUint`], `x^e mod n`
/// for a public key and `x^d mod n` for a private one, as Bouncy Castle's
/// `RsaCoreEngine` runs it for a key that is not a CRT key, at the width
/// of the modulus. The key is copied in at initialization.
///
/// The output always takes the full length of the modulus, `(bits + 7) / 8`
/// bytes, leading zeros kept, in both directions. Bouncy Castle trims them
/// from a decryption, which lets the length show whether the result starts
/// with a zero byte, as Manger's attack on OAEP needs; trimming is left to
/// the padding, once it has checked the block. The output block is one
/// byte longer than Bouncy Castle's when decrypting.
///
/// From a new key to a block encrypted and decrypted. `PaddedBigUint` takes
/// its width from the key, so the size of the modulus can be chosen at run
/// time, and the blocks are sized from the engine:
///
/// ```
/// use tc_asym_cipher::{
///     AsymmetricBlockCipher, AsymmetricBlockCipherInit, CipherDirection, KeyPairGenerator,
///     KeyPairGeneratorInit,
/// };
/// use tc_bigint::PaddedBigUint;
/// use tc_rsa_v2::{PaddedRsaCoreEngine, RsaKeyGenerationParamsOwned, RsaKeyPairGenerator};
///
/// // 1. Generate a key pair: a 2048-bit modulus and the public exponent
/// //    65537, drawn from the system's random source; `with_strength`
/// //    picks another size.
/// let mut generator = RsaKeyPairGenerator::<PaddedBigUint>::new();
/// generator.init(RsaKeyGenerationParamsOwned::new(rand::rng()).with_strength(2048))?;
/// let (public, private) = generator.generate_key_pair()?;
///
/// // 2. Encrypt a block with the public key. Raw RSA is shown here; a real
/// //    message goes through a padding, such as OAEP, first.
/// let message = b"a block shorter than the modulus";
/// let mut engine = PaddedRsaCoreEngine::new();
/// engine.init(CipherDirection::Encrypt, &public)?;
/// let mut ciphertext = vec![0; engine.output_block_size()];
/// engine.process_block(message, &mut ciphertext)?;
///
/// // 3. Decrypt it with the private key. The output takes the full length
/// //    of the modulus: the message comes back at the end, after leading
/// //    zeros, for the padding to take apart.
/// engine.init(CipherDirection::Decrypt, &private)?;
/// let mut plaintext = vec![0; engine.output_block_size()];
/// engine.process_block(&ciphertext, &mut plaintext)?;
/// let recovered = &plaintext[plaintext.len() - message.len()..];
/// # Ok::<(), tc_rsa_v2::RsaError>(())
/// ```
pub struct PaddedRsaCoreEngine {
    key: Option<Key>,
}

impl PaddedRsaCoreEngine {
    /// An engine to be initialized before it processes. Constant time.
    pub const fn new() -> Self {
        Self { key: None }
    }

    /// The key, once the engine is initialized. Constant time.
    fn key(&self) -> Result<&Key, RsaError> {
        self.key.as_ref().ok_or(RsaError::NotInitialized)
    }
}

/// Through [`new`](PaddedRsaCoreEngine::new). Constant time.
impl Default for PaddedRsaCoreEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Writes [`ALGO_NAME`](crate::ALGO_NAME) without inspecting key material.
/// Constant time with respect to the key; output timing depends on the
/// formatter.
impl core::fmt::Display for PaddedRsaCoreEngine {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(crate::ALGO_NAME)
    }
}

/// Copies the key in, once [`validate`](crate::RsaKeyParams::validate)
/// passes it, as Bouncy Castle checks a key when its `RsaKeyParameters` is
/// built, and works out the Montgomery parameters of the modulus; fails
/// with `InvalidKey` when the key does not pass, or when the modulus is
/// even, which a Montgomery form cannot take. The keys of this crate are
/// checked once, however often they are given. Variable time: only for
/// public values, as the modulus and the outcome of the checks are.
impl<P> AsymmetricBlockCipherInit<P> for PaddedRsaCoreEngine
where
    P: RsaKeyParams<PaddedBigUint>,
{
    type Error = RsaError;

    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), RsaError> {
        if !params.validate() {
            return Err(RsaError::InvalidKey);
        }
        let modulus = params.modulus();
        let odd = Odd::new(modulus.clone()).ok_or(RsaError::InvalidKey)?;
        self.key = Some(Key {
            modulus_less_one: modulus - 1u32,
            exponent: params.exponent().clone(),
            is_private: params.is_private_key(),
            params: PaddedMontyParams::new(odd),
            bits: modulus.bits(),
            direction,
        });
        Ok(())
    }
}

/// Reads the input as a big-endian integer `x` with `1 < x < n - 1`, as
/// Bouncy Castle does, raises it to the exponent mod `n` in Montgomery
/// form, and writes the result over the full length of the modulus. A
/// private exponent is raised to in constant time, over every bit of its
/// width; a public one from its top bit only, in variable time, as `e` is
/// public, so that encryption and verification cost the few squarings of
/// `e`. The outcome of the range check shows in the error.
impl AsymmetricBlockCipher for PaddedRsaCoreEngine {
    type Error = RsaError;

    /// `(bits - 1) / 8` bytes when encrypting, so that any input is below
    /// the modulus, and `(bits + 7) / 8` when decrypting; zero before
    /// initialization. Constant time.
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
        let Ok(x) = PaddedBigUint::from_be(input);
        let x = Zeroizing::new(x);
        if x.bits() <= 1 {
            return Err(RsaError::InputTooSmall);
        }
        if *x >= key.modulus_less_one {
            return Err(RsaError::InputTooLarge);
        }
        let form = Zeroizing::new(PaddedMontyForm::new(&x, &key.params));
        let power = Zeroizing::new(match key.is_private {
            true => form.pow(&key.exponent),
            false => form.pow_vartime(&key.exponent),
        });
        let result = Zeroizing::new(power.retrieve());
        write_be(&*result, &mut output[..length]);
        Ok(length)
    }
}

#[cfg(test)]
mod tests {
    use tc_asym_cipher::{AsymmetricBlockCipherInit, CipherDirection};
    use tc_bigint::{ArrayEncoding, PaddedBigUint};

    use super::PaddedRsaCoreEngine;
    use crate::core_engine::fixed::tests::{round_trip, wycheproof};
    use crate::testing::{D, N, hex};
    use crate::{RsaError, RsaKeyOwned};

    fn engines() -> (PaddedRsaCoreEngine, PaddedRsaCoreEngine) {
        let int = |bytes: &[u8]| PaddedBigUint::from_be(bytes).unwrap();
        let n = int(&hex::<256>(N));
        let mut encrypt = PaddedRsaCoreEngine::new();
        encrypt
            .init(
                CipherDirection::Encrypt,
                &RsaKeyOwned::new(false, n.clone(), int(&[1, 0, 1])),
            )
            .unwrap();
        let mut decrypt = PaddedRsaCoreEngine::new();
        decrypt
            .init(
                CipherDirection::Decrypt,
                &RsaKeyOwned::new(true, n, int(&hex::<256>(D))),
            )
            .unwrap();
        (encrypt, decrypt)
    }

    #[test]
    fn a_2048_bit_message_round_trips_as_over_fixed_width_integers() {
        let (mut encrypt, mut decrypt) = engines();
        let (mut fixed_encrypt, mut fixed_decrypt) = wycheproof();
        assert_eq!(
            round_trip(&mut encrypt, &mut decrypt),
            round_trip(&mut fixed_encrypt, &mut fixed_decrypt)
        );
    }

    #[test]
    fn init_turns_down_a_key_that_fails_its_checks() {
        let key = RsaKeyOwned::new(
            false,
            PaddedBigUint::from(3233u32),
            PaddedBigUint::from(17u32),
        );
        let mut engine = PaddedRsaCoreEngine::new();
        assert_eq!(
            engine.init(CipherDirection::Encrypt, &key),
            Err(RsaError::InvalidKey)
        );
    }
}
