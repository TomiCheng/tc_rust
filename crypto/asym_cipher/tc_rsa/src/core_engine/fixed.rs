//! The RSA operation without the CRT, as Bouncy Castle's `RsaCoreEngine`
//! runs it for a key that is not a CRT key, over `FixedBigUint`.

use tc_asym_cipher::{AsymmetricBlockCipher, AsymmetricBlockCipherInit, CipherDirection};
use tc_bigint::{ArrayEncoding, FixedBigUint};
use tc_modular::{FixedMontyForm, FixedMontyParams, Odd};
use tc_zeroize::{Zeroize, Zeroizing};

use crate::block::{input_block_size, output_block_size, write_be};
use crate::{RsaError, RsaKeyParams};

/// What an engine keeps from its initialization: `n - 1` for the range
/// check of the input, the exponent and whether it is private, the
/// Montgomery parameters of the modulus, the size of the modulus in bits,
/// and the direction. The exponent, `n - 1` and the parameters are wiped on
/// drop.
struct Key<const N: usize> {
    modulus_less_one: FixedBigUint<N>,
    exponent: FixedBigUint<N>,
    is_private: bool,
    params: FixedMontyParams<N>,
    bits: u32,
    direction: CipherDirection,
}

/// Wipes the exponent, which is `d` for a private key, `n - 1` and the
/// parameters. Constant time.
impl<const N: usize> Drop for Key<N> {
    fn drop(&mut self) {
        self.exponent.zeroize();
        self.modulus_less_one.zeroize();
        self.params.zeroize();
    }
}

/// The RSA operation without the CRT over [`FixedBigUint`] at `N` limbs,
/// `x^e mod n` for a public key and `x^d mod n` for a private one, as
/// Bouncy Castle's `RsaCoreEngine` runs it for a key that is not a CRT key.
/// The key is copied in at initialization, and nothing is allocated.
///
/// The output always takes the full length of the modulus, `(bits + 7) / 8`
/// bytes, leading zeros kept, in both directions. Bouncy Castle trims them
/// from a decryption, which lets the length show whether the result starts
/// with a zero byte, as Manger's attack on OAEP needs; trimming is left to
/// the padding, once it has checked the block. The output block is one
/// byte longer than Bouncy Castle's when decrypting.
///
/// From a new key to a block encrypted and decrypted; key generation takes
/// the `alloc` feature, while the engine does not:
///
/// ```
/// # #[cfg(feature = "alloc")] {
/// use tc_asym_cipher::{
///     AsymmetricBlockCipher, AsymmetricBlockCipherInit, CipherDirection, KeyPairGenerator,
///     KeyPairGeneratorInit,
/// };
/// use tc_bigint::{FixedBigUint, Word};
/// use tc_rsa_v2::{FixedRsaCoreEngine, RsaKeyGenerationParamsOwned, RsaKeyPairGenerator};
///
/// // Integers of 2048 bits, whatever the width of a limb.
/// type U2048 = FixedBigUint<{ 2048 / Word::BITS as usize }>;
///
/// // 1. Generate a key pair: by default a 2048-bit modulus and the public
/// //    exponent 65537, drawn from the system's random source.
/// let mut generator = RsaKeyPairGenerator::<U2048>::new();
/// generator.init(RsaKeyGenerationParamsOwned::new(rand::rng()))?;
/// let (public, private) = generator.generate_key_pair()?;
///
/// // 2. Encrypt a block with the public key. Raw RSA is shown here; a real
/// //    message goes through a padding, such as OAEP, first.
/// let message = b"a block of at most 255 bytes";
/// let mut engine = FixedRsaCoreEngine::new();
/// engine.init(CipherDirection::Encrypt, &public)?;
/// let mut ciphertext = [0; 256];
/// engine.process_block(message, &mut ciphertext)?;
///
/// // 3. Decrypt it with the private key. The output takes the full 256
/// //    bytes of the modulus: the message comes back at the end, after
/// //    leading zeros, for the padding to take apart.
/// engine.init(CipherDirection::Decrypt, &private)?;
/// let mut plaintext = [0; 256];
/// engine.process_block(&ciphertext, &mut plaintext)?;
/// let recovered = &plaintext[256 - message.len()..];
/// # }
/// # Ok::<(), tc_rsa_v2::RsaError>(())
/// ```
pub struct FixedRsaCoreEngine<const N: usize> {
    key: Option<Key<N>>,
}

impl<const N: usize> FixedRsaCoreEngine<N> {
    /// An engine to be initialized before it processes. Constant time.
    pub const fn new() -> Self {
        Self { key: None }
    }

    /// The key, once the engine is initialized. Constant time.
    fn key(&self) -> Result<&Key<N>, RsaError> {
        self.key.as_ref().ok_or(RsaError::NotInitialized)
    }
}

/// Through [`new`](FixedRsaCoreEngine::new). Constant time.
impl<const N: usize> Default for FixedRsaCoreEngine<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Writes [`ALGO_NAME`](crate::ALGO_NAME) without inspecting key material.
/// Constant time with respect to the key; output timing depends on the
/// formatter.
impl<const N: usize> core::fmt::Display for FixedRsaCoreEngine<N> {
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
impl<P, const N: usize> AsymmetricBlockCipherInit<P> for FixedRsaCoreEngine<N>
where
    P: RsaKeyParams<FixedBigUint<N>>,
{
    type Error = RsaError;

    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), RsaError> {
        if !params.validate() {
            return Err(RsaError::InvalidKey);
        }
        let modulus = params.modulus();
        let odd = Odd::new(modulus.clone()).ok_or(RsaError::InvalidKey)?;
        self.key = Some(Key {
            modulus_less_one: modulus.clone() - 1u32,
            exponent: params.exponent().clone(),
            is_private: params.is_private_key(),
            params: FixedMontyParams::new(odd),
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
impl<const N: usize> AsymmetricBlockCipher for FixedRsaCoreEngine<N> {
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
        let x =
            Zeroizing::new(FixedBigUint::<N>::from_be(input).map_err(|_| RsaError::InputTooLarge)?);
        if x.bits() <= 1 {
            return Err(RsaError::InputTooSmall);
        }
        if *x >= key.modulus_less_one {
            return Err(RsaError::InputTooLarge);
        }
        let form = Zeroizing::new(FixedMontyForm::new(&x, key.params.clone()));
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
pub(crate) mod tests {
    use tc_asym_cipher::{AsymmetricBlockCipher, AsymmetricBlockCipherInit, CipherDirection};
    use tc_bigint::{ArrayEncoding, FixedBigUint, Word};

    use super::FixedRsaCoreEngine;
    use crate::testing::{D, N, hex};
    use crate::{RsaError, RsaKeyOwned};

    const WIDE: usize = 2048 / Word::BITS as usize;
    type U2048 = FixedBigUint<WIDE>;

    fn process(
        engine: &mut impl AsymmetricBlockCipher<Error = RsaError>,
        input: &[u8],
    ) -> Result<[u8; 256], RsaError> {
        let mut output = [0; 256];
        assert_eq!(engine.process_block(input, &mut output)?, 256);
        Ok(output)
    }

    /// Encrypts a message of the full input block with the public key and
    /// decrypts it with the private one, and gives back the ciphertext.
    pub(crate) fn round_trip(
        encrypt: &mut impl AsymmetricBlockCipher<Error = RsaError>,
        decrypt: &mut impl AsymmetricBlockCipher<Error = RsaError>,
    ) -> [u8; 256] {
        let mut message = [0x5a; 255];
        message[0] = 0x01;
        assert_eq!(
            (encrypt.input_block_size(), encrypt.output_block_size()),
            (255, 256)
        );
        let ciphertext = process(encrypt, &message).unwrap();
        assert_ne!(&ciphertext[1..], &message[..]);
        assert_eq!(
            (decrypt.input_block_size(), decrypt.output_block_size()),
            (256, 256)
        );
        let plaintext = process(decrypt, &ciphertext).unwrap();
        assert_eq!(plaintext[0], 0);
        assert_eq!(&plaintext[1..], &message[..]);
        ciphertext
    }

    /// The engines of the Wycheproof key, its public key to encrypt and its
    /// private one to decrypt.
    pub(crate) fn wycheproof() -> (FixedRsaCoreEngine<WIDE>, FixedRsaCoreEngine<WIDE>) {
        let int = |bytes: &[u8]| U2048::from_be(bytes).unwrap();
        let n = int(&hex::<256>(N));
        let mut encrypt = FixedRsaCoreEngine::new();
        encrypt
            .init(
                CipherDirection::Encrypt,
                &RsaKeyOwned::new(false, n.clone(), int(&[1, 0, 1])),
            )
            .unwrap();
        let mut decrypt = FixedRsaCoreEngine::new();
        decrypt
            .init(
                CipherDirection::Decrypt,
                &RsaKeyOwned::new(true, n, int(&hex::<256>(D))),
            )
            .unwrap();
        (encrypt, decrypt)
    }

    #[test]
    fn a_2048_bit_message_round_trips() {
        let (mut encrypt, mut decrypt) = wycheproof();
        round_trip(&mut encrypt, &mut decrypt);
    }

    /// The textbook key, p = 61 and q = 53, marked as checked, as its
    /// modulus has small factors.
    fn textbook(private: bool) -> RsaKeyOwned<FixedBigUint<1>> {
        let exponent = if private { 2753u32 } else { 17 };
        RsaKeyOwned::new(
            private,
            FixedBigUint::from(3233u32),
            FixedBigUint::from(exponent),
        )
        .into_validated()
    }

    #[test]
    fn the_textbook_key_encrypts_65_to_2790_and_back() {
        let mut engine = FixedRsaCoreEngine::new();
        let mut output = [0; 2];
        engine
            .init(CipherDirection::Encrypt, &textbook(false))
            .unwrap();
        assert_eq!(engine.process_block(&[65], &mut output), Ok(2));
        assert_eq!(output, 2790u16.to_be_bytes());
        engine
            .init(CipherDirection::Decrypt, &textbook(true))
            .unwrap();
        assert_eq!(engine.process_block(&output.clone(), &mut output), Ok(2));
        assert_eq!(output, [0, 65]);
    }

    #[test]
    fn inputs_outside_two_to_n_less_two_are_turned_down() {
        let mut engine = FixedRsaCoreEngine::new();
        engine
            .init(CipherDirection::Decrypt, &textbook(true))
            .unwrap();
        let mut output = [0; 2];
        for input in [&[][..], &[0], &[1], &[0, 1]] {
            assert_eq!(
                engine.process_block(input, &mut output),
                Err(RsaError::InputTooSmall),
                "{input:?}"
            );
        }
        assert!(
            engine
                .process_block(&3231u16.to_be_bytes(), &mut output)
                .is_ok()
        );
        for value in [3232u16, 3233, 0xffff] {
            assert_eq!(
                engine.process_block(&value.to_be_bytes(), &mut output),
                Err(RsaError::InputTooLarge),
                "{value}"
            );
        }
        assert_eq!(
            engine.process_block(&[0, 0, 2], &mut output),
            Err(RsaError::InputTooLarge)
        );
        assert_eq!(
            engine.process_block(&[2], &mut [0; 1]),
            Err(RsaError::OutputTooShort)
        );
    }

    #[test]
    fn encryption_takes_no_more_than_the_input_block() {
        let mut engine = FixedRsaCoreEngine::new();
        engine
            .init(CipherDirection::Encrypt, &textbook(false))
            .unwrap();
        assert_eq!(engine.input_block_size(), 1);
        assert_eq!(
            engine.process_block(&[0, 2], &mut [0; 2]),
            Err(RsaError::InputTooLarge)
        );
    }

    #[test]
    fn init_turns_down_a_key_that_fails_its_checks() {
        let key =
            |n: u32| RsaKeyOwned::new(false, FixedBigUint::<1>::from(n), FixedBigUint::from(17u32));
        let mut engine = FixedRsaCoreEngine::new();
        assert_eq!(
            engine.init(CipherDirection::Encrypt, &key(1_022_117)),
            Ok(())
        );
        for n in [0, 1_022_118, 3233, 1_000_003] {
            assert_eq!(
                engine.init(CipherDirection::Encrypt, &key(n)),
                Err(RsaError::InvalidKey),
                "{n}"
            );
        }
    }

    #[test]
    fn a_key_marked_as_passed_skips_the_checks_of_its_modulus() {
        let mut engine = FixedRsaCoreEngine::new();
        assert_eq!(
            engine.init(CipherDirection::Encrypt, &textbook(false)),
            Ok(())
        );
    }

    #[test]
    fn an_engine_not_yet_initialized_processes_nothing() {
        let mut engine = FixedRsaCoreEngine::<1>::new();
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
