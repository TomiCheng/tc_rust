//! The RSA operation without the CRT, as Bouncy Castle's `RsaCoreEngine`
//! runs it for a key that is not a CRT key.

use core::ops::Sub;

use num_traits::Zero;
use tc_asym_cipher::{AsymmetricBlockCipher, AsymmetricBlockCipherInit, CipherDirection};
use tc_bigint::{ArrayEncoding, BitOps};
use tc_modular::{ModPow, NonZero};
use tc_zeroize::{Zeroize, Zeroizing};

use crate::{RsaError, RsaKeyParams};

/// What an engine keeps from its initialization: the key, `n - 1` for the
/// range check of the input, the size of the modulus in bits, and the
/// direction. The exponent and `n - 1` are wiped on drop; the modulus is
/// public.
struct Key<T: Zeroize> {
    modulus: NonZero<T>,
    modulus_less_one: T,
    exponent: T,
    bits: u32,
    direction: CipherDirection,
}

/// Wipes the exponent, which is `d` for a private key, and `n - 1`.
/// Constant time, as the `Zeroize` of `T` is.
impl<T: Zeroize> Drop for Key<T> {
    fn drop(&mut self) {
        self.exponent.zeroize();
        self.modulus_less_one.zeroize();
    }
}

/// The RSA operation without the CRT, `x^e mod n` for a public key and
/// `x^d mod n` for a private one, on integers of type `T`, as Bouncy
/// Castle's `RsaCoreEngine` runs it for a key that is not a CRT key. The
/// key is copied in at initialization, so the engine does not borrow it.
///
/// The output always takes the full length of the modulus, `(bits + 7) / 8`
/// bytes, leading zeros kept, in both directions. Bouncy Castle trims them
/// from a decryption, which lets the length show whether the result starts
/// with a zero byte, as Manger's attack on OAEP needs; trimming is left to
/// the padding, once it has checked the block. The output block is one
/// byte longer than Bouncy Castle's when decrypting.
///
/// ```
/// use tc_asym_cipher::{AsymmetricBlockCipher, AsymmetricBlockCipherInit, CipherDirection};
/// use tc_bigint::FixedBigUint;
/// use tc_rsa_v2::{RsaCoreEngine, RsaKeyOwned};
///
/// // A textbook key, p = 61 and q = 53, far too small for any real use.
/// let public = RsaKeyOwned::new(false, FixedBigUint::<1>::from(3233u32), FixedBigUint::from(17u32));
/// let private = RsaKeyOwned::new(true, FixedBigUint::<1>::from(3233u32), FixedBigUint::from(2753u32));
///
/// let mut engine = RsaCoreEngine::new();
/// engine.init(CipherDirection::Encrypt, &public)?;
/// let mut ciphertext = [0; 2];
/// engine.process_block(&[65], &mut ciphertext)?;
/// assert_eq!(ciphertext, [0x0a, 0xe6]); // 2790
///
/// engine.init(CipherDirection::Decrypt, &private)?;
/// let mut plaintext = [0; 2];
/// engine.process_block(&ciphertext, &mut plaintext)?;
/// assert_eq!(plaintext, [0, 65]); // the leading zero is kept
/// # Ok::<(), tc_rsa_v2::RsaError>(())
/// ```
pub struct RsaCoreEngine<T: Zeroize> {
    key: Option<Key<T>>,
}

impl<T: Zeroize> RsaCoreEngine<T> {
    /// An engine to be initialized before it processes. Constant time.
    pub const fn new() -> Self {
        Self { key: None }
    }

    /// The key, once the engine is initialized. Constant time.
    fn key(&self) -> Result<&Key<T>, RsaError> {
        self.key.as_ref().ok_or(RsaError::NotInitialized)
    }
}

/// Through [`new`](RsaCoreEngine::new). Constant time.
impl<T: Zeroize> Default for RsaCoreEngine<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// Copies the key in, once it is checked: a modulus that is odd, and so not
/// zero, and an exponent that is not zero, and odd for a public key, as
/// Bouncy Castle's `RsaKeyParameters` checks them. Bouncy Castle also turns
/// down a modulus with a small factor, or one a Miller-Rabin test does not
/// prove composite; that is not done here. Constant time, apart from the
/// outcome of the checks, which the error shows.
impl<T, P> AsymmetricBlockCipherInit<P> for RsaCoreEngine<T>
where
    T: Clone + Zero + BitOps + Zeroize + Sub<u32, Output = T>,
    P: RsaKeyParams<T>,
{
    type Error = RsaError;

    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), RsaError> {
        let (modulus, exponent) = (params.modulus(), params.exponent());
        if modulus.is_zero() {
            return Err(RsaError::InvalidModulus);
        }
        if !modulus.bit(0) {
            return Err(RsaError::EvenModulus);
        }
        if exponent.is_zero() {
            return Err(RsaError::InvalidExponent);
        }
        if !params.is_private_key() && !exponent.bit(0) {
            return Err(RsaError::EvenPublicExponent);
        }
        let modulus = NonZero::new(modulus.clone()).expect("an odd modulus is not zero");
        self.key = Some(Key {
            modulus_less_one: (*modulus).clone() - 1u32,
            exponent: exponent.clone(),
            bits: modulus.bits(),
            direction,
            modulus,
        });
        Ok(())
    }
}

/// Reads the input as a big-endian integer `x` with `1 < x < n - 1`, as
/// Bouncy Castle does, raises it to the exponent mod `n`, and writes the
/// result over the full length of the modulus. As constant time as the
/// `ModPow` of `T` is, apart from the outcome of the range check, which the
/// error shows: constant time for the fixed-width and padded integers,
/// while the arbitrary-precision ones are only for public keys, as their
/// power shows the exponent.
impl<T> AsymmetricBlockCipher for RsaCoreEngine<T>
where
    T: Ord + BitOps + ArrayEncoding<u8> + ModPow<Output = T> + Zeroize,
{
    type Error = RsaError;

    /// `(bits - 1) / 8` bytes when encrypting, so that any input is below
    /// the modulus, and `(bits + 7) / 8` when decrypting; zero before
    /// initialization. Constant time.
    fn input_block_size(&self) -> usize {
        self.key.as_ref().map_or(0, |key| match key.direction {
            CipherDirection::Encrypt => (key.bits as usize - 1) / 8,
            CipherDirection::Decrypt => (key.bits as usize).div_ceil(8),
        })
    }

    /// `(bits + 7) / 8` bytes in both directions; zero before
    /// initialization. Constant time.
    fn output_block_size(&self) -> usize {
        self.key
            .as_ref()
            .map_or(0, |key| (key.bits as usize).div_ceil(8))
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
        let value = Zeroizing::new(T::from_be(input).map_err(|_| RsaError::InputTooLarge)?);
        if value.bits() <= 1 {
            return Err(RsaError::InputTooSmall);
        }
        if *value >= key.modulus_less_one {
            return Err(RsaError::InputTooLarge);
        }
        let result = Zeroizing::new(value.mod_pow(&key.exponent, &key.modulus));
        write_be(&*result, &mut output[..length]);
        Ok(length)
    }
}

/// `value` big-endian over all of `output`, which holds it, bit by bit, so
/// that no buffer is needed whatever the width of `T`. As constant time as
/// the `bit` of `T` is: the bits read follow the length of `output`.
fn write_be<T: BitOps>(value: &T, output: &mut [u8]) {
    let length = output.len();
    for (index, byte) in output.iter_mut().enumerate() {
        let low = 8 * (length - 1 - index) as u32;
        *byte = (0..8).fold(0, |byte, bit| {
            byte | (u8::from(value.bit(low + bit)) << bit)
        });
    }
}

#[cfg(test)]
mod tests {
    use tc_asym_cipher::{AsymmetricBlockCipher, AsymmetricBlockCipherInit, CipherDirection};
    use tc_bigint::{ArrayEncoding, BitOps, FixedBigUint, Word};
    use tc_modular::ModPow;
    use tc_zeroize::Zeroize;

    use super::RsaCoreEngine;
    use crate::{RsaError, RsaKeyOwned};

    /// The first key of Wycheproof's `rsa_pkcs1_2048_test.json`, from C2SP:
    /// its modulus and private exponent; the public exponent is 65537.
    const N: &str = concat!(
        "b3510a2bcd4ce644c5b594ae5059e12b2f054b658d5da5959a2fdf1871b808bc",
        "3df3e628d2792e51aad5c124b43bda453dca5cde4bcf28e7bd4effba0cb4b742",
        "bbb6d5a013cb63d1aa3a89e02627ef5398b52c0cfd97d208abeb8d7c9bce0bbe",
        "b019a86ddb589beb29a5b74bf861075c677c81d430f030c265247af9d3c9140c",
        "cb65309d07e0adc1efd15cf17e7b055d7da3868e4648cc3a180f0ee7f8e1e7b1",
        "8098a3391b4ce7161e98d57af8a947e201a463e2d6bbca8059e5706e9dfed8f4",
        "856465ffa712ed1aa18e888d12dc6aa09ce95ecfca83cc5b0b15db09c8647f5d",
        "524c0f2e7620a3416b9623cadc0f097af573261c98c8400aa12af38e43cad84d",
    );
    const D: &str = concat!(
        "1a502d0eea6c7b69e21d5839101f705456ed0ef852fb47fe21071f54c5f33c8c",
        "eb066c62d727e32d26c58137329f89d3195325b795264c195d85472f7507dbd0",
        "961d2951f935a26b34f0ac24d15490e1128a9b7138915bc7dbfa8fe396357131",
        "c543ae9c98507368d9ceb08c1c6198a3eda7aea185a0e976cd42c22d00f003d9",
        "f19d96ea4c9afcbfe1441ccc802cfb0689f59d804c6a4e4f404c15174745ed6c",
        "b8bc88ef0b33ba0d2a80e35e43bc90f350052e72016e75b00d357a381c9c0d46",
        "7069ca660887c987766349fcc43460b4aa516bce079edd87ba164307b752c277",
        "ed9528ad3ba0bf1877349ed3b7966a6c240110409bf4d0fade0c68fdadd847fd",
    );

    fn hex(text: &str) -> [u8; 256] {
        let mut bytes = [0; 256];
        for (byte, pair) in bytes.iter_mut().zip(text.as_bytes().chunks(2)) {
            *byte = u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap();
        }
        bytes
    }

    fn process<T>(engine: &mut RsaCoreEngine<T>, input: &[u8]) -> Result<[u8; 256], RsaError>
    where
        T: Ord + BitOps + ArrayEncoding<u8> + ModPow<Output = T> + Zeroize,
    {
        let mut output = [0; 256];
        assert_eq!(engine.process_block(input, &mut output)?, 256);
        Ok(output)
    }

    /// Encrypts a message of the full input block with the public key and
    /// decrypts it with the private one, over integers of type `T`, and
    /// gives back the ciphertext.
    fn round_trip<T>(int: impl Fn(&[u8]) -> T) -> [u8; 256]
    where
        T: Clone
            + num_traits::Zero
            + BitOps
            + Ord
            + ArrayEncoding<u8>
            + ModPow<Output = T>
            + Zeroize
            + core::ops::Sub<u32, Output = T>,
    {
        let (n, d) = (hex(N), hex(D));
        let public = RsaKeyOwned::new(false, int(&n), int(&[1, 0, 1]));
        let private = RsaKeyOwned::new(true, int(&n), int(&d));
        let mut message = [0x5a; 255];
        message[0] = 0x01;

        let mut engine = RsaCoreEngine::new();
        engine.init(CipherDirection::Encrypt, &public).unwrap();
        assert_eq!(
            (engine.input_block_size(), engine.output_block_size()),
            (255, 256)
        );
        let ciphertext = process(&mut engine, &message).unwrap();
        assert_ne!(&ciphertext[1..], &message[..]);

        engine.init(CipherDirection::Decrypt, &private).unwrap();
        assert_eq!(
            (engine.input_block_size(), engine.output_block_size()),
            (256, 256)
        );
        let plaintext = process(&mut engine, &ciphertext).unwrap();
        assert_eq!(plaintext[0], 0);
        assert_eq!(&plaintext[1..], &message[..]);
        ciphertext
    }

    type U2048 = FixedBigUint<{ 2048 / Word::BITS as usize }>;

    #[test]
    fn a_2048_bit_message_round_trips_over_fixed_width_integers() {
        round_trip(|bytes| U2048::from_be(bytes).unwrap());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn the_padded_and_arbitrary_precision_integers_agree_with_the_fixed_width_ones() {
        let fixed = round_trip(|bytes| U2048::from_be(bytes).unwrap());
        assert_eq!(
            round_trip(|bytes| tc_bigint::PaddedBigUint::from_be(bytes).unwrap()),
            fixed
        );
        assert_eq!(
            round_trip(|bytes| tc_bigint::BigUint::from_be(bytes).unwrap()),
            fixed
        );
    }

    fn textbook(private: bool) -> RsaKeyOwned<FixedBigUint<1>> {
        let exponent = if private { 2753u32 } else { 17 };
        RsaKeyOwned::new(
            private,
            FixedBigUint::from(3233u32),
            FixedBigUint::from(exponent),
        )
    }

    #[test]
    fn the_textbook_key_encrypts_65_to_2790_and_back() {
        let mut engine = RsaCoreEngine::new();
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
        let mut engine = RsaCoreEngine::new();
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
        let mut engine = RsaCoreEngine::new();
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
    fn init_turns_down_keys_bouncy_castle_turns_down() {
        let key = |private, n: u32, e: u32| {
            RsaKeyOwned::new(private, FixedBigUint::<1>::from(n), FixedBigUint::from(e))
        };
        let mut engine = RsaCoreEngine::new();
        let mut init = |key| engine.init(CipherDirection::Encrypt, &key);
        assert_eq!(init(key(false, 0, 17)), Err(RsaError::InvalidModulus));
        assert_eq!(init(key(false, 3234, 17)), Err(RsaError::EvenModulus));
        assert_eq!(init(key(false, 3233, 0)), Err(RsaError::InvalidExponent));
        assert_eq!(init(key(true, 3233, 0)), Err(RsaError::InvalidExponent));
        assert_eq!(
            init(key(false, 3233, 16)),
            Err(RsaError::EvenPublicExponent)
        );
        assert_eq!(init(key(true, 3233, 16)), Ok(()));
    }

    #[test]
    fn an_engine_not_yet_initialized_processes_nothing() {
        let mut engine = RsaCoreEngine::<FixedBigUint<1>>::new();
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
