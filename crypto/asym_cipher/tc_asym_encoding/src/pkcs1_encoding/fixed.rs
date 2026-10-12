//! PKCS#1 v1.5 with its block inline.

use core::fmt;

use rand_core::CryptoRng;
use tc_asym_cipher::{
    AsymmetricBlockCipher, AsymmetricBlockCipherInit, AsymmetricKeyParams, CipherDirection,
};
use tc_zeroize::Zeroizing;

use super::encoder::Encoder;
use crate::EncodingError;

/// PKCS#1 v1.5 encoding over the asymmetric block cipher `E`, as Bouncy
/// Castle's `Pkcs1Encoding`, with the block of the engine inline in `K`
/// bytes, so that nothing is allocated: `K` takes the output block of an
/// RSA engine, `(bits + 7) / 8` bytes. It draws from the random source `R`
/// it holds to pad with a public key, and, with
/// [`with_plaintext_length`](Self::with_plaintext_length), for what it
/// gives back in place of a bad block. `R` can be a `&mut` borrow, so the
/// caller keeps the source and its state. There is no `Debug`, which would
/// show the state of the source.
///
/// Encrypting with a public key pads as block type 2, with random bytes
/// none of which is zero; with a private key, as for a signature, as block
/// type 1, with `ff` bytes. Decrypting checks for the type the other key
/// gave: 2 with a private key and 1 with a public one, and takes the
/// padding off. The input block when encrypting, and the output block when
/// decrypting, are eleven bytes short of the modulus: at least eight bytes
/// of padding, and the type and two zero bytes around them.
///
/// The engine is to write the whole of its output block when it decrypts,
/// the leading zero byte of the block included, and so does an RSA engine
/// that leaves trimming to the padding; a block written shorter fails the
/// check, as Bouncy Castle's strict length check has it, and its setting
/// to turn that off is not taken. Nor is its constructor with a fallback
/// of the caller's: the plaintext length draws its fallback at random.
///
/// Decrypting with a private key without a plaintext length tells, through
/// its error, whether the padding was good, which Bleichenbacher's attack
/// turns into decryption; where an attacker can send ciphertexts, fix the
/// plaintext length, or use OAEP. Constant time in the message and the
/// block, apart from the engine and from the draws of the random padding,
/// as each method tells.
///
/// ```
/// use tc_asym_cipher::{
///     AsymmetricBlockCipher, AsymmetricBlockCipherInit, CipherDirection, KeyPairGenerator,
///     KeyPairGeneratorInit,
/// };
/// use tc_asym_encoding::FixedPkcs1Encoding;
/// use tc_bigint::{FixedBigUint, Word};
/// use tc_rsa_v2::{FixedRsaCoreEngine, RsaKeyGenerationParamsOwned, RsaKeyPairGenerator};
///
/// type U2048 = FixedBigUint<{ 2048 / Word::BITS as usize }>;
///
/// // 1. Generate a 2048-bit key pair.
/// let mut generator = RsaKeyPairGenerator::<U2048>::new();
/// generator.init(RsaKeyGenerationParamsOwned::new(rand::rng()))?;
/// let (public, private) = generator.generate_key_pair()?;
///
/// // 2. Encrypt with the public key: the message, of at most 245 bytes, is
/// //    padded with random bytes into a block of the 256-byte modulus.
/// let mut encoding =
///     FixedPkcs1Encoding::<_, _, 256>::from_parts(FixedRsaCoreEngine::new(), rand::rng());
/// encoding.init(CipherDirection::Encrypt, &public)?;
/// let mut ciphertext = [0; 256];
/// encoding.process_block(b"attack at dawn", &mut ciphertext)?;
///
/// // 3. Decrypt with the private key: the padding is checked and taken off.
/// encoding.init(CipherDirection::Decrypt, &private)?;
/// let mut plaintext = [0; 245];
/// let length = encoding.process_block(&ciphertext, &mut plaintext)?;
/// let message = &plaintext[..length];
/// # assert_eq!(message, b"attack at dawn");
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct FixedPkcs1Encoding<E, R, const K: usize> {
    encoder: Encoder<E, R>,
    block: Zeroizing<[u8; K]>,
}

impl<E: Default, R, const K: usize> FixedPkcs1Encoding<E, R, K> {
    /// A new engine `E`, to be initialized, drawing from `rng`.
    /// Constant time.
    pub fn new(rng: R) -> Self {
        Self::from_parts(E::default(), rng)
    }
}

impl<E, R, const K: usize> FixedPkcs1Encoding<E, R, K> {
    /// `engine`, to be initialized through the encoding, drawing from
    /// `rng`. Constant time.
    pub fn from_parts(engine: E, rng: R) -> Self {
        Self {
            encoder: Encoder::new(engine, rng),
            block: Zeroizing::new([0; K]),
        }
    }

    /// The encoding, decrypting with a private key to a message of exactly
    /// `length` bytes, as Bouncy Castle's `Pkcs1Encoding(cipher, pLen)`: a
    /// block that is not one gives back `length` bytes drawn from the
    /// source in place of an error, so that whether the padding was good
    /// never shows, as a TLS server decrypts its premaster secret. `init`
    /// fails when decrypting with a private key to more than the output
    /// block; otherwise the length is not used. Constant time.
    pub fn with_plaintext_length(mut self, length: usize) -> Self {
        self.encoder.plaintext_length = Some(length);
        self
    }

    /// The engine, as Bouncy Castle's `UnderlyingCipher`. Constant time.
    pub fn underlying_cipher(&self) -> &E {
        &self.encoder.engine
    }

    /// The engine and the random source back. Constant time.
    pub fn into_parts(self) -> (E, R) {
        (self.encoder.engine, self.encoder.rng)
    }
}

impl<E: fmt::Display, R, const K: usize> fmt::Display for FixedPkcs1Encoding<E, R, K> {
    /// Writes the name of the engine and `/PKCS1Padding`, as Bouncy
    /// Castle's `AlgorithmName`, as `RSA/PKCS1Padding`. Constant time when
    /// the engine's `Display` is; output timing depends on the formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.encoder.engine.fmt(f)?;
        f.write_str("/PKCS1Padding")
    }
}

impl<E, R, P, const K: usize> AsymmetricBlockCipherInit<P> for FixedPkcs1Encoding<E, R, K>
where
    E: AsymmetricBlockCipher + AsymmetricBlockCipherInit<P>,
    P: AsymmetricKeyParams + ?Sized,
{
    type Error = EncodingError<<E as AsymmetricBlockCipherInit<P>>::Error>;

    /// Initializes the engine with `params`, and takes block type 1 or 2
    /// after whether the key is private, as Bouncy Castle does. Fails with
    /// the engine's error; with `BlockTooLarge` when the block of the
    /// engine in this direction, its input block when encrypting and its
    /// output block when decrypting, is longer than `K`; and with
    /// `InvalidPlaintextLength` for a plaintext length beyond the output
    /// block. A failed `init` leaves the encoding uninitialized.
    /// Constant time, apart from the engine's `init`: the rest reads only
    /// public lengths.
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), Self::Error> {
        let (state, length) = self.encoder.init(direction, params)?;
        if length > K {
            return Err(EncodingError::BlockTooLarge {
                actual: length,
                capacity: K,
            });
        }
        self.encoder.state = Some(state);
        Ok(())
    }
}

impl<E, R, const K: usize> AsymmetricBlockCipher for FixedPkcs1Encoding<E, R, K>
where
    E: AsymmetricBlockCipher,
    R: CryptoRng,
{
    type Error = EncodingError<E::Error>;

    /// The input block of the engine when decrypting, and ten bytes less
    /// when encrypting, for the header; zero before initialization.
    /// Constant time.
    fn input_block_size(&self) -> usize {
        self.encoder.input_block_size()
    }

    /// The output block of the engine when encrypting, and eleven bytes
    /// less when decrypting, for the header and the leading zero; zero
    /// before initialization. Constant time.
    fn output_block_size(&self) -> usize {
        self.encoder.output_block_size()
    }

    /// Pads and encrypts `input`, or decrypts it and takes the padding
    /// off, writing the message at the start of `output`, and gives the
    /// number of bytes written. Fails with `NotInitialized`,
    /// `InputTooLarge`, `OutputTooShort`, the engine's error, or, when
    /// decrypting without a plaintext length, `InvalidBlock`. Constant time
    /// in the message and the block, apart from the engine: with a public
    /// key, the draws of the padding redraw each zero, which shows where
    /// the source drew one but nothing of the padding kept; without a
    /// plaintext length, whether a decrypted block is good shows through
    /// the error, and its message length through the result.
    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        self.encoder
            .process_block(&mut self.block[..], input, output)
    }
}
