//! PKCS#1 v1.5 with its block on the heap.

use alloc::vec::Vec;
use core::fmt;

use rand_core::CryptoRng;
use tc_asym_cipher::{
    AsymmetricBlockCipher, AsymmetricBlockCipherInit, AsymmetricKeyParams, CipherDirection,
};
use tc_zeroize::Zeroizing;

use super::encoder::Encoder;
use crate::EncodingError;

/// PKCS#1 v1.5 encoding over the asymmetric block cipher `E`, as Bouncy
/// Castle's `Pkcs1Encoding`, with the block of the engine on the heap, sized
/// at `init` as Bouncy Castle sizes its `blockBuffer`, so that it takes an
/// engine of any size. Available with the `alloc` feature. It encodes as
/// [`FixedPkcs1Encoding`](crate::FixedPkcs1Encoding) does, which tells the
/// format, what is not taken from Bouncy Castle, and the timing.
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
/// use tc_asym_encoding::Pkcs1Encoding;
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
/// // 2. Sign with the private key: the digest info is padded with `ff`
/// //    bytes, the same every time.
/// let mut encoding = Pkcs1Encoding::from_parts(FixedRsaCoreEngine::new(), rand::rng());
/// encoding.init(CipherDirection::Encrypt, &private)?;
/// let mut signature = vec![0; encoding.output_block_size()];
/// encoding.process_block(b"a DER DigestInfo", &mut signature)?;
///
/// // 3. Verify with the public key: the padding is checked and taken off.
/// encoding.init(CipherDirection::Decrypt, &public)?;
/// let mut recovered = vec![0; encoding.output_block_size()];
/// let length = encoding.process_block(&signature, &mut recovered)?;
/// recovered.truncate(length);
/// # assert_eq!(recovered, b"a DER DigestInfo");
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct Pkcs1Encoding<E, R> {
    encoder: Encoder<E, R>,
    block: Zeroizing<Vec<u8>>,
}

impl<E: Default, R> Pkcs1Encoding<E, R> {
    /// A new engine `E`, to be initialized, drawing from `rng`.
    /// Constant time.
    pub fn new(rng: R) -> Self {
        Self::from_parts(E::default(), rng)
    }
}

impl<E, R> Pkcs1Encoding<E, R> {
    /// `engine`, to be initialized through the encoding, drawing from
    /// `rng`; the block is allocated at `init`. Constant time.
    pub fn from_parts(engine: E, rng: R) -> Self {
        Self {
            encoder: Encoder::new(engine, rng),
            block: Zeroizing::new(Vec::new()),
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

impl<E: fmt::Display, R> fmt::Display for Pkcs1Encoding<E, R> {
    /// Writes the name of the engine and `/PKCS1Padding`, as Bouncy
    /// Castle's `AlgorithmName`, as `RSA/PKCS1Padding`. Constant time when
    /// the engine's `Display` is; output timing depends on the formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.encoder.engine.fmt(f)?;
        f.write_str("/PKCS1Padding")
    }
}

impl<E, R, P> AsymmetricBlockCipherInit<P> for Pkcs1Encoding<E, R>
where
    E: AsymmetricBlockCipher + AsymmetricBlockCipherInit<P>,
    P: AsymmetricKeyParams + ?Sized,
{
    type Error = EncodingError<<E as AsymmetricBlockCipherInit<P>>::Error>;

    /// Initializes the engine with `params`, takes block type 1 or 2 after
    /// whether the key is private, as Bouncy Castle does, and sizes the
    /// block to that of the engine in this direction: its input block when
    /// encrypting and its output block when decrypting. Fails with the
    /// engine's error, or with `InvalidPlaintextLength` for a plaintext
    /// length beyond the output block. A failed `init` leaves the encoding
    /// uninitialized. Constant time, apart from the engine's `init` and
    /// the allocator: the rest reads only public lengths.
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), Self::Error> {
        let (state, length) = self.encoder.init(direction, params)?;
        // The block is wiped after each use, and so nothing is left behind
        // where it moves from.
        self.block.resize(length, 0);
        self.encoder.state = Some(state);
        Ok(())
    }
}

impl<E, R> AsymmetricBlockCipher for Pkcs1Encoding<E, R>
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
    /// number of bytes written, as
    /// [`FixedPkcs1Encoding`](crate::FixedPkcs1Encoding) does, with the
    /// same errors and timing. Constant time in the message and the block,
    /// apart from the engine, the draws of the padding, and, without a
    /// plaintext length, the outcome of the check.
    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        self.encoder
            .process_block(&mut self.block[..], input, output)
    }
}
