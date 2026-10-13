//! OAEP over an asymmetric block cipher.

use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

use rand_core::CryptoRng;
use tc_asym_cipher::{AsymmetricBlockCipher, AsymmetricBlockCipherInit, CipherDirection};
use tc_digest::Digest;
use tc_zeroize::{Zeroize, Zeroizing};

use crate::EncodingError;

/// The byte that ends the padding and starts the message.
const SEPARATOR: u8 = 0x01;

/// Optimal Asymmetric Encryption Padding over the asymmetric block cipher
/// `E`, as Bouncy Castle's `OaepEncoding`, with MGF1 over the digest `M`.
/// It draws the seed of each encryption from the random source `R` it
/// holds; `R` can be a `&mut` borrow, so the caller keeps the source and
/// its state. The block of the engine is sized at `init` and wiped after
/// each use. There is no `Debug`, which would show the state of the
/// source.
///
/// The hash of the label, `lHash`, is worked out when the encoding is
/// built, as Bouncy Castle does, and its length `hLen` sets that of the
/// seed: by `M` over an empty label, unless
/// [`with_label`](Self::with_label) or
/// [`with_label_digest`](Self::with_label_digest) gives one, the latter
/// with a digest of its own, as Bouncy Castle's constructor with two
/// digests does, such as SHA-256 for the label and SHA-1 for MGF1. The
/// input block when encrypting, and the output block when decrypting, are
/// `2 * hLen + 2` bytes short of the modulus. PKCS#1 defines OAEP for RSA.
///
/// The engine is to write the whole of its output block when it decrypts,
/// the leading zero byte of the block included, and so does an RSA engine
/// that leaves trimming to the padding; the encoding checks that byte, and
/// a block written shorter fails. Every failure of a decrypted block is the
/// same `InvalidBlock`, found after the whole block is checked, so that
/// none tells another apart, as Manger's attack needs; Bouncy Castle's
/// read of the separator at a secret index is not taken either. Its MGF
/// over an XOF is not taken.
///
/// Constant time in the message and the block, apart from the engine and
/// the digest; whether a decrypted block is good shows through the error,
/// and its message length through the result.
///
/// ```
/// use tc_asym_cipher::{
///     AsymmetricBlockCipher, AsymmetricBlockCipherInit, CipherDirection, KeyPairGenerator,
///     KeyPairGeneratorInit,
/// };
/// use tc_asym_encoding::OaepEncoding;
/// use tc_bigint::{FixedBigUint, Word};
/// use tc_rsa_v2::{FixedRsaCoreEngine, RsaKeyGenerationParamsOwned, RsaKeyPairGenerator};
/// use tc_sha::Sha256Digest;
///
/// type U2048 = FixedBigUint<{ 2048 / Word::BITS as usize }>;
///
/// // 1. Generate a 2048-bit key pair.
/// let mut generator = RsaKeyPairGenerator::<U2048>::new();
/// generator.init(RsaKeyGenerationParamsOwned::new(rand::rng()))?;
/// let (public, private) = generator.generate_key_pair()?;
///
/// // 2. Encrypt with the public key, with SHA-256 for the label and MGF1:
/// //    the message, of at most 190 bytes, is masked with a random seed.
/// let mut encoding =
///     OaepEncoding::from_parts(FixedRsaCoreEngine::new(), Sha256Digest::new(), rand::rng());
/// encoding.init(CipherDirection::Encrypt, &public)?;
/// let mut ciphertext = vec![0; encoding.output_block_size()];
/// encoding.process_block(b"attack at dawn", &mut ciphertext)?;
///
/// // 3. Decrypt with the private key: the block is unmasked and checked.
/// encoding.init(CipherDirection::Decrypt, &private)?;
/// let mut plaintext = vec![0; encoding.output_block_size()];
/// let length = encoding.process_block(&ciphertext, &mut plaintext)?;
/// plaintext.truncate(length);
/// # assert_eq!(plaintext, b"attack at dawn");
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct OaepEncoding<E, M, R> {
    engine: E,
    mgf: M,
    rng: R,
    label_hash: Vec<u8>,
    mask: Zeroizing<Vec<u8>>,
    direction: Option<CipherDirection>,
    block: Zeroizing<Vec<u8>>,
}

impl<E: Default, M: Digest + Default, R> OaepEncoding<E, M, R> {
    /// A new engine `E` and digest `M`, to be initialized, drawing from
    /// `rng`, as Bouncy Castle's `OaepEncoding(cipher, hash)`. Constant
    /// time as far as the digest is.
    pub fn new(rng: R) -> Self {
        Self::from_parts(E::default(), M::default(), rng)
    }
}

impl<E, M: Digest, R> OaepEncoding<E, M, R> {
    /// `engine`, to be initialized through the encoding, with MGF1 over
    /// `mgf`, which also hashes the empty label, drawing from `rng`; the
    /// block is allocated at `init`. Constant time as far as the digest
    /// is.
    pub fn from_parts(engine: E, mut mgf: M, rng: R) -> Self {
        let label_hash = hash(&mut mgf, &[]);
        let mask = Zeroizing::new(vec![0; mgf.digest_size()]);
        Self {
            engine,
            mgf,
            rng,
            label_hash,
            mask,
            direction: None,
            block: Zeroizing::new(Vec::new()),
        }
    }

    /// The encoding with `label`, hashed by the digest of MGF1, as Bouncy
    /// Castle's `encodingParams`. The label is public. Constant time as
    /// far as the digest is.
    pub fn with_label(mut self, label: &[u8]) -> Self {
        self.label_hash = hash(&mut self.mgf, label);
        self
    }

    /// The encoding with `label` hashed by `digest` in place of the digest
    /// of MGF1, as Bouncy Castle's `OaepEncoding(cipher, hash, mgf1Hash,
    /// encodingParams)`: the length of its hash sets that of the seed.
    /// The label is public. Constant time as far as `digest` is.
    pub fn with_label_digest(mut self, mut digest: impl Digest, label: &[u8]) -> Self {
        self.label_hash = hash(&mut digest, label);
        self
    }

    /// The engine, as Bouncy Castle's `UnderlyingCipher`. Constant time.
    pub fn underlying_cipher(&self) -> &E {
        &self.engine
    }

    /// The engine, the digest of MGF1 and the random source back. Constant
    /// time.
    pub fn into_parts(self) -> (E, M, R) {
        (self.engine, self.mgf, self.rng)
    }
}

impl<E: fmt::Display, M, R> fmt::Display for OaepEncoding<E, M, R> {
    /// Writes the name of the engine and `/OAEPPadding`, as Bouncy
    /// Castle's `AlgorithmName`, as `RSA/OAEPPadding`. Constant time when
    /// the engine's `Display` is; output timing depends on the formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.engine.fmt(f)?;
        f.write_str("/OAEPPadding")
    }
}

impl<E, M, R, P> AsymmetricBlockCipherInit<P> for OaepEncoding<E, M, R>
where
    E: AsymmetricBlockCipher + AsymmetricBlockCipherInit<P>,
    P: ?Sized,
{
    type Error = EncodingError<<E as AsymmetricBlockCipherInit<P>>::Error>;

    /// Initializes the engine with `params`, as Bouncy Castle does, and
    /// sizes the block to that of the engine in this direction: its input
    /// block when encrypting and its output block when decrypting. Asks
    /// nothing of the key, which only the engine reads. Fails with the
    /// engine's error, and then leaves the encoding uninitialized.
    /// Constant time, apart from the engine's `init` and the allocator:
    /// the rest reads only public lengths.
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), Self::Error> {
        self.direction = None;
        self.engine
            .init(direction, params)
            .map_err(EncodingError::Cipher)?;
        let length = match direction {
            CipherDirection::Encrypt => self.engine.input_block_size(),
            CipherDirection::Decrypt => self.engine.output_block_size(),
        };
        // The block is wiped after each use, and so nothing is left behind
        // where it moves from.
        self.block.resize(length, 0);
        self.direction = Some(direction);
        Ok(())
    }
}

impl<E, M, R> AsymmetricBlockCipher for OaepEncoding<E, M, R>
where
    E: AsymmetricBlockCipher,
    M: Digest,
    R: CryptoRng,
{
    type Error = EncodingError<E::Error>;

    /// The input block of the engine when decrypting, and `2 * hLen + 1`
    /// bytes less when encrypting, for the label hash, the seed and the
    /// separator; zero before initialization. Constant time.
    fn input_block_size(&self) -> usize {
        match self.direction {
            None => 0,
            Some(CipherDirection::Encrypt) => self
                .engine
                .input_block_size()
                .saturating_sub(2 * self.label_hash.len() + 1),
            Some(CipherDirection::Decrypt) => self.engine.input_block_size(),
        }
    }

    /// The output block of the engine when encrypting, and `2 * hLen + 2`
    /// bytes less when decrypting, for the label hash, the seed, the
    /// separator and the leading zero; zero before initialization.
    /// Constant time.
    fn output_block_size(&self) -> usize {
        match self.direction {
            None => 0,
            Some(CipherDirection::Encrypt) => self.engine.output_block_size(),
            Some(CipherDirection::Decrypt) => self
                .engine
                .output_block_size()
                .saturating_sub(2 * self.label_hash.len() + 2),
        }
    }

    /// Masks and encrypts `input`, or decrypts it and takes the message
    /// out of the unmasked block, writing it at the start of `output`, and
    /// gives the number of bytes written; the block and the mask are wiped
    /// afterwards, whatever the outcome. Fails with `NotInitialized`,
    /// `InputTooLarge`, `OutputTooShort`, the engine's error, or, when
    /// decrypting, `InvalidBlock`. Constant time in the message and the
    /// block, apart from the engine and the digest; whether a decrypted
    /// block is good shows through the error, and its message length
    /// through the result.
    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        let direction = self.direction.ok_or(EncodingError::NotInitialized)?;
        let result = match direction {
            CipherDirection::Encrypt => self.encode(input, output),
            CipherDirection::Decrypt => self.decode(input, output),
        };
        self.block.as_mut_slice().zeroize();
        self.mask.as_mut_slice().zeroize();
        result
    }
}

impl<E, M, R> OaepEncoding<E, M, R>
where
    E: AsymmetricBlockCipher,
    M: Digest,
    R: CryptoRng,
{
    /// Lays `input` out in a block of the engine's input block, `seed ||
    /// lHash || 00.. || 01 || input`, masks the rest with the seed and the
    /// seed with the rest, as Bouncy Castle's `EncodeBlock`, and encrypts
    /// it. Constant time in the input, apart from the engine and the
    /// digest; its length is public.
    fn encode(
        &mut self,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, EncodingError<E::Error>> {
        let length = self.engine.input_block_size();
        let hash_length = self.label_hash.len();
        if input.len() + 2 * hash_length + 1 > length {
            return Err(EncodingError::InputTooLarge);
        }
        if output.len() < self.engine.output_block_size() {
            return Err(EncodingError::OutputTooShort);
        }
        let block = &mut self.block[..length];
        block.fill(0);
        let (seed, data) = block.split_at_mut(hash_length);
        data[..hash_length].copy_from_slice(&self.label_hash);
        let start = data.len() - input.len();
        data[start - 1] = SEPARATOR;
        data[start..].copy_from_slice(input);
        self.rng.fill_bytes(seed);
        mgf1(&mut self.mgf, &mut self.mask, seed, data);
        mgf1(&mut self.mgf, &mut self.mask, data, seed);
        self.engine
            .process_block(block, output)
            .map_err(EncodingError::Cipher)
    }

    /// Decrypts `input` into `00 || masked seed || masked data`, unmasks
    /// the seed with the data and the data with the seed, as Bouncy
    /// Castle's `DecodeBlock`, and checks the leading zero, `lHash`, and
    /// that the first byte after it that is not zero is `01`. Constant
    /// time, apart from the engine and the digest: every check runs over
    /// the whole block, and only their sum decides; the length of the
    /// message then shows through the result.
    fn decode(
        &mut self,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, EncodingError<E::Error>> {
        let length = self.engine.output_block_size();
        let hash_length = self.label_hash.len();
        if output.len() < length.saturating_sub(2 * hash_length + 2) {
            return Err(EncodingError::OutputTooShort);
        }
        let block = &mut self.block[..length];
        let written = self
            .engine
            .process_block(input, block)
            .map_err(EncodingError::Cipher)?;
        if length < 2 * hash_length + 2 {
            return Err(EncodingError::InvalidBlock);
        }
        let (leading, rest) = block.split_at_mut(1);
        let (seed, data) = rest.split_at_mut(hash_length);
        mgf1(&mut self.mgf, &mut self.mask, data, seed);
        mgf1(&mut self.mgf, &mut self.mask, seed, data);
        // Anything but zero here, in any bit, makes the block bad.
        let mut bad = isize::from(written != length) | isize::from(leading[0]);
        for (expected, &byte) in self.label_hash.iter().zip(&data[..hash_length]) {
            bad |= isize::from(expected ^ byte);
        }
        let (start, found) = find_separator(&data[hash_length..]);
        bad |= !found;
        if bad != 0 {
            return Err(EncodingError::InvalidBlock);
        }
        let message = &data[hash_length + start + 1..];
        output[..message.len()].copy_from_slice(message);
        Ok(message.len())
    }
}

/// The index in `padding` of its first byte that is not zero, and all ones
/// when that byte is `01`, or zero when it is another or there is none.
/// Constant time: every byte is read, whatever it holds, and no index is
/// taken from them; only the length of `padding`, which is public, steers
/// it.
fn find_separator(padding: &[u8]) -> (usize, isize) {
    // All ones until the first byte that is not zero.
    let mut looking: isize = -1;
    let mut start = 0;
    let mut found = 0;
    for (index, &byte) in padding.iter().enumerate() {
        let is_zero = (isize::from(byte) - 1) >> (isize::BITS - 1);
        let is_separator = (isize::from(byte ^ SEPARATOR) - 1) >> (isize::BITS - 1);
        start |= index as isize & looking & is_separator;
        found |= looking & is_separator;
        looking &= is_zero;
    }
    (start as usize, found)
}

/// XORs into `target` the mask MGF1 makes of `seed` over `digest`, as
/// Bouncy Castle's `MaskGeneratorFunction1`: the hash of `seed` and a
/// big-endian counter, for each block of the hash from zero, through
/// `scratch`, which takes one. Constant time as far as the digest is: the
/// number of blocks follows the length of `target`, which is public.
fn mgf1(digest: &mut impl Digest, scratch: &mut [u8], seed: &[u8], target: &mut [u8]) {
    digest.reset();
    for (counter, chunk) in target.chunks_mut(scratch.len()).enumerate() {
        digest.update(seed);
        digest.update(&(counter as u32).to_be_bytes());
        digest.do_final(scratch);
        for (byte, mask) in chunk.iter_mut().zip(scratch.iter()) {
            *byte ^= mask;
        }
    }
}

/// The hash of `label` by `digest`, reset first. Constant time as far as
/// the digest is; the label is public.
fn hash(digest: &mut impl Digest, label: &[u8]) -> Vec<u8> {
    digest.reset();
    digest.update(label);
    let mut output = vec![0; digest.digest_size()];
    digest.do_final(&mut output);
    output
}

#[cfg(test)]
mod tests {
    use super::find_separator;

    #[test]
    fn the_separator_is_the_first_byte_that_is_not_zero() {
        assert_eq!(find_separator(&[0, 0, 1, 7, 1]), (2, -1));
        assert_eq!(find_separator(&[1, 0]), (0, -1));
        assert_eq!(find_separator(&[0, 0, 0, 1]), (3, -1));
    }

    #[test]
    fn padding_that_ends_on_another_byte_or_not_at_all_has_no_separator() {
        assert_eq!(find_separator(&[0, 0, 2, 1]).1, 0);
        assert_eq!(find_separator(&[0xff, 1]).1, 0);
        assert_eq!(find_separator(&[0, 0, 0]).1, 0);
        assert_eq!(find_separator(&[]).1, 0);
    }
}
