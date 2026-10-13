//! PKCS#1 v1.5 encoding over an asymmetric block cipher.

use alloc::vec::Vec;
use core::fmt;

use rand_core::CryptoRng;
use tc_asym_cipher::{
    AsymmetricBlockCipher, AsymmetricBlockCipherInit, AsymmetricKeyParams, CipherDirection,
};
use tc_zeroize::{Zeroize, Zeroizing};

use crate::EncodingError;

/// The bytes of an encoded block besides the message, as Bouncy Castle's
/// `HeaderLength`: the block type, at least eight bytes of padding, and the
/// zero byte that ends the padding.
const HEADER_LENGTH: usize = 10;

/// The bytes of a decrypted block besides the message: the header, behind
/// the leading zero byte the engine keeps, as it writes its whole output
/// block. Its zero byte that ends the padding is at index `HEADER_LENGTH`
/// or later.
const DECRYPTED_HEADER_LENGTH: usize = HEADER_LENGTH + 1;

/// The block type of an encoding with a private key, padded with `ff`.
const PRIVATE_BLOCK_TYPE: u8 = 0x01;

/// The block type of an encoding with a public key, padded at random.
const PUBLIC_BLOCK_TYPE: u8 = 0x02;

/// The direction and the kind of key the encoding was initialized with.
#[derive(Clone, Copy)]
struct State {
    direction: CipherDirection,
    is_private: bool,
}

/// PKCS#1 v1.5 encoding over the asymmetric block cipher `E`, as Bouncy
/// Castle's `Pkcs1Encoding`. It draws from the random source `R` it holds
/// to pad with a public key, and, with
/// [`with_plaintext_length`](Self::with_plaintext_length), for what it
/// gives back in place of a bad block. `R` can be a `&mut` borrow, so the
/// caller keeps the source and its state. The block of the engine is
/// sized at `init`, as Bouncy Castle sizes its `blockBuffer`, and wiped
/// after each use. There is no `Debug`, which would show the state of the
/// source.
///
/// Encrypting with a public key pads as block type 2, with random bytes
/// none of which is zero; with a private key, as for a signature, as block
/// type 1, with `ff` bytes. Decrypting checks for the type the other key
/// gave: 2 with a private key and 1 with a public one, and takes the
/// padding off. The input block when encrypting, and the output block when
/// decrypting, are eleven bytes short of the modulus: at least eight bytes
/// of padding, and the type and two zero bytes around them. PKCS#1 defines
/// the encoding for RSA; OpenPGP uses it with ElGamal too.
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
/// // 2. Encrypt with the public key: the message, of at most 245 bytes, is
/// //    padded with random bytes into a block of the 256-byte modulus.
/// let mut encoding = Pkcs1Encoding::from_parts(FixedRsaCoreEngine::new(), rand::rng());
/// encoding.init(CipherDirection::Encrypt, &public)?;
/// let mut ciphertext = vec![0; encoding.output_block_size()];
/// encoding.process_block(b"attack at dawn", &mut ciphertext)?;
///
/// // 3. Decrypt with the private key: the padding is checked and taken off.
/// encoding.init(CipherDirection::Decrypt, &private)?;
/// let mut plaintext = vec![0; encoding.output_block_size()];
/// let length = encoding.process_block(&ciphertext, &mut plaintext)?;
/// plaintext.truncate(length);
/// # assert_eq!(plaintext, b"attack at dawn");
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct Pkcs1Encoding<E, R> {
    engine: E,
    rng: R,
    plaintext_length: Option<usize>,
    state: Option<State>,
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
            engine,
            rng,
            plaintext_length: None,
            state: None,
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
        self.plaintext_length = Some(length);
        self
    }

    /// The engine, as Bouncy Castle's `UnderlyingCipher`. Constant time.
    pub fn underlying_cipher(&self) -> &E {
        &self.engine
    }

    /// The engine and the random source back. Constant time.
    pub fn into_parts(self) -> (E, R) {
        (self.engine, self.rng)
    }
}

impl<E: fmt::Display, R> fmt::Display for Pkcs1Encoding<E, R> {
    /// Writes the name of the engine and `/PKCS1Padding`, as Bouncy
    /// Castle's `AlgorithmName`, as `RSA/PKCS1Padding`. Constant time when
    /// the engine's `Display` is; output timing depends on the formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.engine.fmt(f)?;
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
    /// length beyond the output block when decrypting with a private key.
    /// A failed `init` leaves the encoding uninitialized. Constant time,
    /// apart from the engine's `init` and the allocator: the rest reads
    /// only public lengths.
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), Self::Error> {
        self.state = None;
        self.engine
            .init(direction, params)
            .map_err(EncodingError::Cipher)?;
        let is_private = params.is_private_key();
        let length = match direction {
            CipherDirection::Encrypt => self.engine.input_block_size(),
            CipherDirection::Decrypt => self.engine.output_block_size(),
        };
        if let (CipherDirection::Decrypt, true, Some(plaintext)) =
            (direction, is_private, self.plaintext_length)
            && plaintext > length.saturating_sub(DECRYPTED_HEADER_LENGTH)
        {
            return Err(EncodingError::InvalidPlaintextLength);
        }
        // The block is wiped after each use, and so nothing is left behind
        // where it moves from.
        self.block.resize(length, 0);
        self.state = Some(State {
            direction,
            is_private,
        });
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
        match self.state {
            None => 0,
            Some(State {
                direction: CipherDirection::Encrypt,
                ..
            }) => self.engine.input_block_size().saturating_sub(HEADER_LENGTH),
            Some(_) => self.engine.input_block_size(),
        }
    }

    /// The output block of the engine when encrypting, and eleven bytes
    /// less when decrypting, for the header and the leading zero; zero
    /// before initialization. Constant time.
    fn output_block_size(&self) -> usize {
        match self.state {
            None => 0,
            Some(State {
                direction: CipherDirection::Decrypt,
                ..
            }) => self
                .engine
                .output_block_size()
                .saturating_sub(DECRYPTED_HEADER_LENGTH),
            Some(_) => self.engine.output_block_size(),
        }
    }

    /// Pads and encrypts `input`, or decrypts it and takes the padding
    /// off, writing the message at the start of `output`, and gives the
    /// number of bytes written; the block is wiped afterwards, whatever
    /// the outcome. Fails with `NotInitialized`, `InputTooLarge`,
    /// `OutputTooShort`, the engine's error, or, when decrypting without a
    /// plaintext length, `InvalidBlock`. Constant time in the message and
    /// the block, apart from the engine: with a public key, the draws of
    /// the padding redraw each zero, which shows where the source drew one
    /// but nothing of the padding kept; without a plaintext length,
    /// whether a decrypted block is good shows through the error, and its
    /// message length through the result.
    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        let state = self.state.ok_or(EncodingError::NotInitialized)?;
        let result = match state.direction {
            CipherDirection::Encrypt => self.encode(state.is_private, input, output),
            CipherDirection::Decrypt => self.decode(state.is_private, input, output),
        };
        self.block.as_mut_slice().zeroize();
        result
    }
}

impl<E, R> Pkcs1Encoding<E, R>
where
    E: AsymmetricBlockCipher,
    R: CryptoRng,
{
    /// Pads `input` into a block of the engine's input block, `01 || ff.. ||
    /// 00 || input` with a private key and `02 || random.. || 00 || input`
    /// with a public one, as Bouncy Castle's `EncodeBlock`, and encrypts
    /// it. Constant time in the input, apart from the engine and from the
    /// random padding, as [`fill_non_zero`] draws it; its length is public.
    fn encode(
        &mut self,
        is_private: bool,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, EncodingError<E::Error>> {
        let length = self.engine.input_block_size();
        if input.len() + HEADER_LENGTH > length {
            return Err(EncodingError::InputTooLarge);
        }
        if output.len() < self.engine.output_block_size() {
            return Err(EncodingError::OutputTooShort);
        }
        let block = &mut self.block[..length];
        let separator = length - 1 - input.len();
        if is_private {
            block[0] = PRIVATE_BLOCK_TYPE;
            block[1..separator].fill(0xff);
        } else {
            block[0] = PUBLIC_BLOCK_TYPE;
            fill_non_zero(&mut self.rng, &mut block[1..separator]);
        }
        block[separator] = 0x00;
        block[separator + 1..].copy_from_slice(input);
        self.engine
            .process_block(block, output)
            .map_err(EncodingError::Cipher)
    }

    /// Decrypts `input` and takes the message out of the block: type 2 with
    /// a private key and type 1 with a public one, as Bouncy Castle's
    /// `DecodeBlock`, or to a fixed length with a private key, as its
    /// `DecodeBlockOrRandom`. A block the engine writes shorter than its
    /// output block fails the check, as Bouncy Castle's strict length does.
    /// Constant time, apart from the engine, as far as [`decode_whole`] or
    /// [`decode_or_random`] is.
    fn decode(
        &mut self,
        is_private: bool,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, EncodingError<E::Error>> {
        let length = self.engine.output_block_size();
        if output.len() < length.saturating_sub(DECRYPTED_HEADER_LENGTH) {
            return Err(EncodingError::OutputTooShort);
        }
        let block = &mut self.block[..length];
        let written = self
            .engine
            .process_block(input, block)
            .map_err(EncodingError::Cipher)?;
        let short = -isize::from(written != length);
        match (is_private, self.plaintext_length) {
            (true, Some(plaintext)) => Ok(decode_or_random(
                &mut self.rng,
                block,
                short,
                plaintext,
                output,
            )),
            (true, None) => decode_whole(block, short, PUBLIC_BLOCK_TYPE, output),
            (false, _) => decode_whole(block, short, PRIVATE_BLOCK_TYPE, output),
        }
    }
}

/// Writes the message out of `block`, a block of type `block_type`, unless
/// it is not one or `short` is set, as Bouncy Castle's `DecodeBlock`.
/// Constant time in the check, which runs over every byte; its outcome then
/// shows, through the error and the length of the message, as it must
/// here: with a private key, it is the padding oracle of Bleichenbacher's
/// attack, which a fixed plaintext length takes away.
fn decode_whole<X>(
    block: &[u8],
    short: isize,
    block_type: u8,
    output: &mut [u8],
) -> Result<usize, EncodingError<X>> {
    let plaintext = check(block, block_type) | short;
    if plaintext < 0 {
        return Err(EncodingError::InvalidBlock);
    }
    let plaintext = plaintext as usize;
    output[..plaintext].copy_from_slice(&block[block.len() - plaintext..]);
    Ok(plaintext)
}

/// Writes the message of `plaintext` bytes out of `block`, a block of
/// type 2, or as many bytes drawn from `rng` in its place when the block
/// is not one or `short` is set, as Bouncy Castle's `DecodeBlockOrRandom`,
/// so that the outcome of the check never shows. Constant time: the check
/// and the choice of each byte run over every byte whatever the block
/// holds.
fn decode_or_random(
    rng: &mut impl CryptoRng,
    block: &[u8],
    short: isize,
    plaintext: usize,
    output: &mut [u8],
) -> usize {
    let output = &mut output[..plaintext];
    rng.fill_bytes(output);
    // All ones for a bad block, and nothing for a good one.
    let bad = (check_of_length(block, plaintext) | short) as u8;
    for (out, &byte) in output.iter_mut().zip(&block[block.len() - plaintext..]) {
        *out = (byte & !bad) | (*out & bad);
    }
    plaintext
}

/// Fills `pad` from `rng` with bytes none of which is zero, as a zero
/// would end the padding: each zero drawn is drawn again, as Bouncy Castle
/// does. Variable time in the draws only: the time shows where the source
/// drew a zero, which it then draws over, and so nothing of the bytes kept.
fn fill_non_zero(rng: &mut impl CryptoRng, pad: &mut [u8]) {
    rng.fill_bytes(pad);
    for byte in pad {
        while *byte == 0 {
            rng.fill_bytes(core::slice::from_mut(byte));
        }
    }
}

/// The length of the message in `block`, a decrypted block, when it is
/// `00 || block_type || padding || 00 || message` with at least eight
/// bytes of padding, each `ff` for type 1, and a negative number when it is
/// not, as Bouncy Castle's `CheckPkcs1Encoding1` and `CheckPkcs1Encoding2`
/// tell. The first zero after the type ends the padding. Constant time:
/// every byte is read, whatever it holds; only the length of the block and
/// `block_type`, which are public, steer it.
fn check(block: &[u8], block_type: u8) -> isize {
    if block.len() < DECRYPTED_HEADER_LENGTH {
        return -1;
    }
    let all_ff = -isize::from(block_type == PRIVATE_BLOCK_TYPE);
    let mut bad = -isize::from(block[0]) | -isize::from(block[1] ^ block_type);
    let mut found = 0;
    let mut separator = 0;
    for (index, &byte) in block.iter().enumerate().skip(2) {
        // All ones where the byte is zero, or `ff`, and nothing elsewhere.
        let is_zero = (isize::from(byte) - 1) >> (isize::BITS - 1);
        let is_ff = (isize::from(byte ^ 0xff) - 1) >> (isize::BITS - 1);
        separator ^= index as isize & !found & is_zero;
        found |= is_zero;
        bad |= !(found | is_ff) & all_ff;
    }
    // Missing, the separator stays at zero, and fails here too.
    bad |= separator - HEADER_LENGTH as isize;
    (block.len() as isize - 1 - separator) | (bad >> (isize::BITS - 1))
}

/// Zero when `block`, a decrypted block, is `00 || 02 || padding || 00 ||
/// message` with a message of `plaintext` bytes and at least eight bytes
/// of padding, none zero, and minus one when it is not, as Bouncy Castle's
/// `CheckPkcs1Encoding2` with a length tells. Constant time: every byte
/// is read, whatever it holds; only the length of the block and
/// `plaintext`, which are public, steer it.
fn check_of_length(block: &[u8], plaintext: usize) -> isize {
    if block.len() < DECRYPTED_HEADER_LENGTH + plaintext {
        return -1;
    }
    let separator = block.len() - 1 - plaintext;
    let mut bad = -isize::from(block[0]) | -isize::from(block[1] ^ PUBLIC_BLOCK_TYPE);
    for &byte in &block[2..separator] {
        bad |= isize::from(byte) - 1;
    }
    bad |= -isize::from(block[separator]);
    bad >> (isize::BITS - 1)
}

#[cfg(test)]
mod tests {
    use super::{check, check_of_length};

    /// A decrypted block of `L` bytes: the leading zero, `block_type`,
    /// `pad` bytes of `fill`, the zero that ends them, and the message `5a`
    /// over the rest.
    fn block<const L: usize>(block_type: u8, pad: usize, fill: u8) -> [u8; L] {
        let mut block = [0x5a; L];
        block[0] = 0x00;
        block[1] = block_type;
        block[2..2 + pad].fill(fill);
        block[2 + pad] = 0x00;
        block
    }

    #[test]
    fn the_message_is_what_follows_the_first_zero_after_the_padding() {
        assert_eq!(check(&block::<32>(1, 8, 0xff), 1), 21);
        assert_eq!(check(&block::<32>(2, 8, 0x17), 2), 21);
        assert_eq!(check(&block::<32>(2, 29, 0x17), 2), 0);
        let mut second_zero = block::<32>(2, 8, 0x17);
        second_zero[20] = 0x00;
        assert_eq!(check(&second_zero, 2), 21);
        assert_eq!(check_of_length(&block::<32>(2, 8, 0x17), 21), 0);
        assert_eq!(check_of_length(&block::<32>(2, 29, 0x17), 0), 0);
    }

    #[test]
    fn padding_shorter_than_eight_bytes_is_turned_down() {
        assert!(check(&block::<32>(1, 7, 0xff), 1) < 0);
        assert!(check(&block::<32>(2, 7, 0x17), 2) < 0);
        assert_eq!(check_of_length(&block::<32>(2, 7, 0x17), 22), -1);
        assert!(check(&block::<10>(2, 7, 0x17), 2) < 0);
        assert_eq!(check_of_length(&[0, 2, 1, 1, 1, 1, 1, 1, 1, 1], 0), -1);
    }

    #[test]
    fn a_block_without_its_leading_zero_or_type_is_turned_down() {
        let mut leading = block::<32>(1, 8, 0xff);
        leading[0] = 0x01;
        assert!(check(&leading, 1) < 0);
        assert!(check(&block::<32>(2, 8, 0xff), 1) < 0);
        assert!(check(&block::<32>(1, 8, 0xff), 2) < 0);
        assert_eq!(check_of_length(&block::<32>(1, 8, 0x17), 21), -1);
        let mut leading = block::<32>(2, 8, 0x17);
        leading[0] = 0x80;
        assert_eq!(check_of_length(&leading, 21), -1);
    }

    #[test]
    fn type_one_padding_takes_nothing_but_ff() {
        let mut stray = block::<32>(1, 8, 0xff);
        stray[5] = 0xfe;
        assert!(check(&stray, 1) < 0);
        // Type 2 takes any byte but zero.
        let mut stray = block::<32>(2, 8, 0xff);
        stray[5] = 0xfe;
        assert_eq!(check(&stray, 2), 21);
    }

    #[test]
    fn padding_with_no_zero_after_it_is_turned_down() {
        let mut endless = [0xff; 32];
        endless[0] = 0x00;
        endless[1] = 0x01;
        assert!(check(&endless, 1) < 0);
        endless[1] = 0x02;
        assert!(check(&endless, 2) < 0);
    }

    #[test]
    fn a_fixed_length_turns_down_a_message_of_another_length() {
        let good = block::<32>(2, 8, 0x17);
        assert_eq!(check_of_length(&good, 21), 0);
        // Longer: the padding would end on a message byte, not a zero.
        assert_eq!(check_of_length(&good, 22), -1);
        // Shorter: the zero would sit inside the padding.
        assert_eq!(check_of_length(&good, 20), -1);
    }
}
