//! What both PKCS#1 v1.5 encodings share: the engine, the random source and
//! the state of initialization, and the encoding and the checks of a block
//! over the buffer each encoding holds.

use rand_core::CryptoRng;
use tc_asym_cipher::{
    AsymmetricBlockCipher, AsymmetricBlockCipherInit, AsymmetricKeyParams, CipherDirection,
};
use tc_zeroize::Zeroize;

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

/// The direction and the kind of key an encoding was initialized with.
#[derive(Clone, Copy)]
pub(super) struct State {
    direction: CipherDirection,
    is_private: bool,
}

/// The engine, the random source, the plaintext length to decrypt to, if
/// fixed, and the state, once initialized.
pub(super) struct Encoder<E, R> {
    pub(super) engine: E,
    pub(super) rng: R,
    pub(super) plaintext_length: Option<usize>,
    pub(super) state: Option<State>,
}

impl<E, R> Encoder<E, R> {
    /// `engine` and `rng`, not yet initialized. Constant time.
    pub(super) const fn new(engine: E, rng: R) -> Self {
        Self {
            engine,
            rng,
            plaintext_length: None,
            state: None,
        }
    }
}

impl<E: AsymmetricBlockCipher, R> Encoder<E, R> {
    /// Initializes the engine, and gives back the state to start in and the
    /// length of the block the direction works on, for the encoding to fit
    /// its buffer to before it starts; leaves the encoding uninitialized
    /// until it does. Fails with `InvalidPlaintextLength` when decrypting
    /// with a private key to a fixed length beyond the output block.
    /// Constant time, apart from the engine's `init`: the rest reads only
    /// public lengths.
    pub(super) fn init<P>(
        &mut self,
        direction: CipherDirection,
        params: &P,
    ) -> Result<(State, usize), EncodingError<<E as AsymmetricBlockCipherInit<P>>::Error>>
    where
        E: AsymmetricBlockCipherInit<P>,
        P: AsymmetricKeyParams + ?Sized,
    {
        self.state = None;
        self.engine
            .init(direction, params)
            .map_err(EncodingError::Cipher)?;
        let state = State {
            direction,
            is_private: params.is_private_key(),
        };
        let length = match direction {
            CipherDirection::Encrypt => self.engine.input_block_size(),
            CipherDirection::Decrypt => self.engine.output_block_size(),
        };
        if let (CipherDirection::Decrypt, true, Some(plaintext)) =
            (direction, state.is_private, self.plaintext_length)
            && plaintext > length.saturating_sub(DECRYPTED_HEADER_LENGTH)
        {
            return Err(EncodingError::InvalidPlaintextLength);
        }
        Ok((state, length))
    }

    /// The input block of the engine, less the header when encrypting;
    /// zero before initialization. Constant time.
    pub(super) fn input_block_size(&self) -> usize {
        match self.state {
            None => 0,
            Some(State {
                direction: CipherDirection::Encrypt,
                ..
            }) => self.engine.input_block_size().saturating_sub(HEADER_LENGTH),
            Some(_) => self.engine.input_block_size(),
        }
    }

    /// The output block of the engine, less the header and its leading zero
    /// when decrypting; zero before initialization. Constant time.
    pub(super) fn output_block_size(&self) -> usize {
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
}

impl<E: AsymmetricBlockCipher, R: CryptoRng> Encoder<E, R> {
    /// Encrypts or decrypts one block through `buffer`, which holds the
    /// block of the engine, and wipes `buffer` afterwards, whatever the
    /// outcome. Constant time as far as [`encode`](Self::encode) or
    /// [`decode`](Self::decode) is.
    pub(super) fn process_block(
        &mut self,
        buffer: &mut [u8],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, EncodingError<E::Error>> {
        let state = self.state.ok_or(EncodingError::NotInitialized)?;
        let result = match state.direction {
            CipherDirection::Encrypt => self.encode(buffer, state.is_private, input, output),
            CipherDirection::Decrypt => self.decode(buffer, state.is_private, input, output),
        };
        buffer.zeroize();
        result
    }

    /// Pads `input` into a block of the engine's input block, `01 || ff.. ||
    /// 00 || input` with a private key and `02 || random.. || 00 || input`
    /// with a public one, as Bouncy Castle's `EncodeBlock`, and encrypts
    /// it. Constant time in the input, apart from the engine and from the
    /// random padding, as [`fill_non_zero`] draws it; its length is public.
    fn encode(
        &mut self,
        buffer: &mut [u8],
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
        let block = &mut buffer[..length];
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
    /// [`decode_or_random`](Self::decode_or_random) is.
    fn decode(
        &mut self,
        buffer: &mut [u8],
        is_private: bool,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, EncodingError<E::Error>> {
        let length = self.engine.output_block_size();
        if output.len() < length.saturating_sub(DECRYPTED_HEADER_LENGTH) {
            return Err(EncodingError::OutputTooShort);
        }
        let block = &mut buffer[..length];
        let written = self
            .engine
            .process_block(input, block)
            .map_err(EncodingError::Cipher)?;
        let short = -isize::from(written != length);
        match (is_private, self.plaintext_length) {
            (true, Some(plaintext)) => Ok(self.decode_or_random(block, short, plaintext, output)),
            (true, None) => decode_whole(block, short, PUBLIC_BLOCK_TYPE, output),
            (false, _) => decode_whole(block, short, PRIVATE_BLOCK_TYPE, output),
        }
    }

    /// Writes the message of `plaintext` bytes out of `block`, a block of
    /// type 2, or as many bytes drawn from the source in its place when the
    /// block is not one or `short` is set, as Bouncy Castle's
    /// `DecodeBlockOrRandom`, so that the outcome of the check never shows.
    /// Constant time: the check and the choice of each byte run over every
    /// byte whatever the block holds.
    fn decode_or_random(
        &mut self,
        block: &[u8],
        short: isize,
        plaintext: usize,
        output: &mut [u8],
    ) -> usize {
        let output = &mut output[..plaintext];
        self.rng.fill_bytes(output);
        // All ones for a bad block, and nothing for a good one.
        let bad = (check_of_length(block, plaintext) | short) as u8;
        for (out, &byte) in output.iter_mut().zip(&block[block.len() - plaintext..]) {
            *out = (byte & !bad) | (*out & bad);
        }
        plaintext
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

    /// A decrypted block of `length` bytes: the leading zero, `block_type`,
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
