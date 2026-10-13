//! ISO 9796-1 over RSA.

use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use core::marker::PhantomData;

use tc_asym_cipher::{AsymmetricBlockCipher, AsymmetricBlockCipherInit, CipherDirection};
use tc_bigint::BitOps;
use tc_rsa_v2::RsaKeyParams;

use crate::Iso9796Error;

/// The shadow of each nibble, as ISO 9796-1 and Bouncy Castle's `Shadows`.
const SHADOWS: [u8; 16] = [14, 3, 5, 8, 9, 4, 2, 15, 0, 13, 11, 6, 7, 10, 12, 1];

/// The nibble of each shadow, as Bouncy Castle's `Inverse`.
const INVERSE: [u8; 16] = [8, 15, 6, 1, 5, 2, 11, 12, 3, 4, 13, 10, 14, 9, 0, 7];

/// What a block ends in: the nibble six, below the last byte of the
/// message.
const FORCING: u8 = 0x06;

/// The highest pad bits a message takes.
const MAX_PAD_BITS: u8 = 7;

/// The direction, the size of the modulus in bits, and the modulus,
/// big-endian over its bytes, the encoding was initialized with.
struct State {
    direction: CipherDirection,
    bits: u32,
    modulus: Vec<u8>,
}

/// ISO 9796-1 padding over the RSA engine `E`, with keys of the integers
/// `T`, as Bouncy Castle's `ISO9796d1Encoding`: a signature with message
/// recovery, signed by encrypting with a private key and verified by
/// decrypting with the public one, which gives the message back.
///
/// The message is repeated over half the modulus and interleaved with its
/// shadows, its end marked with the pad bits plus one, and the block forced
/// to end in the nibble six and to take one bit less than the modulus.
/// Verifying takes a signature `s` or `n - s`, whichever gives a block
/// that ends in six, so the encoding reads the modulus of the key, and
/// takes only RSA keys. The pad bits of the next message to sign are set
/// with [`set_pad_bits`](Self::set_pad_bits), and those of the last one
/// verified read with [`pad_bits`](Self::pad_bits); a message that fills
/// the input block loses them, as in Bouncy Castle.
///
/// ISO 9796-1 is withdrawn: sign only a hash or a random value with it,
/// never a message as it is, and only with RSA, never Rabin's simpler
/// keys, as Bouncy Castle warns.
///
/// The block takes the whole length of the modulus, below it as its top
/// bit is forced, as Bouncy Castle's engine takes any input below the
/// modulus; the engine is therefore always initialized to decrypt, the
/// direction whose input block is the whole modulus, as RSA raises to the
/// power of the key either way. Moduli whose size in bits leaves 3 to 9
/// over a multiple of 16, as 1027 bits does, are turned down at `init`:
/// Bouncy Castle reads past the start of its block on them. A message
/// longer than the input block, which Bouncy Castle cuts short, an empty
/// one, on which it loops forever, and a decrypted block too short for
/// its pairs of bytes, which it reads past the start of, are turned down
/// too.
///
/// Variable time: only for public values, as a signature, the key that
/// verifies it, and the hash that is signed are; the shadows are looked up
/// in a table at the nibbles of the message.
///
/// ```
/// use tc_asym_cipher::{
///     AsymmetricBlockCipher, AsymmetricBlockCipherInit, CipherDirection, KeyPairGenerator,
///     KeyPairGeneratorInit,
/// };
/// use tc_asym_iso9796::Iso9796d1Encoding;
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
/// // 2. Sign a hash, of at most 128 bytes, with the private key.
/// let hash = [0x5a; 32];
/// let mut encoding = Iso9796d1Encoding::new(FixedRsaCoreEngine::new());
/// encoding.init(CipherDirection::Encrypt, &private)?;
/// let mut signature = vec![0; encoding.output_block_size()];
/// encoding.process_block(&hash, &mut signature)?;
///
/// // 3. Verify with the public key: the hash comes back out of the
/// //    signature.
/// encoding.init(CipherDirection::Decrypt, &public)?;
/// let mut recovered = vec![0; encoding.output_block_size()];
/// let length = encoding.process_block(&signature, &mut recovered)?;
/// recovered.truncate(length);
/// # assert_eq!(recovered, hash);
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct Iso9796d1Encoding<E, T> {
    engine: E,
    pad_bits: u8,
    state: Option<State>,
    key: PhantomData<fn() -> T>,
}

impl<E, T> Iso9796d1Encoding<E, T> {
    /// `engine`, to be initialized through the encoding, with no pad bits.
    /// Constant time.
    pub const fn new(engine: E) -> Self {
        Self {
            engine,
            pad_bits: 0,
            state: None,
            key: PhantomData,
        }
    }

    /// Sets the pad bits of the next message to sign, as Bouncy Castle's
    /// `SetPadBits`: the bits of its first byte, from the top, that are
    /// not part of it. Signing fails with `InvalidPadBits` above seven.
    /// Constant time.
    pub fn set_pad_bits(&mut self, pad_bits: u8) {
        self.pad_bits = pad_bits;
    }

    /// The pad bits of the last message verified, or those set for the
    /// next one to sign, as Bouncy Castle's `GetPadBits`. Constant time.
    pub fn pad_bits(&self) -> u8 {
        self.pad_bits
    }

    /// The engine, as Bouncy Castle's `UnderlyingCipher`. Constant time.
    pub fn underlying_cipher(&self) -> &E {
        &self.engine
    }

    /// The engine back. Constant time.
    pub fn into_inner(self) -> E {
        self.engine
    }
}

impl<E: fmt::Display, T> fmt::Display for Iso9796d1Encoding<E, T> {
    /// Writes the name of the engine and `/ISO9796-1Padding`, as Bouncy
    /// Castle's `AlgorithmName`, as `RSA/ISO9796-1Padding`. Constant time
    /// when the engine's `Display` is; output timing depends on the
    /// formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.engine.fmt(f)?;
        f.write_str("/ISO9796-1Padding")
    }
}

impl<E, T, P> AsymmetricBlockCipherInit<P> for Iso9796d1Encoding<E, T>
where
    E: AsymmetricBlockCipher + AsymmetricBlockCipherInit<P>,
    P: RsaKeyParams<T>,
    T: BitOps,
{
    type Error = Iso9796Error<<E as AsymmetricBlockCipherInit<P>>::Error>;

    /// Initializes the engine with `params`, to decrypt whichever the
    /// direction, and reads the modulus of the key, as Bouncy Castle does.
    /// Fails with the engine's error, or with `UnsupportedKeySize` for a
    /// modulus whose size in bits leaves 3 to 9 over a multiple of 16, or
    /// is below 16; a failed `init` leaves the encoding uninitialized.
    /// Variable time: only for public values, as the modulus is.
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), Self::Error> {
        self.state = None;
        self.engine
            .init(CipherDirection::Decrypt, params)
            .map_err(Iso9796Error::Cipher)?;
        let modulus = params.modulus();
        let bits = modulus.bits();
        if bits < 16 || (3..=9).contains(&(bits % 16)) {
            return Err(Iso9796Error::UnsupportedKeySize);
        }
        self.state = Some(State {
            direction,
            bits,
            modulus: to_be_bytes(modulus, bits.div_ceil(8) as usize),
        });
        Ok(())
    }
}

impl<E: AsymmetricBlockCipher, T> AsymmetricBlockCipher for Iso9796d1Encoding<E, T> {
    type Error = Iso9796Error<E::Error>;

    /// Half the block a modulus of `bits` bits encrypts, `(bits - 1) / 8`
    /// bytes, rounded up, when signing, as Bouncy Castle has it, and the
    /// input block of the engine when verifying; zero before
    /// initialization. Constant time.
    fn input_block_size(&self) -> usize {
        match &self.state {
            None => 0,
            Some(State {
                direction: CipherDirection::Encrypt,
                bits,
                ..
            }) => ((*bits as usize - 1) / 8).div_ceil(2),
            Some(_) => self.engine.input_block_size(),
        }
    }

    /// The output block of the engine when signing, and half of it,
    /// rounded up, when verifying; zero before initialization. Constant
    /// time.
    fn output_block_size(&self) -> usize {
        match &self.state {
            None => 0,
            Some(State {
                direction: CipherDirection::Encrypt,
                ..
            }) => self.engine.output_block_size(),
            Some(_) => self.engine.output_block_size().div_ceil(2),
        }
    }

    /// Signs `input`, or verifies it and writes the message it recovers
    /// at the start of `output`, and gives the number of bytes written.
    /// Fails with `NotInitialized`, `InputTooShort` for an empty message,
    /// `InputTooLarge`, `InvalidPadBits`, `OutputTooShort`, the engine's
    /// error, or, when verifying, `InvalidBlock`. Variable time: only for
    /// public values, as a signature and the hash it signs are.
    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        let state = self.state.as_ref();
        match state.ok_or(Iso9796Error::NotInitialized)?.direction {
            CipherDirection::Encrypt => self.encode(input, output),
            CipherDirection::Decrypt => self.decode(input, output),
        }
    }
}

impl<E: AsymmetricBlockCipher, T> Iso9796d1Encoding<E, T> {
    /// Repeats `input` over half the block, interleaves it with its
    /// shadows, marks where it starts with the pad bits plus one, forces
    /// the ends of the block, and signs it, as Bouncy Castle's
    /// `EncodeBlock`. Variable time: only for public values, as the hash
    /// to sign is; its shadows are looked up in a table.
    fn encode(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Iso9796Error<E::Error>> {
        let Some(State { bits, .. }) = self.state else {
            return Err(Iso9796Error::NotInitialized);
        };
        if input.is_empty() {
            return Err(Iso9796Error::InputTooShort);
        }
        if input.len() > self.input_block_size() {
            return Err(Iso9796Error::InputTooLarge);
        }
        if self.pad_bits > MAX_PAD_BITS {
            return Err(Iso9796Error::InvalidPadBits);
        }
        if output.len() < self.engine.output_block_size() {
            return Err(Iso9796Error::OutputTooShort);
        }
        let length = bits.div_ceil(8) as usize;
        let half = (bits as usize + 13) / 16;
        let size = input.len();
        let mut block = vec![0; length];
        // The message, repeated from the end over `half` bytes, the copy
        // that reaches past them cut to its last bytes.
        for written in (0..half).step_by(size) {
            if written + size > half {
                block[length - half..length - written]
                    .copy_from_slice(&input[size - (half - written)..]);
            } else {
                block[length - written - size..length - written].copy_from_slice(input);
            }
        }
        // Each byte of the half after its shadow, over the whole of the
        // block; the moduli taken leave room for both.
        for index in (length - 2 * half..length).step_by(2) {
            let value = block[length - half + index / 2];
            block[index] = shadow(value);
            block[index + 1] = value;
        }
        block[length - 2 * size] ^= self.pad_bits + 1;
        block[length - 1] = (block[length - 1] << 4) | FORCING;
        // The top bit of the block is the one below that of the modulus.
        let top = 8 - (bits - 1) % 8;
        let offset = if top == 8 {
            block[0] = 0x00;
            block[1] |= 0x80;
            1
        } else {
            block[0] &= 0xff >> top;
            block[0] |= 0x80 >> top;
            0
        };
        self.engine
            .process_block(&block[offset..], output)
            .map_err(Iso9796Error::Cipher)
    }

    /// Verifies `input`: raises it to the public exponent, takes it or the
    /// modulus less it, whichever ends in six, undoes the forcing, finds
    /// where the message starts from the one pair of bytes whose shadow
    /// does not match, as Bouncy Castle's `DecodeBlock`, and writes the
    /// message back. Variable time: only for public values, as a signature
    /// and the key that verifies it are.
    fn decode(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Iso9796Error<E::Error>> {
        let Some(State { bits, modulus, .. }) = &self.state else {
            return Err(Iso9796Error::NotInitialized);
        };
        let length = self.engine.output_block_size();
        if output.len() < length.div_ceil(2) {
            return Err(Iso9796Error::OutputTooShort);
        }
        let mut block = vec![0; length];
        let written = self
            .engine
            .process_block(input, &mut block)
            .map_err(Iso9796Error::Cipher)?;
        if written != length || modulus.len() != length {
            return Err(Iso9796Error::InvalidBlock);
        }
        if block[length - 1] & 0x0f != FORCING {
            subtract_from(modulus, &mut block);
            if block[length - 1] & 0x0f != FORCING {
                return Err(Iso9796Error::InvalidBlock);
            }
        }
        let half = (*bits as usize + 13) / 16;
        let first = block.iter().position(|&byte| byte != 0).unwrap_or(length);
        let block = &mut block[first..];
        let length = block.len();
        if length < 2 * half {
            return Err(Iso9796Error::InvalidBlock);
        }
        block[length - 1] =
            (block[length - 1] >> 4) | (INVERSE[usize::from(block[length - 2] >> 4)] << 4);
        block[0] = shadow(block[1]);
        let mut boundary = None;
        let mut mark = 1;
        for index in (length - 2 * half..length).rev().step_by(2) {
            let tsum = shadow(block[index]) ^ block[index - 1];
            if tsum != 0 {
                if boundary.is_some() {
                    return Err(Iso9796Error::InvalidBlock);
                }
                boundary = Some(index - 1);
                mark = tsum;
            }
        }
        let boundary = boundary.unwrap_or(0);
        let message = (length - boundary) / 2;
        for (index, byte) in output[..message].iter_mut().enumerate() {
            *byte = block[boundary + 1 + 2 * index];
        }
        self.pad_bits = mark - 1;
        Ok(message)
    }
}

/// The shadow of `value`, nibble by nibble. Variable time: only for public
/// values, as the table is indexed by the nibbles.
fn shadow(value: u8) -> u8 {
    (SHADOWS[usize::from(value >> 4)] << 4) | SHADOWS[usize::from(value & 0x0f)]
}

/// `modulus - value` over `value`, both big-endian over the same bytes,
/// `value` below `modulus`. Variable time: only for public values, as the
/// result of a public power and the modulus are.
fn subtract_from(modulus: &[u8], value: &mut [u8]) {
    let mut borrow = 0;
    for (byte, &digit) in value.iter_mut().zip(modulus).rev() {
        let difference = u16::from(digit)
            .wrapping_sub(u16::from(*byte))
            .wrapping_sub(borrow);
        *byte = difference as u8;
        borrow = (difference >> 8) & 1;
    }
}

/// `value`, big-endian over `length` bytes, bit by bit, whatever the width
/// of `T`. Variable time: only for public values, as the modulus is.
fn to_be_bytes<T: BitOps>(value: &T, length: usize) -> Vec<u8> {
    (0..length)
        .map(|index| {
            let low = 8 * (length - 1 - index) as u32;
            (0..8).fold(0, |byte, bit| {
                byte | (u8::from(value.bit(low + bit)) << bit)
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{INVERSE, SHADOWS, shadow, subtract_from};

    #[test]
    fn the_inverse_undoes_each_shadow() {
        for nibble in 0..16 {
            assert_eq!(INVERSE[usize::from(SHADOWS[nibble])], nibble as u8);
        }
        assert_eq!(shadow(0x01), 0xe3);
    }

    #[test]
    fn subtracting_from_the_modulus_borrows_across_bytes() {
        let mut value = [0x00, 0x01, 0xff];
        subtract_from(&[0x01, 0x00, 0x00], &mut value);
        assert_eq!(value, [0x00, 0xfe, 0x01]);
    }
}
