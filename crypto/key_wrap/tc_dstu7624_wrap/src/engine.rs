//! DSTU 7624 key-wrap engine.

use tc_cipher::{
    BlockCipher, BlockCipherInit, BlockError, CipherDirection, KeyWrap, KeyWrapInit, WrapDirection,
};
use tc_crypto::AlgorithmName;
use tc_dstu7624::{Engine, Engine128, Engine256, Engine512};
use tc_params::KeyParams;

use crate::{Dstu7624WrapError, Dstu7624WrapInitError};

const MAX_BLOCK_BYTES: usize = 64;
const MAX_HALF_BLOCK_BYTES: usize = MAX_BLOCK_BYTES / 2;

/// DSTU 7624 key wrapping with a compile-time block width.
///
/// `BLOCK_WORDS` counts 64-bit words. Construct the supported 128-, 256-, and
/// 512-bit variants as `Dstu7624WrapEngine::<2>`, `<4>`, and `<8>`.
pub struct Dstu7624WrapEngine<const BLOCK_WORDS: usize> {
    cipher: Engine<BLOCK_WORDS>,
    direction: Option<WrapDirection>,
}

impl<const BLOCK_WORDS: usize> Dstu7624WrapEngine<BLOCK_WORDS> {
    const BLOCK_BYTES: usize = BLOCK_WORDS * 8;

    const fn from_cipher(cipher: Engine<BLOCK_WORDS>) -> Self {
        Self {
            cipher,
            direction: None,
        }
    }
}

macro_rules! impl_constructor {
    ($words:literal, $engine:ty) => {
        impl Dstu7624WrapEngine<$words> {
            /// Creates an uninitialized DSTU 7624 key wrapper.
            pub const fn new() -> Self {
                Self::from_cipher(<$engine>::new())
            }
        }

        impl Default for Dstu7624WrapEngine<$words> {
            fn default() -> Self {
                Self::new()
            }
        }
    };
}

impl_constructor!(2, Engine128);
impl_constructor!(4, Engine256);
impl_constructor!(8, Engine512);

impl<const BLOCK_WORDS: usize> AlgorithmName for Dstu7624WrapEngine<BLOCK_WORDS> {
    fn write_algo_name(&self, output: &mut dyn core::fmt::Write) -> core::fmt::Result {
        output.write_str("DSTU7624Wrap")
    }
}

impl<const BLOCK_WORDS: usize> Dstu7624WrapEngine<BLOCK_WORDS>
where
    Engine<BLOCK_WORDS>: BlockCipher<Error = BlockError>,
{
    fn crypt_block(&mut self, block: &mut [u8]) -> Result<(), Dstu7624WrapError> {
        let mut scratch = [0u8; MAX_BLOCK_BYTES];
        let block_bytes = Self::BLOCK_BYTES;
        self.cipher
            .process_block(block, &mut scratch[..block_bytes])
            .map_err(Dstu7624WrapError::Cipher)?;
        block.copy_from_slice(&scratch[..block_bytes]);
        scratch.fill(0);
        Ok(())
    }

    fn wrap_layout(&self, input_len: usize) -> Result<(usize, usize), Dstu7624WrapError> {
        if !input_len.is_multiple_of(Self::BLOCK_BYTES) {
            return Err(Dstu7624WrapError::InvalidWrapLength);
        }
        let output_len = input_len
            .checked_add(Self::BLOCK_BYTES)
            .ok_or(Dstu7624WrapError::InvalidWrapLength)?;
        let half_blocks = output_len / (Self::BLOCK_BYTES / 2);
        let rounds = half_blocks
            .checked_sub(1)
            .and_then(|count| count.checked_mul(6))
            .ok_or(Dstu7624WrapError::InvalidWrapLength)?;
        if u32::try_from(rounds).is_err() {
            return Err(Dstu7624WrapError::InvalidWrapLength);
        }
        Ok((output_len, half_blocks))
    }

    fn unwrap_layout(&self, input_len: usize) -> Result<(usize, usize), Dstu7624WrapError> {
        if input_len < Self::BLOCK_BYTES || !input_len.is_multiple_of(Self::BLOCK_BYTES) {
            return Err(Dstu7624WrapError::InvalidUnwrapLength);
        }
        let output_len = input_len - Self::BLOCK_BYTES;
        let half_blocks = input_len / (Self::BLOCK_BYTES / 2);
        let rounds = half_blocks
            .checked_sub(1)
            .and_then(|count| count.checked_mul(6))
            .ok_or(Dstu7624WrapError::InvalidUnwrapLength)?;
        if u32::try_from(rounds).is_err() {
            return Err(Dstu7624WrapError::InvalidUnwrapLength);
        }
        Ok((output_len, half_blocks))
    }
}

impl<const BLOCK_WORDS: usize> KeyWrap for Dstu7624WrapEngine<BLOCK_WORDS>
where
    Engine<BLOCK_WORDS>: BlockCipher<Error = BlockError>,
{
    type Error = Dstu7624WrapError;

    fn wrapped_len(&self, input_len: usize) -> Result<usize, Self::Error> {
        self.wrap_layout(input_len).map(|(length, _)| length)
    }

    fn max_unwrapped_len(&self, input_len: usize) -> Result<usize, Self::Error> {
        self.unwrap_layout(input_len).map(|(length, _)| length)
    }

    fn wrap_into(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        match self.direction {
            Some(WrapDirection::Wrap) => {}
            Some(WrapDirection::Unwrap) => return Err(Dstu7624WrapError::NotForWrapping),
            None => return Err(Dstu7624WrapError::NotInitialised),
        }
        let (required, half_blocks) = self.wrap_layout(input.len())?;
        if output.len() < required {
            return Err(Dstu7624WrapError::OutputTooShort {
                required,
                available: output.len(),
            });
        }

        let block_bytes = Self::BLOCK_BYTES;
        let half = block_bytes / 2;
        let rounds = (half_blocks - 1) * 6;
        let buffer = &mut output[..required];
        buffer.fill(0);
        buffer[..input.len()].copy_from_slice(input);

        let mut b = [0u8; MAX_HALF_BLOCK_BYTES];
        b[..half].copy_from_slice(&buffer[..half]);
        let mut block = [0u8; MAX_BLOCK_BYTES];

        for round in 0..rounds {
            block[..half].copy_from_slice(&b[..half]);
            block[half..block_bytes].copy_from_slice(&buffer[half..block_bytes]);
            if let Err(error) = self.crypt_block(&mut block[..block_bytes]) {
                buffer.fill(0);
                b.fill(0);
                block.fill(0);
                return Err(error);
            }

            for (index, byte) in ((round as u32) + 1).to_le_bytes().iter().enumerate() {
                block[half + index] ^= byte;
            }
            b[..half].copy_from_slice(&block[half..block_bytes]);
            buffer.copy_within(block_bytes..required, half);
            buffer[required - half..].copy_from_slice(&block[..half]);
        }

        buffer[..half].copy_from_slice(&b[..half]);
        b.fill(0);
        block.fill(0);
        Ok(required)
    }

    fn unwrap_into(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        match self.direction {
            Some(WrapDirection::Unwrap) => {}
            Some(WrapDirection::Wrap) => return Err(Dstu7624WrapError::NotForUnwrapping),
            None => return Err(Dstu7624WrapError::NotInitialised),
        }
        let (required, half_blocks) = self.unwrap_layout(input.len())?;
        if output.len() < required {
            return Err(Dstu7624WrapError::OutputTooShort {
                required,
                available: output.len(),
            });
        }

        let block_bytes = Self::BLOCK_BYTES;
        let half = block_bytes / 2;
        let rounds = (half_blocks - 1) * 6;
        let buffer = &mut output[..required];
        let mut b = [0u8; MAX_HALF_BLOCK_BYTES];
        b[..half].copy_from_slice(&input[..half]);
        if required != 0 {
            buffer.copy_from_slice(&input[half..input.len() - half]);
        }
        let mut extra = [0u8; MAX_HALF_BLOCK_BYTES];
        extra[..half].copy_from_slice(&input[input.len() - half..]);
        let mut block = [0u8; MAX_BLOCK_BYTES];

        for round in 0..rounds {
            block[..half].copy_from_slice(&extra[..half]);
            block[half..block_bytes].copy_from_slice(&b[..half]);
            for (index, byte) in ((rounds - round) as u32).to_le_bytes().iter().enumerate() {
                block[half + index] ^= byte;
            }
            if let Err(error) = self.crypt_block(&mut block[..block_bytes]) {
                buffer.fill(0);
                b.fill(0);
                extra.fill(0);
                block.fill(0);
                return Err(error);
            }
            b[..half].copy_from_slice(&block[..half]);

            if required == 0 {
                extra[..half].copy_from_slice(&block[half..block_bytes]);
            } else {
                extra[..half].copy_from_slice(&buffer[required - half..]);
                buffer.copy_within(..required - half, half);
                buffer[..half].copy_from_slice(&block[half..block_bytes]);
            }
        }

        let mut difference = 0u8;
        if required == 0 {
            for byte in b[..half].iter().chain(&extra[..half]) {
                difference |= *byte;
            }
        } else {
            for byte in buffer[required - half..].iter().chain(&extra[..half]) {
                difference |= *byte;
            }
        }
        if difference != 0 {
            buffer.fill(0);
            b.fill(0);
            extra.fill(0);
            block.fill(0);
            return Err(Dstu7624WrapError::IntegrityCheckFailed);
        }

        if required != 0 {
            buffer.copy_within(..required - half, half);
            buffer[..half].copy_from_slice(&b[..half]);
        }
        b.fill(0);
        extra.fill(0);
        block.fill(0);
        Ok(required)
    }
}

impl<const BLOCK_WORDS: usize, P> KeyWrapInit<P> for Dstu7624WrapEngine<BLOCK_WORDS>
where
    Engine<BLOCK_WORDS>:
        BlockCipher<Error = BlockError> + BlockCipherInit<P, Error = tc_cipher::InitError>,
    P: KeyParams + ?Sized,
{
    type Error = Dstu7624WrapInitError;

    fn init(&mut self, direction: WrapDirection, params: &P) -> Result<(), Self::Error> {
        self.direction = None;
        let cipher_direction = match direction {
            WrapDirection::Wrap => CipherDirection::Encrypt,
            WrapDirection::Unwrap => CipherDirection::Decrypt,
        };
        self.cipher
            .init(cipher_direction, params)
            .map_err(Dstu7624WrapInitError::Cipher)?;
        self.direction = Some(direction);
        Ok(())
    }
}
