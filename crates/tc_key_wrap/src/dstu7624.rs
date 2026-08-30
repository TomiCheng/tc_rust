//! DSTU 7624 (Kalyna) key wrap engine.
//!
//! Mirrors Bouncy Castle's `Dstu7624WrapEngine`. Unlike the RFC 3394 / 5649
//! wrappers this is a scheme of its own: it appends an all-zero checking block,
//! then runs a swap network over half-blocks with a per-round counter XOR, using
//! the DSTU 7624 cipher. The block and key widths are the cipher's compile-time
//! word counts, so only the five combinations the standard defines can be named.

use tc_block_cipher::dstu7624::{Dstu7624Config, ValidDstu7624Config};
use tc_block_cipher::{BlockCipherError, Dstu7624Engine, Dstu7624Params};
use tc_cipher_core::{
    BlockCipher, BlockCipherInit, CipherDirection, KeyWrap, KeyWrapInit, WrapDirection,
};

/// DSTU 7624 (Kalyna) key wrap over a block and key of the selected widths.
///
/// Both const parameters count 64-bit words and match the underlying cipher, so
/// the key is necessarily the block size or twice it. Build with [`new`](Self::new),
/// then use the allocation-free [`KeyWrap`] interface.
pub struct Dstu7624WrapEngine<const BLOCK_WORDS: usize, const KEY_WORDS: usize>
where
    Dstu7624Config<BLOCK_WORDS, KEY_WORDS>: ValidDstu7624Config<BLOCK_WORDS>,
{
    /// The underlying DSTU 7624 cipher.
    engine: Dstu7624Engine<BLOCK_WORDS, KEY_WORDS>,
    /// The key-level operation selected during initialization.
    direction: Option<WrapDirection>,
}

impl<const BLOCK_WORDS: usize, const KEY_WORDS: usize> Dstu7624WrapEngine<BLOCK_WORDS, KEY_WORDS>
where
    Dstu7624Config<BLOCK_WORDS, KEY_WORDS>: ValidDstu7624Config<BLOCK_WORDS>,
{
    /// Block size in bytes.
    const BLOCK_SIZE: usize = BLOCK_WORDS * 8;

    /// Builds a wrapper over a DSTU 7624 cipher of the selected widths.
    pub fn new() -> Self {
        Self {
            engine: Dstu7624Engine::new(),
            direction: None,
        }
    }

    /// Processes one full block in place using the already-keyed engine, routing
    /// through a scratch buffer (max 512-bit block = 64 bytes) to avoid aliasing.
    fn crypt_block(&mut self, block: &mut [u8]) -> Result<(), Dstu7624WrapError> {
        // 暫存取最大分組（512 bit = 64 bytes），只在轉換期間存在。
        let mut scratch = [0u8; 64];
        let bs = Self::BLOCK_SIZE;
        self.engine
            .process_block(block, &mut scratch[..bs])
            .map_err(Dstu7624WrapError::BlockCipher)?;
        block.copy_from_slice(&scratch[..bs]);
        Ok(())
    }
}

/// Error type for the DSTU 7624 key wrapper.
#[derive(Debug)]
pub enum Dstu7624WrapError {
    /// wrap / unwrap called before `init`.
    Uninitialised,
    /// Initialised for unwrapping, but `wrap` was called.
    NotForWrapping,
    /// Initialised for wrapping, but `unwrap` was called.
    NotForUnwrapping,
    /// Wrap input length is not a multiple of the block size (padding unsupported).
    WrapDataLength,
    /// Unwrap input length is not a positive multiple of the block size.
    UnwrapDataLength,
    /// The caller-provided output buffer is shorter than the required length.
    OutputBufferTooShort {
        /// Required output capacity in bytes.
        required: usize,
        /// Available output capacity in bytes.
        available: usize,
    },
    /// Integrity check failed on unwrap (the trailing checking block is nonzero).
    IntegrityCheckFailed,
    /// Error reported by the underlying DSTU 7624 cipher.
    BlockCipher(BlockCipherError),
}

impl core::fmt::Display for Dstu7624WrapError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Dstu7624WrapError::Uninitialised => f.write_str("key wrapper not initialised"),
            Dstu7624WrapError::NotForWrapping => f.write_str("wrapper not set for wrapping"),
            Dstu7624WrapError::NotForUnwrapping => f.write_str("wrapper not set for unwrapping"),
            Dstu7624WrapError::WrapDataLength => {
                f.write_str("wrap data must be a multiple of the block size (padding unsupported)")
            }
            Dstu7624WrapError::UnwrapDataLength => {
                f.write_str("unwrap data must be a positive multiple of the block size")
            }
            Dstu7624WrapError::OutputBufferTooShort {
                required,
                available,
            } => write!(
                f,
                "output buffer is too short: requires {required} bytes, has {available}"
            ),
            Dstu7624WrapError::IntegrityCheckFailed => f.write_str("integrity check failed"),
            Dstu7624WrapError::BlockCipher(e) => write!(f, "underlying block cipher error: {e}"),
        }
    }
}

impl core::error::Error for Dstu7624WrapError {}

impl<const BLOCK_WORDS: usize, const KEY_WORDS: usize> Dstu7624WrapEngine<BLOCK_WORDS, KEY_WORDS>
where
    Dstu7624Config<BLOCK_WORDS, KEY_WORDS>: ValidDstu7624Config<BLOCK_WORDS>,
{
    /// Validates a wrap length and returns `(output length, half-block count)`.
    fn wrap_layout(&self, input_len: usize) -> Result<(usize, usize), Dstu7624WrapError> {
        if !input_len.is_multiple_of(Self::BLOCK_SIZE) {
            return Err(Dstu7624WrapError::WrapDataLength);
        }

        let output_len = input_len
            .checked_add(Self::BLOCK_SIZE)
            .ok_or(Dstu7624WrapError::WrapDataLength)?;
        let half_blocks = output_len / (Self::BLOCK_SIZE / 2);
        let rounds = half_blocks
            .checked_sub(1)
            .and_then(|count| count.checked_mul(6))
            .ok_or(Dstu7624WrapError::WrapDataLength)?;
        if u32::try_from(rounds).is_err() {
            return Err(Dstu7624WrapError::WrapDataLength);
        }

        Ok((output_len, half_blocks))
    }

    /// Validates an unwrap length and returns `(output length, half-block count)`.
    fn unwrap_layout(&self, input_len: usize) -> Result<(usize, usize), Dstu7624WrapError> {
        if input_len < Self::BLOCK_SIZE || !input_len.is_multiple_of(Self::BLOCK_SIZE) {
            return Err(Dstu7624WrapError::UnwrapDataLength);
        }

        let output_len = input_len - Self::BLOCK_SIZE;
        let half_blocks = input_len / (Self::BLOCK_SIZE / 2);
        let rounds = half_blocks
            .checked_sub(1)
            .and_then(|count| count.checked_mul(6))
            .ok_or(Dstu7624WrapError::UnwrapDataLength)?;
        if u32::try_from(rounds).is_err() {
            return Err(Dstu7624WrapError::UnwrapDataLength);
        }

        Ok((output_len, half_blocks))
    }

    /// Keys the underlying cipher and records the key-level direction.
    fn initialize(
        &mut self,
        direction: WrapDirection,
        params: &Dstu7624Params<KEY_WORDS>,
    ) -> Result<(), Dstu7624WrapError> {
        let cipher_direction = match direction {
            WrapDirection::Wrap => CipherDirection::Encrypt,
            WrapDirection::Unwrap => CipherDirection::Decrypt,
        };
        self.engine
            .init(cipher_direction, params)
            .map_err(Dstu7624WrapError::BlockCipher)?;
        self.direction = Some(direction);
        Ok(())
    }
}

impl<const BLOCK_WORDS: usize, const KEY_WORDS: usize> Default
    for Dstu7624WrapEngine<BLOCK_WORDS, KEY_WORDS>
where
    Dstu7624Config<BLOCK_WORDS, KEY_WORDS>: ValidDstu7624Config<BLOCK_WORDS>,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<const BLOCK_WORDS: usize, const KEY_WORDS: usize> KeyWrap
    for Dstu7624WrapEngine<BLOCK_WORDS, KEY_WORDS>
where
    Dstu7624Config<BLOCK_WORDS, KEY_WORDS>: ValidDstu7624Config<BLOCK_WORDS>,
{
    type Error = Dstu7624WrapError;

    fn algorithm_name(&self) -> &str {
        self.engine.algorithm_name()
    }

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
            None => return Err(Dstu7624WrapError::Uninitialised),
        }
        let (required, half_blocks) = self.wrap_layout(input.len())?;
        if output.len() < required {
            return Err(Dstu7624WrapError::OutputBufferTooShort {
                required,
                available: output.len(),
            });
        }

        let bs = Self::BLOCK_SIZE;
        let half = bs / 2;
        let rounds = (half_blocks - 1) * 6;
        let buffer = &mut output[..required];
        buffer.fill(0);
        buffer[..input.len()].copy_from_slice(input);

        let mut b = [0_u8; 32];
        b[..half].copy_from_slice(&buffer[..half]);
        let mut block = [0_u8; 64];

        for round in 0..rounds {
            block[..half].copy_from_slice(&b[..half]);
            block[half..bs].copy_from_slice(&buffer[half..bs]);
            self.crypt_block(&mut block[..bs])?;

            let counter = (round as u32 + 1).to_le_bytes();
            for (index, byte) in counter.iter().enumerate() {
                block[half + index] ^= byte;
            }

            b[..half].copy_from_slice(&block[half..bs]);
            buffer.copy_within(bs..required, half);
            buffer[required - half..required].copy_from_slice(&block[..half]);
        }

        buffer[..half].copy_from_slice(&b[..half]);
        Ok(required)
    }

    fn unwrap_into(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        match self.direction {
            Some(WrapDirection::Unwrap) => {}
            Some(WrapDirection::Wrap) => return Err(Dstu7624WrapError::NotForUnwrapping),
            None => return Err(Dstu7624WrapError::Uninitialised),
        }
        let (required, half_blocks) = self.unwrap_layout(input.len())?;
        if output.len() < required {
            return Err(Dstu7624WrapError::OutputBufferTooShort {
                required,
                available: output.len(),
            });
        }
        let bs = Self::BLOCK_SIZE;
        let half = bs / 2;
        let rounds = (half_blocks - 1) * 6;
        let buffer = &mut output[..required];

        let mut b = [0_u8; 32];
        b[..half].copy_from_slice(&input[..half]);
        if required != 0 {
            buffer.copy_from_slice(&input[half..input.len() - half]);
        }
        let mut extra = [0_u8; 32];
        extra[..half].copy_from_slice(&input[input.len() - half..]);
        let mut block = [0_u8; 64];

        for round in 0..rounds {
            block[..half].copy_from_slice(&extra[..half]);
            block[half..bs].copy_from_slice(&b[..half]);

            let counter = ((rounds - round) as u32).to_le_bytes();
            for (index, byte) in counter.iter().enumerate() {
                block[half + index] ^= byte;
            }

            if let Err(error) = self.crypt_block(&mut block[..bs]) {
                buffer.fill(0);
                return Err(error);
            }
            b[..half].copy_from_slice(&block[..half]);

            if required == 0 {
                extra[..half].copy_from_slice(&block[half..bs]);
            } else {
                extra[..half].copy_from_slice(&buffer[required - half..required]);
                buffer.copy_within(..required - half, half);
                buffer[..half].copy_from_slice(&block[half..bs]);
            }
        }

        // The final full checking block is the last two half-block registers.
        let mut diff = 0_u8;
        if required == 0 {
            for byte in b[..half].iter().chain(&extra[..half]) {
                diff |= *byte;
            }
        } else {
            for byte in buffer[required - half..required]
                .iter()
                .chain(&extra[..half])
            {
                diff |= *byte;
            }
        }

        if diff != 0 {
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
        Ok(required)
    }
}

impl<const BLOCK_WORDS: usize, const KEY_WORDS: usize> KeyWrapInit
    for Dstu7624WrapEngine<BLOCK_WORDS, KEY_WORDS>
where
    Dstu7624Config<BLOCK_WORDS, KEY_WORDS>: ValidDstu7624Config<BLOCK_WORDS>,
{
    type Params<'a> = Dstu7624Params<KEY_WORDS>;

    fn init(
        &mut self,
        direction: WrapDirection,
        params: &Self::Params<'_>,
    ) -> Result<(), Self::Error> {
        self.initialize(direction, params)
    }
}
