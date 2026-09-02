//! DSTU 7624 (Kalyna) MAC implementation.

use core::fmt;

use tc_cipher::{BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError};
use tc_crypto::AlgorithmName;
use tc_dstu7624::Engine;
use tc_macs::{Mac, MacError, MacInit};
use tc_params::KeyParams;

const MAX_BLOCK_BYTES: usize = 64;

/// A failure while constructing a DSTU 7624 MAC.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Dstu7624MacCreateError {
    /// DSTU 7624 supports 128-, 256-, and 512-bit blocks.
    UnsupportedBlockSize(usize),
    /// The requested tag is zero, is not byte-aligned, or exceeds the block.
    InvalidMacSize {
        requested_bits: usize,
        maximum_bits: usize,
    },
}

impl fmt::Display for Dstu7624MacCreateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedBlockSize(bits) => write!(
                f,
                "DSTU 7624 MAC requires a 128-, 256-, or 512-bit block, got {bits} bits"
            ),
            Self::InvalidMacSize {
                requested_bits,
                maximum_bits,
            } => write!(
                f,
                "invalid DSTU 7624 MAC size: requested {requested_bits} bits, maximum {maximum_bits} bits"
            ),
        }
    }
}

impl core::error::Error for Dstu7624MacCreateError {}

/// DSTU 7624 MAC whose const parameter is the cipher block size in 64-bit words.
pub struct Dstu7624Mac<const BLOCK_WORDS: usize> {
    cipher: Engine<BLOCK_WORDS>,
    block_size: usize,
    mac_size: usize,
    chain: [u8; MAX_BLOCK_BYTES],
    temporary: [u8; MAX_BLOCK_BYTES],
    delta: [u8; MAX_BLOCK_BYTES],
    buffer: [u8; MAX_BLOCK_BYTES],
    buffer_offset: usize,
    initialized: bool,
}

/// DSTU 7624 MAC using the 128-bit block cipher.
pub type Dstu7624Mac128 = Dstu7624Mac<2>;
/// DSTU 7624 MAC using the 256-bit block cipher.
pub type Dstu7624Mac256 = Dstu7624Mac<4>;
/// DSTU 7624 MAC using the 512-bit block cipher.
pub type Dstu7624Mac512 = Dstu7624Mac<8>;

impl<const BLOCK_WORDS: usize> Dstu7624Mac<BLOCK_WORDS> {
    /// Creates an uninitialized DSTU 7624 MAC with a `mac_size_bits`-bit tag.
    pub fn new(mac_size_bits: usize) -> Result<Self, Dstu7624MacCreateError>
    where
        Engine<BLOCK_WORDS>: Default,
    {
        let block_size = BLOCK_WORDS * 8;
        let block_size_bits = block_size * 8;
        if ![128, 256, 512].contains(&block_size_bits) {
            return Err(Dstu7624MacCreateError::UnsupportedBlockSize(
                block_size_bits,
            ));
        }
        if mac_size_bits == 0 || !mac_size_bits.is_multiple_of(8) || mac_size_bits > block_size_bits
        {
            return Err(Dstu7624MacCreateError::InvalidMacSize {
                requested_bits: mac_size_bits,
                maximum_bits: block_size_bits,
            });
        }

        Ok(Self {
            cipher: Engine::default(),
            block_size,
            mac_size: mac_size_bits / 8,
            chain: [0; MAX_BLOCK_BYTES],
            temporary: [0; MAX_BLOCK_BYTES],
            delta: [0; MAX_BLOCK_BYTES],
            buffer: [0; MAX_BLOCK_BYTES],
            buffer_offset: 0,
            initialized: false,
        })
    }

    fn clear_message(&mut self) {
        self.chain.fill(0);
        self.temporary.fill(0);
        self.buffer.fill(0);
        self.buffer_offset = 0;
    }
}

impl<const BLOCK_WORDS: usize> Dstu7624Mac<BLOCK_WORDS>
where
    Engine<BLOCK_WORDS>: BlockCipher<Error = BlockError>,
{
    fn process_buffer(&mut self) -> Result<(), MacError> {
        for index in 0..self.block_size {
            self.temporary[index] = self.chain[index] ^ self.buffer[index];
        }
        self.cipher
            .process_block(
                &self.temporary[..self.block_size],
                &mut self.chain[..self.block_size],
            )
            .map_err(|_| MacError::InternalFailure)?;
        self.buffer[..self.block_size].fill(0);
        self.buffer_offset = 0;
        Ok(())
    }
}

impl<const BLOCK_WORDS: usize> AlgorithmName for Dstu7624Mac<BLOCK_WORDS> {
    fn write_algo_name(&self, output: &mut dyn fmt::Write) -> fmt::Result {
        output.write_str("DSTU7624Mac")
    }
}

impl<const BLOCK_WORDS: usize> Mac for Dstu7624Mac<BLOCK_WORDS>
where
    Engine<BLOCK_WORDS>: BlockCipher<Error = BlockError>,
{
    type Error = MacError;

    fn mac_size(&self) -> usize {
        self.mac_size
    }

    fn update(&mut self, mut input: &[u8]) -> Result<(), Self::Error> {
        if !self.initialized {
            return Err(MacError::NotInitialised);
        }

        let gap = self.block_size - self.buffer_offset;
        if input.len() > gap {
            self.buffer[self.buffer_offset..self.block_size].copy_from_slice(&input[..gap]);
            self.process_buffer()?;
            input = &input[gap..];
            while input.len() > self.block_size {
                self.buffer[..self.block_size].copy_from_slice(&input[..self.block_size]);
                self.buffer_offset = self.block_size;
                self.process_buffer()?;
                input = &input[self.block_size..];
            }
        }

        let end = self.buffer_offset + input.len();
        self.buffer[self.buffer_offset..end].copy_from_slice(input);
        self.buffer_offset = end;
        Ok(())
    }

    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialized {
            return Err(MacError::NotInitialised);
        }
        if self.buffer_offset != 0 && self.buffer_offset != self.block_size {
            return Err(MacError::InputNotBlockAligned {
                block_size: self.block_size,
                remainder: self.buffer_offset,
            });
        }
        if output.len() < self.mac_size {
            return Err(MacError::OutputTooShort {
                required: self.mac_size,
                available: output.len(),
            });
        }

        for index in 0..self.block_size {
            self.temporary[index] = self.chain[index] ^ self.buffer[index] ^ self.delta[index];
        }
        self.cipher
            .process_block(
                &self.temporary[..self.block_size],
                &mut self.chain[..self.block_size],
            )
            .map_err(|_| MacError::InternalFailure)?;
        output[..self.mac_size].copy_from_slice(&self.chain[..self.mac_size]);
        self.clear_message();
        Ok(self.mac_size)
    }

    fn reset(&mut self) {
        self.clear_message();
    }
}

impl<P, const BLOCK_WORDS: usize> MacInit<P> for Dstu7624Mac<BLOCK_WORDS>
where
    P: KeyParams + ?Sized,
    Engine<BLOCK_WORDS>: BlockCipher<Error = BlockError> + BlockCipherInit<P, Error = InitError>,
{
    type Error = InitError;

    fn init(&mut self, params: &P) -> Result<(), Self::Error> {
        self.initialized = false;
        self.clear_message();
        self.delta.fill(0);
        self.cipher.init(CipherDirection::Encrypt, params)?;
        let zeroes = [0_u8; MAX_BLOCK_BYTES];
        self.cipher
            .process_block(
                &zeroes[..self.block_size],
                &mut self.delta[..self.block_size],
            )
            .map_err(|_| InitError::InternalFailure)?;
        self.initialized = true;
        Ok(())
    }
}

impl<const BLOCK_WORDS: usize> Drop for Dstu7624Mac<BLOCK_WORDS> {
    fn drop(&mut self) {
        self.chain.fill(0);
        self.temporary.fill(0);
        self.delta.fill(0);
        self.buffer.fill(0);
    }
}
