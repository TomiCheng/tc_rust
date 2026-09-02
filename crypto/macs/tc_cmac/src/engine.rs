//! Allocation-free CMAC engine.

use core::fmt;

use tc_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
use tc_crypto::AlgorithmName;
use tc_iso7816_pad::Iso7816d4Padding;
use tc_macs::{Mac, MacInit};
use tc_pad::BlockCipherPadding;
use tc_params::KeyParams;

use crate::{CreateError, Error, InitError};

const BLOCK_64_BYTES: usize = 8;
const BLOCK_128_BYTES: usize = 16;
const MAX_BLOCK_BYTES: usize = BLOCK_128_BYTES;
const RB_64: u8 = 0x1b;
const RB_128: u8 = 0x87;

/// CMAC over a 64- or 128-bit block cipher.
///
/// The cipher and all working state are owned by the value. A complete final
/// message block is deliberately buffered until [`Mac::do_final`] so that it
/// receives the first CMAC subkey instead of ISO/IEC 7816-4 padding.
pub struct CMac<C> {
    cipher: C,
    block_size: usize,
    mac_size: usize,
    mac: [u8; MAX_BLOCK_BYTES],
    buffer: [u8; MAX_BLOCK_BYTES],
    buffer_offset: usize,
    k1: [u8; MAX_BLOCK_BYTES],
    k2: [u8; MAX_BLOCK_BYTES],
    initialized: bool,
}

impl<C: BlockCipher> CMac<C> {
    /// Creates CMAC with a full-block authentication tag.
    pub fn new(cipher: C) -> Result<Self, CreateError> {
        let block_size = cipher.block_size();
        if block_size != BLOCK_64_BYTES && block_size != BLOCK_128_BYTES {
            return Err(CreateError::UnsupportedBlockSize(block_size));
        }

        let mac_size_bits = block_size * 8;
        Self::with_mac_size_bits(cipher, mac_size_bits)
    }

    /// Creates CMAC with an authentication tag of `mac_size_bits` bits.
    ///
    /// The size must be a non-zero multiple of eight and must not exceed the
    /// underlying cipher's block size.
    pub fn with_mac_size_bits(cipher: C, mac_size_bits: usize) -> Result<Self, CreateError> {
        let block_size = cipher.block_size();
        if block_size != BLOCK_64_BYTES && block_size != BLOCK_128_BYTES {
            return Err(CreateError::UnsupportedBlockSize(block_size));
        }

        let maximum_bits = block_size * 8;
        if mac_size_bits == 0 || !mac_size_bits.is_multiple_of(8) || mac_size_bits > maximum_bits {
            return Err(CreateError::InvalidMacSize {
                requested_bits: mac_size_bits,
                maximum_bits,
            });
        }

        Ok(Self {
            cipher,
            block_size,
            mac_size: mac_size_bits / 8,
            mac: [0; MAX_BLOCK_BYTES],
            buffer: [0; MAX_BLOCK_BYTES],
            buffer_offset: 0,
            k1: [0; MAX_BLOCK_BYTES],
            k2: [0; MAX_BLOCK_BYTES],
            initialized: false,
        })
    }

    /// Returns the block cipher wrapped by CMAC.
    pub const fn underlying_cipher(&self) -> &C {
        &self.cipher
    }

    fn double_block(input: &[u8], output: &mut [u8], reduction: u8) {
        let carry = input[0] >> 7;
        let mut next_bit = 0;

        for (&source, target) in input.iter().zip(output.iter_mut()).rev() {
            *target = (source << 1) | next_bit;
            next_bit = source >> 7;
        }

        let last = output.len() - 1;
        output[last] ^= reduction & 0_u8.wrapping_sub(carry);
    }

    fn process_buffer(&mut self) -> Result<(), C::Error> {
        for index in 0..self.block_size {
            self.buffer[index] ^= self.mac[index];
        }

        let written = self.cipher.process_block(
            &self.buffer[..self.block_size],
            &mut self.mac[..self.block_size],
        )?;
        debug_assert_eq!(written, self.block_size);
        self.buffer[..self.block_size].fill(0);
        self.buffer_offset = 0;
        Ok(())
    }

    fn clear_message(&mut self) {
        self.mac.fill(0);
        self.buffer.fill(0);
        self.buffer_offset = 0;
    }
}

impl<C: AlgorithmName> AlgorithmName for CMac<C> {
    fn write_algo_name(&self, output: &mut dyn fmt::Write) -> fmt::Result {
        self.cipher.write_algo_name(output)?;
        output.write_str("/CMAC")
    }
}

impl<C: BlockCipher> Mac for CMac<C> {
    type Error = Error<C::Error>;

    fn mac_size(&self) -> usize {
        self.mac_size
    }

    fn update(&mut self, mut input: &[u8]) -> Result<(), Self::Error> {
        if !self.initialized {
            return Err(Error::NotInitialised);
        }

        let gap = self.block_size - self.buffer_offset;
        if input.len() > gap {
            self.buffer[self.buffer_offset..self.block_size].copy_from_slice(&input[..gap]);
            self.process_buffer().map_err(Error::Cipher)?;
            input = &input[gap..];

            while input.len() > self.block_size {
                self.buffer[..self.block_size].copy_from_slice(&input[..self.block_size]);
                self.buffer_offset = self.block_size;
                self.process_buffer().map_err(Error::Cipher)?;
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
            return Err(Error::NotInitialised);
        }
        if output.len() < self.mac_size {
            return Err(Error::OutputTooShort {
                required: self.mac_size,
                available: output.len(),
            });
        }

        let subkey = if self.buffer_offset == self.block_size {
            &self.k1[..self.block_size]
        } else {
            Iso7816d4Padding::new()
                .add_padding(&mut self.buffer[..self.block_size], self.buffer_offset)
                .map_err(Error::Padding)?;
            &self.k2[..self.block_size]
        };

        for (index, &subkey_byte) in subkey.iter().enumerate() {
            self.buffer[index] ^= subkey_byte ^ self.mac[index];
        }

        let written = self.cipher.process_block(
            &self.buffer[..self.block_size],
            &mut self.mac[..self.block_size],
        );
        match written {
            Ok(written) => debug_assert_eq!(written, self.block_size),
            Err(error) => return Err(Error::Cipher(error)),
        }

        output[..self.mac_size].copy_from_slice(&self.mac[..self.mac_size]);
        self.clear_message();
        Ok(self.mac_size)
    }

    fn reset(&mut self) {
        self.clear_message();
    }
}

impl<C, P> MacInit<P> for CMac<C>
where
    C: BlockCipher + BlockCipherInit<P>,
    P: KeyParams + ?Sized,
{
    type Error = InitError<<C as BlockCipherInit<P>>::Error, <C as BlockCipher>::Error>;

    fn init(&mut self, params: &P) -> Result<(), Self::Error> {
        self.initialized = false;
        self.clear_message();
        self.k1.fill(0);
        self.k2.fill(0);

        self.cipher
            .init(CipherDirection::Encrypt, params)
            .map_err(InitError::CipherInit)?;

        let zeroes = [0_u8; MAX_BLOCK_BYTES];
        let mut l = [0_u8; MAX_BLOCK_BYTES];
        let written = self
            .cipher
            .process_block(&zeroes[..self.block_size], &mut l[..self.block_size])
            .map_err(InitError::Cipher)?;
        debug_assert_eq!(written, self.block_size);

        let reduction = if self.block_size == BLOCK_128_BYTES {
            RB_128
        } else {
            RB_64
        };
        Self::double_block(
            &l[..self.block_size],
            &mut self.k1[..self.block_size],
            reduction,
        );
        Self::double_block(
            &self.k1[..self.block_size],
            &mut self.k2[..self.block_size],
            reduction,
        );
        l.fill(0);

        self.initialized = true;
        Ok(())
    }
}

impl<C> Drop for CMac<C> {
    fn drop(&mut self) {
        self.mac.fill(0);
        self.buffer.fill(0);
        self.k1.fill(0);
        self.k2.fill(0);
    }
}
