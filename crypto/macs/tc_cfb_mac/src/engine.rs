use core::{convert::Infallible, fmt};

use tc_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
use tc_crypto::AlgorithmName;
use tc_macs::{Mac, MacInit};
use tc_pad::BlockCipherPadding;
use tc_params::{KeyParams, OptionalIvParams};

use crate::{CreateError, Error, InitError};

const MAX_BLOCK_BYTES: usize = 64;

#[derive(Clone, Copy, Debug)]
pub struct Params<'a> {
    key: &'a [u8],
    iv: Option<&'a [u8]>,
}

impl<'a> Params<'a> {
    pub const fn new(key: &'a [u8]) -> Self {
        Self { key, iv: None }
    }

    pub const fn with_iv(mut self, iv: &'a [u8]) -> Self {
        self.iv = Some(iv);
        self
    }
}

impl KeyParams for Params<'_> {
    fn key(&self) -> &[u8] {
        self.key
    }
}

impl OptionalIvParams for Params<'_> {
    fn optional_iv(&self) -> Option<&[u8]> {
        self.iv
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct NoPadding;

pub struct WithPadding<D>(D);

pub trait CfbMacPadding {
    type Error: core::error::Error;

    fn pad(&mut self, block: &mut [u8], position: usize) -> Result<(), Self::Error>;
}

impl CfbMacPadding for NoPadding {
    type Error = Infallible;

    fn pad(&mut self, block: &mut [u8], position: usize) -> Result<(), Self::Error> {
        block[position..].fill(0);
        Ok(())
    }
}

impl<D: BlockCipherPadding> CfbMacPadding for WithPadding<D> {
    type Error = D::Error;

    fn pad(&mut self, block: &mut [u8], position: usize) -> Result<(), Self::Error> {
        if position != block.len() {
            self.0.add_padding(block, position)?;
        }
        Ok(())
    }
}

pub struct CfbMac<C, D = NoPadding> {
    cipher: C,
    padding: D,
    cipher_block_size: usize,
    segment_size: usize,
    mac_size: usize,
    iv: [u8; MAX_BLOCK_BYTES],
    register: [u8; MAX_BLOCK_BYTES],
    keystream: [u8; MAX_BLOCK_BYTES],
    buffer: [u8; MAX_BLOCK_BYTES],
    buffer_offset: usize,
    initialized: bool,
}

impl<C: BlockCipher> CfbMac<C, NoPadding> {
    pub fn new(cipher: C) -> Result<Self, CreateError> {
        let mac_bits = cipher.block_size().saturating_mul(4);
        Self::build(cipher, NoPadding, 8, mac_bits)
    }

    pub fn with_sizes(
        cipher: C,
        feedback_bits: usize,
        mac_size_bits: usize,
    ) -> Result<Self, CreateError> {
        Self::build(cipher, NoPadding, feedback_bits, mac_size_bits)
    }

    pub fn with_padding<D: BlockCipherPadding>(
        cipher: C,
        padding: D,
    ) -> Result<CfbMac<C, WithPadding<D>>, CreateError> {
        let mac_bits = cipher.block_size().saturating_mul(4);
        CfbMac::build(cipher, WithPadding(padding), 8, mac_bits)
    }

    pub fn with_padding_and_sizes<D: BlockCipherPadding>(
        cipher: C,
        feedback_bits: usize,
        mac_size_bits: usize,
        padding: D,
    ) -> Result<CfbMac<C, WithPadding<D>>, CreateError> {
        CfbMac::build(cipher, WithPadding(padding), feedback_bits, mac_size_bits)
    }
}

impl<C: BlockCipher, D> CfbMac<C, D> {
    fn build(
        cipher: C,
        padding: D,
        feedback_bits: usize,
        mac_size_bits: usize,
    ) -> Result<Self, CreateError> {
        let cipher_block_size = cipher.block_size();
        if cipher_block_size == 0 || cipher_block_size > MAX_BLOCK_BYTES {
            return Err(CreateError::InvalidBlockSize(cipher_block_size));
        }
        if feedback_bits == 0
            || !feedback_bits.is_multiple_of(8)
            || feedback_bits / 8 > cipher_block_size
        {
            return Err(CreateError::InvalidFeedbackSize(feedback_bits));
        }
        let maximum_bits = cipher_block_size * 8;
        if mac_size_bits == 0 || !mac_size_bits.is_multiple_of(8) || mac_size_bits > maximum_bits {
            return Err(CreateError::InvalidMacSize {
                requested_bits: mac_size_bits,
                maximum_bits,
            });
        }
        Ok(Self {
            cipher,
            padding,
            cipher_block_size,
            segment_size: feedback_bits / 8,
            mac_size: mac_size_bits / 8,
            iv: [0; MAX_BLOCK_BYTES],
            register: [0; MAX_BLOCK_BYTES],
            keystream: [0; MAX_BLOCK_BYTES],
            buffer: [0; MAX_BLOCK_BYTES],
            buffer_offset: 0,
            initialized: false,
        })
    }

    fn clear_message(&mut self) {
        self.register.fill(0);
        self.register[..self.cipher_block_size].copy_from_slice(&self.iv[..self.cipher_block_size]);
        self.keystream.fill(0);
        self.buffer.fill(0);
        self.buffer_offset = 0;
    }
}

impl<C: BlockCipher, D: CfbMacPadding> CfbMac<C, D> {
    fn process_segment(&mut self) -> Result<(), Error<C::Error, D::Error>> {
        self.cipher
            .process_block(
                &self.register[..self.cipher_block_size],
                &mut self.keystream[..self.cipher_block_size],
            )
            .map_err(Error::Cipher)?;
        for index in 0..self.segment_size {
            self.buffer[index] ^= self.keystream[index];
        }
        self.register
            .copy_within(self.segment_size..self.cipher_block_size, 0);
        let tail = self.cipher_block_size - self.segment_size;
        self.register[tail..self.cipher_block_size]
            .copy_from_slice(&self.buffer[..self.segment_size]);
        self.buffer[..self.segment_size].fill(0);
        self.buffer_offset = 0;
        Ok(())
    }
}

impl<C: AlgorithmName, D> AlgorithmName for CfbMac<C, D> {
    fn write_algo_name(&self, output: &mut dyn fmt::Write) -> fmt::Result {
        self.cipher.write_algo_name(output)?;
        write!(output, "/CFB{}MAC", self.segment_size * 8)
    }
}

impl<C: BlockCipher, D: CfbMacPadding> Mac for CfbMac<C, D> {
    type Error = Error<C::Error, D::Error>;

    fn mac_size(&self) -> usize {
        self.mac_size
    }

    fn update(&mut self, mut input: &[u8]) -> Result<(), Self::Error> {
        if !self.initialized {
            return Err(Error::NotInitialised);
        }
        let gap = self.segment_size - self.buffer_offset;
        if input.len() > gap {
            self.buffer[self.buffer_offset..self.segment_size].copy_from_slice(&input[..gap]);
            self.process_segment()?;
            input = &input[gap..];
            while input.len() > self.segment_size {
                self.buffer[..self.segment_size].copy_from_slice(&input[..self.segment_size]);
                self.buffer_offset = self.segment_size;
                self.process_segment()?;
                input = &input[self.segment_size..];
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
        self.padding
            .pad(&mut self.buffer[..self.segment_size], self.buffer_offset)
            .map_err(Error::Padding)?;
        self.buffer_offset = self.segment_size;
        self.process_segment()?;
        self.cipher
            .process_block(
                &self.register[..self.cipher_block_size],
                &mut self.keystream[..self.cipher_block_size],
            )
            .map_err(Error::Cipher)?;
        output[..self.mac_size].copy_from_slice(&self.keystream[..self.mac_size]);
        self.clear_message();
        Ok(self.mac_size)
    }

    fn reset(&mut self) {
        self.clear_message();
    }
}

impl<C, D, P> MacInit<P> for CfbMac<C, D>
where
    C: BlockCipher + BlockCipherInit<P>,
    P: KeyParams + OptionalIvParams + ?Sized,
{
    type Error = InitError<<C as BlockCipherInit<P>>::Error>;

    fn init(&mut self, params: &P) -> Result<(), Self::Error> {
        self.initialized = false;
        self.iv.fill(0);
        if let Some(iv) = params.optional_iv() {
            if iv.len() < self.cipher_block_size {
                let offset = self.cipher_block_size - iv.len();
                self.iv[offset..self.cipher_block_size].copy_from_slice(iv);
            } else {
                self.iv[..self.cipher_block_size].copy_from_slice(&iv[..self.cipher_block_size]);
            }
        }
        self.cipher
            .init(CipherDirection::Encrypt, params)
            .map_err(InitError::Cipher)?;
        self.initialized = true;
        self.clear_message();
        Ok(())
    }
}
