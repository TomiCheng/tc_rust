use core::{convert::Infallible, fmt};

use tc_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
use tc_crypto::AlgorithmName;
use tc_macs::{Mac, MacInit};
use tc_pad::BlockCipherPadding;
use tc_params::{KeyParams, OptionalIvParams};

use crate::{CreateError, Error, InitError};

const MAX_BLOCK_BYTES: usize = 64;

/// Borrowed CBC-MAC parameters with an optional IV.
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

/// Marker for CBC-MAC's default zero padding.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoPadding;

/// Wrapper used when a caller supplies a block padding implementation.
pub struct WithPadding<D>(D);

/// Internal final-block policy implemented by the public padding wrappers.
///
/// Callers select [`NoPadding`] through the normal constructors or pass any
/// [`BlockCipherPadding`] to `CbcMac::with_padding`; direct implementations are
/// normally unnecessary.
pub trait CbcMacPadding {
    type Error: core::error::Error;

    fn requires_extra_block(&self) -> bool;
    fn pad(&mut self, block: &mut [u8], position: usize) -> Result<(), Self::Error>;
}

impl CbcMacPadding for NoPadding {
    type Error = Infallible;

    fn requires_extra_block(&self) -> bool {
        false
    }

    fn pad(&mut self, block: &mut [u8], position: usize) -> Result<(), Self::Error> {
        block[position..].fill(0);
        Ok(())
    }
}

impl<D: BlockCipherPadding> CbcMacPadding for WithPadding<D> {
    type Error = D::Error;

    fn requires_extra_block(&self) -> bool {
        true
    }

    fn pad(&mut self, block: &mut [u8], position: usize) -> Result<(), Self::Error> {
        self.0.add_padding(block, position)?;
        Ok(())
    }
}

/// Allocation-free CBC-MAC over block cipher `C`.
pub struct CbcMac<C, D = NoPadding> {
    cipher: C,
    padding: D,
    block_size: usize,
    mac_size: usize,
    iv: [u8; MAX_BLOCK_BYTES],
    chain: [u8; MAX_BLOCK_BYTES],
    buffer: [u8; MAX_BLOCK_BYTES],
    buffer_offset: usize,
    initialized: bool,
}

impl<C: BlockCipher> CbcMac<C, NoPadding> {
    pub fn new(cipher: C) -> Result<Self, CreateError> {
        let bits = cipher.block_size().saturating_mul(4);
        Self::build(cipher, NoPadding, bits)
    }

    pub fn with_mac_size_bits(cipher: C, mac_size_bits: usize) -> Result<Self, CreateError> {
        Self::build(cipher, NoPadding, mac_size_bits)
    }

    pub fn with_padding<D: BlockCipherPadding>(
        cipher: C,
        padding: D,
    ) -> Result<CbcMac<C, WithPadding<D>>, CreateError> {
        let bits = cipher.block_size().saturating_mul(4);
        CbcMac::build(cipher, WithPadding(padding), bits)
    }

    pub fn with_padding_and_mac_size_bits<D: BlockCipherPadding>(
        cipher: C,
        mac_size_bits: usize,
        padding: D,
    ) -> Result<CbcMac<C, WithPadding<D>>, CreateError> {
        CbcMac::build(cipher, WithPadding(padding), mac_size_bits)
    }
}

impl<C: BlockCipher, D> CbcMac<C, D> {
    fn build(cipher: C, padding: D, mac_size_bits: usize) -> Result<Self, CreateError> {
        let block_size = cipher.block_size();
        if block_size == 0 || block_size > MAX_BLOCK_BYTES {
            return Err(CreateError::InvalidBlockSize(block_size));
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
            padding,
            block_size,
            mac_size: mac_size_bits / 8,
            iv: [0; MAX_BLOCK_BYTES],
            chain: [0; MAX_BLOCK_BYTES],
            buffer: [0; MAX_BLOCK_BYTES],
            buffer_offset: 0,
            initialized: false,
        })
    }

    fn clear_message(&mut self) {
        self.chain.fill(0);
        self.chain[..self.block_size].copy_from_slice(&self.iv[..self.block_size]);
        self.buffer.fill(0);
        self.buffer_offset = 0;
    }
}

impl<C: BlockCipher, D: CbcMacPadding> CbcMac<C, D> {
    fn process_buffer(&mut self) -> Result<(), Error<C::Error, D::Error>> {
        for index in 0..self.block_size {
            self.buffer[index] ^= self.chain[index];
        }
        self.cipher
            .process_block(
                &self.buffer[..self.block_size],
                &mut self.chain[..self.block_size],
            )
            .map_err(Error::Cipher)?;
        self.buffer[..self.block_size].fill(0);
        self.buffer_offset = 0;
        Ok(())
    }
}

impl<C: AlgorithmName, D> AlgorithmName for CbcMac<C, D> {
    fn write_algo_name(&self, output: &mut dyn fmt::Write) -> fmt::Result {
        self.cipher.write_algo_name(output)?;
        output.write_str("/CBCMAC")
    }
}

impl<C: BlockCipher, D: CbcMacPadding> Mac for CbcMac<C, D> {
    type Error = Error<C::Error, D::Error>;

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
            return Err(Error::NotInitialised);
        }
        if output.len() < self.mac_size {
            return Err(Error::OutputTooShort {
                required: self.mac_size,
                available: output.len(),
            });
        }
        if self.padding.requires_extra_block() && self.buffer_offset == self.block_size {
            self.process_buffer()?;
        }
        self.padding
            .pad(&mut self.buffer[..self.block_size], self.buffer_offset)
            .map_err(Error::Padding)?;
        self.buffer_offset = self.block_size;
        self.process_buffer()?;
        output[..self.mac_size].copy_from_slice(&self.chain[..self.mac_size]);
        self.clear_message();
        Ok(self.mac_size)
    }

    fn reset(&mut self) {
        self.clear_message();
    }
}

impl<C, D, P> MacInit<P> for CbcMac<C, D>
where
    C: BlockCipher + BlockCipherInit<P>,
    P: KeyParams + OptionalIvParams + ?Sized,
{
    type Error = InitError<<C as BlockCipherInit<P>>::Error>;

    fn init(&mut self, params: &P) -> Result<(), Self::Error> {
        self.initialized = false;
        self.iv.fill(0);
        if let Some(iv) = params.optional_iv() {
            if iv.len() != self.block_size {
                return Err(InitError::InvalidIvLength(iv.len()));
            }
            self.iv[..self.block_size].copy_from_slice(iv);
        }
        self.cipher
            .init(CipherDirection::Encrypt, params)
            .map_err(InitError::Cipher)?;
        self.initialized = true;
        self.clear_message();
        Ok(())
    }
}
