//! ISO/IEC 9797-1 MAC algorithm 3 (ANSI X9.19 Retail MAC).

#![no_std]

use core::{convert::Infallible, fmt};

use tc_cipher::{BlockCipher, BlockCipherInit, BlockError, CipherDirection};
use tc_crypto::AlgorithmName;
use tc_des::{BLOCK_BYTES, DesEngine};
use tc_macs::{Mac, MacInit};
use tc_pad::BlockCipherPadding;
use tc_params::{KeyParams, KeyRef, OptionalIvParams};

const DOUBLE_KEY_BYTES: usize = 16;
const TRIPLE_KEY_BYTES: usize = 24;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CreateError {
    InvalidMacSize(usize),
}

impl fmt::Display for CreateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMacSize(bits) => write!(f, "invalid ISO9797Alg3 MAC size: {bits} bits"),
        }
    }
}

impl core::error::Error for CreateError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum InitError {
    InvalidKeyLength(usize),
    InvalidIvLength(usize),
    Cipher(tc_cipher::InitError),
}

impl fmt::Display for InitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKeyLength(bytes) => {
                write!(f, "ISO9797Alg3 requires a 16- or 24-byte key, got {bytes}")
            }
            Self::InvalidIvLength(bytes) => {
                write!(f, "ISO9797Alg3 requires an 8-byte IV, got {bytes}")
            }
            Self::Cipher(error) => write!(f, "ISO9797Alg3 DES initialization failed: {error}"),
        }
    }
}

impl core::error::Error for InitError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error<P> {
    NotInitialised,
    OutputTooShort { required: usize, available: usize },
    Cipher(BlockError),
    CipherInit(tc_cipher::InitError),
    Padding(P),
}

impl<P: fmt::Display> fmt::Display for Error<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInitialised => f.write_str("ISO9797Alg3 MAC not initialised"),
            Self::OutputTooShort {
                required,
                available,
            } => write!(
                f,
                "output buffer is too short: requires {required} bytes, has {available}"
            ),
            Self::Cipher(error) => write!(f, "ISO9797Alg3 DES operation failed: {error}"),
            Self::CipherInit(error) => {
                write!(f, "ISO9797Alg3 final DES initialization failed: {error}")
            }
            Self::Padding(error) => write!(f, "ISO9797Alg3 padding failed: {error}"),
        }
    }
}

impl<P: core::error::Error> core::error::Error for Error<P> {}

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

pub trait Iso9797Padding {
    type Error: core::error::Error;

    fn requires_extra_block(&self) -> bool;
    fn pad(&mut self, block: &mut [u8], position: usize) -> Result<(), Self::Error>;
}

impl Iso9797Padding for NoPadding {
    type Error = Infallible;

    fn requires_extra_block(&self) -> bool {
        false
    }

    fn pad(&mut self, block: &mut [u8], position: usize) -> Result<(), Self::Error> {
        block[position..].fill(0);
        Ok(())
    }
}

impl<D: BlockCipherPadding> Iso9797Padding for WithPadding<D> {
    type Error = D::Error;

    fn requires_extra_block(&self) -> bool {
        true
    }

    fn pad(&mut self, block: &mut [u8], position: usize) -> Result<(), Self::Error> {
        self.0.add_padding(block, position)?;
        Ok(())
    }
}

pub struct Iso9797Alg3Mac<D = NoPadding> {
    cipher: DesEngine,
    padding: D,
    mac_size: usize,
    key1: [u8; BLOCK_BYTES],
    key2: [u8; BLOCK_BYTES],
    key3: [u8; BLOCK_BYTES],
    iv: [u8; BLOCK_BYTES],
    chain: [u8; BLOCK_BYTES],
    buffer: [u8; BLOCK_BYTES],
    buffer_offset: usize,
    initialized: bool,
}

impl Iso9797Alg3Mac<NoPadding> {
    pub fn new() -> Self {
        Self::with_mac_size_bits(64).expect("the full DES block is a valid tag size")
    }

    pub fn with_mac_size_bits(mac_size_bits: usize) -> Result<Self, CreateError> {
        Self::build(NoPadding, mac_size_bits)
    }

    pub fn with_padding<D: BlockCipherPadding>(padding: D) -> Iso9797Alg3Mac<WithPadding<D>> {
        Iso9797Alg3Mac::build(WithPadding(padding), 64)
            .expect("the full DES block is a valid tag size")
    }

    pub fn with_padding_and_mac_size_bits<D: BlockCipherPadding>(
        padding: D,
        mac_size_bits: usize,
    ) -> Result<Iso9797Alg3Mac<WithPadding<D>>, CreateError> {
        Iso9797Alg3Mac::build(WithPadding(padding), mac_size_bits)
    }
}

impl Default for Iso9797Alg3Mac<NoPadding> {
    fn default() -> Self {
        Self::new()
    }
}

impl<D> Iso9797Alg3Mac<D> {
    fn build(padding: D, mac_size_bits: usize) -> Result<Self, CreateError> {
        if mac_size_bits == 0 || !mac_size_bits.is_multiple_of(8) || mac_size_bits > 64 {
            return Err(CreateError::InvalidMacSize(mac_size_bits));
        }
        Ok(Self {
            cipher: DesEngine::new(),
            padding,
            mac_size: mac_size_bits / 8,
            key1: [0; BLOCK_BYTES],
            key2: [0; BLOCK_BYTES],
            key3: [0; BLOCK_BYTES],
            iv: [0; BLOCK_BYTES],
            chain: [0; BLOCK_BYTES],
            buffer: [0; BLOCK_BYTES],
            buffer_offset: 0,
            initialized: false,
        })
    }

    fn clear_message(&mut self) {
        self.chain = self.iv;
        self.buffer.fill(0);
        self.buffer_offset = 0;
    }
}

impl<D: Iso9797Padding> Iso9797Alg3Mac<D> {
    fn process_buffer(&mut self) -> Result<(), Error<D::Error>> {
        for index in 0..BLOCK_BYTES {
            self.buffer[index] ^= self.chain[index];
        }
        self.cipher
            .process_block(&self.buffer, &mut self.chain)
            .map_err(Error::Cipher)?;
        self.buffer.fill(0);
        self.buffer_offset = 0;
        Ok(())
    }
}

impl<D> AlgorithmName for Iso9797Alg3Mac<D> {
    fn write_algo_name(&self, output: &mut dyn fmt::Write) -> fmt::Result {
        output.write_str("ISO9797Alg3")
    }
}

impl<D: Iso9797Padding> Mac for Iso9797Alg3Mac<D> {
    type Error = Error<D::Error>;

    fn mac_size(&self) -> usize {
        self.mac_size
    }

    fn update(&mut self, mut input: &[u8]) -> Result<(), Self::Error> {
        if !self.initialized {
            return Err(Error::NotInitialised);
        }
        let gap = BLOCK_BYTES - self.buffer_offset;
        if input.len() > gap {
            self.buffer[self.buffer_offset..].copy_from_slice(&input[..gap]);
            self.process_buffer()?;
            input = &input[gap..];
            while input.len() > BLOCK_BYTES {
                self.buffer.copy_from_slice(&input[..BLOCK_BYTES]);
                self.buffer_offset = BLOCK_BYTES;
                self.process_buffer()?;
                input = &input[BLOCK_BYTES..];
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
        if self.padding.requires_extra_block() && self.buffer_offset == BLOCK_BYTES {
            self.process_buffer()?;
        }
        self.padding
            .pad(&mut self.buffer, self.buffer_offset)
            .map_err(Error::Padding)?;
        self.buffer_offset = BLOCK_BYTES;
        self.process_buffer()?;

        self.cipher
            .init(CipherDirection::Decrypt, &KeyRef::new(&self.key2))
            .map_err(Error::CipherInit)?;
        let mut temporary = [0_u8; BLOCK_BYTES];
        self.cipher
            .process_block(&self.chain, &mut temporary)
            .map_err(Error::Cipher)?;
        self.cipher
            .init(CipherDirection::Encrypt, &KeyRef::new(&self.key3))
            .map_err(Error::CipherInit)?;
        self.cipher
            .process_block(&temporary, &mut self.chain)
            .map_err(Error::Cipher)?;

        output[..self.mac_size].copy_from_slice(&self.chain[..self.mac_size]);
        self.cipher
            .init(CipherDirection::Encrypt, &KeyRef::new(&self.key1))
            .map_err(Error::CipherInit)?;
        self.clear_message();
        Ok(self.mac_size)
    }

    fn reset(&mut self) {
        self.clear_message();
    }
}

impl<D, P> MacInit<P> for Iso9797Alg3Mac<D>
where
    P: KeyParams + OptionalIvParams + ?Sized,
{
    type Error = InitError;

    fn init(&mut self, params: &P) -> Result<(), Self::Error> {
        self.initialized = false;
        let key = params.key();
        if key.len() != DOUBLE_KEY_BYTES && key.len() != TRIPLE_KEY_BYTES {
            return Err(InitError::InvalidKeyLength(key.len()));
        }
        self.iv.fill(0);
        if let Some(iv) = params.optional_iv() {
            if iv.len() != BLOCK_BYTES {
                return Err(InitError::InvalidIvLength(iv.len()));
            }
            self.iv.copy_from_slice(iv);
        }
        self.key1.copy_from_slice(&key[..8]);
        self.key2.copy_from_slice(&key[8..16]);
        if key.len() == TRIPLE_KEY_BYTES {
            self.key3.copy_from_slice(&key[16..24]);
        } else {
            self.key3.copy_from_slice(&key[..8]);
        }
        self.cipher
            .init(CipherDirection::Encrypt, &KeyRef::new(&self.key1))
            .map_err(InitError::Cipher)?;
        self.initialized = true;
        self.clear_message();
        Ok(())
    }
}

impl<D> Drop for Iso9797Alg3Mac<D> {
    fn drop(&mut self) {
        self.key1.fill(0);
        self.key2.fill(0);
        self.key3.fill(0);
        self.iv.fill(0);
        self.chain.fill(0);
        self.buffer.fill(0);
    }
}
