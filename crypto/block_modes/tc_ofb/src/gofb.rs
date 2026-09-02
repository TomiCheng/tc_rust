//! GOST 28147 OFB counter mode (GCTR).

use tc_cipher::{
    BlockCipher, BlockCipherInit, BlockCipherMode, BlockModeError, BlockModeInitError,
    CipherDirection,
};
use tc_crypto::AlgorithmName;
use tc_params::OptionalIvParams;

/// The block size GCTR is defined for, in bytes.
pub const BLOCK_BYTES: usize = 8;

const C1: i32 = 0x0101_0104;
const C2: i32 = 0x0101_0101;

/// Allocation-free GOST 28147 counter mode over `C`.
pub struct GofbBlockCipher<C> {
    cipher: C,
    iv: [u8; BLOCK_BYTES],
    register: [u8; BLOCK_BYTES],
    keystream: [u8; BLOCK_BYTES],
    n3: i32,
    n4: i32,
    first_step: bool,
    initialised: bool,
}

impl<C: BlockCipher> GofbBlockCipher<C> {
    /// Wraps a cipher whose block size must be exactly eight bytes.
    pub fn new(cipher: C) -> Result<Self, BlockModeInitError<core::convert::Infallible>> {
        let actual = cipher.block_size();
        if actual != BLOCK_BYTES {
            return Err(BlockModeInitError::UnsupportedBlockSize {
                actual,
                required: BLOCK_BYTES,
            });
        }

        Ok(Self {
            cipher,
            iv: [0; BLOCK_BYTES],
            register: [0; BLOCK_BYTES],
            keystream: [0; BLOCK_BYTES],
            n3: 0,
            n4: 0,
            first_step: true,
            initialised: false,
        })
    }

    /// Consumes the mode and returns its underlying cipher.
    pub fn into_inner(self) -> C {
        self.cipher
    }
}

impl<C: AlgorithmName> AlgorithmName for GofbBlockCipher<C> {
    fn write_algo_name(&self, output: &mut dyn core::fmt::Write) -> core::fmt::Result {
        self.cipher.write_algo_name(output)?;
        output.write_str("/GCTR")
    }
}

impl<C: BlockCipher> BlockCipher for GofbBlockCipher<C> {
    type Error = BlockModeError<C::Error>;

    fn block_size(&self) -> usize {
        BLOCK_BYTES
    }

    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialised {
            return Err(BlockModeError::NotInitialised);
        }
        if input.len() < BLOCK_BYTES || output.len() < BLOCK_BYTES {
            return Err(BlockModeError::BufferTooShort);
        }

        if self.first_step {
            self.cipher
                .process_block(&self.register, &mut self.keystream)
                .map_err(BlockModeError::Cipher)?;
            self.n3 = u32::from_le_bytes(self.keystream[..4].try_into().unwrap()) as i32;
            self.n4 = u32::from_le_bytes(self.keystream[4..].try_into().unwrap()) as i32;
            self.first_step = false;
        }

        self.n3 = self.n3.wrapping_add(C2);
        self.n4 = self.n4.wrapping_add(C1);
        if self.n4 < C1 && self.n4 > 0 {
            self.n4 = self.n4.wrapping_add(1);
        }
        self.register[..4].copy_from_slice(&(self.n3 as u32).to_le_bytes());
        self.register[4..].copy_from_slice(&(self.n4 as u32).to_le_bytes());

        self.cipher
            .process_block(&self.register, &mut self.keystream)
            .map_err(BlockModeError::Cipher)?;
        for index in 0..BLOCK_BYTES {
            output[index] = self.keystream[index] ^ input[index];
        }
        Ok(BLOCK_BYTES)
    }
}

impl<C, P> BlockCipherInit<P> for GofbBlockCipher<C>
where
    C: BlockCipher + BlockCipherInit<P>,
    P: OptionalIvParams + ?Sized,
{
    type Error = BlockModeInitError<<C as BlockCipherInit<P>>::Error>;

    fn init(
        &mut self,
        _direction: CipherDirection,
        params: &P,
    ) -> Result<(), <Self as BlockCipherInit<P>>::Error> {
        match params.optional_iv() {
            Some(iv) if iv.len() > BLOCK_BYTES => {
                return Err(BlockModeInitError::InvalidIvLength(iv.len()));
            }
            Some(iv) => {
                let offset = BLOCK_BYTES - iv.len();
                self.iv[..offset].fill(0);
                self.iv[offset..].copy_from_slice(iv);
            }
            None => self.iv.fill(0),
        }

        self.cipher
            .init(CipherDirection::Encrypt, params)
            .map_err(BlockModeInitError::Cipher)?;
        self.initialised = true;
        self.reset();
        Ok(())
    }
}

impl<C: BlockCipher> BlockCipherMode for GofbBlockCipher<C> {
    type Cipher = C;

    fn underlying_cipher(&self) -> &Self::Cipher {
        &self.cipher
    }

    fn is_partial_block_okay(&self) -> bool {
        true
    }

    fn reset(&mut self) {
        self.register.copy_from_slice(&self.iv);
        self.keystream.fill(0);
        self.n3 = 0;
        self.n4 = 0;
        self.first_step = true;
    }
}
