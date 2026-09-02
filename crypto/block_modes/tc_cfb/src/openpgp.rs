//! Runtime-sized OpenPGP CFB mode.

use alloc::vec;
use alloc::vec::Vec;

use tc_cipher::{
    BlockCipher, BlockCipherInit, BlockCipherMode, BlockModeError, BlockModeInitError,
    CipherDirection,
};
use tc_crypto::AlgorithmName;
use tc_params::OptionalIvParams;

/// Runtime-sized OpenPGP CFB mode over `C`.
pub struct OpenPgpCfbBlockCipher<C> {
    cipher: C,
    iv: Vec<u8>,
    register: Vec<u8>,
    keystream: Vec<u8>,
    count: usize,
    direction: Option<CipherDirection>,
}

impl<C: BlockCipher> OpenPgpCfbBlockCipher<C> {
    /// Wraps `cipher` and allocates three blocks of state.
    pub fn new(cipher: C) -> Self {
        let block_size = cipher.block_size();
        Self {
            cipher,
            iv: vec![0; block_size],
            register: vec![0; block_size],
            keystream: vec![0; block_size],
            count: 0,
            direction: None,
        }
    }

    /// Consumes the mode and returns its underlying cipher.
    pub fn into_inner(self) -> C {
        self.cipher
    }

    fn encrypt_register(&mut self) -> Result<(), BlockModeError<C::Error>> {
        self.cipher
            .process_block(&self.register, &mut self.keystream)
            .map_err(BlockModeError::Cipher)?;
        Ok(())
    }

    fn encrypt_block(
        &mut self,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), BlockModeError<C::Error>> {
        let block_size = self.register.len();
        if self.count > block_size {
            self.register[block_size - 2] = self.keystream[block_size - 2] ^ input[0];
            output[0] = self.register[block_size - 2];
            self.register[block_size - 1] = self.keystream[block_size - 1] ^ input[1];
            output[1] = self.register[block_size - 1];
            self.encrypt_register()?;
            for index in 2..block_size {
                self.register[index - 2] = self.keystream[index - 2] ^ input[index];
                output[index] = self.register[index - 2];
            }
        } else if self.count == 0 {
            self.encrypt_register()?;
            for index in 0..block_size {
                self.register[index] = self.keystream[index] ^ input[index];
                output[index] = self.register[index];
            }
            self.count += block_size;
        } else {
            self.encrypt_register()?;
            output[0] = self.keystream[0] ^ input[0];
            output[1] = self.keystream[1] ^ input[1];

            self.register.copy_within(2.., 0);
            self.register[block_size - 2..].copy_from_slice(&output[..2]);

            self.encrypt_register()?;
            for index in 2..block_size {
                self.register[index - 2] = self.keystream[index - 2] ^ input[index];
                output[index] = self.register[index - 2];
            }
            self.count += block_size;
        }
        Ok(())
    }

    fn decrypt_block(
        &mut self,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), BlockModeError<C::Error>> {
        let block_size = self.register.len();
        if self.count > block_size {
            self.register[block_size - 2] = input[0];
            output[0] = self.keystream[block_size - 2] ^ input[0];
            self.register[block_size - 1] = input[1];
            output[1] = self.keystream[block_size - 1] ^ input[1];
            self.encrypt_register()?;
            for index in 2..block_size {
                self.register[index - 2] = input[index];
                output[index] = self.keystream[index - 2] ^ input[index];
            }
        } else if self.count == 0 {
            self.encrypt_register()?;
            for index in 0..block_size {
                self.register[index] = input[index];
                output[index] = self.keystream[index] ^ input[index];
            }
            self.count += block_size;
        } else {
            self.encrypt_register()?;
            let first = input[0];
            let second = input[1];
            output[0] = self.keystream[0] ^ first;
            output[1] = self.keystream[1] ^ second;

            self.register.copy_within(2.., 0);
            self.register[block_size - 2] = first;
            self.register[block_size - 1] = second;

            self.encrypt_register()?;
            for index in 2..block_size {
                self.register[index - 2] = input[index];
                output[index] = self.keystream[index - 2] ^ input[index];
            }
            self.count += block_size;
        }
        Ok(())
    }
}

impl<C: AlgorithmName> AlgorithmName for OpenPgpCfbBlockCipher<C> {
    fn write_algo_name(&self, output: &mut dyn core::fmt::Write) -> core::fmt::Result {
        self.cipher.write_algo_name(output)?;
        output.write_str("/OpenPGPCFB")
    }
}

impl<C: BlockCipher> BlockCipher for OpenPgpCfbBlockCipher<C> {
    type Error = BlockModeError<C::Error>;

    fn block_size(&self) -> usize {
        self.cipher.block_size()
    }

    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        let direction = self.direction.ok_or(BlockModeError::NotInitialised)?;
        let block_size = self.cipher.block_size();
        if input.len() < block_size || output.len() < block_size {
            return Err(BlockModeError::BufferTooShort);
        }

        match direction {
            CipherDirection::Encrypt => self.encrypt_block(input, output)?,
            CipherDirection::Decrypt => self.decrypt_block(input, output)?,
        }
        Ok(block_size)
    }
}

impl<C, P> BlockCipherInit<P> for OpenPgpCfbBlockCipher<C>
where
    C: BlockCipher + BlockCipherInit<P>,
    P: OptionalIvParams + ?Sized,
{
    type Error = BlockModeInitError<<C as BlockCipherInit<P>>::Error>;

    fn init(
        &mut self,
        direction: CipherDirection,
        params: &P,
    ) -> Result<(), <Self as BlockCipherInit<P>>::Error> {
        let block_size = self.cipher.block_size();
        if block_size < 2 {
            return Err(BlockModeInitError::UnsupportedBlockSize {
                actual: block_size,
                required: 2,
            });
        }

        match params.optional_iv() {
            Some(iv) if iv.len() > block_size => {
                return Err(BlockModeInitError::InvalidIvLength(iv.len()));
            }
            Some(iv) => {
                let offset = block_size - iv.len();
                self.iv[..offset].fill(0);
                self.iv[offset..].copy_from_slice(iv);
            }
            None => self.iv.fill(0),
        }

        self.cipher
            .init(CipherDirection::Encrypt, params)
            .map_err(BlockModeInitError::Cipher)?;
        self.direction = Some(direction);
        self.reset();
        Ok(())
    }
}

impl<C: BlockCipher> BlockCipherMode for OpenPgpCfbBlockCipher<C> {
    type Cipher = C;

    fn underlying_cipher(&self) -> &Self::Cipher {
        &self.cipher
    }

    fn is_partial_block_okay(&self) -> bool {
        true
    }

    fn reset(&mut self) {
        self.count = 0;
        self.register.copy_from_slice(&self.iv);
        self.keystream.fill(0);
    }
}
