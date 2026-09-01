//! Allocation-free OpenPGP CFB mode.

use tc_cipher::{
    BlockCipher, BlockCipherInit, BlockCipherMode, BlockModeError, BlockModeInitError,
    CipherDirection,
};
use tc_crypto::AlgorithmName;

use crate::Params;

/// Allocation-free OpenPGP CFB with an `N`-byte cipher block.
pub struct FixedOpenPgpCfbBlockCipher<C, const N: usize> {
    cipher: C,
    iv: [u8; N],
    register: [u8; N],
    keystream: [u8; N],
    count: usize,
    direction: Option<CipherDirection>,
}

impl<C, const N: usize> FixedOpenPgpCfbBlockCipher<C, N> {
    /// Wraps `cipher` without allocating.
    pub const fn new(cipher: C) -> Self {
        Self {
            cipher,
            iv: [0; N],
            register: [0; N],
            keystream: [0; N],
            count: 0,
            direction: None,
        }
    }

    /// Consumes the mode and returns its underlying cipher.
    pub fn into_inner(self) -> C {
        self.cipher
    }
}

impl<C: BlockCipher, const N: usize> FixedOpenPgpCfbBlockCipher<C, N> {
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
        if self.count > N {
            self.register[N - 2] = self.keystream[N - 2] ^ input[0];
            output[0] = self.register[N - 2];
            self.register[N - 1] = self.keystream[N - 1] ^ input[1];
            output[1] = self.register[N - 1];
            self.encrypt_register()?;
            for index in 2..N {
                self.register[index - 2] = self.keystream[index - 2] ^ input[index];
                output[index] = self.register[index - 2];
            }
        } else if self.count == 0 {
            self.encrypt_register()?;
            for index in 0..N {
                self.register[index] = self.keystream[index] ^ input[index];
                output[index] = self.register[index];
            }
            self.count += N;
        } else {
            self.encrypt_register()?;
            output[0] = self.keystream[0] ^ input[0];
            output[1] = self.keystream[1] ^ input[1];

            self.register.copy_within(2.., 0);
            self.register[N - 2..].copy_from_slice(&output[..2]);

            self.encrypt_register()?;
            for index in 2..N {
                self.register[index - 2] = self.keystream[index - 2] ^ input[index];
                output[index] = self.register[index - 2];
            }
            self.count += N;
        }
        Ok(())
    }

    fn decrypt_block(
        &mut self,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), BlockModeError<C::Error>> {
        if self.count > N {
            self.register[N - 2] = input[0];
            output[0] = self.keystream[N - 2] ^ input[0];
            self.register[N - 1] = input[1];
            output[1] = self.keystream[N - 1] ^ input[1];
            self.encrypt_register()?;
            for index in 2..N {
                self.register[index - 2] = input[index];
                output[index] = self.keystream[index - 2] ^ input[index];
            }
        } else if self.count == 0 {
            self.encrypt_register()?;
            for index in 0..N {
                self.register[index] = input[index];
                output[index] = self.keystream[index] ^ input[index];
            }
            self.count += N;
        } else {
            self.encrypt_register()?;
            let first = input[0];
            let second = input[1];
            output[0] = self.keystream[0] ^ first;
            output[1] = self.keystream[1] ^ second;

            self.register.copy_within(2.., 0);
            self.register[N - 2] = first;
            self.register[N - 1] = second;

            self.encrypt_register()?;
            for index in 2..N {
                self.register[index - 2] = input[index];
                output[index] = self.keystream[index - 2] ^ input[index];
            }
            self.count += N;
        }
        Ok(())
    }
}

impl<C: AlgorithmName, const N: usize> AlgorithmName for FixedOpenPgpCfbBlockCipher<C, N> {
    fn write_algo_name(&self, output: &mut dyn core::fmt::Write) -> core::fmt::Result {
        self.cipher.write_algo_name(output)?;
        output.write_str("/OpenPGPCFB")
    }
}

impl<C: BlockCipher, const N: usize> BlockCipher for FixedOpenPgpCfbBlockCipher<C, N> {
    type Error = BlockModeError<C::Error>;

    fn block_size(&self) -> usize {
        N
    }

    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        let direction = self.direction.ok_or(BlockModeError::NotInitialised)?;
        if input.len() < N || output.len() < N {
            return Err(BlockModeError::BufferTooShort);
        }

        match direction {
            CipherDirection::Encrypt => self.encrypt_block(input, output)?,
            CipherDirection::Decrypt => self.decrypt_block(input, output)?,
        }
        Ok(N)
    }
}

impl<C: BlockCipherInit, const N: usize> BlockCipherInit for FixedOpenPgpCfbBlockCipher<C, N> {
    type Params<'a> = Params<'a, C::Params<'a>>;
    type Error = BlockModeInitError<<C as BlockCipherInit>::Error>;

    fn init(
        &mut self,
        direction: CipherDirection,
        params: &Self::Params<'_>,
    ) -> Result<(), <Self as BlockCipherInit>::Error> {
        let actual = self.cipher.block_size();
        if actual != N {
            return Err(BlockModeInitError::UnsupportedBlockSize {
                actual,
                required: N,
            });
        }
        if N < 2 {
            return Err(BlockModeInitError::UnsupportedBlockSize {
                actual: N,
                required: 2,
            });
        }

        match params.iv() {
            Some(iv) if iv.len() > N => {
                return Err(BlockModeInitError::InvalidIvLength(iv.len()));
            }
            Some(iv) => {
                let offset = N - iv.len();
                self.iv[..offset].fill(0);
                self.iv[offset..].copy_from_slice(iv);
            }
            None => self.iv.fill(0),
        }

        self.cipher
            .init(CipherDirection::Encrypt, params.cipher())
            .map_err(BlockModeInitError::Cipher)?;
        self.direction = Some(direction);
        self.reset();
        Ok(())
    }
}

impl<C: BlockCipher, const N: usize> BlockCipherMode for FixedOpenPgpCfbBlockCipher<C, N> {
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
