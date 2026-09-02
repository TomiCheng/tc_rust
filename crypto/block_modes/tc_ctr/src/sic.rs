//! Runtime-sized CTR/SIC mode.

use alloc::vec;
use alloc::vec::Vec;
use tc_cipher::{
    BlockCipher, BlockCipherInit, BlockCipherMode, BlockModeError, BlockModeInitError,
    CipherDirection, StreamCipher, StreamCipherInit,
};
use tc_crypto::AlgorithmName;
use tc_params::IvParams;

/// Runtime-sized Segmented Integer Counter mode over `C`.
pub struct SicBlockCipher<C> {
    cipher: C,
    iv: Vec<u8>,
    counter: Vec<u8>,
    keystream: Vec<u8>,
    byte_count: usize,
    initialised: bool,
}

impl<C: BlockCipher> SicBlockCipher<C> {
    /// Wraps the given block cipher in CTR mode.
    pub fn new(cipher: C) -> Self {
        let block_size = cipher.block_size();
        Self {
            cipher,
            iv: vec![0; block_size],
            counter: vec![0; block_size],
            keystream: vec![0; block_size],
            byte_count: 0,
            initialised: false,
        }
    }

    /// Consumes the mode and returns its underlying cipher.
    pub fn into_inner(self) -> C {
        self.cipher
    }

    fn calculate_byte(&mut self, input: u8) -> Result<u8, BlockModeError<C::Error>> {
        if self.byte_count == 0 {
            self.cipher
                .process_block(&self.counter, &mut self.keystream)
                .map_err(BlockModeError::Cipher)?;
        }

        let output = input ^ self.keystream[self.byte_count];
        self.byte_count += 1;
        if self.byte_count == self.counter.len() {
            self.byte_count = 0;
            increment_be(&mut self.counter);
        }
        Ok(output)
    }

    fn process_bytes_internal(
        &mut self,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, BlockModeError<C::Error>> {
        if !self.initialised {
            return Err(BlockModeError::NotInitialised);
        }
        if output.len() < input.len() {
            return Err(BlockModeError::BufferTooShort);
        }
        for (input, output) in input.iter().copied().zip(output.iter_mut()) {
            *output = self.calculate_byte(input)?;
        }
        Ok(input.len())
    }

    fn reset_internal(&mut self) {
        self.counter.copy_from_slice(&self.iv);
        self.keystream.fill(0);
        self.byte_count = 0;
    }
}

impl<C: AlgorithmName> AlgorithmName for SicBlockCipher<C> {
    fn write_algo_name(&self, output: &mut dyn core::fmt::Write) -> core::fmt::Result {
        self.cipher.write_algo_name(output)?;
        output.write_str("/SIC")
    }
}

impl<C: BlockCipher> StreamCipher for SicBlockCipher<C> {
    type Error = BlockModeError<C::Error>;

    fn return_byte(&mut self, input: u8) -> Result<u8, Self::Error> {
        if !self.initialised {
            return Err(BlockModeError::NotInitialised);
        }
        self.calculate_byte(input)
    }

    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        self.process_bytes_internal(input, output)
    }

    fn reset(&mut self) {
        self.reset_internal();
    }
}

impl<C: BlockCipher> BlockCipher for SicBlockCipher<C> {
    type Error = BlockModeError<C::Error>;

    fn block_size(&self) -> usize {
        self.counter.len()
    }

    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialised {
            return Err(BlockModeError::NotInitialised);
        }
        let block_size = self.counter.len();
        if input.len() < block_size || output.len() < block_size {
            return Err(BlockModeError::BufferTooShort);
        }
        self.process_bytes_internal(&input[..block_size], &mut output[..block_size])
    }
}

impl<C, P> BlockCipherInit<P> for SicBlockCipher<C>
where
    C: BlockCipher + BlockCipherInit<P>,
    P: IvParams + ?Sized,
{
    type Error = BlockModeInitError<<C as BlockCipherInit<P>>::Error>;

    fn init(
        &mut self,
        _direction: CipherDirection,
        params: &P,
    ) -> Result<(), <Self as BlockCipherInit<P>>::Error> {
        self.init_internal(params)
    }
}

impl<C, P> StreamCipherInit<P> for SicBlockCipher<C>
where
    C: BlockCipher + BlockCipherInit<P>,
    P: IvParams + ?Sized,
{
    type Error = BlockModeInitError<<C as BlockCipherInit<P>>::Error>;

    fn init(
        &mut self,
        _direction: CipherDirection,
        params: &P,
    ) -> Result<(), <Self as StreamCipherInit<P>>::Error> {
        self.init_internal(params)
    }
}

impl<C: BlockCipher> BlockCipherMode for SicBlockCipher<C> {
    type Cipher = C;

    fn underlying_cipher(&self) -> &Self::Cipher {
        &self.cipher
    }

    fn is_partial_block_okay(&self) -> bool {
        true
    }

    fn reset(&mut self) {
        self.reset_internal();
    }
}

impl<C: BlockCipher> SicBlockCipher<C> {
    fn init_internal<P>(
        &mut self,
        params: &P,
    ) -> Result<(), BlockModeInitError<<C as BlockCipherInit<P>>::Error>>
    where
        C: BlockCipherInit<P>,
        P: IvParams + ?Sized,
    {
        let block_size = self.cipher.block_size();
        let iv = params.iv();
        let max_counter_size = 8.min(block_size / 2);
        if iv.len() > block_size || block_size - iv.len() > max_counter_size {
            return Err(BlockModeInitError::InvalidIvLength(iv.len()));
        }

        self.iv[..iv.len()].copy_from_slice(iv);
        self.iv[iv.len()..].fill(0);
        self.cipher
            .init(CipherDirection::Encrypt, params)
            .map_err(BlockModeInitError::Cipher)?;
        self.initialised = true;
        self.reset_internal();
        Ok(())
    }
}

fn increment_be(counter: &mut [u8]) {
    for byte in counter.iter_mut().rev() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            break;
        }
    }
}
