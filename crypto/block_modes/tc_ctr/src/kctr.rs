//! Runtime-sized DSTU 7624 KCTR mode.

use alloc::vec;
use alloc::vec::Vec;
use tc_cipher::{
    BlockCipher, BlockCipherInit, BlockCipherMode, BlockModeError, BlockModeInitError,
    CipherDirection, StreamCipher, StreamCipherInit,
};
use tc_crypto::AlgorithmName;
use tc_params::IvParams;

/// Runtime-sized KCTR mode over `C`.
pub struct KctrBlockCipher<C> {
    cipher: C,
    iv: Vec<u8>,
    initial_counter: Vec<u8>,
    counter: Vec<u8>,
    keystream: Vec<u8>,
    byte_count: usize,
    seeded: bool,
    initialised: bool,
}

impl<C: BlockCipher> KctrBlockCipher<C> {
    /// Wraps the given block cipher in KCTR mode.
    pub fn new(cipher: C) -> Self {
        let block_size = cipher.block_size();
        Self {
            cipher,
            iv: vec![0; block_size],
            initial_counter: vec![0; block_size],
            counter: vec![0; block_size],
            keystream: vec![0; block_size],
            byte_count: 0,
            seeded: false,
            initialised: false,
        }
    }

    /// Consumes the mode and returns its underlying cipher.
    pub fn into_inner(self) -> C {
        self.cipher
    }

    fn ensure_seeded(&mut self) -> Result<(), BlockModeError<C::Error>> {
        if !self.seeded {
            self.cipher
                .process_block(&self.iv, &mut self.initial_counter)
                .map_err(BlockModeError::Cipher)?;
            self.counter.copy_from_slice(&self.initial_counter);
            self.seeded = true;
        }
        Ok(())
    }

    fn calculate_byte(&mut self, input: u8) -> Result<u8, BlockModeError<C::Error>> {
        self.ensure_seeded()?;
        if self.byte_count == 0 {
            increment_le(&mut self.counter);
            self.cipher
                .process_block(&self.counter, &mut self.keystream)
                .map_err(BlockModeError::Cipher)?;
        }

        let output = input ^ self.keystream[self.byte_count];
        self.byte_count += 1;
        if self.byte_count == self.counter.len() {
            self.byte_count = 0;
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
        if self.seeded {
            self.counter.copy_from_slice(&self.initial_counter);
        } else {
            self.counter.fill(0);
        }
        self.keystream.fill(0);
        self.byte_count = 0;
    }

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
        if iv.len() > block_size {
            return Err(BlockModeInitError::InvalidIvLength(iv.len()));
        }

        let offset = block_size - iv.len();
        self.iv[..offset].fill(0);
        self.iv[offset..].copy_from_slice(iv);
        self.cipher
            .init(CipherDirection::Encrypt, params)
            .map_err(BlockModeInitError::Cipher)?;

        self.initial_counter.fill(0);
        self.counter.fill(0);
        self.keystream.fill(0);
        self.byte_count = 0;
        self.seeded = false;
        self.initialised = true;
        Ok(())
    }
}

impl<C: AlgorithmName> AlgorithmName for KctrBlockCipher<C> {
    fn write_algo_name(&self, output: &mut dyn core::fmt::Write) -> core::fmt::Result {
        self.cipher.write_algo_name(output)?;
        output.write_str("/KCTR")
    }
}

impl<C: BlockCipher> StreamCipher for KctrBlockCipher<C> {
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

impl<C: BlockCipher> BlockCipher for KctrBlockCipher<C> {
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

impl<C, P> BlockCipherInit<P> for KctrBlockCipher<C>
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

impl<C, P> StreamCipherInit<P> for KctrBlockCipher<C>
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

impl<C: BlockCipher> BlockCipherMode for KctrBlockCipher<C> {
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

fn increment_le(counter: &mut [u8]) {
    for byte in counter {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            break;
        }
    }
}
