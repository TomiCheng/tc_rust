//! Allocation-free DSTU 7624 KCTR mode.

use tc_cipher::{
    BlockCipher, BlockCipherInit, BlockCipherMode, BlockModeError, BlockModeInitError,
    CipherDirection, StreamCipher, StreamCipherInit,
};
use tc_crypto::AlgorithmName;
use tc_params::IvParams;

/// Allocation-free KCTR mode over an `N`-byte block cipher.
pub struct FixedKctrBlockCipher<C, const N: usize> {
    cipher: C,
    iv: [u8; N],
    initial_counter: [u8; N],
    counter: [u8; N],
    keystream: [u8; N],
    byte_count: usize,
    seeded: bool,
    initialised: bool,
}

impl<C, const N: usize> FixedKctrBlockCipher<C, N> {
    /// Wraps `cipher` without allocating.
    pub const fn new(cipher: C) -> Self {
        Self {
            cipher,
            iv: [0; N],
            initial_counter: [0; N],
            counter: [0; N],
            keystream: [0; N],
            byte_count: 0,
            seeded: false,
            initialised: false,
        }
    }

    /// Consumes the mode and returns its underlying cipher.
    pub fn into_inner(self) -> C {
        self.cipher
    }
}

impl<C: BlockCipher, const N: usize> FixedKctrBlockCipher<C, N> {
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
        if self.byte_count == N {
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
        let actual = self.cipher.block_size();
        if actual != N {
            return Err(BlockModeInitError::UnsupportedBlockSize {
                actual,
                required: N,
            });
        }

        let iv = params.iv();
        if iv.len() > N {
            return Err(BlockModeInitError::InvalidIvLength(iv.len()));
        }
        let offset = N - iv.len();
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

impl<C: AlgorithmName, const N: usize> AlgorithmName for FixedKctrBlockCipher<C, N> {
    fn write_algo_name(&self, output: &mut dyn core::fmt::Write) -> core::fmt::Result {
        self.cipher.write_algo_name(output)?;
        output.write_str("/KCTR")
    }
}

impl<C: BlockCipher, const N: usize> StreamCipher for FixedKctrBlockCipher<C, N> {
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

impl<C: BlockCipher, const N: usize> BlockCipher for FixedKctrBlockCipher<C, N> {
    type Error = BlockModeError<C::Error>;

    fn block_size(&self) -> usize {
        N
    }

    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialised {
            return Err(BlockModeError::NotInitialised);
        }
        if input.len() < N || output.len() < N {
            return Err(BlockModeError::BufferTooShort);
        }
        self.process_bytes_internal(&input[..N], &mut output[..N])
    }
}

impl<C, P, const N: usize> BlockCipherInit<P> for FixedKctrBlockCipher<C, N>
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

impl<C, P, const N: usize> StreamCipherInit<P> for FixedKctrBlockCipher<C, N>
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

impl<C: BlockCipher, const N: usize> BlockCipherMode for FixedKctrBlockCipher<C, N> {
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

fn increment_le<const N: usize>(counter: &mut [u8; N]) {
    for byte in counter {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            break;
        }
    }
}
