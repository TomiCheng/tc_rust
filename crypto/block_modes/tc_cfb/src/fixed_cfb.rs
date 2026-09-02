//! Allocation-free standard CFB mode.

use tc_cipher::{
    BlockCipher, BlockCipherInit, BlockCipherMode, BlockModeError, BlockModeInitError,
    CipherDirection,
};
use tc_crypto::AlgorithmName;
use tc_params::OptionalIvParams;

/// Allocation-free CFB with an `N`-byte cipher block and `S`-byte segment.
pub struct FixedCfbBlockCipher<C, const N: usize, const S: usize> {
    cipher: C,
    iv: [u8; N],
    register: [u8; N],
    keystream: [u8; N],
    direction: Option<CipherDirection>,
}

impl<C, const N: usize, const S: usize> FixedCfbBlockCipher<C, N, S> {
    /// Wraps `cipher` without allocating.
    pub const fn new(cipher: C) -> Self {
        Self {
            cipher,
            iv: [0; N],
            register: [0; N],
            keystream: [0; N],
            direction: None,
        }
    }

    /// Consumes the mode and returns its underlying cipher.
    pub fn into_inner(self) -> C {
        self.cipher
    }
}

impl<C: AlgorithmName, const N: usize, const S: usize> AlgorithmName
    for FixedCfbBlockCipher<C, N, S>
{
    fn write_algo_name(&self, output: &mut dyn core::fmt::Write) -> core::fmt::Result {
        self.cipher.write_algo_name(output)?;
        write!(output, "/CFB{}", S * 8)
    }
}

impl<C: BlockCipher, const N: usize, const S: usize> BlockCipher for FixedCfbBlockCipher<C, N, S> {
    type Error = BlockModeError<C::Error>;

    fn block_size(&self) -> usize {
        S
    }

    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        let direction = self.direction.ok_or(BlockModeError::NotInitialised)?;
        if input.len() < S || output.len() < S {
            return Err(BlockModeError::BufferTooShort);
        }

        self.cipher
            .process_block(&self.register, &mut self.keystream)
            .map_err(BlockModeError::Cipher)?;

        let tail = N - S;
        match direction {
            CipherDirection::Encrypt => {
                for index in 0..S {
                    output[index] = self.keystream[index] ^ input[index];
                }
                self.register.copy_within(S.., 0);
                self.register[tail..].copy_from_slice(&output[..S]);
            }
            CipherDirection::Decrypt => {
                self.register.copy_within(S.., 0);
                self.register[tail..].copy_from_slice(&input[..S]);
                for index in 0..S {
                    output[index] = self.keystream[index] ^ input[index];
                }
            }
        }
        Ok(S)
    }
}

impl<C, P, const N: usize, const S: usize> BlockCipherInit<P> for FixedCfbBlockCipher<C, N, S>
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
        let actual = self.cipher.block_size();
        if actual != N {
            return Err(BlockModeInitError::UnsupportedBlockSize {
                actual,
                required: N,
            });
        }
        if S == 0 || S > N {
            return Err(BlockModeInitError::InvalidFeedbackSize(S * 8));
        }

        match params.optional_iv() {
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
            .init(CipherDirection::Encrypt, params)
            .map_err(BlockModeInitError::Cipher)?;
        self.direction = Some(direction);
        self.reset();
        Ok(())
    }
}

impl<C: BlockCipher, const N: usize, const S: usize> BlockCipherMode
    for FixedCfbBlockCipher<C, N, S>
{
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
    }
}
