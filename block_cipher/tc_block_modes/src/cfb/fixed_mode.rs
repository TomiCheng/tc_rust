//! Allocation-free standard CFB mode.

use core::fmt::{Display, Formatter};
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
use crate::{BlockCipherMode, BlockModeError, BlockModeInitError, IvOptParams};

/// Allocation-free Cipher Feedback mode with an `N`-byte cipher block and an
/// `S`-byte segment.
///
/// Initialization rejects an underlying cipher whose runtime block size is not
/// `N`, and a segment size outside `1..=N`.
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

impl<C: Display, const N: usize, const S: usize> Display for FixedCfbBlockCipher<C, N, S> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        self.cipher.fmt(f)?;
        write!(f, "/CFB{}", S * 8)
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
        for ((output, input), keystream) in output[..S].iter_mut().zip(input).zip(&self.keystream) {
            *output = input ^ keystream;
        }

        let ciphertext = match direction {
            CipherDirection::Encrypt => &output[..S],
            CipherDirection::Decrypt => &input[..S],
        };
        self.register.copy_within(S.., 0);
        self.register[N - S..].copy_from_slice(ciphertext);
        Ok(S)
    }
}

impl<C, P, const N: usize, const S: usize> BlockCipherInit<P> for FixedCfbBlockCipher<C, N, S>
where
    C: BlockCipher + BlockCipherInit<P>,
    P: IvOptParams + ?Sized,
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

        let iv = params.iv_opt();
        if let Some(iv) = iv.filter(|iv| iv.len() > N) {
            return Err(BlockModeInitError::InvalidIvLength(iv.len()));
        }

        self.cipher
            .init(CipherDirection::Encrypt, params)
            .map_err(BlockModeInitError::Cipher)?;

        // 短 IV 靠右放、左補零（FIPS 81）；省略 IV 等同全零。
        let iv = iv.unwrap_or(&[]);
        let offset = N - iv.len();
        self.iv[..offset].fill(0);
        self.iv[offset..].copy_from_slice(iv);
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
