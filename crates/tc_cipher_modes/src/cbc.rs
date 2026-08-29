//! Cipher Block Chaining (CBC) mode, ported from Bouncy Castle's `CbcBlockCipher`.
//!
//! CBC chains blocks together: each plaintext block is XORed with the previous
//! ciphertext block before encryption, starting from an initialisation vector.
//! Equal plaintext blocks therefore no longer produce equal ciphertext blocks,
//! which is what ECB fails to hide.
//!
//! The mode processes whole blocks only; padding is a separate concern and is
//! not applied here.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use tc_cipher_core::{BlockCipher, BlockCipherInit, CipherDirection};

/// Parameters for CBC: the underlying cipher's key parameters plus an IV.
///
/// The caller builds the underlying parameters (e.g. `AesParams::new(key)`) and
/// hands them in, so the generic mode needs no separate keying capability. The
/// IV must be exactly one block long, which is checked at `init` because the
/// block size is only known from the cipher.
pub struct CbcParams<'a, E: BlockCipherInit> {
    /// The underlying block cipher's key parameters.
    key_params: E::Params<'a>,
    /// The initialisation vector; `None` means an all-zero IV.
    iv: Option<&'a [u8]>,
}

impl<'a, E: BlockCipherInit> CbcParams<'a, E> {
    /// Builds parameters with an all-zero IV (bc's behaviour when no IV is given).
    pub fn new(key_params: E::Params<'a>) -> Self {
        Self {
            key_params,
            iv: None,
        }
    }

    /// Builds parameters with the given IV, which must be one block long.
    pub fn with_iv(key_params: E::Params<'a>, iv: &'a [u8]) -> Self {
        Self {
            key_params,
            iv: Some(iv),
        }
    }
}

/// CBC mode over the block cipher `E` (bc `CbcBlockCipher`).
pub struct CbcBlockCipher<E> {
    /// The underlying block cipher.
    cipher: E,
    /// The composed name, built at construction and refreshed on `init`.
    name: String,
    /// The IV chosen at `init`, kept so the chain can be restarted.
    iv: Vec<u8>,
    /// The current chaining vector.
    cbc_v: Vec<u8>,
    /// Holds the ciphertext block while decrypting, to become the next `cbc_v`.
    cbc_next_v: Vec<u8>,
    /// `None` until `init`; then the direction the chain runs in.
    direction: Option<CipherDirection>,
}

impl<E: BlockCipher> CbcBlockCipher<E> {
    /// Wraps the given block cipher in CBC mode.
    pub fn new(cipher: E) -> Self {
        let mut mode = Self {
            cipher,
            name: String::new(),
            iv: Vec::new(),
            cbc_v: Vec::new(),
            cbc_next_v: Vec::new(),
            direction: None,
        };
        mode.refresh_name();
        mode
    }

    /// Rebuilds the composed algorithm name.
    ///
    /// 名稱在建構與 init 後各組一次：部分 engine（如 Threefish）要等 keying
    /// 之後才知道自己的名稱。
    fn refresh_name(&mut self) {
        let base = self.cipher.algorithm_name();
        let mut name = String::with_capacity(base.len() + 4);
        name.push_str(base);
        name.push_str("/CBC");
        self.name = name;
    }
}

/// Error type for CBC mode.
pub enum CbcError<E: BlockCipher> {
    /// `process_block` was called before `init`.
    NotInitialised,
    /// The IV length does not equal the cipher's block size.
    InvalidIvLength {
        /// The block size the cipher requires.
        expected: usize,
        /// The IV length that was supplied.
        actual: usize,
    },
    /// The input or output buffer is shorter than one block.
    BufferTooShort,
    /// Error reported by the underlying block cipher.
    BlockCipher(E::Error),
}

// Debug 手寫，不用 derive：derive 會對型別參數加上 `E: Debug` 約束（錯的
// 對象），而我們需要的是 `E::Error: Debug`——由 BlockCipher 的
// `type Error: core::error::Error`（其 supertrait 含 Debug）保證。
impl<E: BlockCipher> core::fmt::Debug for CbcError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CbcError::NotInitialised => f.write_str("NotInitialised"),
            CbcError::InvalidIvLength { expected, actual } => f
                .debug_struct("InvalidIvLength")
                .field("expected", expected)
                .field("actual", actual)
                .finish(),
            CbcError::BufferTooShort => f.write_str("BufferTooShort"),
            CbcError::BlockCipher(e) => f.debug_tuple("BlockCipher").field(e).finish(),
        }
    }
}

impl<E: BlockCipher> core::fmt::Display for CbcError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CbcError::NotInitialised => f.write_str("cipher mode not initialised"),
            CbcError::InvalidIvLength { expected, actual } => write!(
                f,
                "initialisation vector must be {expected} bytes to match the block size, got {actual}"
            ),
            CbcError::BufferTooShort => f.write_str("buffer shorter than one block"),
            CbcError::BlockCipher(e) => write!(f, "underlying block cipher error: {e}"),
        }
    }
}

impl<E: BlockCipher> core::error::Error for CbcError<E> {}

impl<E: BlockCipher> BlockCipher for CbcBlockCipher<E> {
    type Error = CbcError<E>;

    fn algorithm_name(&self) -> &str {
        &self.name
    }

    fn block_size(&self) -> usize {
        self.cipher.block_size()
    }

    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        let direction = self.direction.ok_or(CbcError::NotInitialised)?;
        let block_size = self.cipher.block_size();
        if input.len() < block_size || output.len() < block_size {
            return Err(CbcError::BufferTooShort);
        }

        match direction {
            CipherDirection::Encrypt => {
                // 明文先與上一塊密文（初始為 IV）相 XOR，再送進 cipher。
                for (v, &byte) in self.cbc_v.iter_mut().zip(input.iter()) {
                    *v ^= byte;
                }
                let written = self
                    .cipher
                    .process_block(&self.cbc_v, output)
                    .map_err(CbcError::BlockCipher)?;
                // 本塊密文成為下一塊的鏈結向量。
                self.cbc_v.copy_from_slice(&output[..block_size]);
                Ok(written)
            }
            CipherDirection::Decrypt => {
                // 先留存本塊密文，解密後它就是下一塊的鏈結向量。
                self.cbc_next_v.copy_from_slice(&input[..block_size]);
                let written = self
                    .cipher
                    .process_block(input, output)
                    .map_err(CbcError::BlockCipher)?;
                for (byte, &v) in output.iter_mut().zip(self.cbc_v.iter()) {
                    *byte ^= v;
                }
                core::mem::swap(&mut self.cbc_v, &mut self.cbc_next_v);
                Ok(written)
            }
        }
    }
}

impl<E: BlockCipherInit> BlockCipherInit for CbcBlockCipher<E> {
    type Params<'a> = CbcParams<'a, E>;

    fn init(
        &mut self,
        direction: CipherDirection,
        params: &Self::Params<'_>,
    ) -> Result<(), Self::Error> {
        let block_size = self.cipher.block_size();
        self.iv = match params.iv {
            Some(iv) if iv.len() != block_size => {
                return Err(CbcError::InvalidIvLength {
                    expected: block_size,
                    actual: iv.len(),
                });
            }
            Some(iv) => iv.to_vec(),
            // 未給 IV 時視為全零（照 bc）。
            None => vec![0u8; block_size],
        };
        self.cbc_v = self.iv.clone();
        self.cbc_next_v = vec![0u8; block_size];

        self.cipher
            .init(direction, &params.key_params)
            .map_err(CbcError::BlockCipher)?;
        self.direction = Some(direction);
        self.refresh_name();
        Ok(())
    }
}
