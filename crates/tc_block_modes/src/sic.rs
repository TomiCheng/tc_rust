//! Counter (CTR) mode, ported from Bouncy Castle's `SicBlockCipher`.
//!
//! CTR encrypts a counter block to produce keystream and XORs it with the data,
//! incrementing the counter for each block. The keystream depends only on the
//! key and the counter, so encryption and decryption are the same operation and
//! the direction passed to `init` is ignored; the underlying cipher is always
//! keyed for encryption.
//!
//! The counter block starts as the IV, left-aligned and zero-filled, so the IV
//! must leave room for the counter to run: the trailing counter may be at most
//! eight bytes, and no more than half the block.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use tc_cipher_core::{BlockCipher, BlockCipherInit, CipherDirection};

use crate::BlockCipherModeError;

/// Parameters for CTR: the underlying cipher's key parameters plus a nonce/IV.
///
/// Unlike CBC, CFB, and OFB the IV is required — a counter mode with a fixed
/// all-zero nonce would repeat its keystream across messages.
pub struct SicParams<'a, E: BlockCipherInit> {
    /// The underlying block cipher's key parameters.
    key_params: E::Params<'a>,
    /// The initial counter block prefix.
    iv: &'a [u8],
}

impl<'a, E: BlockCipherInit> SicParams<'a, E> {
    /// Builds parameters from the cipher's key parameters and the IV.
    pub fn new(key_params: E::Params<'a>, iv: &'a [u8]) -> Self {
        Self { key_params, iv }
    }
}

/// CTR (counter) mode over the block cipher `E` (bc `SicBlockCipher`).
pub struct SicBlockCipher<E> {
    /// The underlying block cipher, always keyed for encryption.
    cipher: E,
    /// The composed name, built at construction and refreshed on `init`.
    name: String,
    /// The IV chosen at `init`, kept so the counter can be restarted.
    iv: Vec<u8>,
    /// The current counter block.
    counter: Vec<u8>,
    /// The cipher's output over the counter, i.e. the keystream.
    counter_out: Vec<u8>,
    /// `true` once `init` has run.
    initialised: bool,
}

/// CTR mode, the common name for [`SicBlockCipher`].
pub type CtrBlockCipher<E> = SicBlockCipher<E>;

/// CTR mode parameters, the common name for [`SicParams`].
pub type CtrParams<'a, E> = SicParams<'a, E>;

impl<E: BlockCipher> SicBlockCipher<E> {
    /// Wraps the given block cipher in CTR mode.
    pub fn new(cipher: E) -> Self {
        let block_size = cipher.block_size();
        let mut mode = Self {
            cipher,
            name: String::new(),
            iv: vec![0u8; block_size],
            counter: vec![0u8; block_size],
            counter_out: vec![0u8; block_size],
            initialised: false,
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
        name.push_str("/SIC");
        self.name = name;
    }
}

impl<E: BlockCipher> BlockCipher for SicBlockCipher<E> {
    type Error = BlockCipherModeError<E>;

    fn algorithm_name(&self) -> &str {
        &self.name
    }

    fn block_size(&self) -> usize {
        self.cipher.block_size()
    }

    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialised {
            return Err(BlockCipherModeError::NotInitialised);
        }
        let block_size = self.counter.len();
        if input.len() < block_size || output.len() < block_size {
            return Err(BlockCipherModeError::BufferTooShort);
        }

        // 以計數器產生 keystream。
        self.cipher
            .process_block(&self.counter, &mut self.counter_out)
            .map_err(BlockCipherModeError::BlockCipher)?;
        for i in 0..block_size {
            output[i] = self.counter_out[i] ^ input[i];
        }

        // 計數器加一（big-endian，自末端進位）。
        for byte in self.counter.iter_mut().rev() {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                break;
            }
        }
        Ok(block_size)
    }
}

impl<E: BlockCipherInit> BlockCipherInit for SicBlockCipher<E> {
    type Params<'a> = SicParams<'a, E>;

    fn init(
        &mut self,
        _direction: CipherDirection,
        params: &Self::Params<'_>,
    ) -> Result<(), Self::Error> {
        // CTR 的 keystream 只由 key 與計數器決定，加解密同一操作，故忽略方向。
        let block_size = self.cipher.block_size();
        let iv_len = params.iv.len();

        // 計數器最多佔 8 個位元組，且不超過分組的一半；IV 必須留下這些空間。
        let max_counter = 8.min(block_size / 2);
        if iv_len > block_size || block_size - iv_len > max_counter {
            return Err(BlockCipherModeError::InvalidIvLength {
                actual: iv_len,
                block_size,
            });
        }

        self.iv[..iv_len].copy_from_slice(params.iv);
        self.iv[iv_len..].fill(0);
        self.counter.copy_from_slice(&self.iv);

        self.cipher
            .init(CipherDirection::Encrypt, &params.key_params)
            .map_err(BlockCipherModeError::BlockCipher)?;
        self.initialised = true;
        self.refresh_name();
        Ok(())
    }
}
