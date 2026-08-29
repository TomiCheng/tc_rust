//! DSTU 7624 (Kalyna) key wrap engine.
//!
//! Mirrors Bouncy Castle's `Dstu7624WrapEngine`. Unlike the RFC 3394 / 5649
//! wrappers this is a scheme of its own: it appends an all-zero checking block,
//! then runs a swap network over half-blocks with a per-round counter XOR, using
//! the DSTU 7624 cipher at a chosen 128-, 256-, or 512-bit block size. It is not
//! generic over the cipher — the block size is the only parameter.

use alloc::vec;
use alloc::vec::Vec;
use tc_block_cipher::{BlockCipherError, Dstu7624Engine, Dstu7624Params};
use tc_cipher_core::{BlockCipher, BlockCipherInit, CipherDirection};
use tc_crypto_core::Wrapper;

/// DSTU 7624 (Kalyna) key wrap, over a 128-, 256-, or 512-bit block.
///
/// Build with [`new`](Self::new), giving the block size in bits, then wrap /
/// unwrap through the [`Wrapper`] trait. The key (supplied to `init` via
/// [`Dstu7624Params`]) must be the block size or twice the block size.
pub struct Dstu7624WrapEngine {
    /// The underlying DSTU 7624 cipher.
    engine: Dstu7624Engine,
    /// Block size in bytes.
    block_size: usize,
    /// `None` means not yet initialised; `Some(true)` / `Some(false)` selects
    /// wrap / unwrap mode.
    for_wrapping: Option<bool>,
}

impl Dstu7624WrapEngine {
    /// Builds a wrapper over a DSTU 7624 cipher with the given block size in bits
    /// (128, 256, or 512). Fails if the block size is unsupported.
    pub fn new(block_size_bits: usize) -> Result<Self, Dstu7624WrapError> {
        let engine = Dstu7624Engine::new(block_size_bits).map_err(Dstu7624WrapError::BlockCipher)?;
        let block_size = engine.block_size();
        Ok(Self {
            engine,
            block_size,
            for_wrapping: None,
        })
    }

    /// Processes one full block in place using the already-keyed engine, routing
    /// through a scratch buffer (max 512-bit block = 64 bytes) to avoid aliasing.
    fn crypt_block(&mut self, block: &mut [u8]) -> Result<(), Dstu7624WrapError> {
        let mut scratch = [0u8; 64];
        let bs = self.block_size;
        self.engine
            .process_block(block, &mut scratch[..bs])
            .map_err(Dstu7624WrapError::BlockCipher)?;
        block.copy_from_slice(&scratch[..bs]);
        Ok(())
    }
}

/// Error type for the DSTU 7624 key wrapper.
#[derive(Debug)]
pub enum Dstu7624WrapError {
    /// wrap / unwrap called before `init`.
    Uninitialised,
    /// Initialised for unwrapping, but `wrap` was called.
    NotForWrapping,
    /// Initialised for wrapping, but `unwrap` was called.
    NotForUnwrapping,
    /// Wrap input length is not a multiple of the block size (padding unsupported).
    WrapDataLength,
    /// Unwrap input length is not a positive multiple of the block size.
    UnwrapDataLength,
    /// Integrity check failed on unwrap (the trailing checking block is nonzero).
    IntegrityCheckFailed,
    /// Error reported by the underlying DSTU 7624 cipher.
    BlockCipher(BlockCipherError),
}

impl core::fmt::Display for Dstu7624WrapError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Dstu7624WrapError::Uninitialised => f.write_str("key wrapper not initialised"),
            Dstu7624WrapError::NotForWrapping => f.write_str("wrapper not set for wrapping"),
            Dstu7624WrapError::NotForUnwrapping => f.write_str("wrapper not set for unwrapping"),
            Dstu7624WrapError::WrapDataLength => {
                f.write_str("wrap data must be a multiple of the block size (padding unsupported)")
            }
            Dstu7624WrapError::UnwrapDataLength => {
                f.write_str("unwrap data must be a positive multiple of the block size")
            }
            Dstu7624WrapError::IntegrityCheckFailed => f.write_str("integrity check failed"),
            Dstu7624WrapError::BlockCipher(e) => write!(f, "underlying block cipher error: {e}"),
        }
    }
}

impl core::error::Error for Dstu7624WrapError {}

impl Wrapper for Dstu7624WrapEngine {
    type Params<'a> = Dstu7624Params;
    type Error = Dstu7624WrapError;

    fn algorithm_name(&self) -> &str {
        self.engine.algorithm_name()
    }

    fn init(&mut self, for_wrapping: bool, params: &Self::Params<'_>) -> Result<(), Self::Error> {
        // wrap=加密、unwrap=解密；金鑰長度驗證交由底層 engine.init。
        let direction = if for_wrapping {
            CipherDirection::Encrypt
        } else {
            CipherDirection::Decrypt
        };
        self.engine
            .init(direction, params)
            .map_err(Dstu7624WrapError::BlockCipher)?;
        self.for_wrapping = Some(for_wrapping);
        Ok(())
    }

    fn wrap(&mut self, input: &[u8]) -> Result<Vec<u8>, Self::Error> {
        match self.for_wrapping {
            Some(true) => {}
            Some(false) => return Err(Dstu7624WrapError::NotForWrapping),
            None => return Err(Dstu7624WrapError::Uninitialised),
        }
        let bs = self.block_size;
        let half = bs / 2;
        if !input.len().is_multiple_of(bs) {
            return Err(Dstu7624WrapError::WrapDataLength);
        }
        let n = 2 * (1 + input.len() / bs);
        let v = (n - 1) * 6;

        // buffer = input || zeros(bs)（附加一個零塊作為校驗）。
        let mut buffer = vec![0u8; input.len() + bs];
        buffer[..input.len()].copy_from_slice(input);

        // B = 第一個半塊；b_temp = 其餘 n-1 個半塊。
        let mut b = buffer[..half].to_vec();
        let mut b_temp: Vec<Vec<u8>> = buffer[half..].chunks(half).map(<[u8]>::to_vec).collect();

        let mut block = vec![0u8; bs];
        for j in 0..v {
            block[..half].copy_from_slice(&b);
            block[half..].copy_from_slice(&b_temp[0]);
            self.crypt_block(&mut block)?;

            // 把 LE(j+1) XOR 進 block 後半的前 4 bytes。
            let ctr = (j as u32 + 1).to_le_bytes();
            for (bn, &c) in ctr.iter().enumerate() {
                block[half + bn] ^= c;
            }

            b.copy_from_slice(&block[half..]);
            // 半塊左移一格（丟棄第 0 個），末端放入 block 前半。
            b_temp.rotate_left(1);
            b_temp[n - 2].copy_from_slice(&block[..half]);
        }

        buffer[..half].copy_from_slice(&b);
        for (i, chunk) in b_temp.iter().enumerate() {
            let off = half + i * half;
            buffer[off..off + half].copy_from_slice(chunk);
        }
        Ok(buffer)
    }

    fn unwrap(&mut self, input: &[u8]) -> Result<Vec<u8>, Self::Error> {
        match self.for_wrapping {
            Some(false) => {}
            Some(true) => return Err(Dstu7624WrapError::NotForUnwrapping),
            None => return Err(Dstu7624WrapError::Uninitialised),
        }
        let bs = self.block_size;
        let half = bs / 2;
        if input.len() < bs || !input.len().is_multiple_of(bs) {
            return Err(Dstu7624WrapError::UnwrapDataLength);
        }
        let n = 2 * input.len() / bs;
        let v = (n - 1) * 6;

        let mut buffer = input.to_vec();
        let mut b = buffer[..half].to_vec();
        let mut b_temp: Vec<Vec<u8>> = buffer[half..].chunks(half).map(<[u8]>::to_vec).collect();

        let mut block = vec![0u8; bs];
        for j in 0..v {
            block[..half].copy_from_slice(&b_temp[n - 2]);
            block[half..].copy_from_slice(&b);

            // 解密前先把 LE(V-j) XOR 進 block 後半的前 4 bytes（與 wrap 相反）。
            let ctr = ((v - j) as u32).to_le_bytes();
            for (bn, &c) in ctr.iter().enumerate() {
                block[half + bn] ^= c;
            }

            self.crypt_block(&mut block)?;

            b.copy_from_slice(&block[..half]);
            // 半塊右移一格，開頭放入 block 後半。
            b_temp.rotate_right(1);
            b_temp[0].copy_from_slice(&block[half..]);
        }

        buffer[..half].copy_from_slice(&b);
        for (i, chunk) in b_temp.iter().enumerate() {
            let off = half + i * half;
            buffer[off..off + half].copy_from_slice(chunk);
        }

        // 校驗：最後一個完整塊必須全為零（以 OR 累加，時間不隨內容變化）。
        let mut diff = 0u8;
        for &byte in &buffer[buffer.len() - bs..] {
            diff |= byte;
        }
        if diff != 0 {
            return Err(Dstu7624WrapError::IntegrityCheckFailed);
        }

        buffer.truncate(buffer.len() - bs);
        Ok(buffer)
    }
}
