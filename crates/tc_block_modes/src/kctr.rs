//! DSTU 7624 (Kalyna) counter mode, ported from Bouncy Castle's
//! `KCtrBlockCipher`.
//!
//! Known as *gamming* mode in the Ukrainian standard, KCTR differs from the
//! usual CTR mode in three ways: the counter starts as the *encrypted* IV rather
//! than the IV itself, it is incremented from its first byte rather than its
//! last, and it advances *before* each keystream block rather than after.
//!
//! Like the other keystream modes the direction is ignored, and the underlying
//! cipher is always keyed for encryption. Because the mode produces keystream a
//! byte at a time it implements both
//! [`StreamCipher`] — its natural interface, and
//! the one bc also exposes — and [`BlockCipher`],
//! which processes exactly one block per call. Import only the trait you need:
//! both declare `algorithm_name` and `init`, so having both in scope makes an
//! unqualified call ambiguous.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use tc_cipher_core::{
    BlockCipher, BlockCipherInit, CipherDirection, StreamCipher, StreamCipherInit,
};

use crate::BlockCipherModeError;

/// Parameters for KCTR: the underlying cipher's key parameters plus an IV.
///
/// The IV is required, as it is in bc, and may be up to one block long; a
/// shorter one is right-aligned and left-padded with zeros.
pub struct KCtrParams<P> {
    /// The underlying block cipher's key parameters.
    key_params: P,
    /// The initialisation vector, which seeds the counter as `E(iv)`.
    iv: Vec<u8>,
}

impl<P> KCtrParams<P> {
    /// Builds parameters from the cipher's key parameters and a copy of the IV.
    pub fn new(key_params: P, iv: &[u8]) -> Self {
        Self {
            key_params,
            iv: iv.to_vec(),
        }
    }
}

/// DSTU 7624 counter (gamming) mode over the block cipher `E`
/// (bc `KCtrBlockCipher`).
pub struct KCtrBlockCipher<E> {
    /// The underlying block cipher, always keyed for encryption.
    cipher: E,
    /// The composed name, built at construction and refreshed on `init`.
    name: String,
    /// The counter's value just after `init`, i.e. `E(iv)`.
    ///
    /// 在 init 時算好，reset 只需複製它 —— 這讓 `StreamCipher::reset` 能維持
    /// 無誤差回傳（bc 的 Reset 會重跑一次 cipher，但金鑰與 IV 不變，結果相同）。
    initial_counter: Vec<u8>,
    /// The current counter block.
    ofb_v: Vec<u8>,
    /// The cipher's output over the counter, i.e. the current keystream block.
    ofb_out_v: Vec<u8>,
    /// How far into the current keystream block the next byte lies.
    byte_count: usize,
    /// `true` once `init` has run.
    initialised: bool,
}

impl<E: BlockCipher> KCtrBlockCipher<E> {
    /// Wraps the given block cipher in KCTR mode.
    pub fn new(cipher: E) -> Self {
        let block_size = cipher.block_size();
        let mut mode = Self {
            cipher,
            name: String::new(),
            initial_counter: vec![0u8; block_size],
            ofb_v: vec![0u8; block_size],
            ofb_out_v: vec![0u8; block_size],
            byte_count: 0,
            initialised: false,
        };
        mode.refresh_name();
        mode
    }

    /// Rebuilds the composed algorithm name.
    ///
    /// 名稱在建構與 init 後各組一次：部分 engine 要等 keying 之後才知道名稱。
    fn refresh_name(&mut self) {
        let base = self.cipher.algorithm_name();
        let mut name = String::with_capacity(base.len() + 5);
        name.push_str(base);
        name.push_str("/KCTR");
        self.name = name;
    }

    /// Advances the counter from its first byte, carrying upwards.
    ///
    /// 與一般 CTR 相反：KCTR 由開頭進位（little-endian）。
    fn increment_counter(&mut self) {
        for byte in self.ofb_v.iter_mut() {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                break;
            }
        }
    }

    /// Produces the next keystream byte and combines it with `b`.
    fn calculate_byte(&mut self, b: u8) -> Result<u8, BlockCipherModeError<E>> {
        if self.byte_count == 0 {
            // 每塊開始前先遞增計數器，再加密取得新的 keystream。
            self.increment_counter();
            self.cipher
                .process_block(&self.ofb_v, &mut self.ofb_out_v)
                .map_err(BlockCipherModeError::BlockCipher)?;
        }
        let out = self.ofb_out_v[self.byte_count] ^ b;
        self.byte_count += 1;
        if self.byte_count == self.ofb_v.len() {
            self.byte_count = 0;
        }
        Ok(out)
    }

    /// Shared by both `init` implementations.
    fn init_internal<'a>(
        &mut self,
        params: &KCtrParams<E::Params<'a>>,
    ) -> Result<(), BlockCipherModeError<E>>
    where
        E: BlockCipherInit,
    {
        let block_size = self.cipher.block_size();
        if params.iv.len() > block_size {
            return Err(BlockCipherModeError::InvalidIvLength {
                actual: params.iv.len(),
                block_size,
            });
        }

        // IV 靠右對齊、前面補零（照 bc）。
        let mut iv = vec![0u8; block_size];
        let offset = block_size - params.iv.len();
        iv[offset..].copy_from_slice(&params.iv);

        self.cipher
            .init(CipherDirection::Encrypt, &params.key_params)
            .map_err(BlockCipherModeError::BlockCipher)?;

        // 計數器的初值是 IV 的密文，而非 IV 本身。
        self.cipher
            .process_block(&iv, &mut self.initial_counter)
            .map_err(BlockCipherModeError::BlockCipher)?;
        self.ofb_v.copy_from_slice(&self.initial_counter);
        self.byte_count = 0;
        self.initialised = true;
        self.refresh_name();
        Ok(())
    }

    /// Restores the state left by the last `init`.
    fn reset_internal(&mut self) {
        if self.initialised {
            self.ofb_v.copy_from_slice(&self.initial_counter);
        }
        self.byte_count = 0;
    }
}

impl<E: BlockCipher> StreamCipher for KCtrBlockCipher<E> {
    type Error = BlockCipherModeError<E>;

    fn algorithm_name(&self) -> &str {
        &self.name
    }

    fn return_byte(&mut self, input: u8) -> Result<u8, Self::Error> {
        if !self.initialised {
            return Err(BlockCipherModeError::NotInitialised);
        }
        self.calculate_byte(input)
    }

    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialised {
            return Err(BlockCipherModeError::NotInitialised);
        }
        if output.len() < input.len() {
            return Err(BlockCipherModeError::BufferTooShort);
        }
        for (i, &byte) in input.iter().enumerate() {
            output[i] = self.calculate_byte(byte)?;
        }
        Ok(input.len())
    }

    fn reset(&mut self) {
        self.reset_internal();
    }
}

impl<E: BlockCipherInit> StreamCipherInit for KCtrBlockCipher<E> {
    type Params<'a> = KCtrParams<E::Params<'a>>;

    fn init(&mut self, params: &Self::Params<'_>) -> Result<(), Self::Error> {
        self.init_internal(params)
    }
}

impl<E: BlockCipher> BlockCipher for KCtrBlockCipher<E> {
    type Error = BlockCipherModeError<E>;

    fn algorithm_name(&self) -> &str {
        &self.name
    }

    fn block_size(&self) -> usize {
        self.ofb_v.len()
    }

    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialised {
            return Err(BlockCipherModeError::NotInitialised);
        }
        let block_size = self.ofb_v.len();
        if input.len() < block_size || output.len() < block_size {
            return Err(BlockCipherModeError::BufferTooShort);
        }
        for i in 0..block_size {
            output[i] = self.calculate_byte(input[i])?;
        }
        Ok(block_size)
    }
}

impl<E: BlockCipherInit> BlockCipherInit for KCtrBlockCipher<E> {
    type Params<'a> = KCtrParams<E::Params<'a>>;

    fn init(
        &mut self,
        _direction: CipherDirection,
        params: &Self::Params<'_>,
    ) -> Result<(), Self::Error> {
        // KCTR 是 keystream 模式，加解密同一操作，故忽略方向。
        self.init_internal(params)
    }
}
