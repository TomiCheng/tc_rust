//! GOST 28147 OFB counter mode (GCTR), ported from Bouncy Castle's
//! `GOfbBlockCipher`.
//!
//! GCTR is the counter mode defined for GOST 28147-89. It seeds two 32-bit
//! counters from the encrypted IV, then advances them by fixed constants for
//! each block and encrypts the pair to produce keystream. As a keystream mode,
//! encryption and decryption are the same operation, so the direction passed to
//! `init` is ignored and the underlying cipher is always keyed for encryption.
//!
//! The mode is defined only for 64-bit block ciphers.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use tc_cipher_core::{BlockCipher, BlockCipherInit, CipherDirection};

use crate::CipherModeError;

/// The block size GCTR is defined for, in bytes.
const GCTR_BLOCK_BYTES: usize = 8;

/// The constant added to the high counter each block (`0x01010104`).
const C1: i32 = 16843012;
/// The constant added to the low counter each block (`0x01010101`).
const C2: i32 = 16843009;

/// Parameters for GCTR: the underlying cipher's key parameters plus an IV.
///
/// The IV may be shorter than one block, in which case it is left-padded with
/// zeros (per FIPS PUB 81, as bc does); `None` means an all-zero IV.
pub struct GofbParams<'a, E: BlockCipherInit> {
    /// The underlying block cipher's key parameters.
    key_params: E::Params<'a>,
    /// The initialisation vector; `None` means all zeros.
    iv: Option<&'a [u8]>,
}

impl<'a, E: BlockCipherInit> GofbParams<'a, E> {
    /// Builds parameters with an all-zero IV.
    pub fn new(key_params: E::Params<'a>) -> Self {
        Self {
            key_params,
            iv: None,
        }
    }

    /// Builds parameters with the given IV, which may be up to one block long.
    pub fn with_iv(key_params: E::Params<'a>, iv: &'a [u8]) -> Self {
        Self {
            key_params,
            iv: Some(iv),
        }
    }
}

/// GOST 28147 counter mode over the block cipher `E` (bc `GOfbBlockCipher`).
pub struct GofbBlockCipher<E> {
    /// The underlying block cipher, always keyed for encryption.
    cipher: E,
    /// The composed name, built at construction and refreshed on `init`.
    name: String,
    /// The IV chosen at `init`, kept so the counters can be reseeded.
    iv: Vec<u8>,
    /// The counter block fed to the cipher.
    ofb_v: Vec<u8>,
    /// The cipher's output over the counter, i.e. the keystream.
    ofb_out_v: Vec<u8>,
    /// The two 32-bit counters, held as `i32` to match bc's signed arithmetic.
    n3: i32,
    n4: i32,
    /// `true` until the first block seeds the counters from the encrypted IV.
    first_step: bool,
    /// `true` once `init` has run.
    initialised: bool,
}

impl<E: BlockCipher> GofbBlockCipher<E> {
    /// Wraps the given cipher in GCTR mode. The cipher must have a 64-bit block.
    pub fn new(cipher: E) -> Result<Self, CipherModeError<E>> {
        let block_size = cipher.block_size();
        if block_size != GCTR_BLOCK_BYTES {
            return Err(CipherModeError::UnsupportedBlockSize {
                actual: block_size,
                required: GCTR_BLOCK_BYTES,
            });
        }
        let mut mode = Self {
            cipher,
            name: String::new(),
            iv: vec![0u8; GCTR_BLOCK_BYTES],
            ofb_v: vec![0u8; GCTR_BLOCK_BYTES],
            ofb_out_v: vec![0u8; GCTR_BLOCK_BYTES],
            n3: 0,
            n4: 0,
            first_step: true,
            initialised: false,
        };
        mode.refresh_name();
        Ok(mode)
    }

    /// Rebuilds the composed algorithm name.
    ///
    /// 名稱在建構與 init 後各組一次：部分 engine 要等 keying 之後才知道名稱。
    fn refresh_name(&mut self) {
        let base = self.cipher.algorithm_name();
        let mut name = String::with_capacity(base.len() + 5);
        name.push_str(base);
        name.push_str("/GCTR");
        self.name = name;
    }
}

impl<E: BlockCipher> BlockCipher for GofbBlockCipher<E> {
    type Error = CipherModeError<E>;

    fn algorithm_name(&self) -> &str {
        &self.name
    }

    fn block_size(&self) -> usize {
        GCTR_BLOCK_BYTES
    }

    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialised {
            return Err(CipherModeError::NotInitialised);
        }
        if input.len() < GCTR_BLOCK_BYTES || output.len() < GCTR_BLOCK_BYTES {
            return Err(CipherModeError::BufferTooShort);
        }

        if self.first_step {
            // 第一塊：加密 IV，取其兩半當作計數器的初值。
            self.first_step = false;
            self.cipher
                .process_block(&self.ofb_v, &mut self.ofb_out_v)
                .map_err(CipherModeError::BlockCipher)?;
            self.n3 = u32::from_le_bytes(self.ofb_out_v[..4].try_into().unwrap()) as i32;
            self.n4 = u32::from_le_bytes(self.ofb_out_v[4..].try_into().unwrap()) as i32;
        }

        // 計數器遞增。以 i32 環繞運算忠實對應 bc 的 C# int；N4 的進位修正讓
        // 加法在模 (2**32 - 1) 下進行。
        self.n3 = self.n3.wrapping_add(C2);
        self.n4 = self.n4.wrapping_add(C1);
        if self.n4 < C1 && self.n4 > 0 {
            self.n4 = self.n4.wrapping_add(1);
        }

        self.ofb_v[..4].copy_from_slice(&(self.n3 as u32).to_le_bytes());
        self.ofb_v[4..].copy_from_slice(&(self.n4 as u32).to_le_bytes());

        self.cipher
            .process_block(&self.ofb_v, &mut self.ofb_out_v)
            .map_err(CipherModeError::BlockCipher)?;
        for i in 0..GCTR_BLOCK_BYTES {
            output[i] = self.ofb_out_v[i] ^ input[i];
        }

        // bc 此處還把 ofbOutV 複製回 ofbV，但下一次呼叫會立刻用 N3/N4 覆寫
        // 整個 ofbV，故該步驟無作用，這裡省略。
        Ok(GCTR_BLOCK_BYTES)
    }
}

impl<E: BlockCipherInit> BlockCipherInit for GofbBlockCipher<E> {
    type Params<'a> = GofbParams<'a, E>;

    fn init(
        &mut self,
        _direction: CipherDirection,
        params: &Self::Params<'_>,
    ) -> Result<(), Self::Error> {
        // GCTR 是 keystream 模式，加解密同一操作，故忽略方向。
        self.first_step = true;
        self.n3 = 0;
        self.n4 = 0;

        if let Some(iv) = params.iv {
            if iv.len() > GCTR_BLOCK_BYTES {
                return Err(CipherModeError::InvalidIvLength {
                    actual: iv.len(),
                    block_size: GCTR_BLOCK_BYTES,
                });
            }
            // 較短的 IV 靠左補零（照 bc，依 FIPS PUB 81）。
            let offset = GCTR_BLOCK_BYTES - iv.len();
            self.iv[..offset].fill(0);
            self.iv[offset..].copy_from_slice(iv);
        } else {
            self.iv.fill(0);
        }
        self.ofb_v.copy_from_slice(&self.iv);

        self.cipher
            .init(CipherDirection::Encrypt, &params.key_params)
            .map_err(CipherModeError::BlockCipher)?;
        self.initialised = true;
        self.refresh_name();
        Ok(())
    }
}
