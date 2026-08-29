//! Output Feedback (OFB) mode, ported from Bouncy Castle's `OfbBlockCipher`.
//!
//! OFB is CFB's sibling: the cipher is applied to a feedback register to produce
//! keystream, but it is the *cipher's own output* — not the ciphertext — that is
//! shifted back in. The keystream therefore depends only on the key and IV, so
//! encryption and decryption are the same operation and the direction passed to
//! `init` is ignored.
//!
//! Like CFB it works on segments of `feedback_bits / 8` bytes, so
//! [`block_size`](tc_cipher_core::BlockCipher::block_size) reports the segment
//! size, and the underlying cipher is always keyed for encryption.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use tc_cipher_core::{BlockCipher, BlockCipherInit, CipherDirection};

use crate::CipherModeError;
use crate::cfb::push_usize;

/// Parameters for OFB: the underlying cipher's key parameters plus an IV.
///
/// The IV may be shorter than one block, in which case it is left-padded with
/// zeros (bc's behaviour); `None` means an all-zero IV.
pub struct OfbParams<'a, E: BlockCipherInit> {
    /// The underlying block cipher's key parameters.
    key_params: E::Params<'a>,
    /// The initialisation vector; `None` means all zeros.
    iv: Option<&'a [u8]>,
}

impl<'a, E: BlockCipherInit> OfbParams<'a, E> {
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

/// OFB mode over the block cipher `E` (bc `OfbBlockCipher`).
pub struct OfbBlockCipher<E> {
    /// The underlying block cipher, always keyed for encryption.
    cipher: E,
    /// The composed name, built at construction and refreshed on `init`.
    name: String,
    /// The segment size in bytes (`feedback_bits / 8`).
    segment_size: usize,
    /// The IV chosen at `init`, kept so the register can be restarted.
    iv: Vec<u8>,
    /// The feedback register, one cipher block long.
    ofb_v: Vec<u8>,
    /// The cipher's output over the register, i.e. the keystream.
    ofb_out_v: Vec<u8>,
    /// `true` once `init` has run.
    initialised: bool,
}

impl<E: BlockCipher> OfbBlockCipher<E> {
    /// Wraps the given cipher in OFB mode with the given feedback size in bits,
    /// which must be a positive multiple of eight, up to the cipher's block size.
    pub fn new(cipher: E, feedback_bits: usize) -> Result<Self, CipherModeError<E>> {
        let block_size = cipher.block_size();
        if feedback_bits == 0 || !feedback_bits.is_multiple_of(8) || feedback_bits / 8 > block_size {
            return Err(CipherModeError::InvalidFeedbackSize(feedback_bits));
        }
        let mut mode = Self {
            cipher,
            name: String::new(),
            segment_size: feedback_bits / 8,
            iv: vec![0u8; block_size],
            ofb_v: vec![0u8; block_size],
            ofb_out_v: vec![0u8; block_size],
            initialised: false,
        };
        mode.refresh_name();
        Ok(mode)
    }

    /// Rebuilds the composed algorithm name, e.g. `"AES/OFB128"`.
    ///
    /// 名稱在建構與 init 後各組一次：部分 engine（如 Threefish）要等 keying
    /// 之後才知道自己的名稱。
    fn refresh_name(&mut self) {
        let base = self.cipher.algorithm_name();
        let mut name = String::with_capacity(base.len() + 8);
        name.push_str(base);
        name.push_str("/OFB");
        push_usize(&mut name, self.segment_size * 8);
        self.name = name;
    }
}

impl<E: BlockCipher> BlockCipher for OfbBlockCipher<E> {
    type Error = CipherModeError<E>;

    fn algorithm_name(&self) -> &str {
        &self.name
    }

    /// The segment size, which is what one call to `process_block` consumes.
    fn block_size(&self) -> usize {
        self.segment_size
    }

    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialised {
            return Err(CipherModeError::NotInitialised);
        }
        let seg = self.segment_size;
        if input.len() < seg || output.len() < seg {
            return Err(CipherModeError::BufferTooShort);
        }

        // 以回饋暫存器產生 keystream。
        self.cipher
            .process_block(&self.ofb_v, &mut self.ofb_out_v)
            .map_err(CipherModeError::BlockCipher)?;

        for i in 0..seg {
            output[i] = self.ofb_out_v[i] ^ input[i];
        }

        // 回饋的是 cipher 自己的輸出，與資料無關。
        let tail = self.ofb_v.len() - seg;
        self.ofb_v.copy_within(seg.., 0);
        self.ofb_v[tail..].copy_from_slice(&self.ofb_out_v[..seg]);
        Ok(seg)
    }
}

impl<E: BlockCipherInit> BlockCipherInit for OfbBlockCipher<E> {
    type Params<'a> = OfbParams<'a, E>;

    fn init(
        &mut self,
        _direction: CipherDirection,
        params: &Self::Params<'_>,
    ) -> Result<(), Self::Error> {
        // OFB 的 keystream 只由 key 與 IV 決定，加解密是同一操作，故忽略方向。
        let block_size = self.cipher.block_size();
        if let Some(iv) = params.iv {
            if iv.len() > block_size {
                return Err(CipherModeError::InvalidIvLength {
                    actual: iv.len(),
                    block_size,
                });
            }
            // 較短的 IV 靠左補零（照 bc）。
            let offset = block_size - iv.len();
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
