//! Cipher Feedback (CFB) mode, ported from Bouncy Castle's `CfbBlockCipher`.
//!
//! CFB turns a block cipher into a self-synchronising stream cipher: the cipher
//! is applied to a feedback register to produce keystream, which is XORed with
//! the data, and the resulting *ciphertext* is shifted back into the register.
//!
//! The mode works on segments of `feedback_bits / 8` bytes, which may be smaller
//! than the cipher's block — CFB8 processes one byte at a time — so
//! [`block_size`](tc_cipher_core::BlockCipher::block_size) reports the segment
//! size, not the cipher's. Because only the forward direction of the cipher is
//! ever used, the underlying cipher is always keyed for encryption.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use tc_cipher_core::{BlockCipher, BlockCipherInit, CipherDirection};

use crate::BlockCipherModeError;

/// Parameters for CFB: the underlying cipher's key parameters plus an IV.
///
/// The IV may be shorter than one block, in which case it is left-padded with
/// zeros (bc's behaviour); `None` means an all-zero IV.
pub struct CfbParams<P> {
    /// The underlying block cipher's key parameters.
    key_params: P,
    /// The initialisation vector; `None` means all zeros.
    iv: Option<Vec<u8>>,
}

impl<P> CfbParams<P> {
    /// Builds parameters with an all-zero IV.
    pub fn new(key_params: P) -> Self {
        Self {
            key_params,
            iv: None,
        }
    }

    /// Copies the given IV, which may be up to one block long, into the parameters.
    pub fn with_iv(key_params: P, iv: &[u8]) -> Self {
        Self {
            key_params,
            iv: Some(iv.to_vec()),
        }
    }
}

/// CFB mode over the block cipher `E` (bc `CfbBlockCipher`).
pub struct CfbBlockCipher<E> {
    /// The underlying block cipher, always keyed for encryption.
    cipher: E,
    /// The composed name, built at construction and refreshed on `init`.
    name: String,
    /// The segment size in bytes (`feedback_bits / 8`).
    segment_size: usize,
    /// The IV chosen at `init`, kept so the register can be restarted.
    iv: Vec<u8>,
    /// The feedback register, one cipher block long.
    cfb_v: Vec<u8>,
    /// The cipher's output over the register, i.e. the keystream.
    cfb_out_v: Vec<u8>,
    /// `None` until `init`; then the direction data is transformed in.
    direction: Option<CipherDirection>,
}

impl<E: BlockCipher> CfbBlockCipher<E> {
    /// Wraps the given cipher in CFB mode with the given feedback size in bits,
    /// which must be a positive multiple of eight, up to the cipher's block size
    /// (e.g. 8 for CFB8, 128 for CFB128 over AES).
    pub fn new(cipher: E, feedback_bits: usize) -> Result<Self, BlockCipherModeError<E>> {
        let block_size = cipher.block_size();
        if feedback_bits == 0 || !feedback_bits.is_multiple_of(8) || feedback_bits / 8 > block_size
        {
            return Err(BlockCipherModeError::InvalidFeedbackSize(feedback_bits));
        }
        let mut mode = Self {
            cipher,
            name: String::new(),
            segment_size: feedback_bits / 8,
            iv: vec![0u8; block_size],
            cfb_v: vec![0u8; block_size],
            cfb_out_v: vec![0u8; block_size],
            direction: None,
        };
        mode.refresh_name();
        Ok(mode)
    }

    /// Rebuilds the composed algorithm name, e.g. `"AES/CFB128"`.
    ///
    /// 名稱在建構與 init 後各組一次：部分 engine（如 Threefish）要等 keying
    /// 之後才知道自己的名稱。
    fn refresh_name(&mut self) {
        let base = self.cipher.algorithm_name();
        let mut name = String::with_capacity(base.len() + 8);
        name.push_str(base);
        name.push_str("/CFB");
        push_usize(&mut name, self.segment_size * 8);
        self.name = name;
    }
}

/// Appends a decimal integer without pulling in `format!`.
pub(crate) fn push_usize(out: &mut String, mut value: usize) {
    if value == 0 {
        out.push('0');
        return;
    }
    let mut digits = [0u8; 20];
    let mut len = 0;
    while value > 0 {
        digits[len] = b'0' + (value % 10) as u8;
        value /= 10;
        len += 1;
    }
    for &d in digits[..len].iter().rev() {
        out.push(d as char);
    }
}

impl<E: BlockCipher> BlockCipher for CfbBlockCipher<E> {
    type Error = BlockCipherModeError<E>;

    fn algorithm_name(&self) -> &str {
        &self.name
    }

    /// The segment size, which is what one call to `process_block` consumes.
    fn block_size(&self) -> usize {
        self.segment_size
    }

    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        let direction = self.direction.ok_or(BlockCipherModeError::NotInitialised)?;
        let seg = self.segment_size;
        if input.len() < seg || output.len() < seg {
            return Err(BlockCipherModeError::BufferTooShort);
        }

        // 以回饋暫存器產生 keystream。
        self.cipher
            .process_block(&self.cfb_v, &mut self.cfb_out_v)
            .map_err(BlockCipherModeError::BlockCipher)?;

        let tail = self.cfb_v.len() - seg;
        match direction {
            CipherDirection::Encrypt => {
                for i in 0..seg {
                    output[i] = self.cfb_out_v[i] ^ input[i];
                }
                // 回饋的是密文（本次的輸出）。
                self.cfb_v.copy_within(seg.., 0);
                self.cfb_v[tail..].copy_from_slice(&output[..seg]);
            }
            CipherDirection::Decrypt => {
                // 解密時密文是輸入，故先回饋再算輸出。
                self.cfb_v.copy_within(seg.., 0);
                self.cfb_v[tail..].copy_from_slice(&input[..seg]);
                for i in 0..seg {
                    output[i] = self.cfb_out_v[i] ^ input[i];
                }
            }
        }
        Ok(seg)
    }
}

impl<E: BlockCipherInit> BlockCipherInit for CfbBlockCipher<E> {
    type Params<'a> = CfbParams<E::Params<'a>>;

    fn init(
        &mut self,
        direction: CipherDirection,
        params: &Self::Params<'_>,
    ) -> Result<(), Self::Error> {
        let block_size = self.cipher.block_size();
        if let Some(iv) = params.iv.as_deref() {
            if iv.len() > block_size {
                return Err(BlockCipherModeError::InvalidIvLength {
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
        self.cfb_v.copy_from_slice(&self.iv);

        // CFB 只用到 cipher 的正向，故底層一律以加密方向 keying。
        self.cipher
            .init(CipherDirection::Encrypt, &params.key_params)
            .map_err(BlockCipherModeError::BlockCipher)?;
        self.direction = Some(direction);
        self.refresh_name();
        Ok(())
    }
}
