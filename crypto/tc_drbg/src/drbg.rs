//! DRBG 的共用介面與錯誤。

use core::{convert::Infallible, fmt};

use rand_core::CryptoRng;

/// NIST SP 800-90A DRBG 的共用操作。
pub trait Drbg {
    /// 產生隨機位元組，並可混入額外輸入。
    ///
    /// 超過重新植入上限時回傳 [`DrbgError::ReseedRequired`]。
    fn generate(&mut self, output: &mut [u8], additional_input: &[u8]) -> Result<(), DrbgError>;

    /// 從呼叫端提供的密碼學安全亂數來源重新植入狀態。
    ///
    /// # Panics
    ///
    /// 若底層密碼原語失敗，或無 derivation function 的 CTR_DRBG 收到長度不符的
    /// 種子材料，則會 panic。
    fn reseed<R: CryptoRng + ?Sized>(&mut self, rng: &mut R, additional_input: &[u8]);
}

/// DRBG 建立或產生輸出時的錯誤。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DrbgError {
    /// 摘要或 MAC 的輸出長度不屬於 SP 800-90A 支援的 SHA 家族。
    UnsupportedOutputSize(usize),
    /// 要求的安全強度超過底層原語可提供的強度。
    UnsupportedSecurityStrength { requested: usize, maximum: usize },
    /// 熵來源每次提供的位元組數不足。
    InsufficientEntropy { required: usize, provided: usize },
    /// CTR_DRBG 只接受 AES-128、AES-192 或 AES-256 的金鑰長度。
    InvalidKeySize(usize),
    /// CTR_DRBG 只接受 AES 的 16-byte block。
    InvalidBlockSize(usize),
    /// 無 derivation function 模式的種子材料長度不等於 seedlen。
    InvalidSeedLength { expected: usize, actual: usize },
    /// 單次輸出要求超過 SP 800-90A 上限。
    RequestTooLarge { requested: usize, maximum: usize },
    /// 重新植入計數已超過允許上限。
    ReseedRequired,
    /// 底層 MAC 初始化或運算失敗。
    MacFailure,
    /// 底層區塊密碼初始化或運算失敗。
    CipherFailure,
    /// 輸入長度無法用 SP 800-90A 指定的 32-bit 欄位表示。
    InputTooLong,
}

impl fmt::Display for DrbgError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedOutputSize(size) => {
                write!(formatter, "unsupported DRBG output size: {size} bytes")
            }
            Self::UnsupportedSecurityStrength { requested, maximum } => write!(
                formatter,
                "requested DRBG security strength {requested} exceeds maximum {maximum}"
            ),
            Self::InsufficientEntropy { required, provided } => write!(
                formatter,
                "DRBG entropy is too short: required {required} bytes, provided {provided}"
            ),
            Self::InvalidKeySize(size) => {
                write!(formatter, "invalid CTR_DRBG AES key size: {size} bits")
            }
            Self::InvalidBlockSize(size) => {
                write!(formatter, "invalid CTR_DRBG block size: {size} bytes")
            }
            Self::InvalidSeedLength { expected, actual } => write!(
                formatter,
                "invalid CTR_DRBG seed length: expected {expected} bytes, got {actual}"
            ),
            Self::RequestTooLarge { requested, maximum } => write!(
                formatter,
                "DRBG request is too large: requested {requested} bytes, maximum {maximum}"
            ),
            Self::ReseedRequired => formatter.write_str("DRBG reseed is required"),
            Self::MacFailure => formatter.write_str("DRBG MAC operation failed"),
            Self::CipherFailure => formatter.write_str("DRBG block-cipher operation failed"),
            Self::InputTooLong => formatter.write_str("DRBG input is too long"),
        }
    }
}

impl core::error::Error for DrbgError {}

pub(crate) fn validate_security_strength(
    requested: usize,
    maximum: usize,
    entropy_size: usize,
) -> Result<(), DrbgError> {
    if requested > maximum {
        return Err(DrbgError::UnsupportedSecurityStrength { requested, maximum });
    }

    let required = requested.div_ceil(8);
    if entropy_size < required {
        return Err(DrbgError::InsufficientEntropy {
            required,
            provided: entropy_size,
        });
    }
    Ok(())
}

pub(crate) fn rng_fill<D: Drbg>(drbg: &mut D, output: &mut [u8]) {
    if let Err(error) = drbg.generate(output, &[]) {
        panic!("Rng::fill_bytes requires a usable DRBG: {error}");
    }
}

pub(crate) fn rng_next_u32<D: Drbg>(drbg: &mut D) -> u32 {
    let mut bytes = [0_u8; 4];
    rng_fill(drbg, &mut bytes);
    u32::from_le_bytes(bytes)
}

pub(crate) fn rng_next_u64<D: Drbg>(drbg: &mut D) -> u64 {
    let mut bytes = [0_u8; 8];
    rng_fill(drbg, &mut bytes);
    u64::from_le_bytes(bytes)
}

pub(crate) type RngResult<T> = Result<T, Infallible>;
