//! DRBG 實作共用的輔助函式。

use crate::{Drbg, DrbgError};

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

// SP 800-90A 的單次請求上限，同 BC：2^18 bits
pub(crate) const MAX_REQUEST_BYTES: usize = (1_usize << 18) / 8;

// rand_core 介面共用：超過單次上限是呼叫端可事先檢查的前置條件，panic；
// 需要重新植入取決於內部計數，回傳錯誤
pub(crate) fn rng_fill<D: Drbg>(drbg: &mut D, output: &mut [u8]) -> Result<(), DrbgError> {
    assert!(
        output.len() <= MAX_REQUEST_BYTES,
        "a DRBG request is limited to {MAX_REQUEST_BYTES} bytes"
    );
    drbg.generate(output, &[])
}

pub(crate) fn rng_next_u32<D: Drbg>(drbg: &mut D) -> Result<u32, DrbgError> {
    let mut bytes = [0_u8; 4];
    rng_fill(drbg, &mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
}

pub(crate) fn rng_next_u64<D: Drbg>(drbg: &mut D) -> Result<u64, DrbgError> {
    let mut bytes = [0_u8; 8];
    rng_fill(drbg, &mut bytes)?;
    Ok(u64::from_le_bytes(bytes))
}
