//! CRT 私鑰運算的後端實作。

use crate::rsa_core::{bit_length, is_odd, is_zero, limbs_for_bits};
use crate::{RsaError, RsaPrivateCrtKeyParams};

mod fixed;
mod heap;

pub use fixed::FixedRsaCrtCoreEngine;
pub use heap::HeapRsaCrtCoreEngine;

/// 模數上限 1024 位元的 CRT 核心。
pub type Rsa1024CrtCore = FixedRsaCrtCoreEngine<{ limbs_for_bits(1024) }, { limbs_for_bits(512) }>;

/// 模數上限 2048 位元的 CRT 核心。
pub type Rsa2048CrtCore = FixedRsaCrtCoreEngine<{ limbs_for_bits(2048) }, { limbs_for_bits(1024) }>;

/// 模數上限 3072 位元的 CRT 核心。
pub type Rsa3072CrtCore = FixedRsaCrtCoreEngine<{ limbs_for_bits(3072) }, { limbs_for_bits(1536) }>;

/// 模數上限 4096 位元的 CRT 核心。
pub type Rsa4096CrtCore = FixedRsaCrtCoreEngine<{ limbs_for_bits(4096) }, { limbs_for_bits(2048) }>;

/// 檢查 CRT 私鑰參數，通過則回傳模數的位元長度。
///
/// 順序與非 CRT 版一致：模數、公開指數、私密指數，再到五個 CRT 欄位。
pub(crate) fn validate<K: RsaPrivateCrtKeyParams + ?Sized>(key: &K) -> Result<usize, RsaError> {
    let modulus = key.modulus();
    if is_zero(modulus) {
        return Err(RsaError::InvalidModulus);
    }
    if !is_odd(modulus) {
        return Err(RsaError::EvenModulus);
    }

    let public_exponent = key.public_exponent();
    if is_zero(public_exponent) {
        return Err(RsaError::InvalidExponent);
    }
    if !is_odd(public_exponent) {
        return Err(RsaError::EvenPublicExponent);
    }

    let private_exponent = key.exponent();
    if is_zero(private_exponent) || !is_odd(private_exponent) {
        return Err(RsaError::InvalidPrivateExponent);
    }

    // p 與 q 是奇質數；dp、dq、qInv 只要求非零，其正確性由 Lenstra 檢查兜底。
    if is_zero(key.p()) || !is_odd(key.p()) {
        return Err(RsaError::InvalidP);
    }
    if is_zero(key.q()) || !is_odd(key.q()) {
        return Err(RsaError::InvalidQ);
    }
    if is_zero(key.dp()) {
        return Err(RsaError::InvalidDp);
    }
    if is_zero(key.dq()) {
        return Err(RsaError::InvalidDq);
    }
    if is_zero(key.q_inv()) {
        return Err(RsaError::InvalidQInv);
    }

    Ok(bit_length(modulus))
}
