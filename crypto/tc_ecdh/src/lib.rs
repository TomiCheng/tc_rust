#![no_std]

//! 固定寬度短 Weierstrass 曲線的 ECDH agreement。
//!
//! 私密純量一律使用 [`tc_ec_core::multiply_secret`]；對方公鑰的
//! 匯入、驗證與 cofactor 倍點則是公開資料，可使用變動時間運算。

extern crate alloc;

mod basic;
mod cofactor;
mod raw;

pub use basic::EcdhBasicAgreement;
pub use cofactor::EcdhcBasicAgreement;
pub use raw::{EcdhRawAgreement, EcdhcRawAgreement};

use alloc::vec::Vec;
use core::fmt;

use tc_bigint::modular::{FixedMontyForm, FixedMontyParams};
use tc_bigint::{ArrayEncoding, FixedBigUint, Odd};

/// ECDH 對固定寬度曲線純量需要的最小運算集合。
///
/// 秘密值只會透過 [`EcdhScalar::mul_mod_ct`] 做固定排程模乘；
/// 變動時間反元素只處理公開 cofactor。
pub trait EcdhScalar: Copy + Eq + Ord {
    /// 一。
    fn one() -> Self;
    /// 完整儲存寬度的 little-endian 編碼。
    fn to_le_bytes_fixed(&self) -> Vec<u8>;
    /// 指定長度的 big-endian 編碼。
    fn to_be_bytes_padded(&self, length: usize) -> Vec<u8>;
    /// 計算秘密 `self * public mod modulus`。
    fn mul_mod_ct(&self, public: &Self, modulus: &Self) -> Option<Self>;
    /// 計算公開值的變動時間模反元素。
    fn inverse_vartime(&self, modulus: &Self) -> Option<Self>;
}

impl<const N: usize> EcdhScalar for FixedBigUint<N> {
    fn one() -> Self {
        Self::from(1_u8)
    }

    fn to_le_bytes_fixed(&self) -> Vec<u8> {
        ArrayEncoding::to_le_bytes(self)
    }

    fn to_be_bytes_padded(&self, length: usize) -> Vec<u8> {
        let full = ArrayEncoding::to_be_bytes(self);
        assert!(length <= full.len(), "要求的 ECDH 編碼長度超過固定寬度");
        full[full.len() - length..].to_vec()
    }

    fn mul_mod_ct(&self, public: &Self, modulus: &Self) -> Option<Self> {
        let params = FixedMontyParams::new(Odd::new(*modulus)?);
        Some(
            (FixedMontyForm::new_ct(self, params) * FixedMontyForm::new(public, params)).retrieve(),
        )
    }

    fn inverse_vartime(&self, modulus: &Self) -> Option<Self> {
        self.mod_odd_inverse_vartime(&Odd::new(*modulus)?)
    }
}

/// ECDH agreement 錯誤。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EcdhError {
    /// 曲線沒有子群階。
    MissingCurveOrder,
    /// 曲線沒有 cofactor。
    MissingCofactor,
    /// 曲線階不能供所需的模運算使用。
    InvalidCurveOrder,
    /// Cofactor 為零或在模曲線階下不可逆。
    InvalidCofactor,
    /// 私鑰不在 `[1, n - 1]`。
    InvalidPrivateKey,
    /// 對方公鑰不屬於目標曲線或是無窮遠點。
    InvalidPublicKey,
    /// 私密純量乘法失敗。
    CurveOperation,
    /// Agreement 結果是無窮遠點或無法轉成純量整數。
    InvalidAgreement,
}

impl fmt::Display for EcdhError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::MissingCurveOrder => "ECDH curve order is missing",
            Self::MissingCofactor => "ECDH curve cofactor is missing",
            Self::InvalidCurveOrder => "ECDH curve order is invalid",
            Self::InvalidCofactor => "ECDH curve cofactor is invalid",
            Self::InvalidPrivateKey => "ECDH private key is invalid",
            Self::InvalidPublicKey => "ECDH peer public key is invalid",
            Self::CurveOperation => "ECDH curve operation failed",
            Self::InvalidAgreement => "ECDH agreement value is invalid",
        })
    }
}

impl core::error::Error for EcdhError {}
