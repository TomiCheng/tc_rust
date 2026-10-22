// 舊 tc_bigint 測試 API 到 crates.io tc_bigint、tc_modular 的轉接，模數直接給 BigUint。

use alloc::vec::Vec;
use tc_bigint::ArrayEncoding;
pub(crate) use tc_bigint::BigUint;
use tc_modular::{ModInverse, ModPow, ModSub, NonZero};

pub(crate) trait Oracle: Sized {
    fn from_le_bytes(bytes: &[u8]) -> Self;
    fn to_le_bytes(&self) -> Vec<u8>;
    fn rem_euclid(&self, modulus: &Self) -> Self;
    fn mod_sub(&self, rhs: &Self, modulus: &Self) -> Self;
    fn mod_pow(&self, exponent: &Self, modulus: &Self) -> Self;
    fn mod_inverse(&self, modulus: &Self) -> Option<Self>;
    fn is_zero(&self) -> bool;
}

impl Oracle for BigUint {
    fn from_le_bytes(bytes: &[u8]) -> Self {
        let Ok(value) = <BigUint as ArrayEncoding<u8>>::from_le(bytes);
        value
    }

    fn to_le_bytes(&self) -> Vec<u8> {
        ArrayEncoding::<u8>::to_le(self)
    }

    fn rem_euclid(&self, modulus: &Self) -> Self {
        self % modulus
    }

    fn mod_sub(&self, rhs: &Self, modulus: &Self) -> Self {
        ModSub::mod_sub(self, rhs, &NonZero::new(modulus.clone()).unwrap())
    }

    fn mod_pow(&self, exponent: &Self, modulus: &Self) -> Self {
        ModPow::mod_pow(self, exponent, &NonZero::new(modulus.clone()).unwrap())
    }

    fn mod_inverse(&self, modulus: &Self) -> Option<Self> {
        ModInverse::mod_inverse(self, &NonZero::new(modulus.clone()).unwrap())
    }

    fn is_zero(&self) -> bool {
        self.bits() == 0
    }
}
