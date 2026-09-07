use alloc::vec::Vec;

use rand_core::CryptoRng;
use tc_bigint::modular::{FixedMontyForm, FixedMontyParams};
use tc_bigint::{ArrayEncoding, BitOps, FixedBigUint, NonZero, Odd, RandomMod};

/// ECDSA 對固定寬度曲線純量需要的運算。
///
/// 工作區的可變長度 `BigUint` 不實作此 trait，避免秘密純量走入值相依的配置與
/// 迴圈。一般使用者不需要直接呼叫這些方法。
pub trait EcdsaScalar: BitOps<Output = Self> + Copy + Eq + Ord {
    /// 零。
    fn zero() -> Self;
    /// 一。
    fn one() -> Self;
    /// 是否為零。
    fn is_zero(&self) -> bool;
    /// 是否為奇數。
    fn is_odd(&self) -> bool;
    /// 解碼無號 big-endian 整數。
    fn from_be_bytes(input: &[u8]) -> Option<Self>;
    /// 固定長度 big-endian 編碼。
    fn to_be_bytes_padded(&self, length: usize) -> Vec<u8>;
    /// 完整儲存寬度的 little-endian 編碼。
    fn to_le_bytes_fixed(&self) -> Vec<u8>;
    /// 公開值右移。
    fn shr_public(&self, count: usize) -> Self;
    /// 公開值減法；呼叫端保證不會 underflow。
    fn sub_public(&self, rhs: &Self) -> Self;
    /// 公開值取餘數。
    fn rem_public(&self, modulus: &Self) -> Self;
    /// 公開值的變動時間模乘。
    fn mul_mod_public(&self, rhs: &Self, modulus: &Self) -> Self;
    /// 秘密值的固定排程奇數模反元素。
    fn inverse_ct(&self, modulus: &Odd<Self>) -> Option<Self>;
    /// 公開值的變動時間模反元素。
    fn inverse_vartime(&self, modulus: &Self) -> Option<Self>;
    /// 計算 `inverse * (e + d * r) mod n`，其中 `inverse` 與 `d` 是秘密。
    fn mul_add_ct(&self, e: &Self, d: &Self, r: &Self, modulus: &Odd<Self>) -> Self;
    /// 從 `[1, n - 1]` 均勻取樣。
    fn random_nonzero_below<R: CryptoRng + ?Sized>(rng: &mut R, modulus: &Self) -> Self;
}

impl<const N: usize> EcdsaScalar for FixedBigUint<N> {
    fn zero() -> Self {
        Self::zero()
    }

    fn one() -> Self {
        Self::from(1_u8)
    }

    fn is_zero(&self) -> bool {
        self.is_zero()
    }

    fn is_odd(&self) -> bool {
        self.test_bit(0)
    }

    fn from_be_bytes(input: &[u8]) -> Option<Self> {
        Self::from_be_bytes(input).ok()
    }

    fn to_be_bytes_padded(&self, length: usize) -> Vec<u8> {
        let full = ArrayEncoding::to_be_bytes(self);
        assert!(length <= full.len(), "要求的純量編碼長度超過固定寬度");
        full[full.len() - length..].to_vec()
    }

    fn to_le_bytes_fixed(&self) -> Vec<u8> {
        ArrayEncoding::to_le_bytes(self)
    }

    fn shr_public(&self, count: usize) -> Self {
        *self >> count
    }

    fn sub_public(&self, rhs: &Self) -> Self {
        *self - *rhs
    }

    fn rem_public(&self, modulus: &Self) -> Self {
        *self % *modulus
    }

    fn mul_mod_public(&self, rhs: &Self, modulus: &Self) -> Self {
        let params = FixedMontyParams::new(Odd::new(*modulus).expect("ECDSA 階必須是奇數"));
        (FixedMontyForm::new(self, params) * FixedMontyForm::new(rhs, params)).retrieve()
    }

    fn inverse_ct(&self, modulus: &Odd<Self>) -> Option<Self> {
        self.mod_odd_inverse_ct(modulus)
    }

    fn inverse_vartime(&self, modulus: &Self) -> Option<Self> {
        self.mod_odd_inverse_vartime(&Odd::new(*modulus).expect("ECDSA 階必須是奇數"))
    }

    fn mul_add_ct(&self, e: &Self, d: &Self, r: &Self, modulus: &Odd<Self>) -> Self {
        let params = FixedMontyParams::new(*modulus);
        let inverse = FixedMontyForm::new_ct(self, params);
        let e = FixedMontyForm::new(e, params);
        let d = FixedMontyForm::new_ct(d, params);
        let r = FixedMontyForm::new(r, params);
        (inverse * (e + d * r)).retrieve()
    }

    fn random_nonzero_below<R: CryptoRng + ?Sized>(rng: &mut R, modulus: &Self) -> Self {
        let modulus = NonZero::new(*modulus).expect("ECDSA 階必須非零");
        loop {
            let candidate = Self::random_mod_vartime(rng, &modulus);
            if !candidate.is_zero() {
                return candidate;
            }
        }
    }
}

pub(crate) fn bits_to_int<S: EcdsaScalar>(n: &S, input: &[u8]) -> Option<S> {
    let qlen = n.bit_length();
    let byte_length = qlen.div_ceil(8).min(input.len());
    let mut value = S::from_be_bytes(&input[..byte_length])?;
    let represented_bits = byte_length * 8;
    if represented_bits > qlen {
        value = value.shr_public(represented_bits - qlen);
    }
    Some(value)
}
